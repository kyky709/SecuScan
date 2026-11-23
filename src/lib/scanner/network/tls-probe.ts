/**
 * Sonde TLS : négocie une connexion avec le serveur (port 443) et décrit le certificat, la chaîne,
 * la version de TLS, la suite de chiffrement et ALPN ; vérifie aussi si TLS 1.0 et 1.1 sont encore
 * acceptés.
 *
 * Pourquoi une sonde dédiée alors que le client HTTP parle déjà TLS ? Elle fournit ce qu'une requête
 * HTTP ne donne pas (certificat détaillé, chaîne, anciens protocoles) et ne dépend pas de la réponse
 * HTTP du site.
 *
 * Choix importants :
 * - mêmes protections anti-SSRF que le client HTTP : `lookup` sûre pour un nom, vérification directe
 *   d'une IP littérale (Node.js n'appelle pas `lookup` dans ce cas) ;
 * - `rejectUnauthorized: false` : on veut décrire un certificat invalide, pas échouer. Aucune donnée
 *   applicative n'est envoyée : la connexion est fermée juste après la négociation ;
 * - nouvelle session à chaque connexion (pas d'option `session`) : une session reprise renverrait le
 *   verdict de validation mémorisé au lieu de le recalculer ;
 * - le nom d'hôte est toujours vérifié séparément (voir `readAuthorization` dans http-client.ts) ;
 * - délai total par AbortSignal : l'option `timeout` de `tls.connect` n'émet qu'un événement et
 *   n'interrompt rien ;
 * - limite connue : Node.js ne vérifie pas la révocation (OCSP, CRL) ; un certificat révoqué
 *   apparaît comme valide.
 *
 * Anciens protocoles : deux connexions courtes, en parallèle, limitées à TLS 1.0 puis à TLS 1.1, avec
 * `DEFAULT@SECLEVEL=0` (sinon OpenSSL refuse lui-même ces versions côté client). Succès → true ;
 * refus de version par le serveur → false ; tout autre échec (délai, coupure…) → null (non concluant).
 *
 * Place dans l'architecture : sonde lancée par l'orchestrateur (scan.ts) ; son résultat `TlsInfo` est
 * noté par les contrôles tls-certificate et tls-protocol.
 */
import type { X509Certificate } from "node:crypto";
import type { LookupFunction } from "node:net";
import {
  type Certificate,
  type ConnectionOptions,
  connect,
  type DetailedPeerCertificate,
  type TLSSocket,
} from "node:tls";
import { TLS_TIMEOUT_MS } from "@/lib/config";
import type { CertificateInfo, Result, TlsInfo, TlsProber } from "@/lib/scanner/types";
import {
  createDeadline,
  interruptionError,
  readAuthorization,
  toNetworkError,
} from "./http-client";
import { type AddressPolicyOptions, applyAddressPolicy, isIpLiteral, stripBrackets } from "./ip";
import { createSafeLookup, describeBlockedAddress, errorCode } from "./safe-lookup";

/** Port HTTPS standard. */
const DEFAULT_PORT = 443;
/** Délai de chaque sonde d'ancien protocole : court, car un serveur moderne refuse aussitôt. */
const LEGACY_TIMEOUT_MS = 3_000;
/** Niveau de sécurité 0 d'OpenSSL : seul moyen de proposer TLS 1.0/1.1 (uniquement sur ces sondes). */
const LEGACY_CIPHERS = "DEFAULT@SECLEVEL=0";
/** Protocoles applicatifs proposés par ALPN, comme un navigateur. */
const ALPN_PROTOCOLS = ["h2", "http/1.1"];
/** Longueur maximale de la chaîne parcourue (garde-fou contre une chaîne anormale). */
const MAX_CHAIN_LENGTH = 10;
/** Millisecondes par jour. */
const MS_PER_DAY = 86_400_000;
/**
 * Erreurs qui prouvent un refus de version par le serveur : alerte « protocol_version », version
 * non prise en charge, échec de négociation (aucune suite commune pour cette version)…
 */
const LEGACY_REFUSAL =
  /PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|HANDSHAKE_FAILURE|WRONG_VERSION_NUMBER|INSUFFICIENT_SECURITY/;
/** Libellés des types de clé publique (Node.js les donne en minuscules). */
const KEY_TYPE_LABELS: Readonly<Record<string, string>> = {
  rsa: "RSA",
  "rsa-pss": "RSA-PSS",
  ec: "EC",
  ed25519: "Ed25519",
  ed448: "Ed448",
  dsa: "DSA",
};

/** Réglages de la sonde TLS. Par défaut tout est strict ; les autres valeurs servent aux tests. */
export interface TlsProberOptions extends AddressPolicyOptions {
  /** Fonction `lookup` des sockets. Défaut : `createSafeLookup()` avec la même politique. */
  lookup?: LookupFunction;
  /** Tester aussi TLS 1.0 et 1.1 (deux connexions de plus). Défaut : true. */
  legacyProbe?: boolean;
}

/** Réglages résolus de la sonde (valeurs par défaut appliquées). */
interface ProberConfig {
  policy: AddressPolicyOptions;
  lookup: LookupFunction;
  legacyProbe: boolean;
}

/** Options d'un appel de sonde (port, délai, signal d'annulation). */
type ProbeOptions = NonNullable<Parameters<TlsProber>[1]>;

/** Ancien protocole testé. */
type LegacyVersion = "TLSv1" | "TLSv1.1";

/**
 * Interprète l'échec d'une connexion limitée à TLS 1.0 ou 1.1.
 * Un refus explicite de version prouve que le serveur n'accepte pas ce protocole : false. Une erreur
 * réseau (délai, coupure, port fermé) ou locale (OpenSSL sans TLS 1.0 :
 * ERR_SSL_NO_PROTOCOLS_AVAILABLE) ne prouve rien : null.
 */
export function interpretLegacyFailure(error: unknown): false | null {
  return LEGACY_REFUSAL.test(errorCode(error) ?? "") ? false : null;
}

/** Ouvre une connexion TLS et attend la fin de la négociation (ou l'échec, ou l'expiration). */
function handshake(options: ConnectionOptions, signal: AbortSignal): Promise<TLSSocket> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason);
      return;
    }
    const socket = connect(options);
    const onAbort = () =>
      socket.destroy(
        Object.assign(new Error("Négociation TLS interrompue"), { code: "ABORT_ERR" }),
      );
    signal.addEventListener("abort", onAbort, { once: true });
    socket.once("secureConnect", () => {
      signal.removeEventListener("abort", onAbort);
      resolve(socket);
    });
    // `on` et non `once` : une erreur tardive doit aussi être écoutée, sinon elle arrêterait le processus.
    socket.on("error", (error) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
  });
}

/** Première valeur d'un attribut de nom X.509 (Node.js renvoie un tableau s'il y en a plusieurs). */
function firstValue(value: unknown): string {
  const first: unknown = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" ? first : "";
}

/** Nom commun (CN), sinon organisation (O) : l'identité usuelle d'un maillon de la chaîne. */
function commonName(name: Certificate | undefined): string {
  return firstValue(name?.CN) || firstValue(name?.O);
}

/** Organisation (O) de l'émetteur, sinon son CN : « Let's Encrypt » est plus parlant que « E7 ». */
function organizationName(name: Certificate | undefined): string {
  return firstValue(name?.O) || firstValue(name?.CN);
}

/**
 * Noms couverts par le certificat, sans préfixe : « DNS:a.fr, DNS:*.a.fr, IP Address:1.2.3.4 » →
 * ["a.fr", "*.a.fr", "1.2.3.4"]. Les autres types (e-mail, URI) ne désignent pas un serveur.
 */
function parseSubjectAltNames(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(", ").flatMap((entry) => {
    const name = /^(?:DNS|IP Address):(.+)$/.exec(entry)?.[1];
    return name ? [name] : [];
  });
}

/** Type de clé publique lisible (« RSA », « EC »…), ou null s'il est inconnu. */
function keyTypeOf(x509: X509Certificate): string | null {
  try {
    const type = x509.publicKey.asymmetricKeyType;
    return type ? (KEY_TYPE_LABELS[type] ?? type.toUpperCase()) : null;
  } catch {
    return null; // algorithme que cette version d'OpenSSL ne sait pas lire
  }
}

/** Décrit le certificat du serveur (feuille). */
function describeCertificate(
  peer: DetailedPeerCertificate,
  x509: X509Certificate,
): CertificateInfo {
  const subjectAltNames = parseSubjectAltNames(peer.subjectaltname);
  const validTo = x509.validToDate;
  return {
    subject: commonName(peer.subject) || subjectAltNames[0] || "",
    subjectAltNames,
    issuer: organizationName(peer.issuer),
    validFrom: x509.validFromDate.toISOString(),
    validTo: validTo.toISOString(),
    // Négatif si le certificat est expiré.
    daysRemaining: Math.floor((validTo.getTime() - Date.now()) / MS_PER_DAY),
    serialNumber: peer.serialNumber,
    fingerprint256: peer.fingerprint256,
    keyType: keyTypeOf(x509),
    keyBits: peer.bits ?? null,
    selfSigned: x509.checkIssued(x509),
  };
}

/**
 * Chaîne présentée, du certificat du serveur vers la racine. Le parcours est borné : pour une racine
 * ou un certificat auto-signé, `issuerCertificate` pointe sur le certificat lui-même (référence
 * circulaire), et la boucle ne s'arrêterait jamais.
 */
function describeChain(leaf: DetailedPeerCertificate): TlsInfo["chain"] {
  const chain: TlsInfo["chain"] = [];
  const seen = new Set<string>();
  let current: DetailedPeerCertificate | undefined = leaf;
  while (current?.fingerprint256 && !seen.has(current.fingerprint256)) {
    if (chain.length >= MAX_CHAIN_LENGTH) break;
    seen.add(current.fingerprint256);
    chain.push({ subject: commonName(current.subject), issuer: commonName(current.issuer) });
    current = current.issuerCertificate;
  }
  return chain;
}

/** Décrit une connexion établie (sans les anciens protocoles, testés à part). */
function describeConnection(
  socket: TLSSocket,
  hostname: string,
  port: number,
): Omit<TlsInfo, "legacyProtocols"> {
  const peer = socket.getPeerCertificate(true);
  const x509 = socket.getPeerX509Certificate();
  const hasCertificate = x509 !== undefined && Object.keys(peer).length > 0;
  return {
    hostname,
    address: socket.remoteAddress ?? "",
    port,
    protocol: socket.getProtocol(),
    cipher: socket.getCipher()?.standardName ?? null,
    alpnProtocol: socket.alpnProtocol || null,
    ...readAuthorization(socket, hostname),
    certificate: hasCertificate ? describeCertificate(peer, x509) : null,
    chain: hasCertificate ? describeChain(peer) : [],
  };
}

/** Décrit la connexion puis la ferme, même si la description échoue. */
function describeAndClose(
  socket: TLSSocket,
  hostname: string,
  port: number,
): Omit<TlsInfo, "legacyProtocols"> {
  try {
    return describeConnection(socket, hostname, port);
  } finally {
    socket.destroy(); // la connexion ne sert qu'à observer : aucune donnée n'est envoyée
  }
}

/** Le serveur accepte-t-il exactement cette ancienne version ? (true / false / null) */
async function probeLegacyVersion(
  base: ConnectionOptions,
  version: LegacyVersion,
  parent: AbortSignal,
): Promise<boolean | null> {
  const signal = AbortSignal.any([AbortSignal.timeout(LEGACY_TIMEOUT_MS), parent]);
  try {
    const options = { ...base, minVersion: version, maxVersion: version, ciphers: LEGACY_CIPHERS };
    const socket = await handshake(options, signal);
    const negotiated = socket.getProtocol();
    socket.destroy();
    return negotiated === version;
  } catch (error) {
    return interpretLegacyFailure(error);
  }
}

/** Teste TLS 1.0 et TLS 1.1 en parallèle. Ne rejette jamais. */
async function probeLegacyProtocols(
  base: ConnectionOptions,
  parent: AbortSignal,
): Promise<TlsInfo["legacyProtocols"]> {
  const [tls10, tls11] = await Promise.all([
    probeLegacyVersion(base, "TLSv1", parent),
    probeLegacyVersion(base, "TLSv1.1", parent),
  ]);
  return { tls10, tls11 };
}

/** Sonde complète d'un hôte : validation anti-SSRF, négociation principale, anciens protocoles. */
async function probe(
  hostname: string,
  options: ProbeOptions,
  config: ProberConfig,
): Promise<Result<TlsInfo>> {
  // Ni crochets (IPv6) ni point final : SNI et vérification du nom attendent le nom nu.
  const host = stripBrackets(hostname).replace(/\.$/, "");
  const port = options.port ?? DEFAULT_PORT;
  const isIp = isIpLiteral(host);

  if (isIp) {
    // Node.js n'appelle pas `lookup` pour une IP littérale : on la vérifie ici.
    const verdict = applyAddressPolicy(host, config.policy);
    if (!verdict.allowed) {
      return {
        ok: false,
        error: {
          code: "BLOCKED_ADDRESS",
          message: describeBlockedAddress(host, verdict.address, verdict.reason),
          detail: verdict.range,
        },
      };
    }
  }

  const deadline = createDeadline(options.timeoutMs ?? TLS_TIMEOUT_MS, options.signal);
  const base: ConnectionOptions = {
    host,
    port,
    servername: isIp ? undefined : host, // SNI : jamais une IP (RFC 6066)
    lookup: config.lookup,
    rejectUnauthorized: false,
    ALPNProtocols: ALPN_PROTOCOLS,
  };
  try {
    const connection = describeAndClose(await handshake(base, deadline.signal), host, port);
    // Anciens protocoles testés APRÈS la négociation principale, et seulement si elle a réussi.
    // Les lancer en même temps faisait couper des connexions par les serveurs qui limitent les
    // connexions simultanées d'un même client (constaté sur badssl.com) : la négociation
    // principale échouait alors, et avec elle le contrôle du certificat. Le coût : quelques
    // centaines de millisecondes, pendant lesquelles les autres sondes travaillent de toute façon.
    const legacyProtocols = config.legacyProbe
      ? await probeLegacyProtocols(base, deadline.signal)
      : { tls10: null, tls11: null };
    return { ok: true, value: { ...connection, legacyProtocols } };
  } catch (error) {
    const interrupted = interruptionError(deadline, "La négociation TLS n'a pas abouti");
    return { ok: false, error: interrupted ?? toNetworkError(error) };
  }
}

/**
 * Crée une sonde TLS. Sans option, elle applique la politique stricte (adresses publiques
 * seulement) ; les options servent aux tests (serveur local, DNS simulé).
 */
export function createTlsProber(options: TlsProberOptions = {}): TlsProber {
  const policy: AddressPolicyOptions = {
    allowPrivate: options.allowPrivate,
    isAllowed: options.isAllowed,
  };
  const config: ProberConfig = {
    policy,
    lookup: options.lookup ?? createSafeLookup(policy),
    legacyProbe: options.legacyProbe ?? true,
  };
  return async (hostname, probeOptions = {}) => {
    try {
      return await probe(hostname, probeOptions, config);
    } catch (error) {
      // Filet de sécurité : une sonde ne lève jamais d'exception.
      return { ok: false, error: toNetworkError(error) };
    }
  };
}

/** Sonde TLS par défaut, stricte : c'est elle que le scanner utilise. */
export const probeTls: TlsProber = createTlsProber();
