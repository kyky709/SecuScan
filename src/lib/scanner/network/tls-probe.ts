/**
 * Sonde dédiée : elle donne ce qu'une requête HTTP ne fournit pas (certificat détaillé, chaîne,
 * anciens protocoles) et ne dépend pas de la réponse HTTP du site.
 *
 * - mêmes protections anti-SSRF que le client HTTP : `lookup` sûre pour un nom, vérification
 *   directe d'une IP littérale (Node.js n'appelle pas `lookup` dans ce cas) ;
 * - `rejectUnauthorized: false` pour décrire un certificat invalide au lieu d'échouer ; aucune
 *   donnée applicative n'est envoyée, la connexion est fermée juste après la négociation ;
 * - pas d'option `session` : une session reprise renverrait le verdict de validation mémorisé ;
 * - le nom d'hôte est vérifié séparément (voir `readAuthorization` dans http-client.ts) ;
 * - délai par AbortSignal : l'option `timeout` de `tls.connect` n'émet qu'un événement ;
 * - Node.js ne vérifie pas la révocation (OCSP, CRL) : un certificat révoqué apparaît valide.
 *
 * Anciens protocoles : une connexion limitée à TLS 1.0, une autre à TLS 1.1, avec
 * `DEFAULT@SECLEVEL=0` (sinon OpenSSL refuse lui-même ces versions côté client).
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

const DEFAULT_PORT = 443;
/** Court : un serveur moderne refuse aussitôt. */
const LEGACY_TIMEOUT_MS = 3_000;
const LEGACY_CIPHERS = "DEFAULT@SECLEVEL=0";
/** Comme un navigateur. */
const ALPN_PROTOCOLS = ["h2", "http/1.1"];
const MAX_CHAIN_LENGTH = 10;
const MS_PER_DAY = 86_400_000;
/** Erreurs qui prouvent un refus de version par le serveur. */
const LEGACY_REFUSAL =
  /PROTOCOL_VERSION|UNSUPPORTED_PROTOCOL|HANDSHAKE_FAILURE|WRONG_VERSION_NUMBER|INSUFFICIENT_SECURITY/;
/** Node.js donne les types en minuscules. */
const KEY_TYPE_LABELS: Readonly<Record<string, string>> = {
  rsa: "RSA",
  "rsa-pss": "RSA-PSS",
  ec: "EC",
  ed25519: "Ed25519",
  ed448: "Ed448",
  dsa: "DSA",
};

export interface TlsProberOptions extends AddressPolicyOptions {
  /** Défaut : `createSafeLookup()` avec la même politique. */
  lookup?: LookupFunction;
  /** Deux connexions de plus. Défaut : true. */
  legacyProbe?: boolean;
}

interface ProberConfig {
  policy: AddressPolicyOptions;
  lookup: LookupFunction;
  legacyProbe: boolean;
}

type ProbeOptions = NonNullable<Parameters<TlsProber>[1]>;

type LegacyVersion = "TLSv1" | "TLSv1.1";

/**
 * Seul un refus explicite de version prouve que le serveur n'accepte pas le protocole. Une erreur
 * réseau (délai, coupure) ou locale (OpenSSL sans TLS 1.0 : ERR_SSL_NO_PROTOCOLS_AVAILABLE) ne
 * prouve rien : null.
 */
export function interpretLegacyFailure(error: unknown): false | null {
  return LEGACY_REFUSAL.test(errorCode(error) ?? "") ? false : null;
}

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
    // `on` et non `once` : une erreur tardive non écoutée arrêterait le processus.
    socket.on("error", (error) => {
      signal.removeEventListener("abort", onAbort);
      reject(error);
    });
  });
}

// Node.js renvoie un tableau quand un attribut X.509 a plusieurs valeurs.
function firstValue(value: unknown): string {
  const first: unknown = Array.isArray(value) ? value[0] : value;
  return typeof first === "string" ? first : "";
}

function commonName(name: Certificate | undefined): string {
  return firstValue(name?.CN) || firstValue(name?.O);
}

// Pour l'émetteur, « Let's Encrypt » (O) est plus parlant que « E7 » (CN).
function organizationName(name: Certificate | undefined): string {
  return firstValue(name?.O) || firstValue(name?.CN);
}

/**
 * « DNS:a.fr, DNS:*.a.fr, IP Address:1.2.3.4 » → ["a.fr", "*.a.fr", "1.2.3.4"]. Les autres types
 * (e-mail, URI) ne désignent pas un serveur.
 */
function parseSubjectAltNames(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw.split(", ").flatMap((entry) => {
    const name = /^(?:DNS|IP Address):(.+)$/.exec(entry)?.[1];
    return name ? [name] : [];
  });
}

function keyTypeOf(x509: X509Certificate): string | null {
  try {
    const type = x509.publicKey.asymmetricKeyType;
    return type ? (KEY_TYPE_LABELS[type] ?? type.toUpperCase()) : null;
  } catch {
    return null; // algorithme que cette version d'OpenSSL ne sait pas lire
  }
}

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
    daysRemaining: Math.floor((validTo.getTime() - Date.now()) / MS_PER_DAY),
    serialNumber: peer.serialNumber,
    fingerprint256: peer.fingerprint256,
    keyType: keyTypeOf(x509),
    keyBits: peer.bits ?? null,
    selfSigned: x509.checkIssued(x509),
  };
}

// Pour une racine ou un certificat auto-signé, `issuerCertificate` pointe sur le certificat
// lui-même : sans borne, la boucle ne s'arrêterait jamais.
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

function describeAndClose(
  socket: TLSSocket,
  hostname: string,
  port: number,
): Omit<TlsInfo, "legacyProtocols"> {
  try {
    return describeConnection(socket, hostname, port);
  } finally {
    socket.destroy();
  }
}

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

async function probe(
  hostname: string,
  options: ProbeOptions,
  config: ProberConfig,
): Promise<Result<TlsInfo>> {
  // SNI et vérification du nom attendent le nom nu, sans crochets ni point final.
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
    // Anciens protocoles testés APRÈS la négociation principale : en parallèle, les serveurs qui
    // limitent les connexions simultanées d'un client coupaient la négociation principale (constaté
    // sur badssl.com), et avec elle le contrôle du certificat. Coût : quelques centaines de ms,
    // pendant lesquelles les autres sondes travaillent de toute façon.
    const legacyProtocols = config.legacyProbe
      ? await probeLegacyProtocols(base, deadline.signal)
      : { tls10: null, tls11: null };
    return { ok: true, value: { ...connection, legacyProtocols } };
  } catch (error) {
    const interrupted = interruptionError(deadline, "La négociation TLS n'a pas abouti");
    return { ok: false, error: interrupted ?? toNetworkError(error) };
  }
}

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
      // Une sonde ne lève jamais d'exception.
      return { ok: false, error: toNetworkError(error) };
    }
  };
}

export const probeTls: TlsProber = createTlsProber();
