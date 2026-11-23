/**
 * Première barrière anti-SSRF : on refuse dès la saisie les schémas autres que http(s), les
 * identifiants, les ports autres que 80/443, les IP non publiques et les noms réservés. Un domaine
 * public pouvant pointer vers une adresse privée, `network/` revérifie chaque adresse résolue au
 * moment même de la connexion.
 *
 * Les vérifications portent sur le résultat du parseur WHATWG, jamais sur la chaîne brute : il
 * normalise les formes trompeuses (« http://2130706433/ » et « http://0x7f.1/ » deviennent
 * 127.0.0.1), et deux parseurs différents pourraient ne pas comprendre la même adresse (OWASP :
 * « Normalize before you compare »).
 */
import { isIP } from "node:net";
import { ALLOWED_PORTS, MAX_URL_LENGTH } from "@/lib/config";
import { ScanError } from "@/lib/scanner/errors";
import { checkAddress } from "@/lib/scanner/network/ip";
import type { ScanTarget } from "@/lib/scanner/types";

/** RFC 1035 § 2.3.4. */
const MAX_HOSTNAME_LENGTH = 253;

/**
 * Ne désignent jamais un site public (sous-domaines compris) : localhost (RFC 6761 § 6.3), local
 * (mDNS, RFC 6762), internal (réservé par l'ICANN, ex. metadata.google.internal), home.arpa
 * (RFC 8375), lan (box et routeurs, non normalisé), test/invalid/example (RFC 6761),
 * onion (RFC 7686).
 */
const SPECIAL_USE_DOMAINS: readonly string[] = [
  "localhost",
  "local",
  "internal",
  "home.arpa",
  "lan",
  "test",
  "invalid",
  "example",
  "onion",
];

/** RFC 3986 § 3.1. */
const SCHEME_PREFIX = /^[a-z][a-z\d+.-]*:/i;

// `new URL("example.com:443")` prendrait « example.com: » pour un schéma.
const HOST_AND_PORT = /^[^/?#:@]+:\d+(?:[/?#]|$)/;

// « utilisateur:motdepasse@example.com » : « utilisateur: » ressemble à un schéma, mais l'arobase
// avant toute barre oblique trahit des identifiants. Sans ce cas, le message d'erreur parlerait
// d'un protocole « utilisateur » non pris en charge.
const CREDENTIALS_WITHOUT_SCHEME = /^(?!mailto:)[^/?#:@]+:[^/?#@]*@/i;

const CONTROL_CHARACTER = /\p{Cc}/u;

// Le parseur WHATWG accepte des caractères absurdes dans un nom (« exa$mple.com »). « _ » est
// toléré : certains sous-domaines réels l'utilisent.
const DOMAIN_LABEL = /^[a-z\d_-]{1,63}$/;

const TOP_LEVEL_DOMAIN = /^(?:[a-z]{2,63}|xn--[a-z\d-]{1,59})$/;

/**
 * « HTTP://Bücher.DE.:80/Prix?tri=1#haut » → https://xn--bcher-kva.de/Prix?tri=1
 *
 * Toujours en HTTPS : HTTP est sondé séparément pour contrôler la redirection HTTP → HTTPS.
 */
export function normalizeTarget(input: string): ScanTarget {
  const trimmed = input.trim();
  assertUsableInput(trimmed);

  const url = parseUrl(withDefaultScheme(trimmed));
  assertWebProtocol(url);
  assertNoCredentials(url);
  assertAllowedPort(url);

  const hostname = canonicalHostname(url.hostname);
  const isIpAddress = isIP(hostname) !== 0;
  if (isIpAddress) {
    assertPublicIpAddress(hostname);
  } else {
    assertPublicDomainName(hostname);
  }

  return { input: trimmed, url: buildScanUrl(hostname, url), hostname, isIpAddress };
}

function assertUsableInput(value: string): void {
  if (value === "") {
    throw new ScanError(
      "INVALID_URL",
      "Saisissez l'adresse du site à analyser, par exemple « example.com ».",
    );
  }
  if (value.length > MAX_URL_LENGTH) {
    throw new ScanError(
      "INVALID_URL",
      `L'adresse saisie est trop longue (${MAX_URL_LENGTH} caractères au maximum).`,
    );
  }
  // Le parseur d'URL supprime en silence tabulations et retours à la ligne, et un retour à la
  // ligne pourrait falsifier les journaux : plutôt que de deviner, on refuse.
  if (CONTROL_CHARACTER.test(value)) {
    throw new ScanError(
      "INVALID_URL",
      "L'adresse saisie contient des caractères invisibles (tabulation, retour à la ligne…) : retirez-les puis réessayez.",
    );
  }
}

function withDefaultScheme(value: string): string {
  if (isIP(value) === 6) return `https://[${value}]`;
  const hasScheme =
    SCHEME_PREFIX.test(value) &&
    !HOST_AND_PORT.test(value) &&
    !CREDENTIALS_WITHOUT_SCHEME.test(value);
  return hasScheme ? value : `https://${value}`;
}

function parseUrl(value: string): URL {
  const url = URL.parse(value);
  if (url === null) {
    throw new ScanError(
      "INVALID_URL",
      "L'adresse saisie n'est pas une URL valide (exemple attendu : https://example.com).",
    );
  }
  return url;
}

function assertWebProtocol(url: URL): void {
  if (url.protocol === "http:" || url.protocol === "https:") return;
  const scheme = url.protocol.slice(0, -1);
  throw new ScanError(
    "UNSUPPORTED_PROTOCOL",
    `Le protocole « ${scheme} » n'est pas pris en charge : seules les adresses http:// et https:// peuvent être analysées.`,
  );
}

// Node.js enverrait ces identifiants au site analysé (en-tête Authorization).
function assertNoCredentials(url: URL): void {
  if (url.username === "" && url.password === "") return;
  throw new ScanError(
    "CREDENTIALS_IN_URL",
    "L'adresse ne doit pas contenir d'identifiants (« utilisateur:motdepasse@ ») : ils seraient transmis au site analysé.",
  );
}

// Accepter n'importe quel port ferait de SecuScan un scanner de ports.
function assertAllowedPort(url: URL): void {
  // Vide quand c'est le port par défaut du schéma (« https://site:443 » → "").
  const port = url.port === "" ? defaultPort(url.protocol) : Number(url.port);
  if (ALLOWED_PORTS.has(port)) return;
  throw new ScanError(
    "FORBIDDEN_PORT",
    `Le port ${port} n'est pas autorisé : SecuScan n'analyse que les ports web standard (80 pour HTTP, 443 pour HTTPS).`,
  );
}

function defaultPort(protocol: string): number {
  return protocol === "https:" ? 443 : 80;
}

// Minuscules et punycode sont déjà faits par le parseur.
function canonicalHostname(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return hostname.slice(1, -1);
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

// Même politique que la couche réseau : une seule règle pour la saisie et pour chaque connexion.
function assertPublicIpAddress(address: string): void {
  const verdict = checkAddress(address);
  if (verdict.allowed) return;
  throw new ScanError(
    "TARGET_NOT_ALLOWED",
    `L'adresse ${address} n'est pas une adresse publique : ${verdict.reason}. Par sécurité, SecuScan n'analyse que des sites accessibles depuis Internet.`,
  );
}

function assertPublicDomainName(hostname: string): void {
  if (isSpecialUseDomain(hostname)) {
    throw new ScanError(
      "TARGET_NOT_ALLOWED",
      `« ${hostname} » est un nom réservé à un usage local ou privé : SecuScan n'analyse que des sites publics.`,
    );
  }
  if (hostname.length > MAX_HOSTNAME_LENGTH) {
    throw new ScanError(
      "INVALID_URL",
      `Le nom de domaine est trop long (${MAX_HOSTNAME_LENGTH} caractères au maximum).`,
    );
  }
  const labels = hostname.split(".");
  if (!labels.every((label) => DOMAIN_LABEL.test(label))) {
    throw new ScanError("INVALID_URL", `« ${hostname} » n'est pas un nom de domaine valide.`);
  }
  if (labels.length < 2) {
    throw new ScanError(
      "INVALID_URL",
      `« ${hostname} » n'est pas un nom de domaine complet : il manque l'extension (par exemple « .fr » ou « .com »).`,
    );
  }
  const topLevelDomain = labels.at(-1) ?? "";
  if (!TOP_LEVEL_DOMAIN.test(topLevelDomain)) {
    throw new ScanError(
      "INVALID_URL",
      `« ${hostname} » n'est pas un nom de domaine valide : l'extension « .${topLevelDomain} » n'existe pas.`,
    );
  }
}

function isSpecialUseDomain(hostname: string): boolean {
  return SPECIAL_USE_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );
}

// Ni port (forcément 80 ou 443, les ports par défaut) ni fragment (jamais envoyé au serveur).
function buildScanUrl(hostname: string, url: URL): string {
  const host = isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  return `https://${host}${url.pathname}${url.search}`;
}
