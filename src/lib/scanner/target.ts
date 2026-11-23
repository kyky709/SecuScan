/**
 * Normalisation de l'adresse saisie : première ligne de défense contre les attaques SSRF.
 *
 * L'utilisateur tape une adresse libre (« example.com », « HTTPS://Example.com/page#ancre »,
 * « bücher.de »…). `normalizeTarget` la transforme en une cible unique et canonique (`ScanTarget`)
 * ou la refuse avec une `ScanError`, dont le message en français s'affiche tel quel dans l'interface.
 *
 * Pourquoi c'est un sujet de sécurité : le serveur de SecuScan va se connecter à une adresse fournie
 * par n'importe qui. Sans contrôle, on pourrait lui faire interroger « http://169.254.169.254/ »
 * (métadonnées d'un hébergeur cloud), « http://localhost:3000/ » ou le réseau interne : c'est
 * l'attaque SSRF (Server-Side Request Forgery). Ce module refuse donc dès la saisie :
 * - les schémas autres que http et https (javascript:, file:, ftp:…) ;
 * - les identifiants (« utilisateur:motdepasse@ »), que Node.js transmettrait au site analysé ;
 * - les ports autres que 80 et 443 ;
 * - les adresses IP littérales non publiques (127.0.0.1, 10.0.0.1, [::1]…) ;
 * - les noms réservés à un usage local ou privé (localhost, *.local, *.internal…).
 *
 * Ce n'est que la première barrière : un nom de domaine public peut très bien pointer vers une
 * adresse privée. La couche réseau (`network/`) revérifie donc chaque adresse résolue, au moment
 * même de la connexion (défense en profondeur).
 *
 * L'URL est analysée exclusivement par le parseur WHATWG (`URL`), celui des navigateurs et de
 * Node.js. Il normalise les formes trompeuses : « http://2130706433/ » et « http://0x7f.1/ »
 * deviennent 127.0.0.1, « BÜCHER.de » devient « xn--bcher-kva.de ». Les vérifications portent
 * ensuite sur ce résultat normalisé, jamais sur la chaîne brute : deux parseurs différents
 * pourraient ne pas comprendre la même adresse (OWASP : « Normalize before you compare »).
 */
import { isIP } from "node:net";
import { ALLOWED_PORTS, MAX_URL_LENGTH } from "@/lib/config";
import { ScanError } from "@/lib/scanner/errors";
import { checkAddress } from "@/lib/scanner/network/ip";
import type { ScanTarget } from "@/lib/scanner/types";

/** Longueur maximale d'un nom de domaine complet (RFC 1035 § 2.3.4). */
const MAX_HOSTNAME_LENGTH = 253;

/**
 * Domaines réservés à un usage local, privé ou de test : ils ne désignent jamais un site public.
 * Un nom est refusé s'il est égal à l'un d'eux ou s'il en est un sous-domaine (« nas.local »).
 * - localhost : toujours la machine locale (RFC 6761 § 6.3) ;
 * - local : réseau local en mDNS, imprimantes, NAS… (RFC 6762) ;
 * - internal : réservé par l'ICANN aux réseaux privés (ex. « metadata.google.internal ») ;
 * - home.arpa : réseaux domestiques (RFC 8375) ;
 * - lan : usage courant des box et routeurs (non normalisé) ;
 * - test, invalid, example : tests et documentation (RFC 6761) ;
 * - onion : réseau Tor, inaccessible sans Tor (RFC 7686).
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

/** Schéma explicite en tête de saisie (« https: », « javascript: »…), selon la RFC 3986 § 3.1. */
const SCHEME_PREFIX = /^[a-z][a-z\d+.-]*:/i;

/**
 * Saisie de la forme « hôte:port », sans schéma (« example.com:443 », « localhost:3000/admin »).
 * Cas à part indispensable : `new URL("example.com:443")` prendrait « example.com: » pour un schéma.
 */
const HOST_AND_PORT = /^[^/?#:@]+:\d+(?:[/?#]|$)/;

/**
 * Identifiants saisis sans schéma (« utilisateur:motdepasse@example.com ») : « utilisateur: »
 * ressemble à un schéma, mais une arobase avant toute barre oblique trahit des identifiants.
 * Reconnaître ce cas permet de refuser la saisie avec le bon message (identifiants interdits)
 * plutôt qu'avec « protocole « utilisateur » non pris en charge ». « mailto: » reste un schéma.
 */
const CREDENTIALS_WITHOUT_SCHEME = /^(?!mailto:)[^/?#:@]+:[^/?#@]*@/i;

/** Caractère de contrôle Unicode (catégorie Cc) : NUL, tabulation, retour à la ligne… */
const CONTROL_CHARACTER = /\p{Cc}/u;

/**
 * Partie (« label ») d'un nom de domaine, déjà en minuscules et en punycode : 1 à 63 caractères
 * parmi les lettres, les chiffres, « - » et « _ » (toléré : certains sous-domaines réels l'utilisent).
 * Nécessaire car le parseur WHATWG accepte des caractères absurdes dans un nom (« exa$mple.com »).
 */
const DOMAIN_LABEL = /^[a-z\d_-]{1,63}$/;

/** Extension finale (TLD) : uniquement des lettres, ou une extension internationalisée (« xn--… »). */
const TOP_LEVEL_DOMAIN = /^(?:[a-z]{2,63}|xn--[a-z\d-]{1,59})$/;

/**
 * Transforme la saisie de l'utilisateur en cible d'analyse normalisée.
 *
 * Exemples :
 * - « example.com » → https://example.com/ ;
 * - « HTTP://Bücher.DE.:80/Prix?tri=1#haut » → https://xn--bcher-kva.de/Prix?tri=1 ;
 * - « [2606:4700:4700::1111] » → https://[2606:4700:4700::1111]/ (hostname sans crochets).
 *
 * L'URL produite est toujours en HTTPS, sans port ni fragment : HTTP est sondé séparément par
 * l'orchestrateur (contrôle de la redirection HTTP → HTTPS).
 *
 * @param input saisie libre de l'utilisateur
 * @throws {ScanError} INVALID_URL, UNSUPPORTED_PROTOCOL, CREDENTIALS_IN_URL, FORBIDDEN_PORT ou
 *   TARGET_NOT_ALLOWED, avec un message en français affichable tel quel
 */
export function normalizeTarget(input: string): ScanTarget {
  // Les espaces autour de la saisie (copier-coller) sont sans signification : on les ignore.
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

/** Refuse une saisie vide, trop longue ou contenant des caractères de contrôle. */
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
  // Le parseur d'URL supprime en silence tabulations et retours à la ligne (« exa\tmple.com »
  // deviendrait « example.com ») et un retour à la ligne pourrait falsifier les journaux :
  // plutôt que de deviner ce que l'utilisateur voulait dire, on refuse.
  if (CONTROL_CHARACTER.test(value)) {
    throw new ScanError(
      "INVALID_URL",
      "L'adresse saisie contient des caractères invisibles (tabulation, retour à la ligne…) : retirez-les puis réessayez.",
    );
  }
}

/**
 * Ajoute « https:// » quand la saisie n'a pas de schéma (« example.com », « example.com:443 »).
 * Une adresse IPv6 saisie seule (« 2001:db8::1 ») est mise entre crochets, seule forme valide
 * dans une URL.
 */
function withDefaultScheme(value: string): string {
  if (isIP(value) === 6) return `https://[${value}]`;
  const hasScheme =
    SCHEME_PREFIX.test(value) &&
    !HOST_AND_PORT.test(value) &&
    !CREDENTIALS_WITHOUT_SCHEME.test(value);
  return hasScheme ? value : `https://${value}`;
}

/** Analyse l'adresse avec le parseur WHATWG (sans exception : `URL.parse` renvoie null). */
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

/** Seuls http et https sont acceptés : javascript:, file:, ftp:, gopher:… sont refusés. */
function assertWebProtocol(url: URL): void {
  if (url.protocol === "http:" || url.protocol === "https:") return;
  const scheme = url.protocol.slice(0, -1);
  throw new ScanError(
    "UNSUPPORTED_PROTOCOL",
    `Le protocole « ${scheme} » n'est pas pris en charge : seules les adresses http:// et https:// peuvent être analysées.`,
  );
}

/**
 * Refuse « https://utilisateur:motdepasse@site/ » : Node.js enverrait ces identifiants au site
 * analysé (en-tête Authorization). On ne transmet jamais de secret à un tiers.
 */
function assertNoCredentials(url: URL): void {
  if (url.username === "" && url.password === "") return;
  throw new ScanError(
    "CREDENTIALS_IN_URL",
    "L'adresse ne doit pas contenir d'identifiants (« utilisateur:motdepasse@ ») : ils seraient transmis au site analysé.",
  );
}

/**
 * N'autorise que les ports web standard : un scanner qui accepterait n'importe quel port
 * deviendrait un outil de cartographie des services d'une machine (scan de ports).
 */
function assertAllowedPort(url: URL): void {
  // `url.port` est vide quand le port est celui par défaut du schéma (« https://site:443 » → "").
  const port = url.port === "" ? defaultPort(url.protocol) : Number(url.port);
  if (ALLOWED_PORTS.has(port)) return;
  throw new ScanError(
    "FORBIDDEN_PORT",
    `Le port ${port} n'est pas autorisé : SecuScan n'analyse que les ports web standard (80 pour HTTP, 443 pour HTTPS).`,
  );
}

/** Port implicite d'un schéma web. */
function defaultPort(protocol: string): number {
  return protocol === "https:" ? 443 : 80;
}

/**
 * Nom d'hôte canonique. Le parseur l'a déjà mis en minuscules et converti en punycode ; on retire
 * en plus les crochets d'une adresse IPv6 (« [::1] » → « ::1 ») et le point final d'un nom
 * absolu (« example.com. » désigne le même site que « example.com »).
 */
function canonicalHostname(hostname: string): string {
  if (hostname.startsWith("[") && hostname.endsWith("]")) return hostname.slice(1, -1);
  return hostname.endsWith(".") ? hostname.slice(0, -1) : hostname;
}

/**
 * Refuse une adresse IP littérale non publique (bouclage, réseau privé, lien-local…).
 * La politique d'adresses est celle de la couche réseau (`checkAddress`), pour qu'une seule et
 * même règle s'applique à la saisie et à chaque connexion.
 */
function assertPublicIpAddress(address: string): void {
  const verdict = checkAddress(address);
  if (verdict.allowed) return;
  throw new ScanError(
    "TARGET_NOT_ALLOWED",
    `L'adresse ${address} n'est pas une adresse publique : ${verdict.reason}. Par sécurité, SecuScan n'analyse que des sites accessibles depuis Internet.`,
  );
}

/** Refuse les noms réservés à un usage local et les noms de domaine mal formés. */
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

/** Le nom est-il un domaine réservé, ou l'un de ses sous-domaines ? */
function isSpecialUseDomain(hostname: string): boolean {
  return SPECIAL_USE_DOMAINS.some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`),
  );
}

/**
 * URL analysée : https://hôte/chemin?requête. Le port est omis (80 et 443 sont les ports par
 * défaut de HTTP et HTTPS) ainsi que le fragment (« #ancre » n'est jamais envoyé au serveur).
 */
function buildScanUrl(hostname: string, url: URL): string {
  const host = isIP(hostname) === 6 ? `[${hostname}]` : hostname;
  return `https://${host}${url.pathname}${url.search}`;
}
