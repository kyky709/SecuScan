/**
 * Politique d'adresses IP anti-SSRF : seule une adresse publique peut être contactée.
 *
 * Pourquoi ce fichier ? SecuScan se connecte, depuis son serveur, à des sites choisis par n'importe
 * quel internaute. Sans filtre, un attaquant lui ferait contacter des services internes : les
 * métadonnées du cloud (http://169.254.169.254/, qui délivrent des identifiants), une base de
 * données sur 127.0.0.1, le réseau privé de l'hébergeur… C'est l'attaque SSRF (Server-Side Request
 * Forgery), classée dans l'OWASP Top 10.
 *
 * Place dans l'architecture : brique de base de la couche réseau. `safe-lookup.ts` applique cette
 * politique à chaque adresse renvoyée par le DNS ; `http-client.ts` et `tls-probe.ts` l'appliquent
 * aux IP écrites directement dans l'URL (Node.js ne fait alors aucune résolution DNS).
 *
 * Règles, vérifiées par l'expérience avec Node.js 24 et ipaddr.js 2.5 :
 * 1. le texte doit être une IP canonique selon `net.isIP` : ipaddr.js accepte seul des formes
 *    ambiguës (« 0177.0.0.1 », « 2130706433 ») que tous les résolveurs n'interprètent pas pareil ;
 * 2. une IPv4 « mappée » en IPv6 (::ffff:127.0.0.1) est convertie en IPv4 avant d'être jugée :
 *    le système s'y connecte réellement en IPv4 ;
 * 3. seule la plage « unicast » d'ipaddr.js est acceptée. Toutes les autres sont locales, privées
 *    ou réservées, y compris NAT64, 6to4 et Teredo : refusées sans être décodées, car elles peuvent
 *    transporter une adresse IPv4 interne ;
 * 4. en IPv6, l'adresse doit en plus appartenir à 2000::/3, seul espace attribué par l'IANA à
 *    l'Internet public : ipaddr.js laisse passer ::7f00:1 (IPv4 « compatible »), 100:0:0:1::1 ou
 *    4000::1, qu'il ne connaît pas.
 */
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";

/** Famille d'une adresse IP, au sens de Node.js (4 = IPv4, 6 = IPv6). */
export type IpFamily = 4 | 6;

/** Verdict de la politique d'adresses pour une IP. */
export type AddressCheck =
  | { allowed: true; address: string; family: IpFamily }
  | {
      allowed: false;
      address: string;
      /** Motif du refus, en français (ex. « adresse de bouclage (la machine elle-même) »). */
      reason: string;
      /** Nom technique de la plage : nom ipaddr.js, ou "invalid", "notGlobalUnicast", "policy". */
      range: string;
    };

/** Verdict de refus (utile pour typer les erreurs qui le transportent). */
export type RefusedAddress = Extract<AddressCheck, { allowed: false }>;

/**
 * Réglages de la politique d'adresses, communs aux sondes réseau.
 * Par défaut, la politique est stricte (`checkAddress`). Ces options n'existent que pour les tests,
 * qui utilisent un serveur local sur 127.0.0.1.
 */
export interface AddressPolicyOptions {
  /**
   * Autorise toutes les adresses, même privées ou locales. Ne jamais l'activer en production :
   * cela désactiverait la protection anti-SSRF.
   */
  allowPrivate?: boolean;
  /**
   * Politique de remplacement : `true` si l'adresse peut être contactée. Sert par exemple à
   * n'autoriser que le serveur de test, pour vérifier que tout le reste est bien refusé.
   */
  isAllowed?: (address: string) => boolean;
}

/** Seul espace IPv6 attribué par l'IANA à l'Internet public (« global unicast »). */
const IPV6_GLOBAL_UNICAST = ipaddr.IPv6.parseCIDR("2000::/3");

/**
 * Motif affiché pour chaque plage refusée. Les noms sont ceux d'ipaddr.js, comparés comme de
 * simples chaînes : ses types TypeScript ne listent pas toutes les plages qu'il renvoie.
 */
const RANGE_REASONS: Readonly<Record<string, string>> = {
  invalid: "adresse IP invalide ou écrite sous une forme non canonique",
  unspecified: "adresse non spécifiée, qui désigne la machine elle-même",
  loopback: "adresse de bouclage (la machine elle-même)",
  private: "réseau privé (RFC 1918)",
  uniqueLocal: "réseau privé IPv6 (fc00::/7)",
  linkLocal: "adresse lien-local (métadonnées cloud)",
  carrierGradeNat: "espace partagé des opérateurs (CGNAT), qui héberge aussi des métadonnées cloud",
  multicast: "adresse de multidiffusion",
  broadcast: "adresse de diffusion générale",
  reserved: "plage réservée (documentation, tests ou usage futur)",
  benchmarking: "plage réservée aux tests de performance",
  amt: "plage d'infrastructure réservée (AMT)",
  as112: "plage d'infrastructure DNS réservée (AS112)",
  as112v6: "plage d'infrastructure DNS réservée (AS112)",
  rfc6052: "préfixe NAT64 (RFC 6052), qui peut cacher une adresse IPv4 interne",
  rfc6145: "adresse IPv4 traduite (RFC 6145), qui peut cacher une adresse IPv4 interne",
  "6to4": "adresse 6to4 (2002::/16), qui peut cacher une adresse IPv4 interne",
  teredo: "adresse Teredo (2001::/32), qui peut cacher une adresse IPv4 interne",
  discard: "préfixe de rejet IPv6 (100::/64)",
  orchid2: "identifiant ORCHID, non routable",
  deprecatedOrchid: "identifiant ORCHID, non routable",
  deprecatedSiteLocal: "adresse site-local IPv6 obsolète (fec0::/10)",
  segmentRouting: "plage réservée au routage par segments (SRv6)",
  droneRemoteIdProtocolEntityTags: "plage réservée (identification des drones)",
  notGlobalUnicast: "adresse IPv6 hors de l'espace public 2000::/3",
  policy: "adresse refusée par la politique d'adresses configurée",
};

/** Motif d'une plage spéciale qu'ipaddr.js connaît mais que la table ci-dessus ne nomme pas. */
const DEFAULT_REASON = "plage d'adresses spéciale ou réservée";

/** Retire les crochets d'une IPv6 écrite comme dans une URL (« [::1] » → « ::1 »). */
export function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Indique si `host` est une adresse IP littérale : IPv4, ou IPv6 avec ou sans crochets.
 * Seules les formes canoniques comptent : « 2130706433 » n'est pas une IP ici (l'analyseur d'URL
 * l'a déjà convertie en « 127.0.0.1 » s'il s'agissait de l'hôte d'une URL).
 */
export function isIpLiteral(host: string): boolean {
  const bracketed = host.startsWith("[") && host.endsWith("]");
  const family = isIP(stripBrackets(host));
  return bracketed ? family === 6 : family !== 0;
}

/** Verdict de refus, avec le motif français de la plage. */
function refuse(address: string, range: string): RefusedAddress {
  return { allowed: false, address, reason: RANGE_REASONS[range] ?? DEFAULT_REASON, range };
}

/** Analyse une IP déjà reconnue par `net.isIP` ; null si ipaddr.js la refuse malgré tout. */
function parseAddress(address: string): ipaddr.IPv4 | ipaddr.IPv6 | null {
  try {
    return ipaddr.parse(address);
  } catch {
    // Cas extrême (zone IPv6 exotique, ex. « fe80::1%eth0.5 ») : dans le doute, on refuse.
    return null;
  }
}

/**
 * Applique la politique anti-SSRF stricte : l'adresse n'est autorisée que si elle est publique.
 *
 * @param address IP au format texte (les crochets d'une IPv6 sont acceptés)
 */
export function checkAddress(address: string): AddressCheck {
  const bare = stripBrackets(address);
  const family = isIP(bare);
  const parsed = family === 0 ? null : parseAddress(bare);
  if (parsed === null) return refuse(bare, "invalid");

  // ::ffff:a.b.c.d atteint réellement a.b.c.d : on la juge comme l'IPv4 qu'elle contient.
  const effective =
    parsed instanceof ipaddr.IPv6 && parsed.isIPv4MappedAddress() ? parsed.toIPv4Address() : parsed;
  const range: string = effective.range();
  if (range !== "unicast") return refuse(bare, range);
  if (effective instanceof ipaddr.IPv6 && !effective.match(IPV6_GLOBAL_UNICAST)) {
    return refuse(bare, "notGlobalUnicast");
  }
  return { allowed: true, address: bare, family: family === 4 ? 4 : 6 };
}

/**
 * Juge une adresse selon les réglages : politique stricte par défaut, politique de test sinon.
 * Un refus garde le motif précis de `checkAddress` quand il existe (plus parlant que « refusée »),
 * et une adresse illisible reste refusée dans tous les cas.
 */
export function applyAddressPolicy(
  address: string,
  options: AddressPolicyOptions = {},
): AddressCheck {
  const verdict = checkAddress(address);
  const { allowPrivate = false, isAllowed } = options;
  const strict = !allowPrivate && isAllowed === undefined;
  if (strict || (!verdict.allowed && verdict.range === "invalid")) return verdict;

  if (allowPrivate || isAllowed?.(verdict.address) === true) {
    return { allowed: true, address: verdict.address, family: isIP(verdict.address) === 6 ? 6 : 4 };
  }
  return verdict.allowed ? refuse(verdict.address, "policy") : verdict;
}
