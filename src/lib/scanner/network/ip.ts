/**
 * Politique d'adresses anti-SSRF : seule une adresse publique peut être contactée. `safe-lookup.ts`
 * l'applique à chaque adresse renvoyée par le DNS ; les sondes, aux IP écrites dans l'URL (Node.js
 * ne fait alors aucune résolution).
 *
 * Règles, vérifiées avec Node.js 24 et ipaddr.js 2.5 :
 * 1. forme canonique selon `net.isIP` : ipaddr.js accepte seul des formes ambiguës (« 0177.0.0.1 »,
 *    « 2130706433 ») que tous les résolveurs n'interprètent pas pareil ;
 * 2. une IPv4 mappée (::ffff:127.0.0.1) est jugée comme l'IPv4 à laquelle le système se connecte ;
 * 3. seule la plage « unicast » d'ipaddr.js est acceptée. NAT64, 6to4 et Teredo sont refusées sans
 *    être décodées, car elles peuvent transporter une IPv4 interne ;
 * 4. en IPv6, l'adresse doit aussi appartenir à 2000::/3, seul espace public attribué par l'IANA :
 *    ipaddr.js laisse passer ::7f00:1 (IPv4 « compatible »), 100:0:0:1::1 ou 4000::1.
 */
import { isIP } from "node:net";
import ipaddr from "ipaddr.js";

export type IpFamily = 4 | 6;

export type AddressCheck =
  | { allowed: true; address: string; family: IpFamily }
  | {
      allowed: false;
      address: string;
      /** Affiché à l'utilisateur. */
      reason: string;
      /** Nom ipaddr.js, ou "invalid", "notGlobalUnicast", "policy". */
      range: string;
    };

export type RefusedAddress = Extract<AddressCheck, { allowed: false }>;

/** Uniquement pour les tests, qui utilisent un serveur local sur 127.0.0.1. */
export interface AddressPolicyOptions {
  /** Ne jamais activer en production : désactive la protection anti-SSRF. */
  allowPrivate?: boolean;
  /** Permet de n'autoriser que le serveur de test, pour vérifier que tout le reste est refusé. */
  isAllowed?: (address: string) => boolean;
}

const IPV6_GLOBAL_UNICAST = ipaddr.IPv6.parseCIDR("2000::/3");

// Clés en simples chaînes : les types d'ipaddr.js ne listent pas toutes les plages qu'il renvoie.
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

const DEFAULT_REASON = "plage d'adresses spéciale ou réservée";

export function stripBrackets(host: string): string {
  return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}

/**
 * Formes canoniques uniquement : « 2130706433 » n'est pas une IP ici (le parseur d'URL l'a déjà
 * convertie en « 127.0.0.1 » s'il s'agissait de l'hôte d'une URL).
 */
export function isIpLiteral(host: string): boolean {
  const bracketed = host.startsWith("[") && host.endsWith("]");
  const family = isIP(stripBrackets(host));
  return bracketed ? family === 6 : family !== 0;
}

function refuse(address: string, range: string): RefusedAddress {
  return { allowed: false, address, reason: RANGE_REASONS[range] ?? DEFAULT_REASON, range };
}

function parseAddress(address: string): ipaddr.IPv4 | ipaddr.IPv6 | null {
  try {
    return ipaddr.parse(address);
  } catch {
    // Cas extrême (zone IPv6 exotique, ex. « fe80::1%eth0.5 ») : dans le doute, on refuse.
    return null;
  }
}

export function checkAddress(address: string): AddressCheck {
  const bare = stripBrackets(address);
  const family = isIP(bare);
  const parsed = family === 0 ? null : parseAddress(bare);
  if (parsed === null) return refuse(bare, "invalid");

  // ::ffff:a.b.c.d atteint réellement a.b.c.d.
  const effective =
    parsed instanceof ipaddr.IPv6 && parsed.isIPv4MappedAddress() ? parsed.toIPv4Address() : parsed;
  const range: string = effective.range();
  if (range !== "unicast") return refuse(bare, range);
  if (effective instanceof ipaddr.IPv6 && !effective.match(IPV6_GLOBAL_UNICAST)) {
    return refuse(bare, "notGlobalUnicast");
  }
  return { allowed: true, address: bare, family: family === 4 ? 4 : 6 };
}

// Un refus garde le motif précis de `checkAddress` quand il existe, et une adresse illisible reste
// refusée même avec une politique de test.
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
