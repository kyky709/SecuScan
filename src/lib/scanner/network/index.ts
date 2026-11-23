/**
 * Couche réseau de SecuScan : API publique.
 *
 * Toutes les entrées/sorties réseau du scanner passent par ce dossier, et toutes appliquent la même
 * politique anti-SSRF (ip.ts pour les adresses, safe-lookup.ts pour le DNS) :
 * - `safeFetch` : requête HTTP(S) sûre, redirections revalidées (http-client.ts) ;
 * - `probeTls` : certificat, version de TLS, anciens protocoles (tls-probe.ts) ;
 * - `resolveCaa` : enregistrements DNS CAA (dns.ts) ;
 * - `resolveHost` : pré-contrôle DNS de la cible par l'orchestrateur (safe-lookup.ts).
 *
 * Ces fonctions prêtes à l'emploi sont strictes. Les fabriques (`createFetcher`, `createTlsProber`,
 * `createCaaResolver`, `createSafeLookup`) servent aux tests : DNS simulé, serveur local autorisé.
 * Aucune de ces fonctions ne lève d'exception : elles renvoient un `Result` (voir types.ts).
 */
export type { CaaQuery, CaaResolverOptions } from "./dns";
export { createCaaResolver, resolveCaa } from "./dns";
export type { FetcherOptions } from "./http-client";
export { createFetcher, safeFetch } from "./http-client";
export type { AddressCheck, AddressPolicyOptions, IpFamily, RefusedAddress } from "./ip";
export { applyAddressPolicy, checkAddress, isIpLiteral, stripBrackets } from "./ip";
export type {
  HostResolver,
  ResolvedAddress,
  ResolveHostOptions,
  SafeLookupOptions,
} from "./safe-lookup";
export { BlockedAddressError, createSafeLookup, resolveHost } from "./safe-lookup";
export type { TlsProberOptions } from "./tls-probe";
export { createTlsProber, probeTls } from "./tls-probe";
