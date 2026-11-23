// Toutes les entrées/sorties réseau du scanner passent par ce dossier et appliquent la même
// politique anti-SSRF. Les fonctions prêtes à l'emploi sont strictes ; les fabriques `create*`
// servent aux tests (DNS simulé, serveur local autorisé).
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
