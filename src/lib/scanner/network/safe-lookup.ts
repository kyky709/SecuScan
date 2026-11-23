/**
 * Résolution DNS sûre : un nom d'hôte n'est accepté que si TOUTES ses adresses sont publiques.
 *
 * Pourquoi ? Vérifier le texte de l'URL ne suffit pas : « intranet.exemple.fr » peut pointer vers
 * 10.0.0.5, et un attaquant qui contrôle un serveur DNS peut répondre une adresse publique au
 * moment de la vérification, puis une adresse interne au moment de la connexion (« DNS rebinding »).
 *
 * La parade : la vérification a lieu DANS la fonction `lookup` que le socket appelle lui-même pour
 * se connecter. Les adresses vérifiées sont exactement celles que Node.js utilise : il n'existe
 * aucune fenêtre entre la vérification et la connexion (pas de TOCTOU, « time of check to time of
 * use »).
 *
 * Contraintes de Node.js 24, vérifiées par l'expérience :
 * - avec Happy Eyeballs (actif par défaut), Node.js appelle `lookup` avec `{ all: true }` et attend
 *   un tableau `[{ address, family }, …]` ; sans `all`, il attend `(null, adresse, famille)` ;
 * - un tableau vide fait planter Node.js (TypeError dans node:net) : on renvoie ENOTFOUND à la place ;
 * - une seule adresse interdite suffit à refuser le nom : Node.js peut essayer chacune d'elles.
 *
 * Place dans l'architecture : `createSafeLookup()` est l'option `lookup` des requêtes HTTP
 * (http-client.ts) et des connexions TLS (tls-probe.ts) ; `resolveHost()` est le pré-contrôle de
 * l'orchestrateur (scan.ts) avant le lancement des sondes. Ce module fournit aussi deux petits
 * utilitaires partagés par la couche réseau : `errorCode` et `untilAborted`.
 */
import type { LookupOptions } from "node:dns";
import { lookup as dnsLookup } from "node:dns/promises";
import type { LookupFunction } from "node:net";
import { DNS_TIMEOUT_MS } from "@/lib/config";
import type { NetworkError, Result } from "@/lib/scanner/types";
import {
  type AddressPolicyOptions,
  applyAddressPolicy,
  type IpFamily,
  isIpLiteral,
  type RefusedAddress,
  stripBrackets,
} from "./ip";

/** Adresse IP obtenue par résolution DNS. */
export interface ResolvedAddress {
  address: string;
  family: IpFamily;
}

/** Résolution « nom → adresses ». Remplaçable dans les tests pour simuler un DNS. */
export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;

/** Réglages de la résolution sûre (politique d'adresses + résolveur). */
export interface SafeLookupOptions extends AddressPolicyOptions {
  /** Résolution à utiliser. Défaut : getaddrinfo, exactement comme Node.js pour se connecter. */
  resolve?: HostResolver;
}

/** Réglages du pré-contrôle `resolveHost`. */
export interface ResolveHostOptions extends SafeLookupOptions {
  /** Délai maximal de la résolution, en millisecondes. Défaut : `DNS_TIMEOUT_MS`. */
  timeoutMs?: number;
}

/**
 * Erreur produite quand un nom d'hôte pointe vers une adresse interdite.
 * Son code `EBLOCKED` traverse Node.js intact : il devient l'erreur de la requête, que la couche
 * réseau traduit en `BLOCKED_ADDRESS`.
 */
export class BlockedAddressError extends Error {
  readonly code = "EBLOCKED";
  readonly hostname: string;
  readonly address: string;
  readonly range: string;

  constructor(hostname: string, refusal: RefusedAddress) {
    super(describeBlockedAddress(hostname, refusal.address, refusal.reason));
    this.name = "BlockedAddressError";
    this.hostname = hostname;
    this.address = refusal.address;
    this.range = refusal.range;
  }
}

/**
 * Message français expliquant le refus d'une adresse, pour une IP littérale (« L'adresse … ») comme
 * pour un nom d'hôte (« « nom » pointe vers … »).
 *
 * Pour un nom, l'adresse résolue n'est volontairement PAS citée : le message finit dans le rapport
 * renvoyé au visiteur, et un site piégé qui redirige vers « db.interne » ou « redis » permettrait
 * sinon de lire, rapport après rapport, les adresses que le DNS interne de l'hébergeur associe à ces
 * noms (cartographie du réseau interne). La catégorie (« réseau privé », « bouclage »…) suffit.
 */
export function describeBlockedAddress(hostname: string, address: string, reason: string): string {
  const subject =
    stripBrackets(hostname) === address
      ? `L'adresse ${address} n'est pas publique`
      : `« ${hostname} » pointe vers une adresse non publique`;
  return `${subject} : ${reason}. SecuScan refuse de la contacter (protection anti-SSRF).`;
}

/** Code d'une erreur Node.js (ENOTFOUND, ECONNREFUSED…), s'il existe et s'il est textuel. */
export function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}

/**
 * Attend `promise`, mais abandonne dès que `signal` se déclenche (délai dépassé, scan annulé) en
 * rejetant avec `signal.reason`. L'opération sous-jacente continue (getaddrinfo ne s'annule pas) :
 * son résultat tardif est simplement ignoré.
 */
export function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
    // Toujours s'abonner à `promise` : un rejet tardif non écouté arrêterait le processus.
    promise.then(resolve, reject).finally(() => signal.removeEventListener("abort", onAbort));
  });
}

/** Résolution par défaut : getaddrinfo, qui lit aussi /etc/hosts, comme Node.js pour se connecter. */
const systemResolve: HostResolver = async (hostname) => {
  const entries = await dnsLookup(hostname, { all: true, verbatim: true });
  return entries.map(({ address, family }) => ({ address, family: family === 6 ? 6 : 4 }));
};

/** Erreur « nom introuvable », au format des erreurs DNS de Node.js. */
function notFoundError(hostname: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), {
    code: "ENOTFOUND",
    hostname,
  });
}

/** Garantit une instance d'Error (seul type que le rappel de `lookup` accepte). */
function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

/** Famille imposée par la requête (option `family`), ou null si les deux conviennent. */
function requestedFamily(options: LookupOptions): IpFamily | null {
  if (options.family === 4 || options.family === "IPv4") return 4;
  if (options.family === 6 || options.family === "IPv6") return 6;
  return null;
}

/**
 * Résout un nom et vérifie CHAQUE adresse. Rejette avec `BlockedAddressError` si une seule est
 * interdite, avec ENOTFOUND si le DNS ne renvoie aucune adresse.
 */
async function resolveAllowedAddresses(
  hostname: string,
  options: SafeLookupOptions,
): Promise<ResolvedAddress[]> {
  const addresses = await (options.resolve ?? systemResolve)(hostname);
  if (addresses.length === 0) throw notFoundError(hostname);
  for (const { address } of addresses) {
    const verdict = applyAddressPolicy(address, options);
    if (!verdict.allowed) throw new BlockedAddressError(hostname, verdict);
  }
  return addresses;
}

/**
 * Crée une fonction `lookup` sûre, à passer aux options de `http.request` ou de `tls.connect`.
 * Stricte par défaut : seules les adresses publiques sont renvoyées à Node.js.
 */
export function createSafeLookup(options: SafeLookupOptions = {}): LookupFunction {
  return (hostname, lookupOptions, callback) => {
    resolveAllowedAddresses(hostname, options).then(
      (addresses) => {
        const family = requestedFamily(lookupOptions);
        const usable =
          family === null ? addresses : addresses.filter((entry) => entry.family === family);
        const first = usable[0];
        // Jamais de tableau vide : Node.js 24 planterait en lisant le premier élément.
        if (first === undefined) callback(notFoundError(hostname), "");
        else if (lookupOptions.all) callback(null, usable);
        else callback(null, first.address, first.family);
      },
      (error: unknown) => callback(asError(error), ""),
    );
  };
}

/** Traduit l'échec d'une résolution en `NetworkError` (adresse interdite ou DNS en échec). */
function resolutionFailure(hostname: string, error: unknown, timedOut: boolean): NetworkError {
  if (error instanceof BlockedAddressError) {
    return {
      code: "BLOCKED_ADDRESS",
      message: error.message,
      // Catégorie seulement : l'adresse interne ne doit pas apparaître dans le rapport.
      detail: error.range,
    };
  }
  if (timedOut) {
    return {
      code: "DNS_FAILURE",
      message: `La résolution DNS de « ${hostname} » n'a pas abouti dans le délai imparti.`,
      detail: "ETIMEOUT",
    };
  }
  return {
    code: "DNS_FAILURE",
    message: `Le nom de domaine « ${hostname} » ne se résout pas : aucune adresse IP n'a été trouvée.`,
    detail: errorCode(error) ?? asError(error).message,
  };
}

/**
 * Pré-contrôle anti-SSRF d'un hôte (nom de domaine ou IP littérale) : renvoie ses adresses si
 * toutes sont autorisées. Codes d'erreur : `DNS_FAILURE` ou `BLOCKED_ADDRESS`.
 * Ne lève jamais d'exception.
 *
 * Ce contrôle précoce sert à refuser vite et clairement une cible interdite ; il ne remplace pas
 * la vérification faite à chaque connexion par `createSafeLookup` (le DNS peut changer entre-temps).
 */
export async function resolveHost(
  hostname: string,
  options: ResolveHostOptions = {},
): Promise<Result<ResolvedAddress[]>> {
  if (isIpLiteral(hostname)) {
    const verdict = applyAddressPolicy(hostname, options);
    if (verdict.allowed) {
      return { ok: true, value: [{ address: verdict.address, family: verdict.family }] };
    }
    return {
      ok: false,
      error: {
        code: "BLOCKED_ADDRESS",
        message: describeBlockedAddress(hostname, verdict.address, verdict.reason),
        detail: verdict.range,
      },
    };
  }

  const deadline = AbortSignal.timeout(options.timeoutMs ?? DNS_TIMEOUT_MS);
  try {
    const addresses = await untilAborted(resolveAllowedAddresses(hostname, options), deadline);
    return { ok: true, value: addresses };
  } catch (error) {
    return { ok: false, error: resolutionFailure(hostname, error, deadline.aborted) };
  }
}
