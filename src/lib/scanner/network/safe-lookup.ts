/**
 * Un nom d'hôte n'est accepté que si TOUTES ses adresses sont publiques.
 *
 * Vérifier le texte de l'URL ne suffit pas : un nom peut pointer vers 10.0.0.5, et un DNS contrôlé
 * par un attaquant peut répondre une adresse publique au moment de la vérification puis une
 * adresse interne au moment de la connexion (DNS rebinding). La vérification a donc lieu DANS la
 * fonction `lookup` que le socket appelle lui-même pour se connecter : les adresses vérifiées sont
 * exactement celles que Node.js utilise, sans fenêtre TOCTOU.
 *
 * Contraintes de Node.js 24, vérifiées par l'expérience :
 * - avec Happy Eyeballs (actif par défaut), `lookup` est appelé avec `{ all: true }` et doit
 *   renvoyer `[{ address, family }, …]` ; sans `all`, `(null, adresse, famille)` ;
 * - un tableau vide fait planter node:net (TypeError) : on renvoie ENOTFOUND à la place ;
 * - une seule adresse interdite suffit à refuser le nom : Node.js peut essayer chacune d'elles.
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

export interface ResolvedAddress {
  address: string;
  family: IpFamily;
}

export type HostResolver = (hostname: string) => Promise<ResolvedAddress[]>;

export interface SafeLookupOptions extends AddressPolicyOptions {
  resolve?: HostResolver;
}

export interface ResolveHostOptions extends SafeLookupOptions {
  /** Défaut : `DNS_TIMEOUT_MS`. */
  timeoutMs?: number;
}

// Le code `EBLOCKED` traverse Node.js intact : il devient l'erreur de la requête, que la couche
// réseau traduit en `BLOCKED_ADDRESS`.
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
 * Pour un nom, l'adresse résolue n'est volontairement PAS citée : le message finit dans le
 * rapport, et un site piégé qui redirige vers « db.interne » ou « redis » permettrait sinon de
 * cartographier, rapport après rapport, le DNS interne de l'hébergeur. La catégorie suffit.
 */
export function describeBlockedAddress(hostname: string, address: string, reason: string): string {
  const subject =
    stripBrackets(hostname) === address
      ? `L'adresse ${address} n'est pas publique`
      : `« ${hostname} » pointe vers une adresse non publique`;
  return `${subject} : ${reason}. SecuScan refuse de la contacter (protection anti-SSRF).`;
}

export function errorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) return undefined;
  return typeof error.code === "string" ? error.code : undefined;
}

/**
 * Rejette avec `signal.reason` dès que le signal se déclenche. L'opération sous-jacente continue
 * (getaddrinfo ne s'annule pas) : son résultat tardif est ignoré.
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

// getaddrinfo (qui lit aussi /etc/hosts) : exactement ce que Node.js utilise pour se connecter.
const systemResolve: HostResolver = async (hostname) => {
  const entries = await dnsLookup(hostname, { all: true, verbatim: true });
  return entries.map(({ address, family }) => ({ address, family: family === 6 ? 6 : 4 }));
};

function notFoundError(hostname: string): NodeJS.ErrnoException {
  return Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), {
    code: "ENOTFOUND",
    hostname,
  });
}

// Le rappel de `lookup` n'accepte qu'une Error.
function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function requestedFamily(options: LookupOptions): IpFamily | null {
  if (options.family === 4 || options.family === "IPv4") return 4;
  if (options.family === 6 || options.family === "IPv6") return 6;
  return null;
}

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

/** Option `lookup` de `http.request` et de `tls.connect`. */
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
 * Pré-contrôle pour refuser vite et clairement une cible interdite. Ne remplace pas la vérification
 * faite à chaque connexion par `createSafeLookup` : le DNS peut changer entre-temps.
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
