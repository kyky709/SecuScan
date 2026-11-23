/**
 * Recherche CAA (RFC 8659 § 3) : le nom lui-même, puis ses parents successifs jusqu'à la racine
 * exclue ; le premier ensemble non vide s'applique. Une liste vide (CNAME dont la cible n'a pas de
 * CAA), ENODATA et ENOTFOUND font remonter au parent. Une panne (SERVFAIL, délai, refus) rend la
 * recherche non concluante : on renvoie une erreur plutôt que d'affirmer « aucun CAA ».
 *
 * `Resolver` (c-ares) plutôt que `dns.lookup` (getaddrinfo), qui ne sait résoudre que des adresses.
 */
import { Resolver } from "node:dns/promises";
import { DNS_TIMEOUT_MS } from "@/lib/config";
import type { CaaInfo, CaaRecord, CaaResolver, NetworkError, Result } from "@/lib/scanner/types";
import { isIpLiteral } from "./ip";
import { errorCode, untilAborted } from "./safe-lookup";

/** Enregistrements bruts de Node.js : `{ critical, type: "CAA", <étiquette>: valeur }`. */
export type CaaQuery = (name: string) => Promise<readonly object[]>;

export interface CaaResolverOptions {
  resolveCaa?: CaaQuery;
}

/** Par tentative ; le délai global de la recherche borne le tout. */
const QUERY_TIMEOUT_MS = 1_500;
/** Un paquet UDP perdu ne doit pas rendre le test non concluant. */
const QUERY_TRIES = 2;
const CLIMB_CODES: ReadonlySet<string> = new Set(["ENODATA", "ENOTFOUND"]);

function systemQuery(): CaaQuery {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: QUERY_TRIES });
  return (name) => resolver.resolveCaa(name);
}

/** « a.b.fr » → [a.b.fr, b.fr, fr]. */
function candidateNames(hostname: string): string[] {
  const labels = hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .split(".")
    .filter((label) => label !== "");
  return labels.map((_label, index) => labels.slice(index).join("."));
}

// L'étiquette est la seule propriété autre que `critical` et `type` ; une étiquette inconnue est
// conservée telle quelle.
function normalizeRecord(raw: object): CaaRecord[] {
  const entries: Array<[string, unknown]> = Object.entries(raw);
  let critical = 0;
  let tag: [name: string, value: unknown] | undefined;
  for (const [key, value] of entries) {
    if (key === "critical") critical = typeof value === "number" ? value : 0;
    else if (key !== "type" && tag === undefined) tag = [key, value];
  }
  return tag ? [{ critical, tag: tag[0], value: String(tag[1]) }] : [];
}

function caaFailure(error: unknown, signal: AbortSignal, name: string): NetworkError {
  const code = errorCode(error);
  if (signal.aborted || code === "ETIMEOUT") {
    return {
      code: "TIMEOUT",
      message: "Le serveur DNS n'a pas répondu à temps : enregistrements CAA non vérifiés.",
      detail: code ?? "délai dépassé",
    };
  }
  return {
    code: "DNS_FAILURE",
    message: `Le serveur DNS n'a pas pu répondre pour « ${name} » : enregistrements CAA non vérifiés.`,
    detail: code ?? (error instanceof Error ? error.message : String(error)),
  };
}

async function findCaa(
  hostname: string,
  query: CaaQuery,
  signal: AbortSignal,
): Promise<Result<CaaInfo>> {
  if (isIpLiteral(hostname)) return { ok: true, value: { domain: null, records: [] } };

  for (const name of candidateNames(hostname)) {
    let raw: readonly object[];
    try {
      raw = await untilAborted(query(name), signal);
    } catch (error) {
      if (!signal.aborted && CLIMB_CODES.has(errorCode(error) ?? "")) continue;
      return { ok: false, error: caaFailure(error, signal, name) };
    }
    const records = raw.flatMap(normalizeRecord);
    if (records.length > 0) return { ok: true, value: { domain: name, records } };
  }
  return { ok: true, value: { domain: null, records: [] } };
}

export function createCaaResolver(options: CaaResolverOptions = {}): CaaResolver {
  return async (hostname, { timeoutMs = DNS_TIMEOUT_MS, signal } = {}) => {
    const timer = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([timer, signal]) : timer;
    try {
      return await findCaa(hostname, options.resolveCaa ?? systemQuery(), combined);
    } catch (error) {
      // Aucune exception ne doit remonter à l'orchestrateur.
      return { ok: false, error: caaFailure(error, combined, hostname) };
    }
  };
}

export const resolveCaa: CaaResolver = createCaaResolver();
