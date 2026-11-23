/**
 * Recherche des enregistrements DNS CAA (RFC 8659) qui s'appliquent à un nom d'hôte.
 *
 * Un enregistrement CAA indique quelles autorités de certification ont le droit d'émettre des
 * certificats pour un domaine : il limite les dégâts d'une erreur ou d'une fraude chez une autorité.
 *
 * Algorithme (RFC 8659 § 3) : on interroge le nom lui-même, puis ses parents successifs
 * (www.example.com → example.com → com), jusqu'à la racine EXCLUE ; le premier ensemble non vide
 * s'applique. Font remonter au parent : une liste vide (cas d'un CNAME dont la cible n'a pas de CAA),
 * ENODATA (le nom existe, sans CAA) et ENOTFOUND (le nom n'existe pas). Une panne (SERVFAIL, délai,
 * refus) rend la recherche non concluante : on renvoie une erreur plutôt que d'affirmer « aucun CAA ».
 *
 * On utilise un `Resolver` de Node.js (vraies requêtes DNS via c-ares, avec délai) et non
 * `dns.lookup` (getaddrinfo), qui ne sait résoudre que des adresses.
 *
 * Place dans l'architecture : sonde lancée par l'orchestrateur (scan.ts), sauf pour une IP ; son
 * résultat est noté par le contrôle caa. Seul le résolveur DNS est contacté, jamais le site.
 */
import { Resolver } from "node:dns/promises";
import { DNS_TIMEOUT_MS } from "@/lib/config";
import type { CaaInfo, CaaRecord, CaaResolver, NetworkError, Result } from "@/lib/scanner/types";
import { isIpLiteral } from "./ip";
import { errorCode, untilAborted } from "./safe-lookup";

/**
 * Interrogation CAA d'un seul nom. Renvoie les enregistrements bruts de Node.js, de la forme
 * `{ critical, type: "CAA", <étiquette>: valeur }`. Remplaçable dans les tests.
 */
export type CaaQuery = (name: string) => Promise<readonly object[]>;

/** Réglages du résolveur CAA. */
export interface CaaResolverOptions {
  /** Requête CAA à utiliser. Défaut : un `Resolver` de Node.js avec délai et deux tentatives. */
  resolveCaa?: CaaQuery;
}

/** Délai d'une tentative de requête DNS (le délai global de la recherche borne le tout). */
const QUERY_TIMEOUT_MS = 1_500;
/** Nombre de tentatives par requête : un paquet UDP perdu ne doit pas rendre le test non concluant. */
const QUERY_TRIES = 2;
/** Codes qui signifient « pas de CAA à ce niveau » : on remonte au domaine parent. */
const CLIMB_CODES: ReadonlySet<string> = new Set(["ENODATA", "ENOTFOUND"]);

/** Requête CAA par défaut : résolveur c-ares de Node.js, avec délai par tentative. */
function systemQuery(): CaaQuery {
  const resolver = new Resolver({ timeout: QUERY_TIMEOUT_MS, tries: QUERY_TRIES });
  return (name) => resolver.resolveCaa(name);
}

/** Noms à interroger, du plus précis au domaine de premier niveau : « a.b.fr » → [a.b.fr, b.fr, fr]. */
function candidateNames(hostname: string): string[] {
  const labels = hostname
    .toLowerCase()
    .replace(/\.$/, "")
    .split(".")
    .filter((label) => label !== "");
  return labels.map((_label, index) => labels.slice(index).join("."));
}

/**
 * Convertit un enregistrement de Node.js en `CaaRecord` { critical, tag, value }. L'étiquette est la
 * seule propriété autre que `critical` et `type` : issue, issuewild, iodef, ou une étiquette inconnue
 * conservée telle quelle. Un enregistrement sans étiquette est ignoré.
 */
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

/** Traduit l'échec d'une requête CAA en `NetworkError` (délai dépassé ou panne DNS). */
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

/** Remonte l'arbre DNS jusqu'au premier ensemble CAA non vide. */
async function findCaa(
  hostname: string,
  query: CaaQuery,
  signal: AbortSignal,
): Promise<Result<CaaInfo>> {
  // CAA ne concerne que les noms de domaine : une adresse IP n'a pas d'arbre DNS à remonter.
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

/**
 * Crée un résolveur CAA. Ne lève jamais d'exception : renvoie `{ domain, records }` (domain = null
 * si aucun enregistrement n'existe) ou une erreur `TIMEOUT` / `DNS_FAILURE`.
 */
export function createCaaResolver(options: CaaResolverOptions = {}): CaaResolver {
  return async (hostname, { timeoutMs = DNS_TIMEOUT_MS, signal } = {}) => {
    const timer = AbortSignal.timeout(timeoutMs);
    const combined = signal ? AbortSignal.any([timer, signal]) : timer;
    try {
      return await findCaa(hostname, options.resolveCaa ?? systemQuery(), combined);
    } catch (error) {
      // Filet de sécurité : aucune exception ne doit remonter à l'orchestrateur.
      return { ok: false, error: caaFailure(error, combined, hostname) };
    }
  };
}

/** Résolveur CAA par défaut, utilisé par le scanner. */
export const resolveCaa: CaaResolver = createCaaResolver();
