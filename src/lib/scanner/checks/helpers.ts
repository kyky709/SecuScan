/**
 * Utilitaires partagés par les contrôles.
 *
 * Ils évitent de répéter dans chaque contrôle les mêmes petites opérations : lire un en-tête
 * sans tenir compte de la casse, découper une liste, produire le verdict d'un contrôle impossible…
 */
import type { CheckOutcome, HttpResponse, NetworkError, ScanContext } from "../types";

/** Longueur maximale d'une valeur brute affichée comme preuve (`evidence`). */
export const MAX_EVIDENCE_LENGTH = 600;

/**
 * Valeur d'un en-tête de réponse (nom insensible à la casse), ou null s'il est absent.
 * Les valeurs multiples d'un même en-tête sont déjà jointes par ", " par la sonde HTTP.
 */
export function getHeader(response: HttpResponse | null | undefined, name: string): string | null {
  if (!response) return null;
  const value = response.headers[name.toLowerCase()];
  return value === undefined ? null : value;
}

/** Réponse finale obtenue en HTTPS, ou null si la sonde HTTPS a échoué. */
export function httpsResponse(context: ScanContext): HttpResponse | null {
  return context.https.ok ? context.https.value.response : null;
}

/** La réponse analysée a-t-elle été servie en HTTPS ? */
export function isServedOverHttps(response: HttpResponse | null | undefined): boolean {
  return response?.url.startsWith("https:") ?? false;
}

/** La réponse est-elle un document HTML (d'après Content-Type) ? */
export function isHtmlResponse(response: HttpResponse | null | undefined): boolean {
  const contentType = getHeader(response, "content-type")?.toLowerCase() ?? "";
  return contentType.includes("text/html") || contentType.includes("application/xhtml+xml");
}

/** Découpe une liste séparée par `separator`, en retirant les espaces et les éléments vides. */
export function splitList(value: string, separator: string | RegExp = ","): string[] {
  return value
    .split(separator)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * Valeur associée à `key` dans une table de correspondance (objet littéral), ou undefined.
 *
 * Écrire simplement `table[key]` est piégeux quand la clé vient du site analysé : un en-tête
 * « Referrer-Policy: constructor » renverrait `Object.prototype.constructor`, une fonction héritée,
 * qui finirait affichée dans le rapport (« function Object() { [native code] } »). `Object.hasOwn`
 * ne regarde que les propriétés propres de la table.
 */
export function lookup<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

/** Origine (schéma + hôte + port) d'une URL, ou null si l'URL est invalide. */
export function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** Raccourcit une valeur brute trop longue pour l'affichage. */
export function truncateEvidence(value: string, max = MAX_EVIDENCE_LENGTH): string {
  return value.length <= max ? value : `${value.slice(0, max)}… (${value.length} caractères)`;
}

/** Longueur maximale d'une valeur observée citée dans une phrase (constat, détail). */
export const MAX_QUOTED_LENGTH = 120;

/**
 * Valeur observée, raccourcie pour être citée dans une phrase. Un en-tête peut mesurer des
 * dizaines de kilo-octets : recopié tel quel, il rendrait le constat illisible et alourdirait le
 * rapport. La valeur complète reste disponible dans la preuve (`evidence`).
 */
export function shorten(value: string): string {
  return truncateEvidence(value, MAX_QUOTED_LENGTH);
}

/**
 * Verdict d'un contrôle qui n'a pas pu être réalisé parce qu'une sonde a échoué.
 * Neutre pour le score : on ne pénalise pas ce qu'on n'a pas pu observer.
 *
 * @param error erreur de la sonde
 * @param what  ce qui n'a pas pu être vérifié, ex. "l'en-tête HSTS"
 */
export function probeErrorOutcome(error: NetworkError, what: string): CheckOutcome {
  return {
    status: "error",
    scoreModifier: 0,
    summary: `Impossible de vérifier ${what} : ${error.message}`,
    details: error.detail ? [`Détail technique : ${error.detail}`] : undefined,
    recommendation: null,
  };
}

/** Verdict d'un contrôle sans objet (ex. aucun cookie, pas de HTML) : informatif et neutre. */
export function notApplicable(summary: string, details?: string[]): CheckOutcome {
  return { status: "info", scoreModifier: 0, summary, details, recommendation: null };
}

/**
 * La réponse active-t-elle HSTS de façon effective ? (réponse HTTPS + `max-age` strictement positif)
 * Utilisé par les contrôles qui atténuent une pénalité quand HSTS protège déjà le site (cookies).
 * L'analyse complète de l'en-tête est faite par le contrôle `hsts`.
 */
export function hasEffectiveHsts(response: HttpResponse | null | undefined): boolean {
  if (!isServedOverHttps(response)) return false;
  const value = getHeader(response, "strict-transport-security");
  const match = value?.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i);
  return match?.[1] !== undefined && Number(match[1]) > 0;
}
