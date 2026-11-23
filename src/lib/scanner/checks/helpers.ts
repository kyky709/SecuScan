import type { CheckOutcome, HttpResponse, NetworkError, ScanContext } from "../types";

export const MAX_EVIDENCE_LENGTH = 600;

/** Les valeurs multiples d'un même en-tête sont déjà jointes par ", " par la sonde HTTP. */
export function getHeader(response: HttpResponse | null | undefined, name: string): string | null {
  if (!response) return null;
  const value = response.headers[name.toLowerCase()];
  return value === undefined ? null : value;
}

export function httpsResponse(context: ScanContext): HttpResponse | null {
  return context.https.ok ? context.https.value.response : null;
}

export function isServedOverHttps(response: HttpResponse | null | undefined): boolean {
  return response?.url.startsWith("https:") ?? false;
}

export function isHtmlResponse(response: HttpResponse | null | undefined): boolean {
  const contentType = getHeader(response, "content-type")?.toLowerCase() ?? "";
  return contentType.includes("text/html") || contentType.includes("application/xhtml+xml");
}

export function splitList(value: string, separator: string | RegExp = ","): string[] {
  return value
    .split(separator)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

/**
 * `table[key]` est piégeux quand la clé vient du site analysé : « Referrer-Policy: constructor »
 * renverrait `Object.prototype.constructor`, qui finirait affiché dans le rapport.
 */
export function lookup<T>(table: Readonly<Record<string, T>>, key: string): T | undefined {
  return Object.hasOwn(table, key) ? table[key] : undefined;
}

export function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

export function truncateEvidence(value: string, max = MAX_EVIDENCE_LENGTH): string {
  return value.length <= max ? value : `${value.slice(0, max)}… (${value.length} caractères)`;
}

export const MAX_QUOTED_LENGTH = 120;

/** Pour citer une valeur dans une phrase ; la valeur complète reste dans `evidence`. */
export function shorten(value: string): string {
  return truncateEvidence(value, MAX_QUOTED_LENGTH);
}

/** Neutre pour le score : on ne pénalise pas ce qu'on n'a pas pu observer. */
export function probeErrorOutcome(error: NetworkError, what: string): CheckOutcome {
  return {
    status: "error",
    scoreModifier: 0,
    summary: `Impossible de vérifier ${what} : ${error.message}`,
    details: error.detail ? [`Détail technique : ${error.detail}`] : undefined,
    recommendation: null,
  };
}

export function notApplicable(summary: string, details?: string[]): CheckOutcome {
  return { status: "info", scoreModifier: 0, summary, details, recommendation: null };
}

/** Version minimale du contrôle `hsts`, pour atténuer les pénalités d'autres contrôles. */
export function hasEffectiveHsts(response: HttpResponse | null | undefined): boolean {
  if (!isServedOverHttps(response)) return false;
  const value = getHeader(response, "strict-transport-security");
  const match = value?.match(/(?:^|;)\s*max-age\s*=\s*"?(\d+)"?\s*(?:;|$)/i);
  return match?.[1] !== undefined && Number(match[1]) > 0;
}
