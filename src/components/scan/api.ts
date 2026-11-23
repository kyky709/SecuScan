/**
 * Appel de l'API d'analyse (`POST /api/scan`) depuis le navigateur.
 *
 * Toute la communication avec le serveur est isolée ici, sans React : le composant ScanApp n'a
 * plus qu'à afficher le résultat. `requestScan` ne lève jamais d'exception : elle renvoie soit le
 * rapport, soit un message d'erreur en français prêt à afficher. Trois familles d'échecs :
 * - erreur réseau (hors ligne, requête annulée…) : `fetch` lui-même échoue ;
 * - erreur signalée par l'API : corps JSON `{ error: { code, message } }` (`ApiErrorBody`) ;
 * - réponse inattendue (pas du JSON, format inconnu) : par exemple une page d'erreur renvoyée
 *   par un intermédiaire (CDN, proxy) à la place de l'API.
 */
import type { ApiErrorBody, ScanErrorCode } from "@/lib/scanner/errors";
import type { ScanReport } from "@/lib/scanner/types";
import { formatRetryDelay } from "../report/format";

/** Adresse de l'API d'analyse (même origine que la page : aucune requête vers un autre site). */
export const SCAN_ENDPOINT = "/api/scan";

/** Message affiché quand le serveur de SecuScan est injoignable. */
export const NETWORK_ERROR_MESSAGE =
  "Impossible de joindre SecuScan. Vérifiez votre connexion à Internet, puis réessayez.";

/** Codes d'erreur propres au navigateur, en plus de ceux de l'API (`ScanErrorCode`). */
export type ClientErrorCode = "NETWORK_ERROR" | "UNEXPECTED_RESPONSE";

/** Résultat d'une demande d'analyse. */
export type ScanResponse =
  | { ok: true; report: ScanReport }
  | { ok: false; code: ScanErrorCode | ClientErrorCode; message: string };

/**
 * Demande l'analyse d'un site au serveur.
 *
 * @param url    adresse saisie par l'utilisateur (normalisée et validée par le serveur)
 * @param signal signal d'annulation (nouvelle analyse lancée, page quittée)
 */
export async function requestScan(url: string, signal?: AbortSignal): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(SCAN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal,
    });
  } catch {
    return { ok: false, code: "NETWORK_ERROR", message: NETWORK_ERROR_MESSAGE };
  }

  const body = await readJson(response);
  if (response.ok && isScanReport(body)) return { ok: true, report: body };
  if (isApiErrorBody(body)) {
    return { ok: false, code: body.error.code, message: errorMessage(body, response) };
  }
  return {
    ok: false,
    code: "UNEXPECTED_RESPONSE",
    message: `Le serveur a renvoyé une réponse inattendue (code HTTP ${response.status}). Réessayez dans quelques instants.`,
  };
}

/** Corps de la réponse décodé en JSON, ou null s'il est absent ou illisible. */
async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

/** La valeur est-elle un objet (et pas null) ? Permet de lire ses propriétés sans `any`. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * Vérification minimale de la forme d'un rapport. Le serveur est de confiance, mais une réponse
 * 200 peut venir d'ailleurs (portail captif, proxy) : on évite d'afficher n'importe quoi.
 */
function isScanReport(value: unknown): value is ScanReport {
  return (
    isRecord(value) &&
    value.schemaVersion === 1 &&
    isRecord(value.target) &&
    isRecord(value.score) &&
    Array.isArray(value.checks)
  );
}

/** Le corps est-il une erreur au format de l'API (`{ error: { code, message } }`) ? */
function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (!isRecord(value)) return false;
  const error = value.error;
  return isRecord(error) && typeof error.code === "string" && typeof error.message === "string";
}

/**
 * Message à afficher pour une erreur de l'API. Pour une limitation de débit (429), on précise
 * quand réessayer : d'après le corps (`retryAfterSeconds`), sinon d'après l'en-tête Retry-After.
 */
function errorMessage(body: ApiErrorBody, response: Response): string {
  const { code, message, retryAfterSeconds } = body.error;
  if (code !== "RATE_LIMITED") return message;

  const seconds =
    typeof retryAfterSeconds === "number"
      ? retryAfterSeconds
      : parseRetryAfter(response.headers.get("Retry-After"));
  return seconds === null
    ? message
    : `${message} Vous pourrez réessayer dans ${formatRetryDelay(seconds)}.`;
}

/** Valeur de l'en-tête Retry-After exprimée en secondes, ou null si absente ou illisible. */
function parseRetryAfter(value: string | null): number | null {
  if (value === null || value.trim() === "") return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}
