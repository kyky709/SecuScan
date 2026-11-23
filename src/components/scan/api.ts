// `requestScan` ne lève jamais d'exception : elle renvoie le rapport ou un message prêt à afficher,
// y compris quand un intermédiaire (CDN, proxy) répond à la place de l'API.
import type { ApiErrorBody, ScanErrorCode } from "@/lib/scanner/errors";
import type { ScanReport } from "@/lib/scanner/types";
import { formatRetryDelay } from "../report/format";

export const SCAN_ENDPOINT = "/api/scan";

export const NETWORK_ERROR_MESSAGE =
  "Impossible de joindre SecuScan. Vérifiez votre connexion à Internet, puis réessayez.";

export type ClientErrorCode = "NETWORK_ERROR" | "UNEXPECTED_RESPONSE";

export type ScanResponse =
  | { ok: true; report: ScanReport }
  | { ok: false; code: ScanErrorCode | ClientErrorCode; message: string };

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

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

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

function isApiErrorBody(value: unknown): value is ApiErrorBody {
  if (!isRecord(value)) return false;
  const error = value.error;
  return isRecord(error) && typeof error.code === "string" && typeof error.message === "string";
}

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

function parseRetryAfter(value: string | null): number | null {
  if (value === null || value.trim() === "") return null;
  const seconds = Number(value);
  return Number.isFinite(seconds) && seconds >= 0 ? seconds : null;
}
