// Une ScanError empêche de produire un rapport. L'échec d'une sonde isolée (pas de security.txt…)
// n'en est pas une : c'est un `Result` en erreur, qui donne un contrôle au statut "error".

export type ScanErrorCode =
  /** Corps de requête absent, mal formé ou non JSON. */
  | "INVALID_REQUEST"
  /** En-tête Origin d'un autre site. */
  | "FORBIDDEN_ORIGIN"
  | "PAYLOAD_TOO_LARGE"
  | "INVALID_URL"
  | "UNSUPPORTED_PROTOCOL"
  | "FORBIDDEN_PORT"
  | "CREDENTIALS_IN_URL"
  /** Hôte local, privé ou réservé (anti-SSRF). */
  | "TARGET_NOT_ALLOWED"
  | "DNS_FAILURE"
  /** Ni HTTPS ni HTTP n'ont répondu. */
  | "TARGET_UNREACHABLE"
  | "TIMEOUT"
  | "RATE_LIMITED"
  | "INTERNAL_ERROR";

export const HTTP_STATUS_BY_CODE: Record<ScanErrorCode, number> = {
  INVALID_REQUEST: 400,
  FORBIDDEN_ORIGIN: 403,
  PAYLOAD_TOO_LARGE: 413,
  INVALID_URL: 400,
  UNSUPPORTED_PROTOCOL: 400,
  FORBIDDEN_PORT: 400,
  CREDENTIALS_IN_URL: 400,
  TARGET_NOT_ALLOWED: 422,
  DNS_FAILURE: 422,
  TARGET_UNREACHABLE: 502,
  TIMEOUT: 504,
  RATE_LIMITED: 429,
  INTERNAL_ERROR: 500,
};

export class ScanError extends Error {
  readonly code: ScanErrorCode;

  /** `message` est affiché tel quel à l'utilisateur. */
  constructor(code: ScanErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ScanError";
    this.code = code;
  }

  get httpStatus(): number {
    return HTTP_STATUS_BY_CODE[this.code];
  }
}

export function isScanError(value: unknown): value is ScanError {
  return value instanceof ScanError;
}

export interface ApiErrorBody {
  error: {
    code: ScanErrorCode;
    message: string;
    /** Uniquement pour RATE_LIMITED. */
    retryAfterSeconds?: number;
  };
}
