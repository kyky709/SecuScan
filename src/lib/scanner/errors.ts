/**
 * Erreurs « métier » du scanner : elles empêchent de produire un rapport (saisie invalide,
 * cible interdite, site injoignable…) et sont converties en réponse HTTP par la route /api/scan.
 *
 * Les échecs d'une sonde isolée (ex. pas de security.txt) ne sont PAS des ScanError :
 * ils sont représentés par un `Result` en erreur et donnent un contrôle au statut "error".
 */

export type ScanErrorCode =
  /** Corps de requête de l'API absent, mal formé ou non JSON. */
  | "INVALID_REQUEST"
  /** Requête envoyée depuis un autre site (en-tête Origin étranger). */
  | "FORBIDDEN_ORIGIN"
  /** Corps de requête trop volumineux. */
  | "PAYLOAD_TOO_LARGE"
  /** Saisie vide, illisible ou trop longue. */
  | "INVALID_URL"
  /** Schéma autre que http ou https (ftp:, file:, javascript:…). */
  | "UNSUPPORTED_PROTOCOL"
  /** Port autre que 80 ou 443. */
  | "FORBIDDEN_PORT"
  /** Identifiants dans l'URL (https://utilisateur:motdepasse@…). */
  | "CREDENTIALS_IN_URL"
  /** Hôte local, privé ou réservé (localhost, 192.168.x.x, 169.254.169.254…) : protection anti-SSRF. */
  | "TARGET_NOT_ALLOWED"
  /** Le nom de domaine n'existe pas ou ne se résout pas. */
  | "DNS_FAILURE"
  /** Ni HTTPS ni HTTP n'ont répondu. */
  | "TARGET_UNREACHABLE"
  /** Le scan a dépassé le délai global. */
  | "TIMEOUT"
  /** Trop de scans en peu de temps. */
  | "RATE_LIMITED"
  /** Erreur inattendue. */
  | "INTERNAL_ERROR";

/** Statut HTTP renvoyé par l'API pour chaque code. */
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

  /**
   * @param code    code stable, exploitable par l'interface
   * @param message message en français, affichable tel quel à l'utilisateur
   */
  constructor(code: ScanErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ScanError";
    this.code = code;
  }

  /** Statut HTTP correspondant au code. */
  get httpStatus(): number {
    return HTTP_STATUS_BY_CODE[this.code];
  }
}

/** Indique si une valeur est une ScanError (utile dans les blocs catch). */
export function isScanError(value: unknown): value is ScanError {
  return value instanceof ScanError;
}

/** Corps JSON d'une réponse d'erreur de l'API (`/api/scan`). */
export interface ApiErrorBody {
  error: {
    code: ScanErrorCode;
    /** Message en français, affichable tel quel. */
    message: string;
    /** Pour RATE_LIMITED : nombre de secondes avant de pouvoir réessayer. */
    retryAfterSeconds?: number;
  };
}
