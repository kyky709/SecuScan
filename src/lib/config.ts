// Délais calibrés pour Vercel : le scan complet doit tenir largement dans le `maxDuration` de la
// route /api/scan, même face à un serveur lent.

export const SCANNER_NAME = "SecuScan";
export const SCANNER_VERSION = "1.0.0";

// Le scanner s'identifie clairement ; `SCANNER_CONTACT_URL` (facultatif) indique aux
// administrateurs où se renseigner.
export const USER_AGENT = `Mozilla/5.0 (compatible; ${SCANNER_NAME}/${SCANNER_VERSION}${
  process.env.SCANNER_CONTACT_URL ? `; +${process.env.SCANNER_CONTACT_URL}` : ""
})`;

/** Connexion + réponse + lecture du corps. */
export const REQUEST_TIMEOUT_MS = 8_000;

/** Par négociation TLS. */
export const TLS_TIMEOUT_MS = 6_000;

export const DNS_TIMEOUT_MS = 4_000;

/** Au-delà, les sondes encore en cours sont annulées. */
export const SCAN_TIMEOUT_MS = 20_000;

export const MAX_REDIRECTS = 10;

export const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** RFC 9116 : security.txt est un petit fichier texte. */
export const MAX_SECURITY_TXT_BYTES = 64 * 1024;

export const MAX_URL_LENGTH = 2_048;

/** Uniquement les ports web standard, pour limiter la surface d'abus du scanner. */
export const ALLOWED_PORTS: ReadonlySet<number> = new Set([80, 443]);

export const RATE_LIMIT_PER_CLIENT = { limit: 10, windowMs: 60_000 } as const;

/** Évite d'utiliser SecuScan pour harceler un même site. */
export const RATE_LIMIT_PER_TARGET = { limit: 6, windowMs: 60_000 } as const;

/**
 * Origine envoyée par la sonde CORS. Le TLD `.invalid` est réservé (RFC 2606) : si le serveur
 * la renvoie dans Access-Control-Allow-Origin, il accepte n'importe quelle origine.
 */
export const CORS_PROBE_ORIGIN = "https://secuscan-cors-probe.invalid";
