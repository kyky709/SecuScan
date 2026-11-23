/**
 * Paramètres de SecuScan, regroupés ici pour être ajustés en un seul endroit.
 *
 * Les délais tiennent compte de l'hébergement serverless (Vercel) : une fonction a une durée
 * d'exécution limitée (`maxDuration` de la route /api/scan), le scan complet doit donc tenir
 * largement dans ce budget, même face à un serveur lent.
 */

export const SCANNER_NAME = "SecuScan";
export const SCANNER_VERSION = "1.0.0";

/**
 * User-Agent envoyé aux sites analysés. Un outil d'analyse honnête s'identifie clairement.
 * `SCANNER_CONTACT_URL` (facultatif) ajoute une adresse où les administrateurs peuvent se renseigner.
 */
export const USER_AGENT = `Mozilla/5.0 (compatible; ${SCANNER_NAME}/${SCANNER_VERSION}${
  process.env.SCANNER_CONTACT_URL ? `; +${process.env.SCANNER_CONTACT_URL}` : ""
})`;

/** Délai maximal d'une requête HTTP (connexion + réponse + corps). */
export const REQUEST_TIMEOUT_MS = 8_000;

/** Délai maximal de la sonde TLS (par négociation). */
export const TLS_TIMEOUT_MS = 6_000;

/** Délai maximal d'une résolution DNS. */
export const DNS_TIMEOUT_MS = 4_000;

/** Délai global d'un scan : au-delà, les sondes encore en cours sont annulées. */
export const SCAN_TIMEOUT_MS = 20_000;

/** Nombre maximal de redirections suivies. */
export const MAX_REDIRECTS = 10;

/** Taille maximale de corps lue pour une page HTML (2 Mio). */
export const MAX_BODY_BYTES = 2 * 1024 * 1024;

/** Taille maximale lue pour security.txt (RFC 9116 : un petit fichier texte). */
export const MAX_SECURITY_TXT_BYTES = 64 * 1024;

/** Longueur maximale acceptée pour l'URL saisie. */
export const MAX_URL_LENGTH = 2_048;

/** Ports autorisés : uniquement les ports web standard (limite la surface d'abus du scanner). */
export const ALLOWED_PORTS: ReadonlySet<number> = new Set([80, 443]);

/** Limitation de débit par adresse IP du client. */
export const RATE_LIMIT_PER_CLIENT = { limit: 10, windowMs: 60_000 } as const;

/** Limitation de débit par site analysé (évite d'utiliser SecuScan pour harceler un même site). */
export const RATE_LIMIT_PER_TARGET = { limit: 6, windowMs: 60_000 } as const;

/**
 * Origine fictive envoyée dans l'en-tête `Origin` de la sonde CORS. Le domaine de premier niveau
 * `.invalid` est réservé (RFC 2606) : il ne peut appartenir à personne. Si le serveur renvoie
 * cette origine dans Access-Control-Allow-Origin, il accepte n'importe quelle origine.
 */
export const CORS_PROBE_ORIGIN = "https://secuscan-cors-probe.invalid";
