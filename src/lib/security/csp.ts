/**
 * Content-Security-Policy des pages de SecuScan.
 *
 * Politique « stricte » fondée sur un nonce (nombre aléatoire à usage unique) :
 * - `default-src 'none'` : tout est interdit par défaut, chaque type de ressource est ensuite
 *   autorisé explicitement et seulement depuis notre propre origine ('self') ;
 * - `script-src 'nonce-…' 'strict-dynamic'` : seuls les scripts portant le nonce de la requête
 *   (ceux que Next.js insère lui-même) s'exécutent, ainsi que ceux qu'ils chargent. Un script
 *   injecté par un attaquant (XSS) ne connaît pas le nonce : il est bloqué ;
 * - `frame-ancestors 'none'` : la page ne peut pas être intégrée dans une iframe (clickjacking) ;
 * - `base-uri 'none'` et `form-action 'self'` : empêchent de détourner les URL relatives et les formulaires.
 *
 * En développement, React a besoin de `'unsafe-eval'` (piles d'appels enrichies) et le
 * rechargement à chaud injecte des styles en ligne : la politique est assouplie, jamais en production.
 */

export interface CspOptions {
  /** Nonce de la requête (base64). */
  nonce: string;
  /** Mode développement (`next dev`). */
  isDev: boolean;
}

/** Construit la valeur de l'en-tête Content-Security-Policy. */
export function buildContentSecurityPolicy({ nonce, isDev }: CspOptions): string {
  const directives: Record<string, string[]> = {
    "default-src": ["'none'"],
    "script-src": [
      "'self'",
      `'nonce-${nonce}'`,
      "'strict-dynamic'",
      ...(isDev ? ["'unsafe-eval'"] : []),
    ],
    "style-src": ["'self'", isDev ? "'unsafe-inline'" : `'nonce-${nonce}'`],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'"],
    // L'interface appelle uniquement notre API (/api/scan) ; en dev, le rechargement à chaud utilise un WebSocket.
    "connect-src": ["'self'", ...(isDev ? ["ws:", "wss:"] : [])],
    "manifest-src": ["'self'"],
    "object-src": ["'none'"],
    "base-uri": ["'none'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "upgrade-insecure-requests": [],
  };
  return Object.entries(directives)
    .map(([name, values]) => [name, ...values].join(" "))
    .join("; ");
}

/** Génère un nonce imprévisible (128 bits aléatoires, encodés en base64). */
export function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}
