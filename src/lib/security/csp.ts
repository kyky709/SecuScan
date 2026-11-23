/**
 * CSP stricte fondée sur un nonce : un script injecté (XSS) ne connaît pas le nonce de la requête,
 * et `'strict-dynamic'` autorise seulement ce que les scripts de Next.js chargent eux-mêmes.
 * En développement, React a besoin de `'unsafe-eval'` et le rechargement à chaud injecte des
 * styles en ligne : la politique est assouplie, jamais en production.
 */

export interface CspOptions {
  /** Base64. */
  nonce: string;
  isDev: boolean;
}

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
    // En dev, le rechargement à chaud passe par un WebSocket.
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

/** 128 bits aléatoires. */
export function generateNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}
