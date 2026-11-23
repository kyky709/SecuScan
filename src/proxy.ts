import { type NextRequest, NextResponse } from "next/server";
import { buildContentSecurityPolicy, generateNonce } from "@/lib/security/csp";

/**
 * Proxy Next.js (anciennement « middleware ») : exécuté avant le rendu de chaque page.
 *
 * Il génère un nonce par requête et pose la Content-Security-Policy correspondante :
 * - sur la requête (en-têtes `x-nonce` et `Content-Security-Policy`), d'où Next.js extrait le
 *   nonce pour l'ajouter automatiquement à ses propres balises <script> et <style> ;
 * - sur la réponse, pour que le navigateur applique la politique.
 *
 * Les autres en-têtes de sécurité, identiques pour toutes les réponses, sont dans next.config.ts.
 */
export function proxy(request: NextRequest) {
  const nonce = generateNonce();
  const csp = buildContentSecurityPolicy({ nonce, isDev: process.env.NODE_ENV === "development" });

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      // Toutes les pages, sauf l'API (JSON, CSP fixe dans next.config.ts) et les fichiers statiques.
      source: "/((?!api|_next/static|_next/image|favicon.ico|icon.svg|robots.txt|sitemap.xml).*)",
      // Inutile pour les préchargements de navigation (pas de document HTML rendu).
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
