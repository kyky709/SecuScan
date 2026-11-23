import { type NextRequest, NextResponse } from "next/server";
import { buildContentSecurityPolicy, generateNonce } from "@/lib/security/csp";

// Nonce par requête. La CSP est posée aussi sur la requête : c'est là que Next.js lit le nonce
// pour l'ajouter à ses propres <script> et <style>. Les en-têtes fixes sont dans next.config.ts.
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
      // Les préchargements de navigation ne rendent pas de document HTML.
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
