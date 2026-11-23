import type { NextConfig } from "next";

/**
 * Configuration Next.js de SecuScan.
 *
 * Un scanner de sécurité se doit d'être lui-même exemplaire : chaque réponse porte les en-têtes
 * de sécurité qu'il recommande. La Content-Security-Policy des pages dépend d'un nonce aléatoire
 * renouvelé à chaque requête : elle est donc posée dynamiquement par `src/proxy.ts`, pas ici.
 *
 * `cacheComponents` (Partial Prerendering) reste désactivé : une coquille HTML pré-rendue au build
 * ne peut pas porter le nonce de la requête, ce qui est incompatible avec une CSP stricte
 * (voir node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md).
 */

/** En-têtes communs à toutes les réponses (pages, API, fichiers statiques). */
const securityHeaders = [
  // HTTPS obligatoire pendant 2 ans, sous-domaines compris (RFC 6797).
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  // Interdit au navigateur de « deviner » le type MIME d'une réponse.
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Anti-clickjacking pour les anciens navigateurs (la CSP utilise frame-ancestors).
  { key: "X-Frame-Options", value: "DENY" },
  // N'envoie que l'origine (sans chemin) aux autres sites, et rien en cas de passage à HTTP.
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  // Désactive les fonctionnalités sensibles du navigateur dont l'application n'a pas besoin.
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  },
  // Isole la fenêtre des autres origines (protection contre les attaques XS-Leaks).
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  // Empêche les autres sites d'intégrer nos ressources.
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

/** En-têtes propres à l'API JSON : aucune ressource à charger, aucune mise en cache. */
const apiHeaders = [
  { key: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors 'none'" },
  { key: "Cache-Control", value: "no-store" },
];

const nextConfig: NextConfig = {
  // Supprime l'en-tête `X-Powered-By: Next.js` (divulgation de la technologie utilisée).
  poweredByHeader: false,
  reactStrictMode: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [
      { source: "/:path*", headers: securityHeaders },
      { source: "/api/:path*", headers: apiHeaders },
    ];
  },
};

export default nextConfig;
