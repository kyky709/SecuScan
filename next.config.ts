import type { NextConfig } from "next";

/**
 * La CSP des pages dépend d'un nonce par requête : elle est posée par `src/proxy.ts`, pas ici.
 *
 * `cacheComponents` (Partial Prerendering) reste désactivé : une coquille HTML pré-rendue au build
 * ne peut pas porter le nonce de la requête, ce qui est incompatible avec une CSP stricte
 * (voir node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md).
 */

const securityHeaders = [
  // 2 ans (RFC 6797).
  { key: "Strict-Transport-Security", value: "max-age=63072000; includeSubDomains; preload" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  // Pour les anciens navigateurs ; les autres appliquent frame-ancestors.
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  },
  // Contre les XS-Leaks.
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
];

const apiHeaders = [
  { key: "Content-Security-Policy", value: "default-src 'none'; frame-ancestors 'none'" },
  { key: "Cache-Control", value: "no-store" },
];

const nextConfig: NextConfig = {
  poweredByHeader: false,
  // Évite que `next dev` génère un AGENTS.md.
  agentRules: false,
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
