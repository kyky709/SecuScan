// Sans `NEXT_PUBLIC_SITE_URL`, on retombe sur l'adresse de production fournie par Vercel.
function resolveSiteUrl(): string {
  if (process.env.NEXT_PUBLIC_SITE_URL) return process.env.NEXT_PUBLIC_SITE_URL.replace(/\/+$/, "");
  if (process.env.VERCEL_PROJECT_PRODUCTION_URL) {
    return `https://${process.env.VERCEL_PROJECT_PRODUCTION_URL}`;
  }
  return "http://localhost:3000";
}

export const SITE = {
  name: "SecuScan",
  tagline: "Analysez la sécurité de votre site web",
  description:
    "SecuScan analyse la configuration de sécurité d'un site web (en-têtes HTTP, HTTPS et TLS, cookies) et attribue une note de A+ à F, avec des conseils de correction référencés OWASP.",
  url: resolveSiteUrl(),
  repositoryUrl: process.env.NEXT_PUBLIC_REPOSITORY_URL ?? "https://github.com/kyky709/SecuScan",
} as const;
