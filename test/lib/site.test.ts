/**
 * Tests des informations publiques du site (site.ts) : l'adresse publique sert aux métadonnées
 * (Open Graph, sitemap, robots.txt). Elle vient de NEXT_PUBLIC_SITE_URL, sinon de l'adresse de
 * production fournie par Vercel, sinon de l'adresse de développement.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

/** Recharge le module avec les variables d'environnement du moment. */
async function loadSite() {
  vi.resetModules();
  return (await import("@/lib/site")).SITE;
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("SITE.url", () => {
  it("utilise NEXT_PUBLIC_SITE_URL, sans barre oblique finale", async () => {
    vi.stubEnv("NEXT_PUBLIC_SITE_URL", "https://secuscan.example.com///");
    vi.stubEnv("VERCEL_PROJECT_PRODUCTION_URL", "secuscan.vercel.app");
    expect((await loadSite()).url).toBe("https://secuscan.example.com");
  });

  it("utilise sinon l'adresse de production fournie par Vercel, en HTTPS", async () => {
    vi.stubEnv("NEXT_PUBLIC_SITE_URL", "");
    vi.stubEnv("VERCEL_PROJECT_PRODUCTION_URL", "secuscan.vercel.app");
    expect((await loadSite()).url).toBe("https://secuscan.vercel.app");
  });

  it("utilise enfin l'adresse de développement", async () => {
    vi.stubEnv("NEXT_PUBLIC_SITE_URL", "");
    vi.stubEnv("VERCEL_PROJECT_PRODUCTION_URL", "");
    expect((await loadSite()).url).toBe("http://localhost:3000");
  });
});

describe("SITE.repositoryUrl", () => {
  it("utilise NEXT_PUBLIC_REPOSITORY_URL quand elle est définie", async () => {
    vi.stubEnv("NEXT_PUBLIC_REPOSITORY_URL", "https://example.com/depot");
    expect((await loadSite()).repositoryUrl).toBe("https://example.com/depot");
  });
});
