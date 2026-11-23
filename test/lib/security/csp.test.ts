import { describe, expect, it } from "vitest";
import { buildContentSecurityPolicy, generateNonce } from "@/lib/security/csp";

function parse(policy: string): Map<string, string[]> {
  return new Map(
    policy.split(";").map((part) => {
      const [name = "", ...values] = part.trim().split(/\s+/);
      return [name, values];
    }),
  );
}

describe("buildContentSecurityPolicy", () => {
  it("produit une politique stricte en production", () => {
    const csp = parse(buildContentSecurityPolicy({ nonce: "abc123", isDev: false }));

    expect(csp.get("default-src")).toEqual(["'none'"]);
    expect(csp.get("script-src")).toEqual(["'self'", "'nonce-abc123'", "'strict-dynamic'"]);
    expect(csp.get("style-src")).toEqual(["'self'", "'nonce-abc123'"]);
    expect(csp.get("object-src")).toEqual(["'none'"]);
    expect(csp.get("base-uri")).toEqual(["'none'"]);
    expect(csp.get("frame-ancestors")).toEqual(["'none'"]);
    expect(csp.has("upgrade-insecure-requests")).toBe(true);
  });

  it("n'autorise jamais 'unsafe-inline' ni 'unsafe-eval' pour les scripts en production", () => {
    const policy = buildContentSecurityPolicy({ nonce: "n", isDev: false });
    expect(policy).not.toContain("unsafe-eval");
    expect(policy).not.toContain("unsafe-inline");
  });

  it("assouplit la politique en développement uniquement", () => {
    const csp = parse(buildContentSecurityPolicy({ nonce: "n", isDev: true }));
    expect(csp.get("script-src")).toContain("'unsafe-eval'");
    expect(csp.get("style-src")).toContain("'unsafe-inline'");
    expect(csp.get("connect-src")).toEqual(["'self'", "ws:", "wss:"]);
  });
});

describe("generateNonce", () => {
  it("génère un nonce base64 de 128 bits", () => {
    const nonce = generateNonce();
    expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
    expect(Buffer.from(nonce, "base64")).toHaveLength(16);
  });

  it("génère une valeur différente à chaque appel", () => {
    const nonces = new Set(Array.from({ length: 50 }, () => generateNonce()));
    expect(nonces.size).toBe(50);
  });
});
