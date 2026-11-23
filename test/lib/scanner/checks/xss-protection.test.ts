import { failure, makeContext } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { xssProtectionCheck } from "@/lib/scanner/checks/xss-protection";
import { REFS } from "@/lib/scanner/references";
import type { Reference } from "@/lib/scanner/types";

/** Évalue le contrôle avec cette valeur de X-XSS-Protection (null = en-tête absent). */
function evaluate(value: string | null) {
  const headers: Record<string, string> = value === null ? {} : { "x-xss-protection": value };
  return xssProtectionCheck.evaluate(makeContext({ headers }));
}

/** Rang des familles de références : fiches OWASP, Top 10, ASVS, WSTG, puis MDN, RFC et autres. */
function referenceRank(reference: Reference): number {
  const ranks: Record<string, number> = {
    "owasp-cheatsheet": 0,
    "owasp-secure-headers": 0,
    "owasp-top10": 1,
    "owasp-asvs": 2,
    "owasp-wstg": 3,
  };
  return ranks[reference.kind] ?? 4;
}

describe("xssProtectionCheck : définition", () => {
  it("expose chaque ligne de la grille de notation, sans effet sur la note", () => {
    expect(xssProtectionCheck.id).toBe("xss-protection");
    expect(xssProtectionCheck.category).toBe("headers");
    expect(xssProtectionCheck.scoring.map((row) => row.modifier)).toEqual([0, 0, 0]);
  });

  it("cite uniquement le catalogue de références, OWASP d'abord", () => {
    const catalog = Object.values(REFS).flatMap((group) => Object.values(group));
    for (const reference of xssProtectionCheck.references) expect(catalog).toContain(reference);
    const ranks = xssProtectionCheck.references.map(referenceRank);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe("xssProtectionCheck : grille", () => {
  it("absent : pass 0, rien à recommander", () => {
    const outcome = evaluate(null);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toContain("absent");
    expect(outcome.evidence).toBeNull();
    expect(outcome.recommendation).toBeNull();
    expect(outcome.examples).toEqual([]);
  });

  it.each(["0", " 0 ", "0; mode=block"])("désactivé (%j) : pass 0", (value) => {
    const outcome = evaluate(value);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.recommendation).toBeNull();
  });

  it("1 : warning 0, avec conseil et exemples", () => {
    const outcome = evaluate("1");
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toContain("X-XSS-Protection: 1 active");
    expect(outcome.evidence).toBe("1");
    expect(outcome.details?.some((detail) => detail.includes("Chrome (version 78)"))).toBe(true);
    expect(outcome.recommendation).toContain("Content Security Policy");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    "1; mode=block",
    "1;MODE=BLOCK",
    "1 ; mode = block ;",
  ])("mode=block (%j) : warning 0", (value) => {
    const outcome = evaluate(value);
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toContain("mode=block");
  });

  it("1 avec une adresse de signalement : warning 0", () => {
    const outcome = evaluate("1; report=https://example.com/xss-report");
    expect(outcome.status).toBe("warning");
    expect(outcome.summary).toContain("X-XSS-Protection: 1 active");
  });

  it.each([
    "2",
    "yes",
    "",
    "1; mode=allow",
    "1; foo=bar",
    "on; mode=block",
  ])("valeur invalide (%j) : warning 0", (value) => {
    const outcome = evaluate(value);
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toContain("n'est pas valide");
  });
});

describe("xssProtectionCheck : en-tête répété (valeurs jointes par « , »)", () => {
  it("« 0, 0 » : pass 0 et conseil de n'en envoyer qu'un", () => {
    const outcome = evaluate("0, 0");
    expect(outcome.status).toBe("pass");
    expect(outcome.details?.[0]).toContain("envoyé plusieurs fois");
    expect(outcome.recommendation).toContain("une seule fois");
  });

  it("« 1; mode=block, 1; mode=block » : warning 0 (première valeur analysée)", () => {
    const outcome = evaluate("1; mode=block, 1; mode=block");
    expect(outcome.status).toBe("warning");
    expect(outcome.summary).toContain("mode=block");
    expect(outcome.details?.[0]).toContain("envoyé plusieurs fois");
  });
});

describe("xssProtectionCheck : sonde en échec", () => {
  it("sans aucune réponse : statut error, 0 point", () => {
    const outcome = xssProtectionCheck.evaluate(
      makeContext({ https: failure("TIMEOUT", "Délai dépassé."), http: failure() }),
    );
    expect(outcome.status).toBe("error");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toBe(
      "Impossible de vérifier l'en-tête X-XSS-Protection : Délai dépassé.",
    );
  });
});
