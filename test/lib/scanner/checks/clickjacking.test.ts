import { failure, makeContext, makeHtmlInfo } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { clickjackingCheck } from "@/lib/scanner/checks/clickjacking";
import { REFS } from "@/lib/scanner/references";
import type { Reference } from "@/lib/scanner/types";

function evaluate(headers: Record<string, string>, metaCsp: string[] = []) {
  return clickjackingCheck.evaluate(makeContext({ headers, html: makeHtmlInfo({ metaCsp }) }));
}

function evaluateXfo(value: string) {
  return evaluate({ "x-frame-options": value });
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

describe("clickjackingCheck : définition", () => {
  it("expose chaque ligne de la grille de notation", () => {
    expect(clickjackingCheck.id).toBe("clickjacking");
    expect(clickjackingCheck.category).toBe("headers");
    expect(clickjackingCheck.scoring.map((row) => row.modifier)).toEqual([5, 5, -20, -20]);
  });

  it("cite uniquement le catalogue de références, OWASP d'abord", () => {
    const catalog = Object.values(REFS).flatMap((group) => Object.values(group));
    for (const reference of clickjackingCheck.references) expect(catalog).toContain(reference);
    const ranks = clickjackingCheck.references.map(referenceRank);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe("clickjackingCheck : CSP frame-ancestors en en-tête", () => {
  it("frame-ancestors 'none' : pass +5, rien à recommander", () => {
    const outcome = evaluate({
      "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    });
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toBe(
      "La directive CSP frame-ancestors 'none' interdit à tout site d'afficher la page dans un cadre.",
    );
    expect(outcome.recommendation).toBeNull();
    expect(outcome.examples).toEqual([]);
    expect(outcome.evidence).toBe("Content-Security-Policy: frame-ancestors 'none'");
  });

  it("frame-ancestors 'self' et une origine partenaire : pass +5", () => {
    const outcome = evaluate({
      "content-security-policy": "frame-ancestors 'self' https://partner.example.com",
    });
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toContain("'self' https://partner.example.com");
  });

  it("joker de sous-domaine (https://*.example.com) : restrictif, pass +5", () => {
    expect(
      evaluate({ "content-security-policy": "frame-ancestors https://*.example.com" })
        .scoreModifier,
    ).toBe(5);
  });

  it("frame-ancestors sans valeur équivaut à 'none' : pass +5", () => {
    expect(
      evaluate({ "content-security-policy": "frame-ancestors; default-src 'self'" }).scoreModifier,
    ).toBe(5);
  });

  it("frame-ancestors * l'emporte sur X-Frame-Options: DENY : fail -20", () => {
    const outcome = evaluate({
      "content-security-policy": "frame-ancestors *",
      "x-frame-options": "DENY",
    });
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("n'importe quel site");
    expect(outcome.details).toContain(
      "X-Frame-Options (DENY) est ignoré par les navigateurs récents, car la CSP contient frame-ancestors, qui est prioritaire.",
    );
    expect(outcome.evidence).toBe(
      "Content-Security-Policy: frame-ancestors *\nX-Frame-Options: DENY",
    );
  });

  it.each([
    "https:",
    "https://*",
    "*:*",
  ])("frame-ancestors %s autorise tout le monde : fail -20", (source) => {
    const outcome = evaluate({ "content-security-policy": `frame-ancestors ${source}` });
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.recommendation).toContain("frame-ancestors");
  });

  it("plusieurs politiques : une seule liste restrictive suffit", () => {
    const outcome = evaluate({
      "content-security-policy": "frame-ancestors *, frame-ancestors 'self'",
    });
    expect(outcome.scoreModifier).toBe(5);
  });

  it("X-Frame-Options présent à côté d'une frame-ancestors restrictive : signalé comme ignoré", () => {
    const outcome = evaluate({
      "content-security-policy": "frame-ancestors 'self'",
      "x-frame-options": "SAMEORIGIN",
    });
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details?.[0]).toContain("X-Frame-Options (SAMEORIGIN) est ignoré");
  });
});

describe("clickjackingCheck : X-Frame-Options", () => {
  it("DENY : pass +5, avec le conseil d'ajouter frame-ancestors", () => {
    const outcome = evaluateXfo("DENY");
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toContain("X-Frame-Options: DENY");
    expect(outcome.evidence).toBe("X-Frame-Options: DENY");
    expect(outcome.recommendation).toContain("frame-ancestors");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it("sameorigin en minuscules : pass +5", () => {
    const outcome = evaluateXfo("sameorigin");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toContain("SAMEORIGIN");
  });

  it("valeur entourée de blancs et en casse mixte : pass +5", () => {
    expect(evaluateXfo("  Deny ").scoreModifier).toBe(5);
  });

  it("en-tête répété avec la même valeur (joint par « , ») : pass +5 et détail", () => {
    const outcome = evaluateXfo("SAMEORIGIN, SAMEORIGIN");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toContain(
      "L'en-tête X-Frame-Options est envoyé plusieurs fois avec la même valeur : n'en envoyez qu'un.",
    );
  });

  it.each([
    "SAMEORIGIN, DENY",
    "SAMEORIGIN,",
    "ALLOWALL, foo",
  ])("plusieurs valeurs dont deny/sameorigin/allowall (%s) : le navigateur bloque, pass +5", (value) => {
    const outcome = evaluateXfo(value);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toContain("plusieurs valeurs");
    expect(outcome.recommendation).toContain("une seule valeur");
  });

  it("ALLOW-FROM est ignoré des navigateurs actuels : fail -20", () => {
    const outcome = evaluateXfo("ALLOW-FROM https://partner.example.com");
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("ALLOW-FROM n'est plus pris en charge");
  });

  it.each([
    "ALLOWALL",
    "INVALID, INVALID",
    "foo, bar",
    "",
  ])("valeur ignorée par le navigateur (%j) : fail -20", (value) => {
    const outcome = evaluateXfo(value);
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("n'est pas reconnue");
  });

  it("une CSP sans frame-ancestors laisse X-Frame-Options décider", () => {
    const outcome = evaluate({
      "content-security-policy": "default-src 'self'",
      "x-frame-options": "DENY",
    });
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.summary).toContain("X-Frame-Options: DENY");
  });
});

describe("clickjackingCheck : aucune protection", () => {
  it("ni frame-ancestors ni X-Frame-Options : fail -20", () => {
    const outcome = evaluate({});
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("Aucune protection contre le clickjacking");
    expect(outcome.evidence).toBeNull();
    expect(outcome.examples).toHaveLength(3);
  });

  it("frame-ancestors en Report-Only ne protège pas : fail -20 et détail", () => {
    const outcome = evaluate({ "content-security-policy-report-only": "frame-ancestors 'none'" });
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.details?.[0]).toContain("Content-Security-Policy-Report-Only ne bloque rien");
  });

  it("frame-ancestors en Report-Only ne masque pas X-Frame-Options: DENY", () => {
    const outcome = evaluate({
      "content-security-policy-report-only": "frame-ancestors 'none'",
      "x-frame-options": "DENY",
    });
    expect(outcome.scoreModifier).toBe(5);
  });

  it("frame-ancestors dans une balise <meta> est ignorée : fail -20 et détail", () => {
    const outcome = evaluate({}, ["default-src 'self'; frame-ancestors 'none'"]);
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.details?.[0]).toContain("balise <meta> est ignorée");
  });
});

describe("clickjackingCheck : sonde en échec", () => {
  it("sans aucune réponse : statut error, 0 point", () => {
    const outcome = clickjackingCheck.evaluate(
      makeContext({ https: failure("TIMEOUT", "Délai dépassé."), http: failure() }),
    );
    expect(outcome.status).toBe("error");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toBe(
      "Impossible de vérifier la protection contre le clickjacking : Délai dépassé.",
    );
  });
});
