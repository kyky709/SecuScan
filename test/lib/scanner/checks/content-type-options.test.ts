import { failure, fetched, makeContext, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { contentTypeOptionsCheck } from "@/lib/scanner/checks/content-type-options";
import { REFS } from "@/lib/scanner/references";
import type { Reference } from "@/lib/scanner/types";

/** null = en-tête absent. */
function evaluate(value: string | null) {
  const headers: Record<string, string> = value === null ? {} : { "x-content-type-options": value };
  return contentTypeOptionsCheck.evaluate(makeContext({ headers }));
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

describe("contentTypeOptionsCheck : définition", () => {
  it("expose chaque ligne de la grille de notation", () => {
    expect(contentTypeOptionsCheck.id).toBe("content-type-options");
    expect(contentTypeOptionsCheck.category).toBe("headers");
    expect(contentTypeOptionsCheck.scoring.map((row) => row.modifier)).toEqual([0, -5, -5]);
  });

  it("cite uniquement le catalogue de références, OWASP d'abord", () => {
    const catalog = Object.values(REFS).flatMap((group) => Object.values(group));
    for (const reference of contentTypeOptionsCheck.references)
      expect(catalog).toContain(reference);
    const ranks = contentTypeOptionsCheck.references.map(referenceRank);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe("contentTypeOptionsCheck : grille", () => {
  it("nosniff : pass 0, rien à recommander", () => {
    const outcome = evaluate("nosniff");
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.evidence).toBe("nosniff");
    expect(outcome.details).toEqual([]);
    expect(outcome.recommendation).toBeNull();
    expect(outcome.examples).toEqual([]);
  });

  it.each([
    "NoSniff",
    "  NOSNIFF  ",
  ])("insensible à la casse et aux blancs (%j) : pass 0", (value) => {
    const outcome = evaluate(value);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
  });

  it("absent : warning -5, avec exemples de configuration", () => {
    const outcome = evaluate(null);
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(-5);
    expect(outcome.summary).toContain("absent");
    expect(outcome.evidence).toBeNull();
    expect(outcome.recommendation).toContain("nosniff");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each(["sniff", "no-sniff", '"nosniff"', "1"])("valeur invalide (%j) : warning -5", (value) => {
    const outcome = evaluate(value);
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(-5);
    expect(outcome.summary).toContain("n'est pas valide");
  });

  it("valeur vide : warning -5", () => {
    const outcome = evaluate("");
    expect(outcome.scoreModifier).toBe(-5);
    expect(outcome.summary).toContain("vide");
  });
});

describe("contentTypeOptionsCheck : plusieurs valeurs (règle Fetch : seule la première compte)", () => {
  it("en-tête répété « nosniff, nosniff » : pass 0 et conseil de n'en envoyer qu'un", () => {
    const outcome = evaluate("nosniff, nosniff");
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.details?.[0]).toContain("seule la première compte");
    expect(outcome.recommendation).toContain("une seule fois");
  });

  it("« nosniff, autre » : la première valeur est nosniff, pass 0", () => {
    expect(evaluate("nosniff, autre").scoreModifier).toBe(0);
  });

  it.each([
    "autre, nosniff",
    ", nosniff",
  ])("« %s » : la première valeur n'est pas nosniff, warning -5", (value) => {
    expect(evaluate(value).scoreModifier).toBe(-5);
  });
});

describe("contentTypeOptionsCheck : sonde en échec", () => {
  it("sans aucune réponse : statut error, 0 point", () => {
    const outcome = contentTypeOptionsCheck.evaluate(
      makeContext({ https: failure("TIMEOUT", "Délai dépassé."), http: failure() }),
    );
    expect(outcome.status).toBe("error");
    expect(outcome.scoreModifier).toBe(0);
  });

  it("HTTPS en échec mais HTTP disponible : la réponse HTTP est analysée", () => {
    const httpResponse = makeResponse({
      url: "http://example.com/",
      headers: { "x-content-type-options": "nosniff" },
    });
    const context = makeContext({ https: failure(), http: fetched(httpResponse) });
    expect(contentTypeOptionsCheck.evaluate(context).status).toBe("pass");
  });
});
