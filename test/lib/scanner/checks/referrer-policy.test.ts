/**
 * Tests du contrôle Referrer-Policy : chaque ligne de la grille, la règle « la dernière valeur
 * valide l'emporte », la casse, la balise <meta name="referrer"> et sa priorité sur l'en-tête.
 */

import { failure, makeContext, makeHtmlInfo } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { referrerPolicyCheck } from "@/lib/scanner/checks/referrer-policy";

/** Évalue le contrôle avec l'en-tête et/ou la balise meta donnés. */
function evaluatePolicy(header: string | null, meta: string | null = null) {
  return referrerPolicyCheck.evaluate(
    makeContext({
      headers: header === null ? {} : { "Referrer-Policy": header },
      html: makeHtmlInfo({ metaReferrer: meta }),
    }),
  );
}

describe("referrerPolicyCheck — grille de notation", () => {
  it.each([
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
  ])("donne le bonus (+5) pour la politique stricte %s", (policy) => {
    const outcome = evaluatePolicy(policy);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5, recommendation: null });
    expect(outcome.summary).toContain(`« ${policy} » (en-tête)`);
  });

  it.each([
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "unsafe-url",
  ])("avertit (-5) pour la politique permissive %s", (policy) => {
    const outcome = evaluatePolicy(policy);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.recommendation).toContain(`Remplacez « ${policy} »`);
    expect(outcome.examples?.map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
      "HTML (balise meta)",
    ]);
  });

  it("avertit (-5) pour une valeur invalide", () => {
    const outcome = evaluatePolicy("aucune-idee");
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("invalide");
    expect(outcome.details).toContain("Valeur inconnue ignorée par le navigateur : aucune-idee.");
  });

  it("informe sans pénalité quand aucune politique n'est définie", () => {
    const outcome = evaluatePolicy(null);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("strict-origin-when-cross-origin");
    expect(outcome.recommendation).not.toBeNull();
  });
});

describe("referrerPolicyCheck — cas limites", () => {
  it.each([
    ["no-referrer, unsafe-url", "warning", -5],
    ["unsafe-url, strict-origin-when-cross-origin", "pass", 5],
    ["valeur-future, no-referrer", "pass", 5],
    ["no-referrer, valeur-future", "pass", 5],
  ] as const)("la dernière valeur valide l'emporte : « %s »", (header, status, score) => {
    expect(evaluatePolicy(header)).toMatchObject({ status, scoreModifier: score });
  });

  it("reconnaît une valeur en majuscules et le signale", () => {
    const outcome = evaluatePolicy("  No-Referrer  ");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details?.[0]).toContain("Écrivez No-Referrer en minuscules");
  });

  it("utilise la balise meta quand l'en-tête est absent", () => {
    const outcome = evaluatePolicy(null, "same-origin");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.summary).toContain("(balise meta)");
    expect(outcome.evidence).toBe('<meta name="referrer" content="same-origin">');
  });

  it("donne la priorité à la balise meta valide sur l'en-tête", () => {
    const outcome = evaluatePolicy("unsafe-url", "no-referrer");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details).toContain(
      'La balise <meta name="referrer"> (no-referrer) remplace l\'en-tête (unsafe-url) : elle est appliquée après lui.',
    );
    expect(outcome.evidence).toBe(
      'Referrer-Policy: unsafe-url\n<meta name="referrer" content="no-referrer">',
    );
  });

  it("ignore une balise meta invalide au profit de l'en-tête", () => {
    const outcome = evaluatePolicy("strict-origin", "n-importe-quoi");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details?.[0]).toContain("valeur invalide");
  });

  it("traduit les anciens mots-clés de la balise meta (never = no-referrer)", () => {
    expect(evaluatePolicy(null, "Never")).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(evaluatePolicy(null, "always")).toMatchObject({ status: "warning", scoreModifier: -5 });
  });

  it("considère un en-tête vide comme invalide", () => {
    expect(evaluatePolicy("")).toMatchObject({ status: "warning", scoreModifier: -5 });
  });

  it("renvoie une erreur neutre quand aucune réponse n'a été obtenue", () => {
    const outcome = referrerPolicyCheck.evaluate(
      makeContext({ https: failure("TIMEOUT"), http: failure("TIMEOUT") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(referrerPolicyCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-5, 0, 5]);
  });
});
