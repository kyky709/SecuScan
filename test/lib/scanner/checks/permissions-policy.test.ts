/**
 * Tests du contrôle Permissions-Policy : chaque ligne de la grille, puis la syntaxe des champs
 * structurés (casse des clés, paramètres, espaces, virgule en trop, en-tête dupliqué).
 */

import { failure, makeContext } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { permissionsPolicyCheck } from "@/lib/scanner/checks/permissions-policy";

/** Évalue le contrôle avec les en-têtes donnés sur la réponse analysée. */
function evaluateHeaders(headers: Record<string, string>) {
  return permissionsPolicyCheck.evaluate(makeContext({ headers }));
}

/** Évalue le contrôle avec la valeur de Permissions-Policy donnée. */
function evaluatePolicy(value: string) {
  return evaluateHeaders({ "Permissions-Policy": value });
}

describe("permissionsPolicyCheck — grille de notation", () => {
  it("réussit quand l'en-tête est présent et lisible", () => {
    const outcome = evaluatePolicy(
      'camera=(), microphone=(), geolocation=(self "https://example.com")',
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toContain("3 fonctionnalités encadrées");
    expect(outcome.details?.[0]).toBe("Fonctionnalités désactivées : camera, microphone.");
  });

  it("avertit sans pénalité quand la syntaxe est invalide (ancienne syntaxe Feature-Policy)", () => {
    const outcome = evaluatePolicy("camera 'none'; microphone 'none'");
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("syntaxe est invalide");
    expect(outcome.details?.some((d) => d.includes("ancienne syntaxe Feature-Policy"))).toBe(true);
  });

  it("avertit sans pénalité quand seul l'ancien Feature-Policy est présent", () => {
    const outcome = evaluateHeaders({ "Feature-Policy": "camera 'none'" });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("Feature-Policy");
    expect(outcome.evidence).toBe("Feature-Policy: camera 'none'");
  });

  it("avertit sans pénalité quand l'en-tête est absent", () => {
    const outcome = evaluateHeaders({});
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0, evidence: null });
    expect(outcome.examples?.map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });
});

describe("permissionsPolicyCheck — cas limites", () => {
  it.each([
    "camera=();report-to=main",
    "camera=(),microphone=()",
    "  camera=( )  ,\tgeolocation=self  ",
    "fullscreen=*, autoplay",
    'geolocation=(self "https://a.example" "https://b.example")',
  ])("accepte la syntaxe valide « %s »", (value) => {
    expect(evaluatePolicy(value)).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it.each([
    ["Camera=()", "minuscules"],
    ["camera=(", "Élément invalide"],
    ["camera=(),", "une virgule est en trop"],
    ['geolocation=("https://a.example"', "Élément invalide"],
    ["camera=(self,https://a.example)", "Élément invalide"],
  ])("refuse la syntaxe invalide « %s »", (value, hint) => {
    const outcome = evaluatePolicy(value);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.details?.some((d) => d.includes(hint))).toBe(true);
  });

  it("signale les fonctionnalités ouvertes à toutes les origines", () => {
    const outcome = evaluatePolicy("geolocation=*, camera=(self *)");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details).toContain(
      "Autorisées pour toutes les origines (*) : geolocation, camera ; préférez self ou une liste d'origines précises.",
    );
    expect(outcome.recommendation).toContain("Remplacez *");
  });

  it("accepte un en-tête dupliqué (valeurs jointes par « , ») et signale la répétition", () => {
    const outcome = evaluatePolicy("camera=(), camera=(self)");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("1 fonctionnalité encadrée");
    expect(outcome.details).toContain(
      "Déclarées plusieurs fois (la dernière valeur l'emporte) : camera.",
    );
  });

  it("traite un en-tête vide comme une absence de politique", () => {
    const outcome = evaluatePolicy("   ");
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("vide");
  });

  it("suggère de retirer Feature-Policy quand les deux en-têtes sont présents", () => {
    const outcome = evaluateHeaders({
      "Permissions-Policy": "camera=()",
      "Feature-Policy": "camera 'none'",
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details?.at(-1)).toContain("vous pouvez le retirer");
  });

  it("renvoie une erreur neutre quand aucune réponse n'a été obtenue", () => {
    const outcome = permissionsPolicyCheck.evaluate(
      makeContext({ https: failure("TIMEOUT"), http: failure("TIMEOUT") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("déclare uniquement des modificateurs nuls dans la grille", () => {
    expect(permissionsPolicyCheck.scoring.every((row) => row.modifier === 0)).toBe(true);
    expect(permissionsPolicyCheck.scoring).toHaveLength(4);
  });
});
