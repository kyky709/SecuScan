/**
 * Tests du contrôle « Divulgation d'informations techniques » : chaque ligne de la grille,
 * chaque en-tête examiné, puis les cas limites (CDN, X-Runtime, version majeure seule, casse).
 */

import { failure, makeContext } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { informationDisclosureCheck } from "@/lib/scanner/checks/information-disclosure";

/** Évalue le contrôle avec les en-têtes donnés sur la réponse analysée. */
function evaluateHeaders(headers: Record<string, string>) {
  return informationDisclosureCheck.evaluate(makeContext({ headers }));
}

describe("informationDisclosureCheck — grille de notation", () => {
  it.each([
    ["Server", "Apache/2.4.41 (Ubuntu)"],
    ["X-Powered-By", "PHP/8.1"],
    ["X-AspNet-Version", "4.0.30319"],
    ["X-AspNetMvc-Version", "5.2"],
    ["X-Generator", "WordPress 6.4.2"],
    ["X-Version", "1.4.2"],
  ])("avertit (-5) quand %s expose une version (%s)", (name, value) => {
    const outcome = evaluateHeaders({ [name]: value });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toBe(`L'en-tête ${name} révèle une version logicielle précise.`);
    expect(outcome.evidence).toBe(`${name}: ${value}`);
    expect(outcome.examples?.slice(0, 3).map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    ["Server", "nginx"],
    ["X-Powered-By", "Express"],
    ["X-Powered-By", "Next.js"],
  ])("informe sans pénalité quand %s expose une technologie sans version (%s)", (name, value) => {
    const outcome = evaluateHeaders({ [name]: value });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("sans version précise");
    expect(outcome.recommendation).toContain("Facultatif");
  });

  it.each([
    "cloudflare",
    "Vercel",
    "AmazonS3",
    "Netlify",
  ])("considère Server: %s (hébergeur ou CDN) comme informatif", (value) => {
    const outcome = evaluateHeaders({ Server: value });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toContain("hébergeur ou du CDN");
  });

  it("réussit quand rien n'est exposé", () => {
    const outcome = evaluateHeaders({});
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
  });
});

describe("informationDisclosureCheck — cas limites", () => {
  it("ne prend pas la durée de X-Runtime pour une version", () => {
    const outcome = evaluateHeaders({ "X-Runtime": "0.012345" });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
  });

  it("ne compte pas une version majeure seule comme version précise", () => {
    const outcome = evaluateHeaders({ "X-Generator": "Drupal 10 (https://www.drupal.org)" });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
  });

  it("le pire l'emporte et cite tous les en-têtes concernés, sans cumuler les pénalités", () => {
    const outcome = evaluateHeaders({
      Server: "Apache/2.4.41",
      "X-Powered-By": "PHP/8.1.2, PleskLin",
      "X-Generator": "Drupal 10",
    });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toBe(
      "Les en-têtes Server et X-Powered-By révèlent des versions logicielles précises.",
    );
    expect(outcome.details).toContain(
      "X-Generator : « Drupal 10 », technologie exposée sans version précise (CMS ou générateur du site).",
    );
    expect(outcome.evidence).toBe(
      "Server: Apache/2.4.41\nX-Powered-By: PHP/8.1.2, PleskLin\nX-Generator: Drupal 10",
    );
  });

  it("ignore la casse des noms d'en-têtes", () => {
    const outcome = evaluateHeaders({ "x-POWERED-by": "PHP/7.4.3" });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
  });

  it("ignore un en-tête vide", () => {
    expect(evaluateHeaders({ Server: "   " })).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it("signale une technologie même derrière un CDN", () => {
    const outcome = evaluateHeaders({ Server: "cloudflare", "X-Powered-By": "Express" });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("X-Powered-By");
    expect(outcome.details?.[0]).toContain("hébergeur ou le CDN");
  });

  it("renvoie une erreur neutre quand aucune réponse n'a été obtenue", () => {
    const outcome = informationDisclosureCheck.evaluate(
      makeContext({ https: failure("TIMEOUT"), http: failure("TIMEOUT") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(informationDisclosureCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-5, 0]);
  });
});
