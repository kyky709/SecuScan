/**
 * Tests du contrôle « Partage entre origines (CORS) » : chaque ligne de la grille et les règles
 * de la spécification Fetch (« CORS check ») : Access-Control-Allow-Origin comparé exactement à
 * l'origine de la requête, Access-Control-Allow-Credentials valable seulement s'il vaut
 * exactement « true », « * » incompatible avec les cookies, plusieurs valeurs = accès refusé.
 */

import { failure, fetched, makeContext, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { CORS_PROBE_ORIGIN } from "@/lib/config";
import { corsCheck } from "@/lib/scanner/checks/cors";

/** Évalue le contrôle quand la sonde CORS reçoit ces en-têtes. */
function evaluate(headers: Record<string, string>) {
  return corsCheck.evaluate(makeContext({ cors: fetched(makeResponse({ headers })) }));
}

const REFLECTED = { "access-control-allow-origin": CORS_PROBE_ORIGIN };
const CREDENTIALS = { "access-control-allow-credentials": "true" };

describe("corsCheck — grille de notation", () => {
  it("renvoie une erreur neutre (0) quand la sonde a échoué", () => {
    const outcome = corsCheck.evaluate(makeContext({ cors: failure("TIMEOUT", "Délai dépassé.") }));
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
    expect(outcome.summary).toBe("Impossible de vérifier la politique CORS : Délai dépassé.");
  });

  it("réussit (0) sans en-tête Access-Control-Allow-Origin", () => {
    const outcome = evaluate({});
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, evidence: null });
    expect(outcome.details).toEqual([`Origine de test envoyée : ${CORS_PROBE_ORIGIN}.`]);
  });

  it("échoue (-50) quand l'origine est recopiée avec les cookies autorisés", () => {
    const outcome = evaluate({ ...REFLECTED, ...CREDENTIALS, vary: "Origin" });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("tout site peut lire les réponses destinées au visiteur");
    expect(outcome.evidence).toBe(
      `Access-Control-Allow-Origin: ${CORS_PROBE_ORIGIN}\nAccess-Control-Allow-Credentials: true\nVary: Origin`,
    );
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache (mod_setenvif et mod_headers)",
      "Next.js (next.config.ts)",
    ]);
  });

  it("échoue (-50) sur l'origine « null » avec les cookies autorisés", () => {
    const outcome = evaluate({ "access-control-allow-origin": "null", ...CREDENTIALS });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("iframe sandbox");
  });

  it("avertit sans pénalité (0) quand l'origine est recopiée sans cookies : équivaut à *", () => {
    const outcome = evaluate(REFLECTED);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("cela équivaut à *");
  });

  it("avertit sans pénalité (0) sur l'origine « null » sans cookies", () => {
    const outcome = evaluate({ "access-control-allow-origin": "null" });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
  });

  it("informe (0) sur * : contenu public", () => {
    const outcome = evaluate({ "access-control-allow-origin": "*" });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("le contenu est public");
  });

  it("réussit (0) quand l'accès est limité à une origine précise", () => {
    const outcome = evaluate({
      "access-control-allow-origin": "https://app.example.com",
      ...CREDENTIALS,
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toBe(
      "L'accès entre origines est limité à une origine précise (https://app.example.com), différente de l'origine de test.",
    );
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(corsCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-50, 0]);
  });
});

describe("corsCheck — règles exactes de la spécification Fetch", () => {
  it.each([
    "TRUE",
    "True",
    "1",
    "yes",
  ])("ignore Access-Control-Allow-Credentials: %s (seul « true » exact compte)", (value) => {
    const outcome = evaluate({ ...REFLECTED, "access-control-allow-credentials": value });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.details).toContain(
      `Access-Control-Allow-Credentials vaut « ${value} » : seule la valeur exacte « true » est reconnue, l'en-tête est donc sans effet.`,
    );
  });

  it("tolère les espaces autour de « true » (retirés par l'analyse HTTP)", () => {
    const outcome = evaluate({ ...REFLECTED, "access-control-allow-credentials": " true " });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
  });

  it("note que * avec les cookies est refusé par les navigateurs", () => {
    const outcome = evaluate({ "access-control-allow-origin": "*", ...CREDENTIALS });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.details).toContain(
      "Access-Control-Allow-Credentials: true est ignoré avec * : les navigateurs refusent cette combinaison pour les requêtes avec cookies.",
    );
  });

  it("considère plusieurs valeurs (en-tête dupliqué) comme invalides : accès refusé", () => {
    const outcome = evaluate({
      "access-control-allow-origin": `${CORS_PROBE_ORIGIN}, https://app.example.com`,
      ...CREDENTIALS,
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("contient plusieurs valeurs");
    expect(outcome.recommendation).toContain("une seule origine");
  });

  it("compare l'origine exactement : une variante ne correspond pas à l'origine de test", () => {
    const outcome = evaluate({
      "access-control-allow-origin": CORS_PROBE_ORIGIN.toUpperCase(),
      ...CREDENTIALS,
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it("signale une origine recopiée sans Vary: Origin (risque de cache partagé)", () => {
    const outcome = evaluate({ ...REFLECTED, ...CREDENTIALS });
    expect(outcome.details?.some((d) => d.includes("sans Vary: Origin"))).toBe(true);
  });

  it("accepte Vary: * ou Vary: origin (casse ignorée) comme variation par origine", () => {
    for (const vary of ["*", "Accept-Encoding, origin"]) {
      const outcome = evaluate({ ...REFLECTED, ...CREDENTIALS, vary });
      expect(outcome.details?.some((d) => d.includes("sans Vary: Origin"))).toBe(false);
    }
  });
});
