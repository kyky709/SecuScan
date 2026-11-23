/**
 * Tests du contrôle COOP / COEP / CORP : chaque ligne de la grille, puis les cas limites
 * (casse, paramètres structurés, en-tête dupliqué, page servie en HTTP, isolation complète).
 */

import { failure, fetched, makeContext, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { crossOriginIsolationCheck } from "@/lib/scanner/checks/cross-origin-isolation";

/** Évalue le contrôle avec les en-têtes donnés sur la réponse HTTPS analysée. */
function evaluateHeaders(headers: Record<string, string>) {
  return crossOriginIsolationCheck.evaluate(makeContext({ headers }));
}

describe("crossOriginIsolationCheck — grille de notation", () => {
  it.each<Record<string, string>>([
    { "Cross-Origin-Opener-Policy": "nimporte-quoi" },
    { "Cross-Origin-Embedder-Policy": "require-everything" },
    { "Cross-Origin-Resource-Policy": "same-host" },
    { "Cross-Origin-Opener-Policy": "same-origin, same-origin" },
  ])("avertit (-5) sur une valeur invalide : %o", (headers) => {
    const outcome = evaluateHeaders(headers);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("est invalide");
    expect(outcome.examples?.map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    "same-origin",
    "same-origin-allow-popups",
    "noopener-allow-popups",
  ])("donne le bonus (+5) pour COOP %s", (value) => {
    const outcome = evaluateHeaders({
      "Cross-Origin-Opener-Policy": value,
      "Cross-Origin-Resource-Policy": "same-origin",
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5, recommendation: null });
    expect(outcome.summary).toContain(`« ${value} »`);
  });

  it("informe sans pénalité quand COOP est absent", () => {
    const outcome = evaluateHeaders({});
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0, evidence: null });
    expect(outcome.summary).toContain("absent");
    expect(outcome.details).toEqual([
      "Cross-Origin-Opener-Policy : absent, ce qui équivaut à unsafe-none.",
      "Cross-Origin-Embedder-Policy : absent (facultatif, nécessaire seulement pour l'isolation complète).",
      "Cross-Origin-Resource-Policy : absent, n'importe quel site peut intégrer les ressources.",
    ]);
  });

  it("informe sans pénalité quand COOP vaut unsafe-none", () => {
    const outcome = evaluateHeaders({ "Cross-Origin-Opener-Policy": "unsafe-none" });
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("unsafe-none");
  });
});

describe("crossOriginIsolationCheck — cas limites", () => {
  it("le pire l'emporte : COOP isolant mais COEP invalide", () => {
    const outcome = evaluateHeaders({
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require_corp",
    });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.recommendation).toContain("unsafe-none, require-corp, credentialless");
  });

  it("refuse une valeur en majuscules (jetons sensibles à la casse) et l'explique", () => {
    const outcome = evaluateHeaders({ "Cross-Origin-Opener-Policy": "Same-Origin" });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.details?.[0]).toContain("sensibles à la casse");
  });

  it("ignore les paramètres structurés et les espaces", () => {
    const outcome = evaluateHeaders({
      "Cross-Origin-Opener-Policy": ' same-origin ; report-to="coop" ',
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
  });

  it("regroupe plusieurs en-têtes invalides en un seul -5", () => {
    const outcome = evaluateHeaders({
      "Cross-Origin-Opener-Policy": "foo",
      "Cross-Origin-Resource-Policy": "bar",
    });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("Plusieurs en-têtes");
  });

  it("signale l'isolation complète (COOP same-origin + COEP require-corp)", () => {
    const outcome = evaluateHeaders({
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Resource-Policy": "same-site",
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details?.at(-1)).toContain("crossOriginIsolated");
    expect(outcome.evidence).toBe(
      "Cross-Origin-Opener-Policy: same-origin\nCross-Origin-Embedder-Policy: require-corp\nCross-Origin-Resource-Policy: same-site",
    );
  });

  it("conseille CORP quand COOP est isolant mais CORP absent", () => {
    const outcome = evaluateHeaders({ "Cross-Origin-Opener-Policy": "same-origin" });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.recommendation).toContain("Cross-Origin-Resource-Policy");
  });

  it("n'accorde pas de bonus quand la page est servie en HTTP clair (COOP ignoré)", () => {
    const response = makeResponse({
      url: "http://example.com/",
      headers: { "content-type": "text/html", "cross-origin-opener-policy": "same-origin" },
    });
    const outcome = crossOriginIsolationCheck.evaluate(
      makeContext({ https: failure("CONNECTION_REFUSED"), http: fetched(response) }),
    );
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("HTTP clair");
  });

  it("renvoie une erreur neutre quand aucune réponse n'a été obtenue", () => {
    const outcome = crossOriginIsolationCheck.evaluate(
      makeContext({ https: failure("TIMEOUT"), http: failure("TIMEOUT") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(crossOriginIsolationCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-5, 0, 5]);
  });
});
