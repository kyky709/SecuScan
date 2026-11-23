/**
 * Tests du contrôle HSTS : chaque ligne de la grille, la grammaire de la RFC 6797 (casse,
 * guillemets, espaces, directives répétées) et les constats secondaires (en-tête dupliqué,
 * HSTS envoyé en HTTP clair, certificat invalide, adresse IP).
 */

import { failure, fetched, makeContext, makeResponse, makeTarget } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { hstsCheck } from "@/lib/scanner/checks/hsts";

/** Évalue le contrôle avec l'en-tête HSTS donné sur la réponse HTTPS finale. */
function evaluateHeader(value: string) {
  return hstsCheck.evaluate(makeContext({ headers: { "Strict-Transport-Security": value } }));
}

describe("hstsCheck — grille de notation", () => {
  it("échoue (-20) quand le site n'est pas accessible en HTTPS", () => {
    const outcome = hstsCheck.evaluate(
      makeContext({
        https: failure("CONNECTION_REFUSED"),
        http: fetched(makeResponse({ url: "http://example.com/" })),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("pas accessible en HTTPS");
  });

  it("échoue (-20) quand l'en-tête est absent", () => {
    const outcome = hstsCheck.evaluate(makeContext());
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20, evidence: null });
    expect(outcome.examples?.map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    ["includeSubDomains", "max-age, obligatoire, est absente"],
    ["max-age=abc", "n'est pas un nombre entier"],
    ["max-age", "n'est pas un nombre entier"],
    ["max-age=-5", "n'est pas un nombre entier"],
    ["max-age=31536000; max-age=31536000", "« max-age » apparaît plusieurs fois"],
    ["max-age=31536000; include subdomains", "« include subdomains » est mal formée"],
  ])("échoue (-20) sur un en-tête invalide « %s »", (value, reason) => {
    const outcome = evaluateHeader(value);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20, evidence: value });
    expect(outcome.summary).toContain(reason);
  });

  it("échoue (-20) avec max-age=0", () => {
    const outcome = evaluateHeader("max-age=0; includeSubDomains");
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("max-age=0");
  });

  it("avertit (-10) quand max-age est inférieur à 15552000 s", () => {
    const outcome = evaluateHeader("max-age=15551999");
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.recommendation).toContain("15552000");
  });

  it("réussit sans bonus avec exactement 15552000 s (180 jours)", () => {
    const outcome = evaluateHeader("max-age=15552000");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toBe("L'en-tête HSTS est présent avec max-age=15552000 (180 jours).");
    expect(outcome.recommendation).toContain("includeSubDomains");
  });

  it("donne le bonus (+5) quand l'en-tête est éligible au préchargement", () => {
    const outcome = evaluateHeader("max-age=31536000; includeSubDomains; preload");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5, recommendation: null });
    expect(outcome.details?.some((d) => d.includes("hstspreload.org"))).toBe(true);
  });
});

describe("hstsCheck — cas limites", () => {
  it("ignore la casse des noms de directives", () => {
    const outcome = evaluateHeader("MAX-AGE=63072000; INCLUDESUBDOMAINS; Preload");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
  });

  it("accepte un max-age entre guillemets, des espaces et un « ; » final", () => {
    const outcome = evaluateHeader('  max-age = "63072000" ;  includeSubDomains ; ');
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.details?.some((d) => d.includes("préchargement"))).toBe(false);
  });

  it("n'analyse que le premier en-tête quand il est envoyé plusieurs fois", () => {
    const outcome = evaluateHeader("max-age=63072000; includeSubDomains, max-age=0");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details?.[0]).toContain("seul le premier en-tête est pris en compte");
  });

  it("échoue si le premier des en-têtes dupliqués est invalide", () => {
    const outcome = evaluateHeader("max-age=0, max-age=63072000; includeSubDomains");
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
  });

  it("explique pourquoi preload seul ne suffit pas au préchargement", () => {
    const outcome = evaluateHeader("max-age=15552000; preload");
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details).toContain(
      "La directive preload est présente, mais le préchargement exige aussi max-age ≥ 31536000 (un an) et includeSubDomains.",
    );
  });

  it("signale un en-tête HSTS envoyé en HTTP clair, ignoré par les navigateurs", () => {
    const header = { "strict-transport-security": "max-age=63072000; includeSubDomains" };
    const redirect = makeResponse({
      url: "http://example.com/",
      status: 301,
      headers: { location: "https://example.com/", ...header },
    });
    const outcome = hstsCheck.evaluate(
      makeContext({ headers: header, http: fetched(makeResponse(), [redirect]) }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details?.[0]).toContain("aussi envoyé en HTTP clair");
  });

  it("signale un certificat invalide sans pénalité supplémentaire", () => {
    const response = makeResponse({
      headers: { "strict-transport-security": "max-age=63072000; includeSubDomains" },
      tls: { authorized: false, authorizationError: "CERT_HAS_EXPIRED", protocol: "TLSv1.3" },
    });
    const outcome = hstsCheck.evaluate(makeContext({ https: fetched(response) }));
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details?.[0]).toContain("certificat présenté est invalide");
  });

  it("rappelle que HSTS ne s'applique pas à une adresse IP", () => {
    const outcome = hstsCheck.evaluate(
      makeContext({
        target: makeTarget({ hostname: "93.184.215.14", isIpAddress: true }),
        headers: { "strict-transport-security": "max-age=63072000; includeSubDomains" },
      }),
    );
    expect(outcome.details?.some((d) => d.includes("adresse IP"))).toBe(true);
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(hstsCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-20, -10, 0, 5]);
  });
});
