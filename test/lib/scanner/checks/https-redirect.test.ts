import { failure, fetched, makeContext, makeRedirect, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { httpsRedirectCheck } from "@/lib/scanner/checks/https-redirect";

const evaluate = httpsRedirectCheck.evaluate;

describe("httpsRedirectCheck — grille de notation", () => {
  it("réussit sans pénalité quand HTTP est injoignable et HTTPS répond", () => {
    const outcome = evaluate(makeContext({ http: failure("CONNECTION_REFUSED") }));
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toContain("port 80");
  });

  it("échoue (-20) quand HTTPS est indisponible alors que HTTP répond", () => {
    const outcome = evaluate(
      makeContext({
        https: failure("CONNECTION_REFUSED"),
        http: fetched(makeResponse({ url: "http://example.com/" })),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("pas en HTTPS");
  });

  it("échoue (-20) quand la première réponse HTTP n'est pas une redirection", () => {
    const outcome = evaluate(
      makeContext({ http: fetched(makeResponse({ url: "http://example.com/" })) }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("statut 200");
    expect(outcome.examples?.map((e) => e.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    "INVALID_REDIRECT",
    "TOO_MANY_REDIRECTS",
  ] as const)("échoue (-20) sur une erreur de redirection %s", (code) => {
    const outcome = evaluate(makeContext({ http: failure(code, "Redirection refusée.") }));
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20, evidence: null });
    expect(outcome.details).toContain("Erreur : Redirection refusée.");
  });

  it("échoue (-20) quand la chaîne se termine en http://", () => {
    const outcome = evaluate(
      makeContext({
        http: fetched(makeResponse({ url: "http://www.example.com/" }), [
          makeRedirect("http://example.com/", "http://www.example.com/"),
        ]),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
  });

  it("avertit (-10) quand la première redirection passe par une autre URL en HTTP", () => {
    const outcome = evaluate(
      makeContext({
        http: fetched(makeResponse({ url: "https://www.example.com/" }), [
          makeRedirect("http://example.com/", "http://www.example.com/"),
          makeRedirect("http://www.example.com/", "https://www.example.com/"),
        ]),
      }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.details).toContain("La chaîne compte 2 redirections.");
  });

  it("avertit (-5) quand la première redirection mène en HTTPS sur un autre hôte", () => {
    const outcome = evaluate(
      makeContext({
        http: fetched(makeResponse({ url: "https://www.example.com/" }), [
          makeRedirect("http://example.com/", "https://www.example.com/"),
        ]),
      }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("HSTS ne peut pas être activé pour example.com");
  });

  it("réussit quand la première redirection mène en HTTPS sur le même hôte (301)", () => {
    const outcome = evaluate(makeContext());
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toContain("code 301");
    expect(outcome.evidence).toBe("http://example.com/ (301) → https://example.com/ (200)");
    expect(outcome.details).toContain(
      "Les redirections sont permanentes (301 ou 308) : c'est le bon choix.",
    );
  });
});

describe("httpsRedirectCheck — cas limites", () => {
  it("recommande 301/308 quand la redirection est temporaire (302), sans pénalité", () => {
    const outcome = evaluate(
      makeContext({
        http: fetched(makeResponse(), [
          makeRedirect("http://example.com/", "https://example.com/", 302),
        ]),
      }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.recommendation).toContain("301 ou 308");
    expect(outcome.details?.some((d) => d.includes("code 302"))).toBe(true);
  });

  it("résout une Location relative pour une chaîne interrompue par une erreur réseau", () => {
    const outcome = evaluate(
      makeContext({
        http: failure("TIMEOUT", "Délai dépassé.", {
          chain: [makeRedirect("http://example.com/", "/accueil", 308)],
        }),
      }),
    );
    // La 1re redirection (http → http) passe en clair : seule la 1re étape est jugée.
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.evidence).toBe("http://example.com/ (308) → http://example.com/accueil");
    expect(outcome.details?.some((d) => d.includes("Délai dépassé."))).toBe(true);
  });

  it("juge la première étape d'une chaîne interrompue qui menait bien vers HTTPS", () => {
    const outcome = evaluate(
      makeContext({
        http: failure("CONNECTION_RESET", "Connexion interrompue.", {
          chain: [makeRedirect("http://example.com/", "https://example.com/")],
        }),
      }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it("montre la chaîne partielle d'une redirection invalide", () => {
    const outcome = evaluate(
      makeContext({
        http: failure("INVALID_REDIRECT", "Schéma interdit.", {
          chain: [makeRedirect("http://example.com/", "ftp://example.com/")],
        }),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.evidence).toBe("http://example.com/ (301) → ftp://example.com/");
  });

  it("considère une réponse 3xx sans Location comme une absence de redirection", () => {
    const outcome = evaluate(
      makeContext({ http: fetched(makeResponse({ url: "http://example.com/", status: 301 })) }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
  });

  it("compare les hôtes sans tenir compte de la casse", () => {
    const outcome = evaluate(
      makeContext({
        http: fetched(makeResponse(), [
          makeRedirect("http://example.com/", "HTTPS://EXAMPLE.COM/", 308),
        ]),
      }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
  });

  it("renvoie une erreur neutre quand HTTP et HTTPS ont tous deux échoué", () => {
    const outcome = evaluate(
      makeContext({ http: failure("TIMEOUT", "Délai dépassé."), https: failure("TIMEOUT") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(httpsRedirectCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-20, -10, -5, 0]);
  });
});
