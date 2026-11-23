import {
  failure,
  fetched,
  makeContext,
  makeRedirect,
  makeResponse,
  makeTlsInfo,
  ok,
} from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { tlsCertificateCheck } from "@/lib/scanner/checks/tls-certificate";
import type { CertificateInfo, TlsInfo } from "@/lib/scanner/types";

const evaluate = tlsCertificateCheck.evaluate;

function withCertificate(overrides: Partial<CertificateInfo>, tls: Partial<TlsInfo> = {}) {
  const base = makeTlsInfo();
  if (!base.certificate) throw new Error("Certificat de test manquant.");
  return ok(makeTlsInfo({ ...tls, certificate: { ...base.certificate, ...overrides } }));
}

function rejected(code: string | null, overrides: Partial<CertificateInfo> = {}) {
  return withCertificate(overrides, { authorized: false, authorizationError: code });
}

function finalOnWww(authorizationError: string) {
  return fetched(
    makeResponse({
      url: "https://www.example.com/",
      tls: { authorized: false, authorizationError, protocol: "TLSv1.3" },
    }),
    [makeRedirect("https://example.com/", "https://www.example.com/")],
  );
}

describe("tlsCertificateCheck — grille de notation", () => {
  it.each([
    "CONNECTION_REFUSED",
    "TIMEOUT",
    "TLS_ERROR",
    "CONNECTION_RESET",
  ] as const)("échoue (-30) sans HTTPS quand la sonde TLS échoue (%s)", (code) => {
    const outcome = evaluate(
      makeContext({
        tls: failure(code),
        https: failure(code),
        http: fetched(makeResponse({ url: "http://example.com/" })),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
    expect(outcome.summary).toContain("HTTPS n'est pas disponible");
  });

  it("renvoie une erreur neutre pour un autre échec de sonde, sans réponse HTTPS", () => {
    const outcome = evaluate(
      makeContext({
        tls: failure("DNS_FAILURE", "Nom introuvable."),
        https: failure("DNS_FAILURE", "Nom introuvable."),
        http: fetched(makeResponse({ url: "http://example.com/" })),
      }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it.each([
    ["CERT_HAS_EXPIRED", "il a expiré"],
    ["CERT_NOT_YET_VALID", "pas encore valide"],
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "auto-signé"],
    ["SELF_SIGNED_CERT_IN_CHAIN", "autorité racine inconnue"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "ne couvre pas ce nom d'hôte"],
    ["CERT_REVOKED", "révoqué"],
    ["X509_UNKNOWN_PROBLEM", "code X509_UNKNOWN_PROBLEM"],
  ])("échoue (-50) sur un certificat invalide (%s) avec un message en français", (code, text) => {
    const outcome = evaluate(makeContext({ tls: rejected(code) }));
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain(text);
    expect(outcome.evidence).toContain(`erreur=${code}`);
  });

  it("échoue (-50) quand le certificat de l'hôte final, après redirection, est invalide", () => {
    const outcome = evaluate(makeContext({ https: finalOnWww("CERT_HAS_EXPIRED") }));
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("www.example.com, atteint après redirection");
  });

  it.each([
    "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  ])("avertit (-10) sur une chaîne incomplète (%s)", (code) => {
    const outcome = evaluate(makeContext({ tls: rejected(code) }));
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.summary).toContain("incomplète");
    expect(outcome.recommendation).toContain("fullchain.pem");
  });

  it.each([
    ["RSA", 1024],
    ["EC", 224],
  ])("avertit (-10) sur une clé faible (%s %i bits)", (keyType, keyBits) => {
    const outcome = evaluate(makeContext({ tls: withCertificate({ keyType, keyBits }) }));
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.summary).toContain("clé trop faible");
  });

  it("avertit sans pénalité quand le renouvellement est en retard", () => {
    const outcome = evaluate(
      makeContext({
        tls: withCertificate({
          validFrom: "2026-08-22T00:00:00.000Z",
          validTo: "2026-11-20T00:00:00.000Z",
          daysRemaining: 5,
        }),
      }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("expire dans 5 jours");
  });

  it("réussit avec un certificat valide et détaille ses caractéristiques", () => {
    const outcome = evaluate(makeContext());
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toBe(
      "Le certificat de example.com est valide (émis par Let's Encrypt, expire dans 60 jours).",
    );
    expect(outcome.details).toEqual(
      expect.arrayContaining([
        "Émetteur : Let's Encrypt.",
        "Validité : du 01/10/2026 au 30/12/2026 (60 jours restants).",
        "Noms couverts (SAN) : example.com, www.example.com.",
        "Clé publique : EC de 256 bits.",
        "Chaîne présentée : example.com → E7 → ISRG Root X1.",
      ]),
    );
    expect(outcome.details?.some((d) => d.includes("révocation"))).toBe(true);
  });
});

describe("tlsCertificateCheck — cas limites", () => {
  it("ne conclut pas à l'absence de HTTPS si seule la sonde TLS a échoué", () => {
    // HTTPS a répondu avec un certificat accepté : verdict de repli « valide », sans pénalité.
    const outcome = evaluate(makeContext({ tls: failure("TIMEOUT", "Délai dépassé.") }));
    expect(outcome).toMatchObject({
      status: "pass",
      scoreModifier: 0,
      evidence: "certificat accepté",
    });
    expect(outcome.summary).toBe(
      "Le certificat présenté par example.com lors de la connexion HTTPS est valide.",
    );
    expect(outcome.details?.[0]).toContain("La sonde TLS dédiée a échoué (Délai dépassé.)");
  });

  // Cas réel (expired.badssl.com) : le serveur coupe la connexion de la sonde TLS dédiée, mais la
  // sonde HTTPS a vu le certificat expiré. Le verdict doit rester « invalide », pas « non vérifié ».
  it.each([
    ["CERT_HAS_EXPIRED", "fail", -50, "il a expiré"],
    ["DEPTH_ZERO_SELF_SIGNED_CERT", "fail", -50, "auto-signé"],
    ["ERR_TLS_CERT_ALTNAME_INVALID", "fail", -50, "ne couvre pas ce nom d'hôte"],
    ["UNABLE_TO_VERIFY_LEAF_SIGNATURE", "warning", -10, "incomplète"],
  ] as const)("s'appuie sur la connexion HTTPS quand la sonde TLS échoue (%s)", (code, status, modifier, text) => {
    const response = makeResponse({
      tls: { authorized: false, authorizationError: code, protocol: "TLSv1.2" },
    });
    const outcome = evaluate(
      makeContext({
        tls: failure("CONNECTION_RESET", "La connexion a été interrompue par le serveur."),
        https: fetched(response),
      }),
    );
    expect(outcome).toMatchObject({ status, scoreModifier: modifier, evidence: code });
    expect(outcome.summary).toContain(text);
    expect(outcome.recommendation).toBeTruthy();
  });

  it("juge le certificat de l'hôte analysé (première réponse HTTPS), pas celui de la redirection", () => {
    const first = makeResponse({
      url: "https://example.com/",
      status: 301,
      headers: { location: "https://www.example.com/" },
      tls: { authorized: false, authorizationError: "CERT_HAS_EXPIRED", protocol: "TLSv1.3" },
    });
    const final = makeResponse({ url: "https://www.example.com/" });
    const outcome = evaluate(
      makeContext({ tls: failure("TIMEOUT", "Délai dépassé."), https: fetched(final, [first]) }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("Le certificat de example.com est invalide");
  });

  it("échoue (-50) quand une chaîne incomplète masque un nom d'hôte non couvert", () => {
    const outcome = evaluate(
      makeContext({
        tls: rejected("UNABLE_TO_VERIFY_LEAF_SIGNATURE", { subjectAltNames: ["autre-site.fr"] }),
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("ne couvre pas ce nom d'hôte");
  });

  it.each([
    ["www.example.com", "warning", -10],
    ["example.com", "fail", -50],
    ["a.b.example.com", "fail", -50],
  ] as const)("applique le joker *.example.com sur un seul niveau (%s)", (hostname, status, score) => {
    const tls = withCertificate(
      { subjectAltNames: ["DNS:*.Example.com"] },
      { hostname, authorized: false, authorizationError: "UNABLE_TO_VERIFY_LEAF_SIGNATURE" },
    );
    expect(evaluate(makeContext({ tls }))).toMatchObject({ status, scoreModifier: score });
  });

  it("traite une chaîne incomplète sur l'hôte final comme un avertissement (-10)", () => {
    const outcome = evaluate(makeContext({ https: finalOnWww("UNABLE_TO_VERIFY_LEAF_SIGNATURE") }));
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.summary).toContain("www.example.com");
  });

  it("ne cumule pas chaîne incomplète et clé faible : un seul -10, l'autre en détail", () => {
    const outcome = evaluate(
      makeContext({
        tls: rejected("UNABLE_TO_VERIFY_LEAF_SIGNATURE", { keyType: "RSA", keyBits: 1024 }),
      }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -10 });
    expect(outcome.details?.[0]).toContain("clé trop faible");
  });

  it("accepte une clé RSA de 2048 bits", () => {
    const outcome = evaluate(
      makeContext({ tls: withCertificate({ keyType: "RSA", keyBits: 2048 }) }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it.each([
    [1, "warning"],
    [3, "pass"],
  ] as const)("certificat de 6 jours avec %i jour(s) restant(s) : %s", (daysRemaining, status) => {
    const tls = withCertificate({
      validFrom: "2026-11-14T00:00:00.000Z",
      validTo: "2026-11-20T00:00:00.000Z",
      daysRemaining,
    });
    expect(evaluate(makeContext({ tls }))).toMatchObject({ status, scoreModifier: 0 });
  });

  it("explique un échec de validation sans code d'erreur", () => {
    const outcome = evaluate(makeContext({ tls: rejected(null) }));
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -50 });
    expect(outcome.summary).toContain("n'a pas pu être validé");
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(tlsCertificateCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-50, -30, -10, 0]);
  });
});
