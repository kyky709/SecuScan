import { failure, makeContext, makeTlsInfo, ok } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { tlsProtocolCheck } from "@/lib/scanner/checks/tls-protocol";
import type { TlsInfo } from "@/lib/scanner/types";

function evaluateTls(overrides: Partial<TlsInfo>) {
  return tlsProtocolCheck.evaluate(makeContext({ tls: ok(makeTlsInfo(overrides)) }));
}

describe("tlsProtocolCheck — grille de notation", () => {
  it("renvoie une erreur neutre quand la sonde TLS a échoué", () => {
    const outcome = tlsProtocolCheck.evaluate(makeContext({ tls: failure("TLS_ERROR") }));
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it.each([
    ["SSLv3", "SSL 3.0"],
    ["TLSv1", "TLS 1.0"],
    ["TLSv1.1", "TLS 1.1"],
  ])("échoue (-30) quand le protocole négocié est %s", (protocol, label) => {
    const outcome = evaluateTls({ protocol });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
    expect(outcome.summary).toContain(label);
  });

  it.each([
    [{ tls10: true, tls11: false }, "TLS 1.0"],
    [{ tls10: false, tls11: true }, "TLS 1.1"],
    [{ tls10: true, tls11: true }, "TLS 1.0 et TLS 1.1"],
  ])("échoue (-20) quand d'anciens protocoles sont acceptés (%o)", (legacyProtocols, text) => {
    const outcome = evaluateTls({ legacyProtocols });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain(`accepte encore ${text}`);
    expect(outcome.examples?.map((e) => e.label)).toEqual(["Nginx", "Apache"]);
  });

  it("réussit avec TLS 1.2 en recommandant TLS 1.3", () => {
    const outcome = evaluateTls({ protocol: "TLSv1.2", cipher: "ECDHE-RSA-AES128-GCM-SHA256" });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("ne propose pas TLS 1.3");
    expect(outcome.recommendation).toContain("TLS 1.3");
  });

  it("réussit avec TLS 1.3 sans recommandation", () => {
    const outcome = evaluateTls({});
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toContain("refuse les anciennes versions");
    expect(outcome.evidence).toBe("TLSv1.3 (TLS_AES_256_GCM_SHA384)");
    expect(outcome.details).toEqual([
      "Suite de chiffrement négociée : TLS_AES_256_GCM_SHA384.",
      "Protocole applicatif négocié (ALPN) : h2, c'est-à-dire HTTP/2.",
      "TLS 1.0 : refusé.",
      "TLS 1.1 : refusé.",
    ]);
  });
});

describe("tlsProtocolCheck — cas limites", () => {
  it("ne pénalise pas un test des anciens protocoles non concluant", () => {
    const outcome = evaluateTls({ legacyProtocols: { tls10: null, tls11: null } });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).not.toContain("refuse");
    expect(outcome.details).toContain("TLS 1.0 : test non concluant, sans pénalité.");
  });

  it("le pire l'emporte : protocole obsolète négocié et anciens protocoles acceptés", () => {
    const outcome = evaluateTls({
      protocol: "TLSv1",
      legacyProtocols: { tls10: true, tls11: true },
    });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
  });

  it.each([null, "TLSv9"])("signale une version indéterminée (%s) sans pénalité", (protocol) => {
    expect(evaluateTls({ protocol })).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("décrit un ALPN sans HTTP/2 et un ALPN absent", () => {
    expect(evaluateTls({ alpnProtocol: "http/1.1" }).details).toContain(
      "Protocole applicatif négocié (ALPN) : http/1.1 (HTTP/2 n'est pas proposé).",
    );
    expect(evaluateTls({ alpnProtocol: null }).details?.[1]).toContain("Aucun protocole");
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(tlsProtocolCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-30, -20, 0]);
  });
});
