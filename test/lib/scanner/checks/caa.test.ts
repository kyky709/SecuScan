/**
 * Tests du contrôle « Enregistrements DNS CAA » (RFC 8659) : chaque ligne de la grille (toutes
 * neutres pour la note, les navigateurs n'appliquant pas CAA), la lecture des étiquettes issue,
 * issuewild et iodef (casse ignorée, paramètres après l'autorité, valeur « ; » qui interdit tout),
 * l'étiquette critique inconnue et les enregistrements hérités d'un domaine parent.
 */

import { failure, makeContext, makeTarget, ok } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { caaCheck } from "@/lib/scanner/checks/caa";
import type { CaaRecord } from "@/lib/scanner/types";

function record(tag: string, value: string, critical = 0): CaaRecord {
  return { critical, tag, value };
}

/** Évalue le contrôle pour example.com avec ces enregistrements, trouvés sur `domain`. */
function evaluate(records: CaaRecord[], domain: string | null = "example.com") {
  return caaCheck.evaluate(
    makeContext({ caa: ok({ domain: records.length ? domain : null, records }) }),
  );
}

describe("caaCheck — grille de notation (tout est neutre pour la note)", () => {
  it("est sans objet (info, 0) pour une adresse IP", () => {
    const outcome = caaCheck.evaluate(
      makeContext({
        target: makeTarget({
          input: "93.184.215.14",
          url: "https://93.184.215.14/",
          hostname: "93.184.215.14",
          isIpAddress: true,
        }),
      }),
    );
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("adresse IP");
  });

  it("renvoie une erreur neutre (0) quand la résolution DNS a échoué", () => {
    const outcome = caaCheck.evaluate(makeContext({ caa: failure("TIMEOUT", "Délai dépassé.") }));
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("informe (0) qu'aucun enregistrement n'existe, avec un exemple de zone", () => {
    const outcome = evaluate([]);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0, evidence: null });
    expect(outcome.summary).toBe(
      "Aucun enregistrement CAA : toute autorité de certification peut émettre un certificat pour ce domaine.",
    );
    expect(outcome.examples?.[0]?.code).toContain(
      'example.com.  3600  IN  CAA  0 issue "letsencrypt.org"',
    );
  });

  it("informe (0) quand les enregistrements ne contiennent ni issue ni issuewild", () => {
    const outcome = evaluate([record("iodef", "mailto:secu@example.com")]);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("ne contiennent ni issue ni issuewild");
    expect(outcome.details).toContain(
      "Signalement des demandes refusées (iodef) : mailto:secu@example.com.",
    );
  });

  it("réussit (0) en listant les autorités autorisées, sans doublon ni paramètres", () => {
    const outcome = evaluate([
      record("issue", "letsencrypt.org; validationmethods=dns-01"),
      record("ISSUE", "LetsEncrypt.org"),
      record("issue", "sectigo.com"),
    ]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toBe(
      "Les enregistrements CAA n'autorisent que letsencrypt.org, sectigo.com à émettre des certificats pour ce domaine.",
    );
    expect(outcome.evidence).toContain(
      'example.com. CAA 0 issue "letsencrypt.org; validationmethods=dns-01"',
    );
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    expect(new Set(caaCheck.scoring.map((row) => row.modifier))).toEqual(new Set([0]));
  });
});

describe("caaCheck — lecture des enregistrements (RFC 8659)", () => {
  it("reconnaît issue « ; » : aucune autorité ne peut émettre", () => {
    const outcome = evaluate([record("issue", ";")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("interdisent à toute autorité");
    expect(outcome.details).toContain(
      "Valeur issue « ; » : aucune autorité ne peut émettre de certificat classique.",
    );
  });

  it("précise qu'issuewild seul laisse libre l'émission des certificats classiques", () => {
    const outcome = evaluate([record("issuewild", "digicert.com")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("sans enregistrement issue, toute autorité peut émettre");
    expect(outcome.recommendation).toContain("issue");
    expect(outcome.details).toContain(
      "Certificats génériques (*.example.com) autorisés pour : digicert.com.",
    );
  });

  it("signale les certificats génériques interdits (issuewild « ; »)", () => {
    const outcome = evaluate([record("issue", "letsencrypt.org"), record("issuewild", ";")]);
    expect(outcome.details).toContain(
      "Certificats génériques (wildcard) interdits (issuewild « ; »).",
    );
  });

  it("recommande iodef quand il manque", () => {
    const outcome = evaluate([record("issue", "letsencrypt.org")]);
    expect(outcome.details).toContain(
      "Aucun enregistrement iodef : les autorités ne peuvent pas vous signaler une demande refusée.",
    );
  });

  it("signale une étiquette critique inconnue, qui interdit toute émission", () => {
    const outcome = evaluate([record("issue", "letsencrypt.org"), record("tbs", "x", 128)]);
    expect(outcome.details).toContain(
      "Étiquette critique inconnue « tbs » : les autorités doivent refuser toute émission.",
    );
  });

  it("ignore une étiquette inconnue non critique", () => {
    const outcome = evaluate([record("issue", "letsencrypt.org"), record("tbs", "x", 0)]);
    expect(outcome.details?.some((d) => d.includes("critique"))).toBe(false);
  });

  it("indique quand les enregistrements viennent d'un domaine parent", () => {
    const outcome = caaCheck.evaluate(
      makeContext({
        target: makeTarget({
          input: "www.example.com",
          url: "https://www.example.com/",
          hostname: "www.example.com",
        }),
        caa: ok({ domain: "example.com", records: [record("issue", "letsencrypt.org")] }),
      }),
    );
    expect(outcome.details?.[0]).toBe(
      "Enregistrements trouvés sur le domaine parent example.com : ils s'appliquent aussi à www.example.com.",
    );
  });
});
