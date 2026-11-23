import { makeReport, sampleReport } from "@test/fixtures/sample-report";
import { describe, expect, it } from "vitest";
import {
  BONUS_THRESHOLD,
  describeModifier,
  describeRedirectStatus,
  displayHeaderValue,
  explainScore,
  exportFileName,
  formatDate,
  formatDateTime,
  formatDaysRemaining,
  formatDuration,
  formatLegacyProtocol,
  formatModifier,
  formatRetryDelay,
  formatScore,
  formatTlsVersion,
  isProblem,
  maskSetCookie,
  probeLabel,
  shareUrlFor,
} from "@/components/report/format";
import { computeScore, BONUS_THRESHOLD as ENGINE_BONUS_THRESHOLD } from "@/lib/scanner/scoring";

const NBSP = " ";
const MINUS = "−";

describe("formatDuration", () => {
  it("affiche des secondes avec une décimale et une virgule (« 3,2 s »)", () => {
    expect(formatDuration(3200)).toBe(`3,2${NBSP}s`);
    expect(formatDuration(12_345)).toBe(`12,3${NBSP}s`);
    expect(formatDuration(0)).toBe(`0,0${NBSP}s`);
  });
});

describe("formatDateTime et formatDate", () => {
  it("écrivent le mois en toutes lettres", () => {
    expect(formatDateTime("2026-11-15T12:00:00.000Z")).toMatch(/15 novembre 2026/);
    expect(formatDate("2026-12-30T12:00:00.000Z")).toBe("30 décembre 2026");
  });

  it("renvoient telle quelle une date illisible", () => {
    expect(formatDateTime("pas une date")).toBe("pas une date");
    expect(formatDate("")).toBe("");
  });
});

describe("formatModifier et describeModifier", () => {
  it("signent le modificateur avec un vrai signe moins", () => {
    expect(formatModifier(5)).toBe("+5");
    expect(formatModifier(-20)).toBe(`${MINUS}20`);
    expect(formatModifier(0)).toBe("0");
  });

  it("décrivent le modificateur en toutes lettres, avec l'accord du pluriel", () => {
    expect(describeModifier(-20)).toBe("pénalité de 20 points");
    expect(describeModifier(-1)).toBe("pénalité de 1 point");
    expect(describeModifier(5)).toBe("bonus de 5 points");
    expect(describeModifier(1)).toBe("bonus de 1 point");
    expect(describeModifier(0)).toBe("sans effet sur la note");
  });
});

describe("formatScore", () => {
  it("affiche le score sur 100, sans plafond", () => {
    expect(formatScore(85)).toBe("85/100");
    expect(formatScore(115)).toBe("115/100");
  });
});

describe("formatTlsVersion", () => {
  it("rend la version lisible", () => {
    expect(formatTlsVersion("TLSv1.3")).toBe("TLS 1.3");
    expect(formatTlsVersion("TLSv1")).toBe("TLS 1");
    expect(formatTlsVersion("SSLv3")).toBe("SSL 3");
    expect(formatTlsVersion(null)).toBe("inconnue");
  });
});

describe("formatDaysRemaining", () => {
  it("gère l'avenir, le jour même et le passé", () => {
    expect(formatDaysRemaining(60)).toBe("60 jours");
    expect(formatDaysRemaining(1)).toBe("1 jour");
    expect(formatDaysRemaining(0)).toBe("expire aujourd'hui");
    expect(formatDaysRemaining(-1)).toBe("expiré depuis 1 jour");
    expect(formatDaysRemaining(-3)).toBe("expiré depuis 3 jours");
  });
});

describe("formatRetryDelay", () => {
  it("exprime le délai en secondes, puis en minutes au-delà de deux minutes", () => {
    expect(formatRetryDelay(42)).toBe("42 secondes");
    expect(formatRetryDelay(1)).toBe("1 seconde");
    expect(formatRetryDelay(0.2)).toBe("1 seconde");
    expect(formatRetryDelay(0)).toBe("1 seconde");
    expect(formatRetryDelay(119.5)).toBe("2 minutes");
    expect(formatRetryDelay(150)).toBe("3 minutes");
  });
});

describe("exportFileName", () => {
  it("combine l'hôte et la date de l'analyse", () => {
    expect(exportFileName(sampleReport)).toBe("secuscan-example.com-2026-11-15.json");
  });

  it("remplace les caractères impropres à un nom de fichier (IPv6)", () => {
    const report = makeReport({ target: { ...sampleReport.target, hostname: "2001:DB8::1" } });
    expect(exportFileName(report)).toBe("secuscan-2001-db8-1-2026-11-15.json");
  });
});

describe("shareUrlFor", () => {
  it("construit le lien de la page d'accueil avec ?url=", () => {
    expect(shareUrlFor("example.com", "https://secuscan.example")).toBe(
      "https://secuscan.example/?url=example.com",
    );
  });

  it("encode les caractères spéciaux", () => {
    expect(shareUrlFor("a&b=c", "https://secuscan.example")).toBe(
      "https://secuscan.example/?url=a%26b%3Dc",
    );
  });
});

describe("isProblem", () => {
  it("ne retient que les statuts « À corriger » et « À améliorer »", () => {
    expect(isProblem("fail")).toBe(true);
    expect(isProblem("warning")).toBe(true);
    expect(isProblem("pass")).toBe(false);
    expect(isProblem("info")).toBe(false);
    expect(isProblem("error")).toBe(false);
  });
});

describe("describeRedirectStatus", () => {
  it("distingue les redirections permanentes et temporaires", () => {
    expect(describeRedirectStatus(301)).toBe("Redirection permanente");
    expect(describeRedirectStatus(308)).toBe("Redirection permanente");
    expect(describeRedirectStatus(302)).toBe("Redirection temporaire");
    expect(describeRedirectStatus(303)).toBe("Redirection temporaire");
    expect(describeRedirectStatus(307)).toBe("Redirection temporaire");
    expect(describeRedirectStatus(200)).toBeNull();
  });
});

describe("formatLegacyProtocol", () => {
  it("traduit les trois résultats possibles", () => {
    expect(formatLegacyProtocol(true)).toBe("accepté (à désactiver)");
    expect(formatLegacyProtocol(false)).toBe("refusé");
    expect(formatLegacyProtocol(null)).toBe("test non concluant");
  });
});

describe("probeLabel", () => {
  it("nomme chaque sonde en français, et laisse un nom inconnu tel quel", () => {
    expect(probeLabel("caa")).toBe("Enregistrements DNS CAA");
    expect(probeLabel("securityTxt")).toBe("Fichier security.txt");
    expect(probeLabel("https")).toBe("Requête HTTPS");
    expect(probeLabel("autre")).toBe("autre");
  });
});

describe("maskSetCookie et displayHeaderValue", () => {
  it("masquent la valeur d'un cookie mais gardent son nom et ses attributs", () => {
    expect(maskSetCookie("session=abc123; Secure; HttpOnly")).toBe("session=***; Secure; HttpOnly");
    expect(maskSetCookie("token=abc")).toBe("token=***");
    expect(maskSetCookie(" id = x ;Path=/")).toBe("id=***;Path=/");
  });

  it("masquent aussi un cookie sans nom (valeur seule)", () => {
    expect(maskSetCookie("valeur-secrete")).toBe("=***");
  });

  it("ne modifient que les en-têtes Set-Cookie, quelle que soit la casse", () => {
    expect(displayHeaderValue("Set-Cookie", "a=b; Secure")).toBe("a=***; Secure");
    expect(displayHeaderValue("set-cookie", "a=b")).toBe("a=***");
    expect(displayHeaderValue("Server", "nginx")).toBe("nginx");
  });
});

describe("explainScore", () => {
  it("utilise le même seuil de bonus que le moteur de notation", () => {
    expect(BONUS_THRESHOLD).toBe(ENGINE_BONUS_THRESHOLD);
  });

  it("explique un score sans pénalité ni bonus", () => {
    expect(explainScore(computeScore([]))).toEqual({
      formula: "100 (aucune pénalité ni bonus) = 100",
      bonusNote: "Aucun bonus obtenu.",
    });
  });

  it("explique des bonus ignorés car le score après pénalités est sous le seuil", () => {
    const { formula, bonusNote } = explainScore(sampleReport.score);
    expect(formula).toBe(`100 ${MINUS} 45 (pénalités) = 55`);
    expect(bonusNote).toContain("Les bonus (+5) ne sont pas comptés");
    expect(bonusNote).toContain("or il est de 55");
  });

  it("explique des bonus comptés, au-delà de 100", () => {
    const score = computeScore([
      { scoreModifier: -5 },
      { scoreModifier: 10 },
      { scoreModifier: 10 },
    ]);
    const { formula, bonusNote } = explainScore(score);
    expect(formula).toBe(`100 ${MINUS} 5 (pénalités) + 20 (bonus) = 115`);
    expect(bonusNote).toBe(
      "Les bonus (+20) sont comptés : le score après pénalités (95) atteint le seuil de 90.",
    );
  });

  it("signale le plancher à 0", () => {
    const score = computeScore([
      { scoreModifier: -60 },
      { scoreModifier: -50 },
      { scoreModifier: 5 },
    ]);
    const { formula, bonusNote } = explainScore(score);
    expect(formula).toBe(`100 ${MINUS} 110 (pénalités) = 0 (le score ne descend pas sous 0)`);
    expect(bonusNote).toContain("or il est de 0");
  });
});
