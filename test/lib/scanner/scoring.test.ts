/**
 * Tests de la notation : règles d'Observatory (bonus tout ou rien à partir de 90 points sans
 * bonus, plancher à 0, pas de plafond) et seuils des notes de SecuScan, à chaque frontière.
 */
import { describe, expect, it } from "vitest";
import {
  BASE_SCORE,
  BONUS_THRESHOLD,
  computeScore,
  GRADE_THRESHOLDS,
  gradeFor,
} from "@/lib/scanner/scoring";
import type { Grade } from "@/lib/scanner/types";

/** Verdicts réduits à leur modificateur : c'est tout ce que lit `computeScore`. */
function outcomes(...modifiers: number[]): Array<{ scoreModifier: number }> {
  return modifiers.map((scoreModifier) => ({ scoreModifier }));
}

describe("constantes de notation", () => {
  it("part de 100 points et exige 90 points sans bonus pour appliquer les bonus", () => {
    expect(BASE_SCORE).toBe(100);
    expect(BONUS_THRESHOLD).toBe(90);
  });

  it("classe les notes de la meilleure à la moins bonne, F couvrant tout le reste", () => {
    expect(GRADE_THRESHOLDS).toEqual([
      { grade: "A+", minScore: 100 },
      { grade: "A", minScore: 85 },
      { grade: "B", minScore: 70 },
      { grade: "C", minScore: 55 },
      { grade: "D", minScore: 40 },
      { grade: "E", minScore: 25 },
      { grade: "F", minScore: 0 },
    ]);
  });
});

describe("gradeFor", () => {
  it.each<[score: number, grade: Grade]>([
    [145, "A+"],
    [100, "A+"],
    [99, "A"],
    [85, "A"],
    [84, "B"],
    [70, "B"],
    [69, "C"],
    [55, "C"],
    [54, "D"],
    [40, "D"],
    [39, "E"],
    [25, "E"],
    [24, "F"],
    [0, "F"],
    [-10, "F"],
    [Number.NaN, "F"],
  ])("%d points → %s", (score, grade) => {
    expect(gradeFor(score)).toBe(grade);
  });
});

describe("computeScore", () => {
  it("donne 100/100 (A+) à un site sans aucun constat", () => {
    expect(computeScore([])).toEqual({
      base: 100,
      penalties: 0,
      bonuses: 0,
      bonusesApplied: true,
      score: 100,
      grade: "A+",
    });
  });

  it("additionne les pénalités et ignore les modificateurs nuls", () => {
    expect(computeScore(outcomes(-20, 0, -10, 0))).toMatchObject({
      penalties: -30,
      bonuses: 0,
      score: 70,
      grade: "B",
    });
  });

  it("applique tous les bonus quand le score sans bonus vaut exactement 90", () => {
    expect(computeScore(outcomes(-10, 5, 10))).toEqual({
      base: 100,
      penalties: -10,
      bonuses: 15,
      bonusesApplied: true,
      score: 105,
      grade: "A+",
    });
  });

  it("n'applique aucun bonus à 89 points, juste sous le seuil", () => {
    expect(computeScore(outcomes(-11, 10))).toMatchObject({
      bonuses: 10,
      bonusesApplied: false,
      score: 89,
      grade: "A",
    });
  });

  it("écarte tous les bonus à 85 points : un bonus ne masque jamais un vrai problème", () => {
    expect(computeScore(outcomes(-15, 5, 10))).toEqual({
      base: 100,
      penalties: -15,
      bonuses: 15,
      bonusesApplied: false,
      score: 85,
      grade: "A",
    });
  });

  it("ne plafonne pas le score : au-delà de 100, il est conservé et vaut A+", () => {
    expect(computeScore(outcomes(10, 5, 5))).toMatchObject({ score: 120, grade: "A+" });
  });

  it.each<[modifiers: number[], score: number, grade: Grade]>([
    [[-10, 10], 100, "A+"],
    [[-6, 5], 99, "A"],
    [[-15], 85, "A"],
    [[-16], 84, "B"],
    [[-75], 25, "E"],
    [[-76], 24, "F"],
  ])("frontière de note : %j → %d (%s)", (modifiers, score, grade) => {
    expect(computeScore(outcomes(...modifiers))).toMatchObject({ score, grade });
  });

  it("ne descend jamais sous 0", () => {
    expect(computeScore(outcomes(-50, -50, -30))).toEqual({
      base: 100,
      penalties: -130,
      bonuses: 0,
      bonusesApplied: false,
      score: 0,
      grade: "F",
    });
  });

  it("reste à 0 malgré des bonus, qui ne sont pas appliqués", () => {
    expect(computeScore(outcomes(-120, 10))).toMatchObject({
      bonusesApplied: false,
      score: 0,
      grade: "F",
    });
  });
});
