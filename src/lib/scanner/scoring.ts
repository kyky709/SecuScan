/**
 * Règles de MDN HTTP Observatory (algorithme v6, vérifié dans son code source) : 100 points moins
 * toutes les pénalités ; les bonus ne s'ajoutent que si ce score atteint 90, sinon aucun. Un bonus
 * ne doit jamais masquer un vrai problème (une excellente CSP ne compense pas un cookie de session
 * envoyé en clair). Plancher à 0, pas de plafond : 115/100 est possible et vaut A+.
 *
 * Chaque contrôle fournit un seul modificateur (son constat le plus grave) : les pénalités d'un
 * même contrôle ne se cumulent pas.
 *
 * Ne dépend que des types : l'interface l'importe pour afficher le barème.
 */
import type { CheckOutcome, Grade, ScoreBreakdown } from "@/lib/scanner/types";

export const BASE_SCORE = 100;

export const BONUS_THRESHOLD = 90;

// 7 lettres comme securityheaders.com, seuils inspirés d'Observatory. `gradeFor` dépend de l'ordre.
export const GRADE_THRESHOLDS: ReadonlyArray<{ grade: Grade; minScore: number }> = [
  { grade: "A+", minScore: 100 },
  { grade: "A", minScore: 85 },
  { grade: "B", minScore: 70 },
  { grade: "C", minScore: 55 },
  { grade: "D", minScore: 40 },
  { grade: "E", minScore: 25 },
  { grade: "F", minScore: 0 },
];

/** Un score négatif ou invalide (NaN) vaut F. */
export function gradeFor(score: number): Grade {
  const threshold = GRADE_THRESHOLDS.find(({ minScore }) => score >= minScore);
  return threshold?.grade ?? "F";
}

/**
 * Pénalités -15 et bonus +10 → 85 sans bonus (< 90) → bonus ignorés → 85 (A).
 * Pénalité -10 seulement → 90 → bonus appliqués → 100 (A+).
 */
export function computeScore(
  results: ReadonlyArray<Pick<CheckOutcome, "scoreModifier">>,
): ScoreBreakdown {
  const modifiers = results.map((result) => result.scoreModifier);
  const penalties = sum(modifiers.filter((modifier) => modifier < 0));
  const bonuses = sum(modifiers.filter((modifier) => modifier > 0));

  const scoreWithoutBonuses = BASE_SCORE + penalties;
  // Vrai dès que le seuil est atteint, même si aucun bonus n'a été obtenu.
  const bonusesApplied = scoreWithoutBonuses >= BONUS_THRESHOLD;
  const rawScore = bonusesApplied ? scoreWithoutBonuses + bonuses : scoreWithoutBonuses;
  const score = Math.max(0, rawScore);

  return { base: BASE_SCORE, penalties, bonuses, bonusesApplied, score, grade: gradeFor(score) };
}

function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}
