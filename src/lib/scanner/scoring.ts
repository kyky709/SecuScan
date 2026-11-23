/**
 * Calcul du score et de la note finale (A+ à F) à partir des verdicts des contrôles.
 *
 * Les règles reprennent celles de MDN HTTP Observatory (algorithme v6, vérifié dans son code
 * source) :
 * 1. on part de 100 points ;
 * 2. on applique toutes les pénalités (modificateurs négatifs) : c'est le score « sans bonus » ;
 * 3. si ce score atteint 90, on ajoute tous les bonus (modificateurs positifs), sinon aucun.
 *    C'est du tout ou rien : un bonus ne doit jamais masquer un vrai problème (une excellente CSP
 *    ne compense pas un cookie de session envoyé en clair) ;
 * 4. le score ne descend pas sous 0, mais n'a pas de plafond : 115/100 est possible et vaut A+.
 *
 * Chaque contrôle ne fournit qu'un seul modificateur (le plus grave de ses constats) : les
 * pénalités d'un même contrôle ne se cumulent jamais. Ce module se contente d'additionner.
 *
 * Il ne dépend que des types : l'interface peut l'importer pour afficher le barème.
 */
import type { CheckOutcome, Grade, ScoreBreakdown } from "@/lib/scanner/types";

/** Score de départ, avant pénalités et bonus. */
export const BASE_SCORE = 100;

/** Score « sans bonus » minimal pour que les bonus comptent (90, comme Observatory). */
export const BONUS_THRESHOLD = 90;

/**
 * Score minimal de chaque note, de la meilleure à la moins bonne. Échelle de SecuScan : 7 lettres
 * comme securityheaders.com, seuils inspirés d'Observatory. F couvre tout ce qui reste (< 25).
 */
export const GRADE_THRESHOLDS: ReadonlyArray<{ grade: Grade; minScore: number }> = [
  { grade: "A+", minScore: 100 },
  { grade: "A", minScore: 85 },
  { grade: "B", minScore: 70 },
  { grade: "C", minScore: 55 },
  { grade: "D", minScore: 40 },
  { grade: "E", minScore: 25 },
  { grade: "F", minScore: 0 },
];

/**
 * Note correspondant à un score : la première note dont le seuil est atteint.
 * Un score supérieur à 100 vaut A+ ; un score négatif (ou invalide) vaut F.
 */
export function gradeFor(score: number): Grade {
  const threshold = GRADE_THRESHOLDS.find(({ minScore }) => score >= minScore);
  return threshold?.grade ?? "F";
}

/**
 * Calcule le score final et son détail à partir des verdicts des contrôles.
 *
 * Exemple : pénalités -15 et bonus +10 → score sans bonus 85 (< 90) → bonus ignorés → 85 (A).
 * Avec une pénalité de -10 seulement : 90 → bonus appliqués → 100 (A+).
 *
 * @param results verdicts des contrôles (seul `scoreModifier` est utilisé)
 */
export function computeScore(
  results: ReadonlyArray<Pick<CheckOutcome, "scoreModifier">>,
): ScoreBreakdown {
  const modifiers = results.map((result) => result.scoreModifier);
  const penalties = sum(modifiers.filter((modifier) => modifier < 0));
  const bonuses = sum(modifiers.filter((modifier) => modifier > 0));

  const scoreWithoutBonuses = BASE_SCORE + penalties;
  // `bonusesApplied` indique que le seuil est atteint, même si aucun bonus n'a été obtenu.
  const bonusesApplied = scoreWithoutBonuses >= BONUS_THRESHOLD;
  const rawScore = bonusesApplied ? scoreWithoutBonuses + bonuses : scoreWithoutBonuses;
  // Plancher à 0, pas de plafond (au-delà de 100, le score reste affiché tel quel).
  const score = Math.max(0, rawScore);

  return { base: BASE_SCORE, penalties, bonuses, bonusesApplied, score, grade: gradeFor(score) };
}

/** Somme d'une liste de nombres (0 pour une liste vide). */
function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}
