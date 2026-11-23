// Le score est lu « 55 sur 100 » par les lecteurs d'écran : « 55/100 » serait lu « 55 barre
// oblique 100 ».
import type { CheckStatus, ScoreBreakdown } from "@/lib/scanner/types";
import { ExternalLink } from "../ui/external-link";
import { CARD, MUTED_TEXT } from "../ui/styles";
import { explainScore, formatScore } from "./format";
import { GradeBadge } from "./grade-badge";
import { StatusSummary } from "./status-summary";

export interface ScoreOverviewProps {
  score: ScoreBreakdown;
  summary: Record<CheckStatus, number>;
}

export function ScoreOverview({ score, summary }: ScoreOverviewProps) {
  const { formula, bonusNote } = explainScore(score);

  return (
    <section
      aria-labelledby="note-titre"
      className={`${CARD} flex flex-col gap-6 p-6 sm:flex-row sm:items-start`}
    >
      <h3 id="note-titre" className="sr-only">
        Note globale
      </h3>
      <GradeBadge grade={score.grade} size="lg" />
      <div className="min-w-0 flex-1 space-y-4">
        <div className="space-y-1.5">
          <p className="text-3xl font-bold tracking-tight text-zinc-900 tabular-nums dark:text-zinc-50">
            <span aria-hidden="true">{formatScore(score.score)}</span>
            <span className="sr-only">Score : {score.score} sur 100</span>
          </p>
          <p className="text-sm text-zinc-800 dark:text-zinc-200">
            <span className="font-semibold">Calcul :</span> {formula}
          </p>
          <p className={`text-sm ${MUTED_TEXT}`}>{bonusNote}</p>
          <p className="text-sm">
            <ExternalLink href="/methodologie#notation">Comment la note est calculée</ExternalLink>
          </p>
        </div>
        <StatusSummary summary={summary} />
      </div>
    </section>
  );
}
