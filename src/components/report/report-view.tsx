"use client";

import { useEffect, useRef, useState } from "react";
import { CATEGORIES } from "@/lib/scanner/labels";
import type { ScanReport } from "@/lib/scanner/types";
import { CategorySection } from "./category-section";
import { isProblem } from "./format";
import { HttpStatusWarning } from "./http-status-warning";
import { ProbeErrorsPanel } from "./probe-errors-panel";
import { RawHeadersPanel } from "./raw-headers-panel";
import { RedirectsPanel } from "./redirects-panel";
import { ReportActions } from "./report-actions";
import { type CheckFilter, ReportFilter } from "./report-filter";
import { ReportHeader } from "./report-header";
import { ScoreOverview } from "./score-overview";
import { TlsPanel } from "./tls-panel";

export interface ReportViewProps {
  report: ScanReport;
  onNewScan: () => void;
}

export function ReportView({ report, onNewScan }: ReportViewProps) {
  const [filter, setFilter] = useState<CheckFilter>("all");
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Le focus passe sur le titre du rapport : un lecteur d'écran l'annonce et la navigation au
  // clavier reprend au début du résultat, au lieu de rester sur le bouton « Analyser ».
  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  const problems = report.checks.filter((check) => isProblem(check.status));
  const visibleChecks = filter === "problems" ? problems : report.checks;

  return (
    <article aria-labelledby="rapport-titre" className="space-y-8">
      <ReportHeader report={report} headingRef={headingRef} />
      <HttpStatusWarning response={report.response} />
      <ScoreOverview score={report.score} summary={report.summary} />
      <ReportActions report={report} onNewScan={onNewScan} />

      <section aria-labelledby="resultats-titre" className="space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h3
            id="resultats-titre"
            className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50"
          >
            Résultats par famille
          </h3>
          <ReportFilter
            value={filter}
            onChange={setFilter}
            totalCount={report.checks.length}
            problemCount={problems.length}
          />
        </div>
        {CATEGORIES.map((category) => (
          <CategorySection
            key={category.id}
            category={category}
            checks={visibleChecks.filter((check) => check.category === category.id)}
            problemsOnly={filter === "problems"}
          />
        ))}
      </section>

      <section aria-labelledby="details-techniques-titre" className="space-y-4">
        <h3
          id="details-techniques-titre"
          className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50"
        >
          Détails techniques
        </h3>
        <TlsPanel tls={report.tls} />
        <RedirectsPanel redirects={report.redirects} />
        <RawHeadersPanel response={report.response} />
        <ProbeErrorsPanel probeErrors={report.probeErrors} />
      </section>
    </article>
  );
}
