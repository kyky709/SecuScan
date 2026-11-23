"use client";

/**
 * Rapport d'analyse complet, affiché quand l'API a renvoyé un `ScanReport`.
 *
 * Organisation, du plus important au plus technique :
 * 1. en-tête (site, adresses, date, durée) et avertissement éventuel (page en erreur HTTP) ;
 * 2. note globale, calcul expliqué et décompte par statut ;
 * 3. actions (nouvelle analyse, lien, export JSON) ;
 * 4. résultats par famille, avec un filtre « Problèmes seulement » ;
 * 5. détails techniques : TLS, redirections, en-têtes bruts, sondes en échec.
 *
 * Composant client : le filtre est un état local. Le rapport est déjà calculé par le serveur ;
 * ce composant ne fait qu'afficher, sans rien recalculer (la note vient de `report.score`).
 */
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
  /** Revient au formulaire vide pour analyser un autre site. */
  onNewScan: () => void;
}

/** Rapport d'analyse. */
export function ReportView({ report, onNewScan }: ReportViewProps) {
  const [filter, setFilter] = useState<CheckFilter>("all");
  const headingRef = useRef<HTMLHeadingElement>(null);

  // Le rapport remplace l'écran d'attente : on place le focus sur son titre, pour qu'un lecteur
  // d'écran l'annonce et que la navigation au clavier reprenne depuis le début du rapport
  // (sinon le focus resterait sur le bouton « Analyser », loin du résultat).
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
