/**
 * Le titre reçoit le focus à l'apparition du rapport (report-view.tsx) : il porte donc un nom
 * complet pour les lecteurs d'écran (« Rapport d'analyse de example.com »).
 *
 * Les adresses sont affichées en texte, pas en liens : un lien partagé (`?url=…`) peut viser
 * n'importe quel site, et SecuScan ne doit pas servir de tremplin vers une page piégée.
 */
import type { Ref } from "react";
import type { ScanReport } from "@/lib/scanner/types";
import { EYEBROW } from "../ui/styles";
import { formatDateTime, formatDuration } from "./format";
import { InfoItem, InfoList } from "./panel";

export interface ReportHeaderProps {
  report: ScanReport;
  headingRef?: Ref<HTMLHeadingElement>;
}

export function ReportHeader({ report, headingRef }: ReportHeaderProps) {
  const { target } = report;
  const redirected = target.finalUrl !== null && target.finalUrl !== target.url;

  return (
    <header className="space-y-4">
      <div className="space-y-1">
        <p aria-hidden="true" className={EYEBROW}>
          Rapport d'analyse
        </p>
        <h2
          id="rapport-titre"
          ref={headingRef}
          tabIndex={-1}
          className="text-2xl font-bold tracking-tight wrap-anywhere text-zinc-900 sm:text-3xl dark:text-zinc-50"
        >
          {/* Espace hors du <span> masqué : sinon il disparaîtrait du nom accessible. */}
          <span className="sr-only">Rapport d'analyse de</span> {target.hostname}
        </h2>
      </div>
      <InfoList>
        <InfoItem label="Adresse analysée" mono>
          {target.url}
        </InfoItem>
        {redirected ? (
          <InfoItem label="Adresse finale (après redirections)" mono>
            {target.finalUrl}
          </InfoItem>
        ) : null}
        <InfoItem label="Adresse IP contactée" mono>
          {target.ip ?? "inconnue"}
        </InfoItem>
        <InfoItem label="Date de l'analyse">
          <time dateTime={report.scannedAt}>{formatDateTime(report.scannedAt)}</time>
        </InfoItem>
        <InfoItem label="Durée">{formatDuration(report.durationMs)}</InfoItem>
      </InfoList>
    </header>
  );
}
