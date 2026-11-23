/**
 * En-tête du rapport : site analysé, adresses demandée et finale, adresse IP, date et durée.
 *
 * Le titre (niveau 2) reçoit le focus quand le rapport apparaît (voir report-view.tsx) : il
 * porte donc un nom complet (« Rapport d'analyse de example.com »), lu en entier par les lecteurs
 * d'écran, alors que l'affichage reste sobre (le nom d'hôte en grand).
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
  /** Référence vers le titre, pour y placer le focus. */
  headingRef?: Ref<HTMLHeadingElement>;
}

/** En-tête du rapport d'analyse. */
export function ReportHeader({ report, headingRef }: ReportHeaderProps) {
  const { target } = report;
  // L'adresse finale n'est mentionnée que si une redirection a mené ailleurs.
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
