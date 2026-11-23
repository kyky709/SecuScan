"use client";

/**
 * Actions sur le rapport : nouvelle analyse, copie du lien de partage, export JSON.
 *
 * L'export est entièrement local : le rapport, déjà présent dans la page, est transformé en
 * fichier (`Blob`) puis téléchargé grâce à un lien temporaire. Rien n'est renvoyé au serveur, qui
 * ne conserve d'ailleurs aucun rapport. Le lien de partage, lui, ne contient que le nom d'hôte :
 * l'ouvrir relance une analyse.
 */
import { Download, RotateCcw } from "lucide-react";
import type { ScanReport } from "@/lib/scanner/types";
import { CopyButton } from "../ui/copy-button";
import { BUTTON_SECONDARY } from "../ui/styles";
import { exportFileName, shareUrlFor } from "./format";

/** Télécharge le rapport au format JSON, sous le nom « secuscan-<hôte>-<date>.json ». */
export function downloadReport(report: ScanReport): void {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = exportFileName(report);
  document.body.append(link);
  link.click();
  link.remove();
  // L'adresse `blob:` garde le fichier en mémoire : on la libère une fois le téléchargement lancé.
  setTimeout(() => URL.revokeObjectURL(objectUrl), 0);
}

export interface ReportActionsProps {
  report: ScanReport;
  /** Revient au formulaire vide pour analyser un autre site. */
  onNewScan: () => void;
}

/** Barre d'actions du rapport. */
export function ReportActions({ report, onNewScan }: ReportActionsProps) {
  // Lecture de `window` pendant le rendu : sans risque ici, car un rapport n'existe qu'après une
  // analyse lancée dans le navigateur (ce composant n'est jamais rendu côté serveur).
  const shareUrl = shareUrlFor(report.target.hostname, window.location.origin);

  return (
    <div className="flex flex-wrap gap-2">
      <button type="button" onClick={onNewScan} className={BUTTON_SECONDARY}>
        <RotateCcw aria-hidden="true" className="size-4 shrink-0" />
        Nouvelle analyse
      </button>
      <CopyButton text={shareUrl} label="Copier le lien" context="de cette analyse" />
      <button type="button" onClick={() => downloadReport(report)} className={BUTTON_SECONDARY}>
        <Download aria-hidden="true" className="size-4 shrink-0" />
        Exporter le JSON
      </button>
    </div>
  );
}
