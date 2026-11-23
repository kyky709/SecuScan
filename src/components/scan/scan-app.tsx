"use client";

/**
 * Application d'analyse de la page d'accueil : formulaire, attente, rapport ou erreur.
 *
 * C'est une petite machine à états :
 *
 *   idle ──(Analyser)──► loading ──(rapport reçu)──► success ──(Nouvelle analyse)──► idle
 *                           │
 *                           └────(erreur API ou réseau)──► error ──(Analyser)──► loading
 *
 * Responsabilités :
 * - lancer l'analyse (`requestScan`), en annulant la précédente si elle est encore en cours
 *   (`AbortController`) : seule la dernière demande peut s'afficher ;
 * - lire `?url=` au chargement pour relancer une analyse partagée par lien, puis, après un succès,
 *   écrire `?url=<hôte>` dans la barre d'adresse (sans recharger la page) ;
 * - annoncer l'avancement aux lecteurs d'écran dans une zone `aria-live` toujours présente.
 *
 * Seuls les types et les libellés du moteur sont importés : aucun code serveur (sondes réseau,
 * contrôles) n'est envoyé au navigateur.
 */
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import type { ScanReport } from "@/lib/scanner/types";
import { ReportView } from "../report/report-view";
import { requestScan } from "./api";
import { ErrorAlert } from "./error-alert";
import { LoadingCard } from "./loading-card";
import { ScanForm } from "./scan-form";

/** État de l'application. */
type ScanState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; report: ScanReport }
  | { status: "error"; message: string };

export interface ScanAppProps {
  /**
   * Présentation du service (étapes, familles de contrôles), rendue par le serveur et affichée
   * tant qu'aucune analyse n'est en cours ni affichée.
   */
  children?: ReactNode;
}

/** Texte de la zone d'annonce pour les lecteurs d'écran. */
function announcementFor(state: ScanState): string {
  if (state.status === "loading") return "Analyse en cours…";
  if (state.status === "success") {
    const { grade, score } = state.report.score;
    return `Analyse terminée : note ${grade}, score de ${score} sur 100.`;
  }
  // Les erreurs sont annoncées par l'encadré d'erreur lui-même (role="alert").
  return "";
}

/** Inscrit l'hôte analysé dans l'adresse de la page, sans la recharger ni créer d'historique. */
function writeUrlParameter(hostname: string): void {
  window.history.replaceState(null, "", `?url=${encodeURIComponent(hostname)}`);
}

/** Retire `?url=` de l'adresse de la page. */
function clearUrlParameter(): void {
  window.history.replaceState(null, "", window.location.pathname);
}

/** Application d'analyse (composant client). */
export function ScanApp({ children }: ScanAppProps) {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<ScanState>({ status: "idle" });
  const inputRef = useRef<HTMLInputElement>(null);
  const controllerRef = useRef<AbortController | null>(null);

  const runScan = useCallback(async (target: string) => {
    // Une seule analyse à la fois : la précédente, si elle est encore en cours, est annulée.
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState({ status: "loading" });

    const result = await requestScan(target, controller.signal);
    // Réponse d'une analyse annulée entre-temps (nouvelle demande, page quittée) : ignorée.
    if (controller.signal.aborted) return;
    controllerRef.current = null;

    if (result.ok) {
      setState({ status: "success", report: result.report });
      writeUrlParameter(result.report.target.hostname);
    } else {
      setState({ status: "error", message: result.message });
    }
  }, []);

  // Au chargement : une adresse dans l'URL (lien partagé, ex. /?url=example.com) lance l'analyse.
  // La lecture se fait ici, dans le navigateur, car `window` n'existe pas lors du rendu serveur.
  useEffect(() => {
    const initialUrl = new URLSearchParams(window.location.search).get("url")?.trim();
    if (initialUrl) {
      setUrl(initialUrl);
      void runScan(initialUrl);
    }
    // Quitter la page annule l'analyse en cours (sa réponse ne serait plus affichée).
    return () => controllerRef.current?.abort();
  }, [runScan]);

  function handleNewScan() {
    controllerRef.current?.abort();
    setState({ status: "idle" });
    setUrl("");
    clearUrlParameter();
    // Le champ est toujours affiché : on peut y placer le focus immédiatement.
    inputRef.current?.focus();
  }

  const showIntroduction = state.status === "idle" || state.status === "error";

  return (
    <div className="space-y-12">
      <ScanForm
        value={url}
        onValueChange={setUrl}
        onSubmit={(target) => void runScan(target)}
        isLoading={state.status === "loading"}
        inputRef={inputRef}
      />

      {/*
        Zone d'annonce présente en permanence : les lecteurs d'écran lisent ses changements.
        L'élément <output> a le rôle ARIA « status » ; aria-live le rend explicite partout.
      */}
      <output aria-live="polite" aria-atomic="true" className="sr-only">
        {announcementFor(state)}
      </output>

      {state.status === "loading" ? <LoadingCard /> : null}
      {state.status === "error" ? <ErrorAlert message={state.message} /> : null}
      {state.status === "success" ? (
        // La clé recrée le rapport à chaque nouvelle analyse (filtre réinitialisé, focus replacé).
        <ReportView
          key={`${state.report.target.hostname} ${state.report.scannedAt}`}
          report={state.report}
          onNewScan={handleNewScan}
        />
      ) : null}
      {showIntroduction ? children : null}
    </div>
  );
}
