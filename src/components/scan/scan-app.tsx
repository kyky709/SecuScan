"use client";

// Seuls les types et les libellés du moteur sont importés : aucun code serveur (sondes réseau,
// contrôles) n'est envoyé au navigateur.
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import type { ScanReport } from "@/lib/scanner/types";
import { ReportView } from "../report/report-view";
import { requestScan } from "./api";
import { ErrorAlert } from "./error-alert";
import { LoadingCard } from "./loading-card";
import { ScanForm } from "./scan-form";

type ScanState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "success"; report: ScanReport }
  | { status: "error"; message: string };

export interface ScanAppProps {
  children?: ReactNode;
}

function announcementFor(state: ScanState): string {
  if (state.status === "loading") return "Analyse en cours…";
  if (state.status === "success") {
    const { grade, score } = state.report.score;
    return `Analyse terminée : note ${grade}, score de ${score} sur 100.`;
  }
  // Les erreurs sont annoncées par l'encadré d'erreur lui-même (role="alert").
  return "";
}

function writeUrlParameter(hostname: string): void {
  window.history.replaceState(null, "", `?url=${encodeURIComponent(hostname)}`);
}

function clearUrlParameter(): void {
  window.history.replaceState(null, "", window.location.pathname);
}

export function ScanApp({ children }: ScanAppProps) {
  const [url, setUrl] = useState("");
  const [state, setState] = useState<ScanState>({ status: "idle" });
  const inputRef = useRef<HTMLInputElement>(null);
  const controllerRef = useRef<AbortController | null>(null);

  const runScan = useCallback(async (target: string) => {
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

  // Lien partagé (/?url=example.com) : l'analyse se lance au chargement.
  useEffect(() => {
    const initialUrl = new URLSearchParams(window.location.search).get("url")?.trim();
    if (initialUrl) {
      setUrl(initialUrl);
      void runScan(initialUrl);
    }
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
