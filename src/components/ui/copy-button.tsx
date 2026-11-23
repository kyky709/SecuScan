"use client";

// Le résultat est aussi annoncé dans une zone `aria-live` : un changement de libellé seul n'est
// pas toujours lu par les lecteurs d'écran.
import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { BUTTON_SECONDARY } from "./styles";

const FEEDBACK_DURATION_MS = 2_000;

type CopyState = "idle" | "copied" | "failed";

export interface CopyButtonProps {
  text: string;
  label: string;
  /**
   * Précision pour les lecteurs d'écran (« l'exemple Nginx ») : plusieurs boutons « Copier » à la
   * suite doivent avoir des noms distincts.
   */
  context?: string;
  className?: string;
}

export function CopyButton({
  text,
  label,
  context,
  className = BUTTON_SECONDARY,
}: CopyButtonProps) {
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timer = setTimeout(() => setState("idle"), FEEDBACK_DURATION_MS);
    return () => clearTimeout(timer);
  }, [state]);

  async function copy() {
    try {
      // `navigator.clipboard` n'existe que dans un contexte sécurisé (HTTPS ou localhost).
      if (!navigator.clipboard) throw new Error("API Clipboard indisponible");
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
  }

  const Icon = state === "copied" ? Check : Copy;
  const visibleLabel =
    state === "copied" ? "Copié" : state === "failed" ? "Copie impossible" : label;
  // Le nom accessible commence par le libellé visible (WCAG 2.5.3, « Label in Name »).
  const accessibleName = context && state === "idle" ? `${label} ${context}` : undefined;

  return (
    <>
      <button type="button" onClick={copy} aria-label={accessibleName} className={className}>
        <Icon aria-hidden="true" className="size-4 shrink-0" />
        <span>{visibleLabel}</span>
      </button>
      <span aria-live="polite" className="sr-only">
        {state === "copied" ? "Copié dans le presse-papiers." : ""}
        {state === "failed"
          ? "La copie a échoué : sélectionnez le texte et copiez-le manuellement."
          : ""}
      </span>
    </>
  );
}
