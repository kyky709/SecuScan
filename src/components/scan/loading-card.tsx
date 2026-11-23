"use client";

/**
 * Carte d'attente affichée pendant l'analyse.
 *
 * L'API ne renvoie qu'une réponse finale : le navigateur ne sait pas où en est le serveur. Les
 * étapes défilent donc sur un minuteur, à titre indicatif, pour montrer ce qui est vérifié pendant
 * les quelques secondes d'attente (en réalité, les sondes s'exécutent en parallèle). La dernière
 * étape reste active jusqu'à la réponse.
 *
 * L'annonce « Analyse en cours… » destinée aux lecteurs d'écran n'est pas faite ici, mais par
 * ScanApp, dans une zone `aria-live` présente en permanence dans la page : une zone ajoutée en
 * même temps que son texte n'est pas toujours annoncée.
 */
import { Check, Circle, LoaderCircle } from "lucide-react";
import { useEffect, useState } from "react";
import { CARD, MUTED_TEXT } from "../ui/styles";

/** Étapes affichées, dans l'ordre logique d'une analyse. */
export const LOADING_STEPS = [
  "DNS et adresse",
  "Connexion HTTPS et TLS",
  "En-têtes et cookies",
  "Contenu de la page",
  "Calcul de la note",
] as const;

/** Durée d'affichage de chaque étape, en millisecondes. */
export const STEP_DURATION_MS = 1_500;

type StepState = "done" | "active" | "pending";

/** Précision lue par les lecteurs d'écran après chaque étape. */
const STEP_STATE_LABELS: Record<StepState, string> = {
  done: " : terminé",
  active: " : en cours",
  pending: " : à venir",
};

/** État d'une étape par rapport à l'étape active. */
function stepState(index: number, activeIndex: number): StepState {
  if (index < activeIndex) return "done";
  return index === activeIndex ? "active" : "pending";
}

/** Icône d'une étape : coche (terminée), roue animée (en cours) ou cercle vide (à venir). */
function StepIcon({ state }: { state: StepState }) {
  if (state === "done") {
    return <Check aria-hidden="true" className="size-4 text-emerald-600 dark:text-emerald-400" />;
  }
  if (state === "active") {
    return (
      <LoaderCircle
        aria-hidden="true"
        className="size-4 text-indigo-600 motion-safe:animate-spin dark:text-indigo-400"
      />
    );
  }
  return <Circle aria-hidden="true" className="size-4 text-zinc-400 dark:text-zinc-600" />;
}

/** Carte « Analyse en cours… » avec la liste des étapes. */
export function LoadingCard() {
  const [activeIndex, setActiveIndex] = useState(0);

  // Avance d'une étape à intervalle régulier, sans dépasser la dernière ; minuteur arrêté quand
  // la carte disparaît (réponse reçue).
  useEffect(() => {
    const timer = setInterval(() => {
      setActiveIndex((index) => Math.min(index + 1, LOADING_STEPS.length - 1));
    }, STEP_DURATION_MS);
    return () => clearInterval(timer);
  }, []);

  return (
    <div className={`${CARD} mx-auto max-w-2xl space-y-4 p-6`}>
      <div className="space-y-1">
        <p className="flex items-center gap-2 font-semibold text-zinc-900 dark:text-zinc-50">
          <LoaderCircle
            aria-hidden="true"
            className="size-5 text-indigo-600 motion-safe:animate-spin dark:text-indigo-400"
          />
          Analyse en cours…
        </p>
        <p className={`text-sm ${MUTED_TEXT}`}>
          Cela prend en général quelques secondes, jusqu'à une vingtaine pour un serveur lent. Les
          étapes ci-dessous sont indicatives : les vérifications se déroulent en parallèle.
        </p>
      </div>
      <ol className="space-y-2.5 text-sm">
        {LOADING_STEPS.map((label, index) => {
          const state = stepState(index, activeIndex);
          return (
            <li key={label} className="flex items-center gap-3">
              <StepIcon state={state} />
              <span
                className={
                  state === "pending"
                    ? "text-zinc-500 dark:text-zinc-400"
                    : "font-medium text-zinc-900 dark:text-zinc-100"
                }
              >
                {label}
                <span className="sr-only">{STEP_STATE_LABELS[state]}</span>
              </span>
            </li>
          );
        })}
      </ol>
    </div>
  );
}
