/**
 * Filtre du rapport : afficher tous les contrôles, ou seulement ceux qui demandent une action
 * (statuts « À corriger » et « À améliorer »).
 *
 * Deux boutons radio natifs dans un `<fieldset>` : le navigateur gère seul le clavier (Tab pour
 * entrer dans le groupe, flèches pour changer d'option) et les lecteurs d'écran annoncent « bouton
 * radio, coché, 1 sur 2 ». Les boutons sont masqués visuellement (`sr-only`) mais restent
 * focalisables ; leur étiquette prend l'apparence d'un bouton, avec un contour visible quand le
 * bouton radio a le focus (`has-[:focus-visible]`) et une coche sur l'option choisie.
 */
import { Check } from "lucide-react";

/** Filtre courant : tous les contrôles ou seulement les problèmes. */
export type CheckFilter = "all" | "problems";

export interface ReportFilterProps {
  value: CheckFilter;
  onChange: (value: CheckFilter) => void;
  /** Nombre total de contrôles. */
  totalCount: number;
  /** Nombre de contrôles à corriger ou à améliorer. */
  problemCount: number;
}

/** Sélecteur « Tous / Problèmes seulement ». */
export function ReportFilter({ value, onChange, totalCount, problemCount }: ReportFilterProps) {
  const options: ReadonlyArray<{ value: CheckFilter; label: string; count: number }> = [
    { value: "all", label: "Tous", count: totalCount },
    { value: "problems", label: "Problèmes seulement", count: problemCount },
  ];

  return (
    <fieldset className="flex flex-wrap items-center gap-2">
      <legend className="sr-only">Contrôles à afficher</legend>
      <span aria-hidden="true" className="text-sm text-zinc-600 dark:text-zinc-400">
        Afficher :
      </span>
      <div className="inline-flex rounded-lg border border-zinc-200 bg-zinc-100 p-1 dark:border-zinc-800 dark:bg-zinc-900">
        {options.map((option) => {
          const checked = value === option.value;
          return (
            <label
              key={option.value}
              className="relative inline-flex cursor-pointer items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-zinc-700 hover:text-zinc-900 has-[:checked]:bg-white has-[:checked]:text-zinc-900 has-[:checked]:shadow-sm has-[:focus-visible]:outline-2 has-[:focus-visible]:outline-offset-2 has-[:focus-visible]:outline-indigo-600 dark:text-zinc-300 dark:hover:text-zinc-100 dark:has-[:checked]:bg-zinc-700 dark:has-[:checked]:text-zinc-50 dark:has-[:focus-visible]:outline-indigo-400"
            >
              <input
                type="radio"
                name="filtre-controles"
                value={option.value}
                checked={checked}
                onChange={() => onChange(option.value)}
                className="sr-only"
              />
              {checked ? <Check aria-hidden="true" className="size-4" /> : null}
              {option.label} <span className="tabular-nums">({option.count})</span>
            </label>
          );
        })}
      </div>
    </fieldset>
  );
}
