/**
 * Boutons radio natifs dans un `<fieldset>` : le navigateur gère le clavier (flèches) et les
 * lecteurs d'écran annoncent « bouton radio, coché, 1 sur 2 ». Masqués visuellement, ils restent
 * focalisables et leur focus se voit sur l'étiquette (`has-[:focus-visible]`).
 */
import { Check } from "lucide-react";

export type CheckFilter = "all" | "problems";

export interface ReportFilterProps {
  value: CheckFilter;
  onChange: (value: CheckFilter) => void;
  totalCount: number;
  problemCount: number;
}

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
