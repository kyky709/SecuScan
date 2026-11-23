// La couleur n'est jamais le seul indice (WCAG 1.4.1) : elle accompagne toujours une lettre, une
// icône ou un libellé. Contrastes vérifiés (WCAG AA) dans les deux thèmes ; texte très foncé sur
// l'ambre et l'orange, où le blanc serait illisible.
import type { CheckStatus, Grade } from "@/lib/scanner/types";

export const GRADE_STYLES: Record<Grade, string> = {
  "A+": "bg-emerald-700 text-white",
  A: "bg-green-700 text-white",
  B: "bg-lime-700 text-white",
  C: "bg-amber-400 text-amber-950",
  D: "bg-orange-500 text-orange-950",
  E: "bg-orange-700 text-white",
  F: "bg-red-700 text-white",
};

export interface StatusStyle {
  badge: string;
  icon: string;
  // La variante `dark:` est nécessaire : sinon `dark:border-zinc-800`, émise plus loin dans la
  // feuille de style, recouvrirait aussi le côté gauche.
  accent: string;
}

export const STATUS_STYLES: Record<CheckStatus, StatusStyle> = {
  pass: {
    badge:
      "bg-emerald-50 text-emerald-800 ring-emerald-600/25 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-400/25",
    icon: "text-emerald-600 dark:text-emerald-400",
    accent: "border-l-emerald-500 dark:border-l-emerald-400",
  },
  warning: {
    badge:
      "bg-amber-50 text-amber-800 ring-amber-600/25 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-400/25",
    icon: "text-amber-600 dark:text-amber-400",
    accent: "border-l-amber-500 dark:border-l-amber-400",
  },
  fail: {
    badge:
      "bg-red-50 text-red-800 ring-red-600/25 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-400/25",
    icon: "text-red-600 dark:text-red-400",
    accent: "border-l-red-500 dark:border-l-red-400",
  },
  info: {
    badge:
      "bg-sky-50 text-sky-800 ring-sky-600/25 dark:bg-sky-950/40 dark:text-sky-300 dark:ring-sky-400/25",
    icon: "text-sky-600 dark:text-sky-400",
    accent: "border-l-sky-500 dark:border-l-sky-400",
  },
  error: {
    badge:
      "bg-zinc-100 text-zinc-700 ring-zinc-500/25 dark:bg-zinc-800 dark:text-zinc-300 dark:ring-zinc-400/25",
    icon: "text-zinc-500 dark:text-zinc-400",
    accent: "border-l-zinc-400 dark:border-l-zinc-500",
  },
};

export function modifierStyle(modifier: number): string {
  if (modifier > 0) {
    return "bg-emerald-50 text-emerald-800 ring-emerald-600/25 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-400/25";
  }
  if (modifier < 0) {
    return "bg-red-50 text-red-800 ring-red-600/25 dark:bg-red-950/40 dark:text-red-300 dark:ring-red-400/25";
  }
  return "bg-zinc-100 text-zinc-700 ring-zinc-500/25 dark:bg-zinc-800 dark:text-zinc-300 dark:ring-zinc-400/25";
}
