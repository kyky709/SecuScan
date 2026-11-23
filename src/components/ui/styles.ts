// Chaque chaîne est écrite en entier : Tailwind découvre les classes en lisant le code source et
// ne verrait pas une classe construite dynamiquement. La CSP interdit les attributs `style` en
// ligne : toute la mise en forme passe par des classes.

export const CONTAINER = "mx-auto w-full max-w-5xl px-4 sm:px-6";

export const CARD =
  "rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900";

export const BUTTON_PRIMARY =
  "inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 aria-disabled:cursor-not-allowed aria-disabled:opacity-70 motion-safe:transition-colors";

export const BUTTON_SECONDARY =
  "inline-flex items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-800 hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800 motion-safe:transition-colors";

// Souligné : la couleur seule ne suffit pas à distinguer un lien du texte.
export const LINK =
  "font-medium text-indigo-700 underline decoration-indigo-300 underline-offset-2 hover:decoration-indigo-700 dark:text-indigo-300 dark:decoration-indigo-700 dark:hover:decoration-indigo-300";

// Contraste d'au moins 4,5:1 dans les deux thèmes.
export const MUTED_TEXT = "text-zinc-600 dark:text-zinc-400";

export const EYEBROW =
  "text-xs font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-400";

// Sans arrondi : chaque usage choisit le sien.
export const CODE_BLOCK =
  "whitespace-pre-wrap wrap-anywhere bg-zinc-100 p-3 font-mono text-xs leading-relaxed text-zinc-800 dark:bg-zinc-950 dark:text-zinc-200";
