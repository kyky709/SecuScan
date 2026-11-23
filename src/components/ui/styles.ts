/**
 * Classes Tailwind partagées par plusieurs composants (conteneur, cartes, boutons, liens).
 *
 * Les regrouper ici garantit une apparence cohérente (mêmes couleurs, mêmes états de survol) et
 * évite de recopier de longues listes de classes. Chaque chaîne est écrite en entier : Tailwind
 * découvre les classes en lisant le code source, il ne verrait pas une classe construite
 * dynamiquement (par exemple `bg-${couleur}-600`).
 *
 * Rappel : la Content-Security-Policy de SecuScan interdit les attributs `style` en ligne. Toute
 * la mise en forme passe donc par ces classes, compilées dans une feuille de style externe.
 */

/** Conteneur centré de la largeur du site (64 rem), avec des marges latérales adaptées au mobile. */
export const CONTAINER = "mx-auto w-full max-w-5xl px-4 sm:px-6";

/** Carte : fond, bordure et ombre légère, en thème clair comme en thème sombre. */
export const CARD =
  "rounded-xl border border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900";

/** Bouton principal (action la plus importante de l'écran), couleur de la marque (indigo). */
export const BUTTON_PRIMARY =
  "inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm hover:bg-indigo-700 aria-disabled:cursor-not-allowed aria-disabled:opacity-70 motion-safe:transition-colors";

/** Bouton secondaire (actions annexes : copier, exporter, annuler…). */
export const BUTTON_SECONDARY =
  "inline-flex items-center justify-center gap-2 rounded-lg border border-zinc-300 bg-white px-3 py-2 text-sm font-medium text-zinc-800 hover:bg-zinc-100 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:hover:bg-zinc-800 motion-safe:transition-colors";

/** Lien dans un texte : souligné (la couleur seule ne suffit pas à le distinguer du texte). */
export const LINK =
  "font-medium text-indigo-700 underline decoration-indigo-300 underline-offset-2 hover:decoration-indigo-700 dark:text-indigo-300 dark:decoration-indigo-700 dark:hover:decoration-indigo-300";

/** Texte secondaire (descriptions, légendes), contrasté au moins à 4,5:1 dans les deux thèmes. */
export const MUTED_TEXT = "text-zinc-600 dark:text-zinc-400";

/** Petite étiquette de section en capitales (« Valeur observée », « Recommandation »…). */
export const EYEBROW =
  "text-xs font-semibold uppercase tracking-wide text-zinc-600 dark:text-zinc-400";

/**
 * Bloc de code ou de valeur brute : police à chasse fixe, retour à la ligne automatique (une
 * longue CSP reste lisible sans défilement horizontal). Sans arrondi : chaque usage choisit le sien.
 */
export const CODE_BLOCK =
  "whitespace-pre-wrap wrap-anywhere bg-zinc-100 p-3 font-mono text-xs leading-relaxed text-zinc-800 dark:bg-zinc-950 dark:text-zinc-200";
