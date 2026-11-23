/**
 * Lien d'évitement « Aller au contenu principal » (WCAG 2.4.1).
 *
 * C'est le premier élément atteint avec la touche Tab : il permet aux personnes qui naviguent au
 * clavier ou avec un lecteur d'écran de sauter l'en-tête et le menu, répétés sur chaque page.
 * Invisible au repos, il apparaît dès qu'il reçoit le focus. Il pointe vers `<main id="contenu">`
 * (voir src/app/layout.tsx).
 */

/** Lien d'évitement vers le contenu principal de la page. */
export function SkipLink() {
  return (
    <a
      href="#contenu"
      className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:rounded-lg focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-semibold focus:text-zinc-900 focus:shadow-lg dark:focus:bg-zinc-900 dark:focus:text-zinc-100"
    >
      Aller au contenu principal
    </a>
  );
}
