// WCAG 2.4.1. La cible est `<main id="contenu">` (src/app/layout.tsx).

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
