// SVG en ligne plutôt qu'une image : aucune requête, `currentColor` suit le thème, et les attributs
// de présentation (`fill`, `stroke`…) ne sont pas interdits par la CSP, contrairement à `style`.

export function ShieldLogo({ className = "size-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" aria-hidden="true" focusable="false" className={className}>
      <path
        d="M16 2.5 5 6.6v8.2c0 7 4.7 12.9 11 14.7 6.3-1.8 11-7.7 11-14.7V6.6L16 2.5Z"
        fill="currentColor"
      />
      <path
        d="m10.5 16 3.8 3.8 7.2-7.6"
        fill="none"
        stroke="white"
        strokeWidth="2.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Logo() {
  return (
    <span className="inline-flex items-center gap-2 text-lg font-semibold tracking-tight text-zinc-900 dark:text-zinc-50">
      <ShieldLogo className="size-7 text-indigo-600 dark:text-indigo-500" />
      SecuScan
    </span>
  );
}
