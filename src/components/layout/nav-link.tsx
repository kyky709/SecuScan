"use client";

/**
 * Lien du menu principal qui signale la page courante.
 *
 * La mise en page racine (où se trouve le menu) n'est pas rendue à nouveau lors d'une navigation :
 * elle ne peut pas savoir quelle page est affichée. Ce petit composant client lit donc l'adresse
 * courante avec `usePathname()` et pose `aria-current="page"` sur le lien actif. Le style visuel
 * découle de cet attribut (variante Tailwind `aria-[current=page]:`), si bien que ce que voit
 * l'utilisateur et ce qu'annonce un lecteur d'écran restent toujours cohérents.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

export interface NavLinkProps {
  href: string;
  children: ReactNode;
}

/** Lien de navigation interne, marqué `aria-current="page"` quand il mène à la page affichée. */
export function NavLink({ href, children }: NavLinkProps) {
  const pathname = usePathname();
  const isCurrent = pathname === href;

  return (
    <Link
      href={href}
      aria-current={isCurrent ? "page" : undefined}
      className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 font-medium text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 aria-[current=page]:bg-zinc-100 aria-[current=page]:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100 dark:aria-[current=page]:bg-zinc-800 dark:aria-[current=page]:text-zinc-100"
    >
      {children}
    </Link>
  );
}
