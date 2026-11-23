"use client";

/**
 * La mise en page racine, où se trouve le menu, n'est pas rendue à nouveau lors d'une navigation :
 * d'où ce composant client, qui lit l'adresse avec `usePathname()`. Le style découle de
 * `aria-current`, pour que l'affichage et l'annonce des lecteurs d'écran restent cohérents.
 */
import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

export interface NavLinkProps {
  href: string;
  children: ReactNode;
}

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
