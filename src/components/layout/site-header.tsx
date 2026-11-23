/**
 * En-tête commun à toutes les pages : logo (retour à l'accueil) et menu principal.
 *
 * Composant serveur : seul le lien actif du menu a besoin du navigateur (voir nav-link.tsx).
 * Le menu reste une simple liste de liens qui passe à la ligne sur petit écran, sans menu
 * « hamburger » : moins de JavaScript, et une navigation utilisable au clavier sans effort.
 */
import { CodeXml } from "lucide-react";
import Link from "next/link";
import { SITE } from "@/lib/site";
import { CONTAINER } from "../ui/styles";
import { Logo } from "./logo";
import { NavLink } from "./nav-link";

/** Pages du menu principal, dans l'ordre d'affichage. */
const NAVIGATION = [
  { href: "/", label: "Analyser" },
  { href: "/methodologie", label: "Méthodologie" },
  { href: "/a-propos", label: "À propos" },
] as const;

/** En-tête du site (bandeau `banner`). */
export function SiteHeader() {
  return (
    <header className="border-b border-zinc-200 dark:border-zinc-800">
      <div
        className={`${CONTAINER} flex flex-wrap items-center justify-between gap-x-6 gap-y-2 py-3`}
      >
        <Link href="/" className="rounded-md">
          <Logo />
          <span className="sr-only"> – accueil</span>
        </Link>
        <nav aria-label="Navigation principale">
          <ul className="flex flex-wrap items-center gap-1 text-sm">
            {NAVIGATION.map((item) => (
              <li key={item.href}>
                <NavLink href={item.href}>{item.label}</NavLink>
              </li>
            ))}
            <li>
              <a
                href={SITE.repositoryUrl}
                className="inline-flex items-center gap-1.5 rounded-md px-2.5 py-1.5 font-medium text-zinc-600 hover:bg-zinc-100 hover:text-zinc-900 dark:text-zinc-400 dark:hover:bg-zinc-800 dark:hover:text-zinc-100"
              >
                <CodeXml aria-hidden="true" className="size-4" />
                GitHub
              </a>
            </li>
          </ul>
        </nav>
      </div>
    </header>
  );
}
