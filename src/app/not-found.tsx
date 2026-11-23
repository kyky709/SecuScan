/**
 * Page 404 : adresse inconnue sur le site SecuScan.
 *
 * Placée à la racine de `app/`, elle s'affiche pour toute adresse qui ne correspond à aucune page
 * (et quand une page appelle `notFound()`), à l'intérieur de la mise en page commune : l'en-tête
 * et le menu restent disponibles pour repartir. Next.js y ajoute `<meta name="robots"
 * content="noindex">` pour qu'elle ne soit pas indexée.
 */
import { House } from "lucide-react";
import type { Metadata } from "next";
import Link from "next/link";
import { BUTTON_PRIMARY, CONTAINER, LINK, MUTED_TEXT } from "@/components/ui/styles";

export const metadata: Metadata = {
  title: "Page introuvable",
};

/** Page « Page introuvable ». */
export default function NotFound() {
  return (
    <div className={`${CONTAINER} py-16 sm:py-24`}>
      <div className="mx-auto max-w-xl space-y-5 text-center">
        <p className="font-mono text-sm font-semibold text-indigo-700 dark:text-indigo-300">
          Erreur 404
        </p>
        <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
          Page introuvable
        </h1>
        <p className={MUTED_TEXT}>
          L'adresse demandée ne correspond à aucune page de SecuScan. Elle est peut-être mal saisie,
          ou la page a été déplacée.
        </p>
        <div className="flex flex-wrap items-center justify-center gap-4">
          <Link href="/" className={BUTTON_PRIMARY}>
            <House aria-hidden="true" className="size-4" />
            Retour à l'accueil
          </Link>
          <Link href="/methodologie" className={LINK}>
            Consulter la méthodologie
          </Link>
        </div>
      </div>
    </div>
  );
}
