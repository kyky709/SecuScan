/**
 * Pied de page commun à toutes les pages : nature du projet, liens utiles et avertissement.
 *
 * L'avertissement rappelle les limites de l'outil : une analyse passive et automatique donne une
 * indication, elle ne remplace pas un audit de sécurité mené par des professionnels.
 */
import Link from "next/link";
import { SITE } from "@/lib/site";
import { CONTAINER } from "../ui/styles";

const FOOTER_LINK =
  "underline decoration-zinc-300 underline-offset-2 hover:text-zinc-900 hover:decoration-zinc-500 dark:decoration-zinc-600 dark:hover:text-zinc-100";

/** Pied de page du site (bandeau `contentinfo`). */
export function SiteFooter() {
  return (
    <footer className="mt-20 border-t border-zinc-200 dark:border-zinc-800">
      <div className={`${CONTAINER} space-y-4 py-8 text-sm text-zinc-600 dark:text-zinc-400`}>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <p>
            <span className="font-semibold text-zinc-900 dark:text-zinc-100">{SITE.name}</span>
            {" · "}Projet personnel et open source
          </p>
          <nav aria-label="Liens du pied de page">
            <ul className="flex flex-wrap gap-x-4 gap-y-1">
              <li>
                <Link href="/methodologie" className={FOOTER_LINK}>
                  Méthodologie
                </Link>
              </li>
              <li>
                <Link href="/a-propos" className={FOOTER_LINK}>
                  À propos et confidentialité
                </Link>
              </li>
              <li>
                <a href={SITE.repositoryUrl} className={FOOTER_LINK}>
                  Code source
                </a>
              </li>
            </ul>
          </nav>
        </div>
        <p className="max-w-3xl">
          Analyse indicative et passive, fournie sans garantie : elle ne remplace pas un audit de
          sécurité ni un test d'intrusion réalisé par des professionnels.
        </p>
      </div>
    </footer>
  );
}
