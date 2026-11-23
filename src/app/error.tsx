"use client";

/**
 * Page d'erreur : affichée quand le rendu d'une page échoue de façon inattendue (bogue).
 *
 * Next.js entoure chaque page d'une « frontière d'erreur » React qui affiche ce composant au lieu
 * d'une page blanche. Il doit être un composant client : il réagit à l'erreur dans le navigateur
 * et propose de réessayer. En production, Next.js ne transmet pas le message d'une erreur survenue
 * côté serveur (il pourrait contenir des détails sensibles), seulement un identifiant (`digest`)
 * qui permet de retrouver l'erreur dans les journaux du serveur.
 *
 * Next.js 16 fournit `retry()`, qui recharge les données de la page puis la réaffiche (voir
 * node_modules/next/dist/docs/01-app/03-api-reference/03-file-conventions/error.md).
 */
import { RotateCcw } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";
import { BUTTON_PRIMARY, CONTAINER, LINK, MUTED_TEXT } from "@/components/ui/styles";

export interface ErrorPageProps {
  /** Valeur levée : pas forcément une instance d'`Error` si elle vient d'un composant client. */
  error: unknown;
  /** Recharge et réaffiche la page. */
  retry: () => void;
}

/** Identifiant de l'erreur dans les journaux du serveur, s'il existe. */
function digestOf(error: unknown): string | null {
  if (error instanceof Error && "digest" in error && typeof error.digest === "string") {
    return error.digest;
  }
  return null;
}

/** Page « Une erreur est survenue ». */
export default function ErrorPage({ error, retry }: ErrorPageProps) {
  // Trace l'erreur dans la console du navigateur, utile pour le débogage.
  useEffect(() => {
    console.error(error);
  }, [error]);

  const digest = digestOf(error);

  return (
    <div className={`${CONTAINER} py-16 sm:py-24`}>
      <div className="mx-auto max-w-xl space-y-5 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-zinc-900 dark:text-zinc-50">
          Une erreur est survenue
        </h1>
        <p className={MUTED_TEXT}>
          La page n'a pas pu s'afficher à cause d'une erreur inattendue de SecuScan. Réessayez dans
          un instant ; si le problème persiste, revenez à l'accueil.
        </p>
        {digest ? (
          <p className={`font-mono text-xs ${MUTED_TEXT}`}>Référence de l'erreur : {digest}</p>
        ) : null}
        <div className="flex flex-wrap items-center justify-center gap-4">
          <button type="button" onClick={() => retry()} className={BUTTON_PRIMARY}>
            <RotateCcw aria-hidden="true" className="size-4" />
            Réessayer
          </button>
          <Link href="/" className={LINK}>
            Retour à l'accueil
          </Link>
        </div>
      </div>
    </div>
  );
}
