/**
 * Message d'erreur d'une analyse qui n'a pas abouti (adresse invalide, site injoignable, trop de
 * demandes…). Le texte vient de l'API (déjà en français) ou de api.ts (erreur réseau).
 *
 * `role="alert"` fait annoncer le message immédiatement par les lecteurs d'écran, sans déplacer
 * le focus : l'utilisateur reste dans le champ et peut corriger l'adresse aussitôt.
 */
import { CircleX } from "lucide-react";

/** Encadré d'erreur. */
export function ErrorAlert({ message }: { message: string }) {
  return (
    <div
      role="alert"
      className="mx-auto flex max-w-2xl gap-3 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-950 dark:border-red-900 dark:bg-red-950/40 dark:text-red-100"
    >
      <CircleX
        aria-hidden="true"
        className="mt-0.5 size-5 shrink-0 text-red-600 dark:text-red-400"
      />
      <div className="space-y-1">
        <p className="font-semibold">L'analyse n'a pas pu aboutir</p>
        <p>{message}</p>
      </div>
    </div>
  );
}
