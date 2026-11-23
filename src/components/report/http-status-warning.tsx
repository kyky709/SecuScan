/**
 * Avertissement affiché quand la page analysée a répondu par une erreur HTTP (statut ≥ 400).
 *
 * SecuScan note quand même la réponse (contrairement à MDN HTTP Observatory, qui refuse de noter) :
 * les en-têtes d'une page d'erreur restent instructifs. Mais une page 404 ou 503 est souvent servie
 * par un autre composant (pare-feu, page d'erreur du CDN) que les pages habituelles du site : la
 * note peut ne pas refléter leur configuration, d'où ce bandeau.
 */
import { TriangleExclamationPoint } from "lucide-react";
import type { ScanReport } from "@/lib/scanner/types";

/** Statut HTTP à partir duquel une réponse est une erreur (4xx client, 5xx serveur). */
const HTTP_ERROR_THRESHOLD = 400;

/** Bandeau d'avertissement, ou rien si la réponse analysée n'est pas une erreur HTTP. */
export function HttpStatusWarning({ response }: { response: ScanReport["response"] }) {
  if (!response || response.status < HTTP_ERROR_THRESHOLD) return null;

  return (
    <div className="flex gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100">
      <TriangleExclamationPoint
        aria-hidden="true"
        className="mt-0.5 size-5 shrink-0 text-amber-600 dark:text-amber-400"
      />
      <div className="space-y-1">
        <p className="font-semibold">
          Attention : la page analysée a répondu avec le code HTTP {response.status}.
        </p>
        <p>
          La note porte sur cette réponse d'erreur, qui peut être configurée différemment des pages
          habituelles du site. Vérifiez l'adresse saisie, puis relancez l'analyse.
        </p>
      </div>
    </div>
  );
}
