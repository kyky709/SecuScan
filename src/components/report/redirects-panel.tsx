/**
 * Panneau « Redirections » : les réponses successives obtenues en partant de http:// puis de
 * https://, jusqu'à la réponse finale.
 *
 * C'est la preuve visible du contrôle « Redirection HTTP vers HTTPS » : on y voit si la version
 * en clair renvoie bien vers HTTPS dès la première étape, et si la redirection est permanente
 * (301, 308) ou temporaire (302, 307).
 */
import { Route } from "lucide-react";
import type { RedirectHop, ScanReport } from "@/lib/scanner/types";
import { MUTED_TEXT } from "../ui/styles";
import { describeRedirectStatus } from "./format";
import { Panel } from "./panel";

/** Une chaîne de redirections, de la première requête à la réponse finale. */
function RedirectChain({ title, hops }: { title: string; hops: readonly RedirectHop[] }) {
  return (
    <div className="min-w-0 space-y-2">
      <h5 className="text-sm font-semibold text-zinc-900 dark:text-zinc-100">{title}</h5>
      {hops.length === 0 ? (
        <p className={`text-sm ${MUTED_TEXT}`}>Aucune réponse obtenue.</p>
      ) : (
        <ol className="space-y-2 text-sm">
          {hops.map((hop, index) => (
            // biome-ignore lint/suspicious/noArrayIndexKey: une chaîne peut repasser par la même URL ; son ordre ne change jamais, l'indice est donc une clé stable.
            <li key={index} className="rounded-lg bg-zinc-50 p-2.5 dark:bg-zinc-950">
              <p className="flex items-baseline gap-2">
                <span className="rounded bg-zinc-200 px-1.5 font-mono text-xs font-semibold text-zinc-800 dark:bg-zinc-800 dark:text-zinc-200">
                  {hop.status}
                </span>
                <span className="min-w-0 font-mono text-xs wrap-anywhere text-zinc-900 dark:text-zinc-100">
                  {hop.url}
                </span>
              </p>
              <p className={`mt-1 text-xs ${MUTED_TEXT}`}>
                {hop.location ? (
                  <>
                    {describeRedirectStatus(hop.status) ?? "Redirection"} vers{" "}
                    <span className="font-mono wrap-anywhere">{hop.location}</span>
                  </>
                ) : (
                  "Réponse finale"
                )}
              </p>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

/** Panneau des redirections observées. */
export function RedirectsPanel({ redirects }: { redirects: ScanReport["redirects"] }) {
  return (
    <Panel
      id="panneau-redirections"
      title="Redirections"
      icon={<Route aria-hidden="true" className="size-4 text-zinc-500 dark:text-zinc-400" />}
      description="Réponses successives obtenues en partant de l'adresse en http:// puis en https://."
    >
      <div className="grid gap-6 lg:grid-cols-2">
        <RedirectChain title="Depuis http://" hops={redirects.fromHttp} />
        <RedirectChain title="Depuis https://" hops={redirects.fromHttps} />
      </div>
    </Panel>
  );
}
