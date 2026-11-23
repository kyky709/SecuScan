import { ChevronDown, FileText } from "lucide-react";
import type { ScanReport } from "@/lib/scanner/types";
import { MUTED_TEXT } from "../ui/styles";
import { displayHeaderValue } from "./format";
import { Panel } from "./panel";

export function RawHeadersPanel({ response }: { response: ScanReport["response"] }) {
  const icon = <FileText aria-hidden="true" className="size-4 text-zinc-500 dark:text-zinc-400" />;

  if (!response) {
    return (
      <Panel id="panneau-en-tetes" title="En-têtes de la réponse" icon={icon}>
        <p className={`text-sm ${MUTED_TEXT}`}>Aucune réponse n'a pu être analysée.</p>
      </Panel>
    );
  }

  return (
    <Panel
      id="panneau-en-tetes"
      title="En-têtes de la réponse"
      icon={icon}
      description={`Réponse finale analysée : code HTTP ${response.status}. Les valeurs des cookies sont masquées.`}
    >
      <details className="group rounded-lg border border-zinc-200 dark:border-zinc-800">
        <summary className="flex list-none items-center justify-between gap-2 rounded-lg px-3 py-2 text-sm font-medium text-zinc-800 hover:bg-zinc-50 dark:text-zinc-200 dark:hover:bg-zinc-800/50 [&::-webkit-details-marker]:hidden">
          <span>En-têtes reçus ({response.headers.length})</span>
          <ChevronDown
            aria-hidden="true"
            className="size-4 shrink-0 text-zinc-500 group-open:rotate-180 motion-safe:transition-transform dark:text-zinc-400"
          />
        </summary>
        <table className="w-full table-fixed border-t border-zinc-200 text-left text-xs dark:border-zinc-800">
          <caption className="sr-only">En-têtes HTTP de la réponse analysée</caption>
          <thead className="bg-zinc-50 text-zinc-700 dark:bg-zinc-900 dark:text-zinc-300">
            <tr>
              <th scope="col" className="w-1/3 px-3 py-2 font-semibold">
                Nom
              </th>
              <th scope="col" className="px-3 py-2 font-semibold">
                Valeur
              </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-200 font-mono dark:divide-zinc-800">
            {response.headers.map(([name, value], index) => (
              // biome-ignore lint/suspicious/noArrayIndexKey: un en-tête peut apparaître plusieurs fois (Set-Cookie) ; l'ordre de réception ne change jamais.
              <tr key={index}>
                <th
                  scope="row"
                  className="px-3 py-1.5 align-top font-medium wrap-anywhere text-zinc-900 dark:text-zinc-100"
                >
                  {name}
                </th>
                <td className="px-3 py-1.5 align-top wrap-anywhere text-zinc-700 dark:text-zinc-300">
                  {displayHeaderValue(name, value)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </Panel>
  );
}
