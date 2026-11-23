/**
 * Panneau « Sondes en échec » : les vérifications qui n'ont pas pu être réalisées (délai dépassé,
 * connexion refusée…), avec leur cause.
 *
 * Il explique les contrôles marqués « Non vérifié » : SecuScan ne pénalise pas ce qu'il n'a pas pu
 * observer, mais il le dit clairement, plutôt que de laisser croire que tout a été examiné.
 * Le panneau n'apparaît pas quand toutes les sondes ont abouti.
 */
import { Unplug } from "lucide-react";
import type { ScanReport } from "@/lib/scanner/types";
import { probeLabel } from "./format";
import { Panel } from "./panel";

/** Panneau des sondes en échec, ou rien si toutes ont réussi. */
export function ProbeErrorsPanel({ probeErrors }: { probeErrors: ScanReport["probeErrors"] }) {
  if (probeErrors.length === 0) return null;

  return (
    <Panel
      id="panneau-sondes"
      title="Sondes en échec"
      icon={<Unplug aria-hidden="true" className="size-4 text-zinc-500 dark:text-zinc-400" />}
      description="Ces vérifications n'ont pas pu être réalisées. Les contrôles concernés sont marqués « Non vérifié » et n'ont aucun effet sur la note."
    >
      <ul className="space-y-2 text-sm">
        {probeErrors.map((probeError) => (
          <li
            key={probeError.probe}
            className="rounded-lg bg-zinc-50 p-2.5 text-zinc-800 dark:bg-zinc-950 dark:text-zinc-200"
          >
            <span className="font-semibold">{probeLabel(probeError.probe)}</span> :{" "}
            {probeError.message}{" "}
            <code className="font-mono text-xs text-zinc-600 dark:text-zinc-400">
              ({probeError.code})
            </code>
          </li>
        ))}
      </ul>
    </Panel>
  );
}
