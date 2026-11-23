import { Unplug } from "lucide-react";
import type { ScanReport } from "@/lib/scanner/types";
import { probeLabel } from "./format";
import { Panel } from "./panel";

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
