// Du plus grave au moins grave (`STATUS_SEVERITY`) : l'œil tombe d'abord sur ce qui demande une
// action.
import { STATUS_LABELS, STATUS_SEVERITY } from "@/lib/scanner/labels";
import type { CheckStatus } from "@/lib/scanner/types";
import { StatusIcon } from "./status";
import { STATUS_STYLES } from "./styles";

export function StatusSummary({ summary }: { summary: Record<CheckStatus, number> }) {
  return (
    <ul aria-label="Nombre de contrôles par statut" className="flex flex-wrap gap-2">
      {STATUS_SEVERITY.map((status) => (
        <li
          key={status}
          className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-sm font-medium ring-1 ring-inset ${STATUS_STYLES[status].badge}`}
        >
          <StatusIcon status={status} className="size-4" />
          <span>
            {STATUS_LABELS[status]} :{" "}
            <span className="font-semibold tabular-nums">{summary[status]}</span>
          </span>
        </li>
      ))}
    </ul>
  );
}
