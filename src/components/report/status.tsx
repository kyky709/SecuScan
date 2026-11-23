import {
  CircleCheck,
  CircleQuestionMark,
  CircleX,
  Info,
  type LucideIcon,
  TriangleExclamationPoint,
} from "lucide-react";
import { STATUS_LABELS } from "@/lib/scanner/labels";
import type { CheckStatus } from "@/lib/scanner/types";
import { STATUS_STYLES } from "./styles";

// Une forme d'icône par statut, en plus de la couleur : l'information reste lisible pour qui
// distingue mal les couleurs, ou en niveaux de gris.
const STATUS_ICONS: Record<CheckStatus, LucideIcon> = {
  pass: CircleCheck,
  warning: TriangleExclamationPoint,
  fail: CircleX,
  info: Info,
  error: CircleQuestionMark,
};

export interface StatusIconProps {
  status: CheckStatus;
  className?: string;
}

// Décorative : le libellé du statut est toujours écrit à côté.
export function StatusIcon({ status, className = "size-5" }: StatusIconProps) {
  const Icon = STATUS_ICONS[status];
  return (
    <Icon aria-hidden="true" className={`shrink-0 ${STATUS_STYLES[status].icon} ${className}`} />
  );
}

export function StatusBadge({ status }: { status: CheckStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset ${STATUS_STYLES[status].badge}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}
