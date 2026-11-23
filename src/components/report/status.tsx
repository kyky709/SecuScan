/**
 * Représentation visuelle du statut d'un contrôle : icône et pastille « Conforme », « À corriger »…
 *
 * Chaque statut a une icône de forme différente (coche, croix, triangle, « i », point
 * d'interrogation) en plus de sa couleur : l'information reste lisible pour les personnes qui
 * distinguent mal les couleurs, ou sur un écran en niveaux de gris.
 */
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

/** Icône de chaque statut. */
const STATUS_ICONS: Record<CheckStatus, LucideIcon> = {
  pass: CircleCheck,
  warning: TriangleExclamationPoint,
  fail: CircleX,
  info: Info,
  error: CircleQuestionMark,
};

export interface StatusIconProps {
  status: CheckStatus;
  /** Taille et marges (Tailwind) ; la couleur dépend du statut. */
  className?: string;
}

/**
 * Icône colorée d'un statut. Décorative (masquée aux lecteurs d'écran) : elle accompagne toujours
 * le libellé du statut écrit en toutes lettres.
 */
export function StatusIcon({ status, className = "size-5" }: StatusIconProps) {
  const Icon = STATUS_ICONS[status];
  return (
    <Icon aria-hidden="true" className={`shrink-0 ${STATUS_STYLES[status].icon} ${className}`} />
  );
}

/** Pastille portant le libellé du statut (« À corriger »…). */
export function StatusBadge({ status }: { status: CheckStatus }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset ${STATUS_STYLES[status].badge}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}
