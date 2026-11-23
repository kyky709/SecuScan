/**
 * Pastille de la note globale (A+ à F), colorée selon la note.
 *
 * Utilisée en grand dans le rapport et en petit dans le barème de la page Méthodologie. Le rôle
 * ARIA `img` et le nom « Note A+ » font lire « Note A+ » aux lecteurs d'écran, plutôt qu'une
 * lettre isolée, sans contexte.
 */
import type { Grade } from "@/lib/scanner/types";
import { GRADE_STYLES } from "./styles";

/** Dimensions de la pastille et taille de la lettre. */
const SIZES = {
  sm: "size-10 rounded-lg text-lg",
  md: "size-14 rounded-xl text-2xl",
  lg: "size-24 rounded-2xl text-5xl",
} as const;

export interface GradeBadgeProps {
  grade: Grade;
  size?: keyof typeof SIZES;
}

/** Pastille colorée affichant une note. */
export function GradeBadge({ grade, size = "md" }: GradeBadgeProps) {
  return (
    <span
      role="img"
      aria-label={`Note ${grade}`}
      className={`inline-flex shrink-0 items-center justify-center font-bold tracking-tight ${SIZES[size]} ${GRADE_STYLES[grade]}`}
    >
      {grade}
    </span>
  );
}
