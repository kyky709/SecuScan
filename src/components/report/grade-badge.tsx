// `role="img"` et son nom font lire « Note A+ » aux lecteurs d'écran, plutôt qu'une lettre isolée.
import type { Grade } from "@/lib/scanner/types";
import { GRADE_STYLES } from "./styles";

const SIZES = {
  sm: "size-10 rounded-lg text-lg",
  md: "size-14 rounded-xl text-2xl",
  lg: "size-24 rounded-2xl text-5xl",
} as const;

export interface GradeBadgeProps {
  grade: Grade;
  size?: keyof typeof SIZES;
}

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
