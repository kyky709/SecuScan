import type { ReactNode } from "react";
import { CARD, EYEBROW, MUTED_TEXT } from "../ui/styles";

export interface PanelProps {
  id: string;
  title: string;
  icon: ReactNode;
  description?: string;
  children: ReactNode;
}

// Titre de niveau 4 sous le h2 du rapport et le h3 « Détails techniques » : les lecteurs d'écran
// naviguent par niveaux de titre.
export function Panel({ id, title, icon, description, children }: PanelProps) {
  return (
    <section aria-labelledby={id} className={`${CARD} space-y-4 p-5`}>
      <div className="space-y-1">
        <h4
          id={id}
          className="flex items-center gap-2 font-semibold text-zinc-900 dark:text-zinc-50"
        >
          {icon}
          {title}
        </h4>
        {description ? <p className={`text-sm ${MUTED_TEXT}`}>{description}</p> : null}
      </div>
      {children}
    </section>
  );
}

export function InfoList({ children }: { children: ReactNode }) {
  return <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">{children}</dl>;
}

export interface InfoItemProps {
  label: string;
  children: ReactNode;
  mono?: boolean;
}

export function InfoItem({ label, children, mono = false }: InfoItemProps) {
  return (
    <div className="min-w-0">
      <dt className={EYEBROW}>{label}</dt>
      <dd
        className={`mt-0.5 wrap-anywhere text-zinc-900 dark:text-zinc-100 ${mono ? "font-mono text-xs" : ""}`}
      >
        {children}
      </dd>
    </div>
  );
}
