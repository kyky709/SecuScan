/**
 * Briques de mise en page des panneaux techniques du rapport (TLS, redirections, en-têtes…).
 *
 * - `Panel` : carte titrée, avec un titre de niveau 4 (le rapport est un titre de niveau 2, la
 *   rubrique « Détails techniques » un titre de niveau 3) : la hiérarchie des titres reste
 *   cohérente pour les lecteurs d'écran, qui s'en servent pour naviguer ;
 * - `InfoList` / `InfoItem` : liste de définitions `<dl>` (« libellé : valeur »), l'élément HTML
 *   prévu pour des paires nom-valeur, annoncé comme tel par les technologies d'assistance.
 */
import type { ReactNode } from "react";
import { CARD, EYEBROW, MUTED_TEXT } from "../ui/styles";

export interface PanelProps {
  /** Identifiant du titre (relie la section à son titre via `aria-labelledby`). */
  id: string;
  title: string;
  /** Icône décorative placée devant le titre. */
  icon: ReactNode;
  /** Phrase d'introduction facultative. */
  description?: string;
  children: ReactNode;
}

/** Carte titrée d'un panneau technique. */
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

/** Liste de paires « libellé : valeur », sur deux colonnes à partir des écrans moyens. */
export function InfoList({ children }: { children: ReactNode }) {
  return <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">{children}</dl>;
}

export interface InfoItemProps {
  label: string;
  children: ReactNode;
  /** Valeur technique (empreinte, suite de chiffrement…) affichée en police à chasse fixe. */
  mono?: boolean;
}

/** Une paire « libellé : valeur ». Les valeurs longues (URL, empreintes) passent à la ligne. */
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
