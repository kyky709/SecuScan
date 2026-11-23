/**
 * `rel="noopener noreferrer"` : la page ouverte ne peut pas manipuler SecuScan via `window.opener`
 * (« reverse tabnabbing ») et ne reçoit pas l'adresse d'origine. L'ouverture d'un onglet est
 * annoncée (icône, texte pour les lecteurs d'écran) pour ne pas surprendre (WCAG 3.2.5).
 */
import { ExternalLinkIcon } from "lucide-react";
import type { ReactNode } from "react";
import { LINK } from "./styles";

export interface ExternalLinkProps {
  href: string;
  children: ReactNode;
  className?: string;
}

export function ExternalLink({ href, children, className = LINK }: ExternalLinkProps) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
      {children}
      <ExternalLinkIcon aria-hidden="true" className="ml-1 inline size-3.5 align-[-0.125em]" />
      <span className="sr-only"> (nouvel onglet)</span>
    </a>
  );
}
