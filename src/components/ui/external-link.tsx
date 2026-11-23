/**
 * Lien vers un site externe (OWASP, MDN, RFC…), ouvert dans un nouvel onglet.
 *
 * Ouvrir un nouvel onglet permet de consulter une référence sans perdre le rapport affiché.
 * Deux précautions l'accompagnent :
 * - `rel="noopener noreferrer"` : la page ouverte ne peut pas manipuler SecuScan via
 *   `window.opener` (attaque dite de « reverse tabnabbing ») et ne reçoit pas l'adresse de la
 *   page d'origine ;
 * - l'ouverture d'un onglet est annoncée : icône visible et texte « (nouvel onglet) » réservé
 *   aux lecteurs d'écran, pour ne pas surprendre l'utilisateur (WCAG 3.2.5).
 */
import { ExternalLinkIcon } from "lucide-react";
import type { ReactNode } from "react";
import { LINK } from "./styles";

export interface ExternalLinkProps {
  href: string;
  children: ReactNode;
  /** Classes Tailwind remplaçant le style de lien par défaut. */
  className?: string;
}

/** Lien externe sûr, ouvert dans un nouvel onglet et signalé comme tel. */
export function ExternalLink({ href, children, className = LINK }: ExternalLinkProps) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
      {children}
      <ExternalLinkIcon aria-hidden="true" className="ml-1 inline size-3.5 align-[-0.125em]" />
      <span className="sr-only"> (nouvel onglet)</span>
    </a>
  );
}
