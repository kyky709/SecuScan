/**
 * Liste des références documentaires d'un contrôle (OWASP, MDN, RFC…), avec un badge indiquant
 * la nature de chaque source.
 *
 * Utilisée par les cartes du rapport (« Pour aller plus loin ») et par la page Méthodologie. Les
 * liens s'ouvrent dans un nouvel onglet pour ne pas faire perdre le rapport affiché.
 */
import type { Reference, ReferenceKind } from "@/lib/scanner/types";
import { ExternalLink } from "../ui/external-link";

/** Libellé court du badge de chaque famille de référence. */
export const REFERENCE_KIND_LABELS: Record<ReferenceKind, string> = {
  "owasp-top10": "OWASP Top 10",
  "owasp-asvs": "ASVS",
  "owasp-cheatsheet": "Cheat Sheet",
  "owasp-wstg": "WSTG",
  "owasp-secure-headers": "Secure Headers",
  mdn: "MDN",
  rfc: "RFC",
  spec: "Spécification",
  other: "Ressource",
};

/** Liste de références, chacune précédée de son badge. */
export function ReferenceList({ references }: { references: readonly Reference[] }) {
  return (
    <ul className="space-y-2 text-sm">
      {references.map((reference) => (
        // Deux références peuvent partager une URL (même chapitre de l'ASVS) : la clé combine
        // l'URL et le libellé.
        <li key={`${reference.url} ${reference.label}`} className="flex items-baseline gap-2">
          {/* Badge décoratif : le libellé du lien nomme déjà la source (« OWASP… », « MDN… »). */}
          <span
            aria-hidden="true"
            className="inline-flex shrink-0 rounded bg-zinc-100 px-1.5 py-0.5 text-[0.6875rem] font-semibold whitespace-nowrap text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
          >
            {REFERENCE_KIND_LABELS[reference.kind]}
          </span>
          <ExternalLink href={reference.url}>{reference.label}</ExternalLink>
        </li>
      ))}
    </ul>
  );
}
