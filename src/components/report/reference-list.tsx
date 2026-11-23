import type { Reference, ReferenceKind } from "@/lib/scanner/types";
import { ExternalLink } from "../ui/external-link";

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
