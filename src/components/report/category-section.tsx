/**
 * Section du rapport consacrée à une famille de contrôles (« Chiffrement et transport »,
 * « En-têtes de sécurité »…) : titre, description, puis une carte par contrôle.
 *
 * Quand le filtre « Problèmes seulement » ne laisse aucun contrôle dans la famille, la section
 * reste affichée avec un message explicite : l'utilisateur voit que la famille a bien été examinée
 * et qu'elle ne pose pas de problème, au lieu de la voir disparaître sans explication.
 */
import type { CheckCategory, CheckResult } from "@/lib/scanner/types";
import { MUTED_TEXT } from "../ui/styles";
import { CategoryIcon } from "./category-icon";
import { CheckCard } from "./check-card";

export interface CategorySectionProps {
  category: { id: CheckCategory; label: string; description: string };
  /** Contrôles de la famille à afficher (déjà filtrés), dans l'ordre du rapport. */
  checks: readonly CheckResult[];
  /** Le filtre « Problèmes seulement » est-il actif ? (adapte le message d'une famille vide) */
  problemsOnly: boolean;
}

/** Section d'une famille de contrôles. */
export function CategorySection({ category, checks, problemsOnly }: CategorySectionProps) {
  const headingId = `famille-${category.id}`;

  return (
    <section aria-labelledby={headingId} className="space-y-3">
      <div className="space-y-1">
        <h4
          id={headingId}
          className="flex items-center gap-2 text-lg font-semibold text-zinc-900 dark:text-zinc-50"
        >
          <CategoryIcon
            category={category.id}
            className="size-5 text-indigo-600 dark:text-indigo-400"
          />
          {category.label}
        </h4>
        <p className={`text-sm ${MUTED_TEXT}`}>{category.description}</p>
      </div>
      {checks.length > 0 ? (
        <ul className="space-y-3">
          {checks.map((check) => (
            <li key={check.id}>
              <CheckCard check={check} />
            </li>
          ))}
        </ul>
      ) : (
        <p className="rounded-lg border border-dashed border-zinc-300 px-4 py-3 text-sm text-zinc-600 dark:border-zinc-700 dark:text-zinc-400">
          {problemsOnly
            ? "Aucun point à corriger ou à améliorer dans cette famille."
            : "Aucun contrôle dans cette famille."}
        </p>
      )}
    </section>
  );
}
