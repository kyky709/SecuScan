// Une famille vidée par le filtre reste affichée avec un message : l'utilisateur voit qu'elle a
// été examinée, au lieu de la voir disparaître sans explication.
import type { CheckCategory, CheckResult } from "@/lib/scanner/types";
import { MUTED_TEXT } from "../ui/styles";
import { CategoryIcon } from "./category-icon";
import { CheckCard } from "./check-card";

export interface CategorySectionProps {
  category: { id: CheckCategory; label: string; description: string };
  checks: readonly CheckResult[];
  problemsOnly: boolean;
}

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
