/**
 * Carte d'un contrôle dans le rapport : verdict résumé, puis détail dépliable.
 *
 * La carte repose sur l'élément HTML natif `<details>` / `<summary>` : le dépliage fonctionne
 * sans JavaScript, au clavier (Entrée ou Espace sur le résumé) et est annoncé correctement par
 * les lecteurs d'écran (« réduit » / « développé »). Les contrôles à corriger ou à améliorer sont
 * dépliés d'office : c'est là que l'utilisateur a quelque chose à faire.
 *
 * Contenu du détail : rôle du mécanisme, constat, valeur observée, recommandation, exemples de
 * configuration à copier et références pour aller plus loin.
 */
import { ChevronDown, Lightbulb } from "lucide-react";
import type { ReactNode } from "react";
import type { CheckResult } from "@/lib/scanner/types";
import { ExternalLink } from "../ui/external-link";
import { CODE_BLOCK, EYEBROW, MUTED_TEXT } from "../ui/styles";
import { CodeExample } from "./code-example";
import { isProblem } from "./format";
import { ModifierBadge } from "./modifier-badge";
import { ReferenceList } from "./reference-list";
import { StatusBadge, StatusIcon } from "./status";
import { STATUS_STYLES } from "./styles";

/** Bloc titré du détail d'une carte. */
function CardSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-1.5">
      <p className={EYEBROW}>{label}</p>
      {children}
    </div>
  );
}

/** Carte dépliable présentant le résultat d'un contrôle. */
export function CheckCard({ check }: { check: CheckResult }) {
  const details = check.details ?? [];
  const examples = check.examples ?? [];

  return (
    <details
      open={isProblem(check.status)}
      className={`group rounded-xl border border-l-4 border-zinc-200 bg-white shadow-sm dark:border-zinc-800 dark:bg-zinc-900 ${STATUS_STYLES[check.status].accent}`}
    >
      <summary className="flex list-none items-start gap-3 rounded-xl p-4 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 [&::-webkit-details-marker]:hidden">
        <StatusIcon status={check.status} className="mt-0.5 size-5" />
        <span className="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1.5">
          <span className="min-w-0 flex-1 basis-56 font-medium text-zinc-900 dark:text-zinc-50">
            {check.title}
          </span>
          <span className="flex items-center gap-2">
            <ModifierBadge modifier={check.scoreModifier} />
            <StatusBadge status={check.status} />
          </span>
        </span>
        <ChevronDown
          aria-hidden="true"
          className="mt-0.5 size-5 shrink-0 text-zinc-500 group-open:rotate-180 motion-safe:transition-transform dark:text-zinc-400"
        />
      </summary>

      <div className="space-y-4 border-t border-zinc-200 px-4 pt-3 pb-5 text-sm leading-relaxed dark:border-zinc-800">
        <CardSection label="À quoi ça sert ?">
          <p className={MUTED_TEXT}>{check.description}</p>
        </CardSection>

        <CardSection label="Constat">
          <p className="text-zinc-900 dark:text-zinc-100">{check.summary}</p>
          {details.length > 0 ? (
            <ul className="list-disc space-y-1 pl-5 text-zinc-700 dark:text-zinc-300">
              {details.map((detail) => (
                <li key={detail}>{detail}</li>
              ))}
            </ul>
          ) : null}
        </CardSection>

        {check.evidence ? (
          <CardSection label="Valeur observée">
            <pre className={`${CODE_BLOCK} rounded-lg`}>{check.evidence}</pre>
          </CardSection>
        ) : null}

        {check.recommendation ? (
          <div className="flex gap-3 rounded-lg border border-indigo-200 bg-indigo-50 p-3 dark:border-indigo-900 dark:bg-indigo-950/40">
            <Lightbulb
              aria-hidden="true"
              className="mt-0.5 size-4 shrink-0 text-indigo-700 dark:text-indigo-300"
            />
            <div className="space-y-1">
              <p className="font-semibold text-indigo-900 dark:text-indigo-200">Recommandation</p>
              <p className="text-indigo-950 dark:text-indigo-100">{check.recommendation}</p>
            </div>
          </div>
        ) : null}

        {examples.length > 0 ? (
          <CardSection label="Exemples de configuration">
            <div className="space-y-3">
              {examples.map((example) => (
                <CodeExample key={example.label} example={example} />
              ))}
            </div>
          </CardSection>
        ) : null}

        <CardSection label="Pour aller plus loin">
          {check.references.length > 0 ? <ReferenceList references={check.references} /> : null}
          <p className="text-sm">
            <ExternalLink href={`/methodologie#controle-${check.id}`}>
              Comment ce contrôle est noté
            </ExternalLink>
          </p>
        </CardSection>
      </div>
    </details>
  );
}
