// Le code passe à la ligne au lieu de défiler : lisible sur mobile, sans zone de défilement à
// atteindre au clavier.
import type { FixExample } from "@/lib/scanner/types";
import { CopyButton } from "../ui/copy-button";
import { CODE_BLOCK } from "../ui/styles";

export function CodeExample({ example }: { example: FixExample }) {
  return (
    <figure className="overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800">
      <figcaption className="flex items-center justify-between gap-2 border-b border-zinc-200 bg-zinc-50 py-1.5 pr-1.5 pl-3 text-xs font-semibold text-zinc-700 dark:border-zinc-800 dark:bg-zinc-900 dark:text-zinc-300">
        <span>{example.label}</span>
        <CopyButton
          text={example.code}
          label="Copier"
          context={`l'exemple ${example.label}`}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 font-medium text-zinc-700 hover:bg-zinc-200 dark:text-zinc-300 dark:hover:bg-zinc-800"
        />
      </figcaption>
      <pre className={CODE_BLOCK}>
        <code>{example.code}</code>
      </pre>
    </figure>
  );
}
