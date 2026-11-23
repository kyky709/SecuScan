"use client";

/**
 * Formulaire de saisie de l'adresse à analyser, avec des exemples cliquables.
 *
 * Composant « contrôlé » : la valeur du champ appartient à ScanApp, qui peut ainsi la remplir
 * (lien partagé `?url=…`) ou la vider (« Nouvelle analyse »). Le formulaire ne vérifie que
 * l'essentiel (champ non vide) : la validation complète (schéma, port, adresse interdite…) est
 * faite par le serveur, seul juge fiable, qui renvoie un message précis.
 *
 * Choix d'accessibilité et d'ergonomie :
 * - `type="text"` plutôt que `type="url"` : le navigateur exigerait un schéma (« https:// ») et
 *   refuserait « exemple.fr » ; `inputMode="url"` garde le clavier adapté sur mobile ;
 * - étiquette visible reliée au champ, aide et erreur reliées par `aria-describedby` ;
 * - pendant l'analyse, le bouton est `aria-disabled` plutôt que `disabled` : un bouton désactivé
 *   perd le focus clavier, alors qu'ici il reste focalisable et annonce « Analyse en cours… ».
 */
import { LoaderCircle, Search, ShieldCheck } from "lucide-react";
import { type FormEvent, type Ref, useState } from "react";
import { BUTTON_PRIMARY, MUTED_TEXT } from "../ui/styles";

/** Sites proposés en exemple : publics, connus et habitués à ce genre d'analyse. */
export const EXAMPLE_SITES = ["mozilla.org", "github.com", "example.com"] as const;

/** Message affiché quand on lance l'analyse sans adresse. */
export const EMPTY_URL_MESSAGE = "Saisissez l'adresse du site à analyser, par exemple exemple.fr.";

const INPUT_ID = "adresse-site";
const HINT_ID = "adresse-site-aide";
const ERROR_ID = "adresse-site-erreur";
const EXAMPLES_LABEL_ID = "exemples-titre";

export interface ScanFormProps {
  /** Valeur du champ. */
  value: string;
  onValueChange: (value: string) => void;
  /** Appelé avec l'adresse saisie (sans espaces superflus) quand l'utilisateur lance l'analyse. */
  onSubmit: (url: string) => void;
  /** Une analyse est-elle en cours ? (le formulaire ignore alors les nouvelles demandes) */
  isLoading: boolean;
  /** Référence vers le champ, pour que ScanApp puisse y placer le focus. */
  inputRef?: Ref<HTMLInputElement>;
}

/** Formulaire d'analyse. */
export function ScanForm({ value, onValueChange, onSubmit, isLoading, inputRef }: ScanFormProps) {
  const [error, setError] = useState<string | null>(null);

  /** Valide puis transmet l'adresse ; renvoie false si elle est vide. */
  function submit(rawUrl: string): boolean {
    const url = rawUrl.trim();
    if (url === "") {
      setError(EMPTY_URL_MESSAGE);
      return false;
    }
    setError(null);
    onSubmit(url);
    return true;
  }

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    // Pas de rechargement de page : l'analyse passe par l'API, en JavaScript.
    event.preventDefault();
    if (isLoading) return;
    if (!submit(value)) {
      // Ramène le focus dans le champ (si l'erreur vient d'un clic sur le bouton).
      const field = event.currentTarget.elements.namedItem("url");
      if (field instanceof HTMLInputElement) field.focus();
    }
  }

  function handleExample(site: string) {
    if (isLoading) return;
    onValueChange(site);
    submit(site);
  }

  return (
    <form onSubmit={handleSubmit} noValidate className="mx-auto w-full max-w-2xl space-y-3">
      <label
        htmlFor={INPUT_ID}
        className="block text-sm font-semibold text-zinc-900 dark:text-zinc-100"
      >
        Adresse du site
      </label>
      <div className="flex flex-col gap-2 sm:flex-row">
        <input
          ref={inputRef}
          id={INPUT_ID}
          name="url"
          type="text"
          inputMode="url"
          autoComplete="url"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          enterKeyHint="go"
          placeholder="exemple.fr"
          value={value}
          onChange={(event) => {
            onValueChange(event.target.value);
            if (error) setError(null);
          }}
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? `${ERROR_ID} ${HINT_ID}` : HINT_ID}
          className="min-w-0 flex-1 rounded-lg border border-zinc-300 bg-white px-3.5 py-2.5 text-base text-zinc-900 shadow-sm placeholder:text-zinc-500 aria-[invalid=true]:border-red-600 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-100 dark:placeholder:text-zinc-400 dark:aria-[invalid=true]:border-red-400"
        />
        <button
          type="submit"
          aria-disabled={isLoading ? true : undefined}
          className={BUTTON_PRIMARY}
        >
          {isLoading ? (
            <LoaderCircle aria-hidden="true" className="size-4 motion-safe:animate-spin" />
          ) : (
            <Search aria-hidden="true" className="size-4" />
          )}
          {isLoading ? "Analyse en cours…" : "Analyser"}
        </button>
      </div>

      {error ? (
        <p
          id={ERROR_ID}
          role="alert"
          className="text-sm font-medium text-red-700 dark:text-red-400"
        >
          {error}
        </p>
      ) : null}

      <p id={HINT_ID} className={`flex items-start gap-2 text-sm ${MUTED_TEXT}`}>
        <ShieldCheck
          aria-hidden="true"
          className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-400"
        />
        Analyse passive : SecuScan consulte votre site comme un navigateur, sans l'attaquer.
      </p>

      <div className="flex flex-wrap items-center gap-2 text-sm">
        <span id={EXAMPLES_LABEL_ID} className={MUTED_TEXT}>
          Exemples :
        </span>
        <ul aria-labelledby={EXAMPLES_LABEL_ID} className="flex flex-wrap gap-2">
          {EXAMPLE_SITES.map((site) => (
            <li key={site}>
              <button
                type="button"
                onClick={() => handleExample(site)}
                className="rounded-full border border-zinc-300 bg-white px-3 py-1 font-mono text-xs text-zinc-800 hover:border-indigo-400 hover:bg-indigo-50 dark:border-zinc-700 dark:bg-zinc-900 dark:text-zinc-200 dark:hover:border-indigo-500 dark:hover:bg-indigo-950/50 motion-safe:transition-colors"
              >
                {/* L'espace est un nœud de texte distinct : un espace final dans le <span>
                    masqué serait supprimé du nom accessible (« Analysermozilla.org »). */}
                <span className="sr-only">Analyser</span> {site}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </form>
  );
}
