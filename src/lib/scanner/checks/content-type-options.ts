/**
 * Contrôle « content-type-options » : en-tête X-Content-Type-Options.
 *
 * Rôle : vérifier que la réponse envoie X-Content-Type-Options: nosniff.
 *
 * Pourquoi : sans cet en-tête, un navigateur peut « renifler » (MIME sniffing) le contenu d'un
 * fichier pour deviner son type au lieu de croire l'en-tête Content-Type. Un attaquant peut en
 * profiter pour faire exécuter comme script un fichier qu'il a réussi à déposer sur le site (image,
 * texte…). Avec nosniff, un script ou une feuille de style dont le type est incorrect est bloqué.
 *
 * Place dans l'architecture : contrôle pur `ScanContext → CheckOutcome` de la famille « headers ».
 * La lecture suit la spécification Fetch (§ 3.6, « determine nosniff ») : seule la PREMIÈRE valeur
 * compte, sans tenir compte de la casse.
 */
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, CheckStatus, FixExample } from "@/lib/scanner/types";
import { getHeader, notApplicable, probeErrorOutcome, shorten, truncateEvidence } from "./helpers";

/** Ligne de la grille de notation : résultat lisible, statut et effet sur le score. */
interface GridRow {
  outcome: string;
  status: CheckStatus;
  modifier: number;
}

/** Grille de notation du contrôle (docs/22-notation.md). */
const GRID = {
  nosniff: {
    outcome: "nosniff (première valeur, insensible à la casse : règle de la spécification Fetch)",
    status: "pass",
    modifier: 0,
  },
  missing: { outcome: "Absent", status: "warning", modifier: -5 },
  invalid: { outcome: "Valeur invalide", status: "warning", modifier: -5 },
} as const satisfies Record<string, GridRow>;

/** Verdict possible du contrôle : une ligne de la grille. */
type Verdict = keyof typeof GRID;

const NOSNIFF_ADVICE =
  "Envoyez l'en-tête X-Content-Type-Options: nosniff sur toutes les réponses, avec un Content-Type exact : le navigateur cessera de deviner le type des fichiers et refusera d'exécuter comme script ou feuille de style un fichier qui n'en est pas un.";

const SINGLE_HEADER_ADVICE =
  "N'envoyez l'en-tête X-Content-Type-Options qu'une seule fois, avec la seule valeur nosniff.";

const NEXT_CONFIG_EXAMPLE = `// next.config.ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "X-Content-Type-Options", value: "nosniff" }],
      },
    ];
  },
};

export default nextConfig;`;

const EXAMPLES: readonly FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Interdit au navigateur de deviner le type des fichiers (MIME sniffing).
add_header X-Content-Type-Options "nosniff" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Interdit au navigateur de deviner le type des fichiers (module mod_headers).
Header always set X-Content-Type-Options "nosniff"`,
  },
  { label: "Next.js (next.config.ts)", language: "ts", code: NEXT_CONFIG_EXAMPLE },
];

/** Assemble le verdict final : statut et points viennent toujours de la grille. */
function buildOutcome(
  verdict: Verdict,
  summary: string,
  details: string[],
  evidence: string | null,
  recommendation: string | null,
): CheckOutcome {
  const row = GRID[verdict];
  return {
    status: row.status,
    scoreModifier: row.modifier,
    summary,
    details,
    evidence,
    recommendation,
    examples: recommendation === null ? [] : [...EXAMPLES],
  };
}

export const contentTypeOptionsCheck: CheckDefinition = {
  id: "content-type-options",
  category: "headers",
  title: "X-Content-Type-Options",
  description:
    "Sans consigne, certains navigateurs « reniflent » (MIME sniffing) le contenu d'une réponse pour deviner son type, au lieu de se fier à l'en-tête Content-Type. Un attaquant peut en profiter pour faire exécuter comme script un fichier déposé sur le site (image, texte…). L'en-tête X-Content-Type-Options: nosniff désactive ce comportement : un script ou une feuille de style dont le type annoncé est incorrect est bloqué.",
  references: [
    REFS.cheatSheets.httpHeadersXcto,
    REFS.secureHeaders.configuration,
    REFS.top10.A02,
    REFS.asvs["3.4.4"],
    REFS.wstg.CONF14,
    REFS.mdn.xContentTypeOptions,
    REFS.mdn.observatoryScoring,
  ],
  scoring: Object.values(GRID).map(({ outcome, modifier }) => ({ outcome, modifier })),
  evaluate(context) {
    const response = context.response;
    if (!response) {
      // Cas théorique : sans aucune réponse, scan.ts interrompt le scan (TARGET_UNREACHABLE).
      return context.https.ok
        ? notApplicable("Aucune réponse HTTP n'a pu être analysée.")
        : probeErrorOutcome(context.https.error, "l'en-tête X-Content-Type-Options");
    }

    const value = getHeader(response, "x-content-type-options");
    if (value === null) {
      return buildOutcome(
        "missing",
        "L'en-tête X-Content-Type-Options est absent : le navigateur peut deviner le type d'un fichier au lieu de respecter l'en-tête Content-Type.",
        [],
        null,
        NOSNIFF_ADVICE,
      );
    }

    // Fetch § 3.6 : la valeur est découpée sur les virgules (en-têtes répétés compris) et seule la
    // première est examinée. « nosniff, nosniff » est donc valable, « autre, nosniff » ne l'est pas.
    const values = value.split(",").map((item) => item.trim());
    const first = values[0] ?? "";
    const evidence = truncateEvidence(value);
    const details =
      values.length > 1
        ? [
            `L'en-tête contient plusieurs valeurs (« ${shorten(value)} ») : seule la première compte. Envoyez-le une seule fois.`,
          ]
        : [];

    if (first.toLowerCase() === "nosniff") {
      return buildOutcome(
        "nosniff",
        "L'en-tête X-Content-Type-Options vaut nosniff : le navigateur respecte le type annoncé par Content-Type et bloque les scripts et feuilles de style dont le type est incorrect.",
        details,
        evidence,
        details.length > 0 ? SINGLE_HEADER_ADVICE : null,
      );
    }

    const summary =
      first === ""
        ? "L'en-tête X-Content-Type-Options est présent, mais sa première valeur est vide : seule la valeur nosniff est reconnue."
        : `La valeur de X-Content-Type-Options (« ${shorten(first)} ») n'est pas valide : seule la valeur nosniff, en première position, est reconnue.`;
    return buildOutcome("invalid", summary, details, evidence, NOSNIFF_ADVICE);
  },
};
