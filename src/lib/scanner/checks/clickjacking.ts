/**
 * Contrôle « clickjacking » : protection contre l'affichage de la page dans un cadre.
 *
 * Rôle : vérifier que le site interdit (ou limite à des sites choisis) son affichage dans une
 * <iframe>, grâce à la directive CSP frame-ancestors ou, à défaut, à l'en-tête X-Frame-Options.
 *
 * Pourquoi : le clickjacking consiste à afficher le site, rendu invisible, par-dessus une page
 * piégée, pour faire cliquer la victime à son insu (valider un achat, changer un réglage…). Seul le
 * navigateur peut l'empêcher, et il ne le fait que si le site le lui demande.
 *
 * Place dans l'architecture : contrôle pur `ScanContext → CheckOutcome` de la famille « headers ».
 * Il applique l'algorithme de la spécification HTML (§ 7.7) : dès qu'une CSP *appliquée* (en-tête
 * Content-Security-Policy, ni Report-Only ni <meta>) contient frame-ancestors, X-Frame-Options n'est
 * même pas lu. La syntaxe CSP est lue par csp-parser.ts, partagé avec le contrôle csp.
 */
import { REFS } from "@/lib/scanner/references";
import type {
  CheckDefinition,
  CheckOutcome,
  CheckStatus,
  FixExample,
  HttpResponse,
  ScanContext,
} from "@/lib/scanner/types";
import {
  classifySource,
  isBroadSource,
  isNoneSourceList,
  parseCspHeader,
  parseMetaCsp,
} from "./csp-parser";
import { getHeader, notApplicable, probeErrorOutcome, shorten, truncateEvidence } from "./helpers";

/** Ligne de la grille de notation : résultat lisible, statut et effet sur le score. */
interface GridRow {
  outcome: string;
  status: CheckStatus;
  modifier: number;
}

/** Grille de notation du contrôle (docs/22-notation.md). */
const GRID = {
  frameAncestors: {
    outcome:
      "CSP frame-ancestors restrictive, envoyée en en-tête ('none', 'self' ou liste d'origines, sans * ni schéma seul)",
    status: "pass",
    modifier: 5,
  },
  xFrameOptions: { outcome: "X-Frame-Options DENY ou SAMEORIGIN", status: "pass", modifier: 5 },
  xFrameOptionsIgnored: {
    outcome:
      "X-Frame-Options ALLOW-FROM (ignoré des navigateurs actuels) ou valeur invalide/contradictoire",
    status: "fail",
    modifier: -20,
  },
  unprotected: { outcome: "Aucune protection", status: "fail", modifier: -20 },
} as const satisfies Record<string, GridRow>;

/** Verdict possible du contrôle : une ligne de la grille. */
type Verdict = keyof typeof GRID;

/**
 * Effet d'un en-tête X-Frame-Options présent, selon la spécification HTML (§ 7.7) :
 * - deny : intégration interdite ; sameorigin : réservée aux pages de la même origine ;
 * - conflict : plusieurs valeurs dont deny, sameorigin ou allowall → le navigateur bloque tout ;
 * - ignored : valeur inconnue seule (ALLOW-FROM, ALLOWALL…) ou plusieurs valeurs inconnues → le
 *   navigateur fait comme si l'en-tête était absent.
 */
type XFrameOptionsEffect = "deny" | "sameorigin" | "conflict" | "ignored";

/** Valeurs qui, mêlées à d'autres, font bloquer toute intégration par le navigateur (HTML § 7.7). */
const BLOCKING_WHEN_COMBINED: readonly string[] = ["deny", "sameorigin", "allowall"];

const ALLOW_FROM = /^\s*allow-from\b/i;

const FRAMING_ADVICE =
  "Ajoutez la directive CSP frame-ancestors 'none' (ou 'self' si le site s'affiche lui-même dans des cadres, suivi au besoin des sites partenaires autorisés) : c'est la protection standard, prioritaire sur X-Frame-Options. Ajoutez aussi X-Frame-Options: DENY (ou SAMEORIGIN) pour les anciens navigateurs ; la valeur ALLOW-FROM n'est plus prise en charge.";

const PERMISSIVE_ANCESTORS_ADVICE =
  "Remplacez la valeur de frame-ancestors par 'none', 'self' ou la liste précise des sites autorisés : un joker (*) ou un schéma seul (https:) autorise n'importe quel site. X-Frame-Options ne peut pas compenser, car il est ignoré dès que frame-ancestors est présente.";

const ADD_FRAME_ANCESTORS_ADVICE =
  "Ajoutez aussi la directive CSP frame-ancestors : c'est la norme actuelle, prioritaire sur X-Frame-Options, et elle permet d'autoriser précisément des sites partenaires.";

const CONFLICT_ADVICE =
  "Envoyez une seule valeur de X-Frame-Options (DENY ou SAMEORIGIN), et ajoutez la directive CSP frame-ancestors, prioritaire sur X-Frame-Options.";

const NEXT_CONFIG_EXAMPLE = `// next.config.ts
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          // Si une CSP existe déjà, ajoutez-y plutôt la directive frame-ancestors.
          { key: "Content-Security-Policy", value: "frame-ancestors 'none'" },
          { key: "X-Frame-Options", value: "DENY" },
        ],
      },
    ];
  },
};

export default nextConfig;`;

const EXAMPLES: readonly FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Interdit à tout autre site d'afficher vos pages dans un cadre (iframe).
# Si une CSP existe déjà, ajoutez-y plutôt la directive frame-ancestors.
add_header Content-Security-Policy "frame-ancestors 'none'" always;
add_header X-Frame-Options "DENY" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Interdit à tout autre site d'afficher vos pages dans un cadre (module mod_headers).
# Si une CSP existe déjà, ajoutez-y plutôt la directive frame-ancestors.
Header always set Content-Security-Policy "frame-ancestors 'none'"
Header always set X-Frame-Options "DENY"`,
  },
  { label: "Next.js (next.config.ts)", language: "ts", code: NEXT_CONFIG_EXAMPLE },
];

/**
 * Effet de X-Frame-Options, exactement comme le calcule le navigateur (HTML § 7.7) : les valeurs
 * de toutes les lignes (que la sonde a jointes par ", ") sont découpées sur la virgule, débarrassées
 * des blancs, mises en minuscules et dédoublonnées. Une valeur vide est conservée : « SAMEORIGIN, »
 * compte donc deux valeurs, comme dans la spécification.
 */
function xFrameOptionsEffect(value: string): XFrameOptionsEffect {
  const values = new Set(value.split(",").map((item) => item.trim().toLowerCase()));
  if (values.size > 1) {
    return BLOCKING_WHEN_COMBINED.some((blocking) => values.has(blocking)) ? "conflict" : "ignored";
  }
  if (values.has("deny")) return "deny";
  if (values.has("sameorigin")) return "sameorigin";
  return "ignored";
}

/** Listes frame-ancestors des politiques CSP *appliquées* de l'en-tête (ni Report-Only, ni <meta>). */
function enforcedFrameAncestors(response: HttpResponse): Array<readonly string[]> {
  const value = getHeader(response, "content-security-policy");
  if (value === null) return [];
  return parseCspHeader(value, "header").flatMap((policy) => {
    const sources = policy.directives.get("frame-ancestors");
    return sources === undefined ? [] : [sources];
  });
}

/**
 * La source autorise-t-elle n'importe quel site comme parent ? C'est le cas d'un joker (*,
 * https://*) ou d'un schéma seul (https: accepte tous les sites en HTTPS). 'none', 'self' et des
 * origines précises, y compris un joker de sous-domaine (https://*.example.com), sont restrictifs.
 */
function allowsAnyAncestor(source: string): boolean {
  return classifySource(source) === "scheme" || isBroadSource(source);
}

/** frame-ancestors présentes ailleurs que dans une CSP appliquée : le navigateur les ignore. */
function ignoredFrameAncestorsDetails(context: ScanContext, response: HttpResponse): string[] {
  const details: string[] = [];
  const reportOnly = getHeader(response, "content-security-policy-report-only");
  const reportOnlyPolicies = reportOnly === null ? [] : parseCspHeader(reportOnly, "report-only");
  if (reportOnlyPolicies.some((policy) => policy.directives.has("frame-ancestors"))) {
    details.push(
      "La directive frame-ancestors de l'en-tête Content-Security-Policy-Report-Only ne bloque rien : elle se contente de signaler les intégrations.",
    );
  }
  const metaContents = context.html?.metaCsp ?? [];
  if (metaContents.some((content) => parseMetaCsp(content).ignored.includes("frame-ancestors"))) {
    details.push(
      "La directive frame-ancestors placée dans une balise <meta> est ignorée par les navigateurs : elle doit être envoyée dans un en-tête HTTP.",
    );
  }
  return details;
}

/** Preuve affichée : les directives frame-ancestors appliquées et l'en-tête X-Frame-Options. */
function describeEvidence(
  ancestorLists: ReadonlyArray<readonly string[]>,
  xFrameOptions: string | null,
): string | null {
  const lines = [
    ...ancestorLists.map((sources) =>
      `Content-Security-Policy: frame-ancestors ${sources.join(" ")}`.trimEnd(),
    ),
    ...(xFrameOptions === null ? [] : [`X-Frame-Options: ${xFrameOptions}`]),
  ];
  return lines.length === 0 ? null : truncateEvidence(lines.join("\n"));
}

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

/** Verdict quand une CSP appliquée contient frame-ancestors (X-Frame-Options est alors ignoré). */
function judgeFrameAncestors(
  ancestorLists: ReadonlyArray<readonly string[]>,
  xFrameOptions: string | null,
  baseDetails: string[],
  evidence: string | null,
): CheckOutcome {
  const details =
    xFrameOptions === null
      ? baseDetails
      : [
          ...baseDetails,
          `X-Frame-Options (${xFrameOptions}) est ignoré par les navigateurs récents, car la CSP contient frame-ancestors, qui est prioritaire.`,
        ];

  // Toutes les politiques s'appliquent : une seule liste restrictive suffit à protéger la page.
  const restrictive = ancestorLists.find((sources) => !sources.some(allowsAnyAncestor));
  if (restrictive === undefined) {
    const permissive = [...new Set(ancestorLists.flat().filter(allowsAnyAncestor))];
    return buildOutcome(
      "unprotected",
      `La directive CSP frame-ancestors autorise n'importe quel site à afficher la page dans un cadre (${permissive.join(", ")}).`,
      details,
      evidence,
      PERMISSIVE_ANCESTORS_ADVICE,
    );
  }

  const summary = isNoneSourceList(restrictive)
    ? "La directive CSP frame-ancestors 'none' interdit à tout site d'afficher la page dans un cadre."
    : `La directive CSP frame-ancestors n'autorise l'affichage de la page dans un cadre que par : ${restrictive.join(" ")}.`;
  return buildOutcome("frameAncestors", summary, details, evidence, null);
}

/** Verdict fondé sur X-Frame-Options seul (aucune CSP appliquée ne contient frame-ancestors). */
function judgeXFrameOptions(
  value: string | null,
  details: string[],
  evidence: string | null,
): CheckOutcome {
  if (value === null) {
    return buildOutcome(
      "unprotected",
      "Aucune protection contre le clickjacking : ni directive CSP frame-ancestors, ni en-tête X-Frame-Options.",
      details,
      evidence,
      FRAMING_ADVICE,
    );
  }

  const effect = xFrameOptionsEffect(value);
  if (effect === "deny" || effect === "sameorigin") {
    const summary =
      effect === "deny"
        ? "X-Frame-Options: DENY interdit à tout site d'afficher la page dans un cadre."
        : "X-Frame-Options: SAMEORIGIN réserve l'affichage de la page dans un cadre aux pages de la même origine.";
    // « DENY, DENY » : une seule valeur après dédoublonnage, mais l'en-tête est envoyé deux fois.
    const repeated = value.includes(",")
      ? [
          "L'en-tête X-Frame-Options est envoyé plusieurs fois avec la même valeur : n'en envoyez qu'un.",
        ]
      : [];
    return buildOutcome(
      "xFrameOptions",
      summary,
      [...details, ...repeated],
      evidence,
      ADD_FRAME_ANCESTORS_ADVICE,
    );
  }

  if (effect === "conflict") {
    return buildOutcome(
      "xFrameOptions",
      `X-Frame-Options contient plusieurs valeurs (${shorten(value)}) : les navigateurs bloquent alors tout affichage de la page dans un cadre.`,
      [
        ...details,
        "Plusieurs valeurs différentes sont une erreur de configuration : envoyez une seule valeur, DENY ou SAMEORIGIN.",
      ],
      evidence,
      CONFLICT_ADVICE,
    );
  }

  // Valeur ignorée par le navigateur : la page est aussi exposée que sans en-tête.
  const summary = ALLOW_FROM.test(value)
    ? `X-Frame-Options: ${shorten(value)} est ignoré par les navigateurs actuels (ALLOW-FROM n'est plus pris en charge) : n'importe quel site peut afficher la page dans un cadre.`
    : `La valeur de X-Frame-Options (« ${shorten(value)} ») n'est pas reconnue : les navigateurs ignorent l'en-tête, et n'importe quel site peut afficher la page dans un cadre.`;
  return buildOutcome("xFrameOptionsIgnored", summary, details, evidence, FRAMING_ADVICE);
}

export const clickjackingCheck: CheckDefinition = {
  id: "clickjacking",
  category: "headers",
  title: "Protection contre le clickjacking",
  description:
    "Le clickjacking consiste à afficher le site, rendu invisible, par-dessus une page piégée, pour faire cliquer la victime à son insu (valider un paiement, changer un réglage…). La directive CSP frame-ancestors, ou à défaut l'en-tête X-Frame-Options, indique au navigateur quels sites ont le droit d'afficher la page dans un cadre (iframe). Quand une CSP appliquée contient frame-ancestors, le navigateur ignore X-Frame-Options.",
  references: [
    REFS.cheatSheets.clickjacking,
    REFS.cheatSheets.cspFraming,
    REFS.cheatSheets.httpHeadersXfo,
    REFS.top10.A02,
    REFS.asvs["3.4.6"],
    REFS.wstg.CLNT09,
    REFS.mdn.clickjacking,
    REFS.mdn.frameAncestors,
    REFS.mdn.xFrameOptions,
    REFS.mdn.observatoryScoring,
    REFS.rfc.xFrameOptions,
  ],
  scoring: Object.values(GRID).map(({ outcome, modifier }) => ({ outcome, modifier })),
  evaluate(context) {
    const response = context.response;
    if (!response) {
      // Cas théorique : sans aucune réponse, scan.ts interrompt le scan (TARGET_UNREACHABLE).
      return context.https.ok
        ? notApplicable("Aucune réponse HTTP n'a pu être analysée.")
        : probeErrorOutcome(context.https.error, "la protection contre le clickjacking");
    }

    const xFrameOptions = getHeader(response, "x-frame-options");
    const ancestorLists = enforcedFrameAncestors(response);
    const evidence = describeEvidence(ancestorLists, xFrameOptions);
    const details = ignoredFrameAncestorsDetails(context, response);

    // HTML § 7.7 : une CSP appliquée contenant frame-ancestors l'emporte sur X-Frame-Options.
    if (ancestorLists.length > 0) {
      return judgeFrameAncestors(ancestorLists, xFrameOptions, details, evidence);
    }
    return judgeXFrameOptions(xFrameOptions, details, evidence);
  },
};
