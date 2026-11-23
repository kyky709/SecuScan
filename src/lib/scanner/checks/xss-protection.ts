import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, CheckStatus, FixExample } from "@/lib/scanner/types";
import { getHeader, notApplicable, probeErrorOutcome, shorten, truncateEvidence } from "./helpers";

interface GridRow {
  outcome: string;
  status: CheckStatus;
  modifier: number;
}

const GRID = {
  disabled: { outcome: "Absent ou 0", status: "pass", modifier: 0 },
  enabled: {
    outcome: "1 ou 1; mode=block (auditeur XSS supprimé des navigateurs, peut créer des failles)",
    status: "warning",
    modifier: 0,
  },
  invalid: { outcome: "Valeur invalide", status: "warning", modifier: 0 },
} as const satisfies Record<string, GridRow>;

type Verdict = keyof typeof GRID;

type XssFilterMode = "disabled" | "filter" | "block" | "invalid";

const MODE_BLOCK = /^mode\s*=\s*block$/i;
const REPORT_URI = /^report\s*=\s*\S+$/i;

const DISABLE_ADVICE =
  "Supprimez l'en-tête X-XSS-Protection ou fixez-le à 0, et protégez-vous des XSS avec une Content Security Policy (voir le contrôle CSP).";

const SINGLE_HEADER_ADVICE =
  "N'envoyez l'en-tête X-XSS-Protection qu'une seule fois, avec la valeur 0, ou supprimez-le.";

const BROWSER_SUPPORT_DETAIL =
  "Ce filtre a été retiré de Chrome (version 78), d'Edge (version 17) et de Safari (version 15.4), et Firefox ne l'a jamais pris en charge : seul Internet Explorer le lit encore.";

const NEXT_CONFIG_EXAMPLE = `// next.config.ts : Next.js n'envoie pas cet en-tête par défaut ;
// si votre application l'ajoute, remplacez sa valeur par 0 (ou supprimez-le).
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "X-XSS-Protection", value: "0" }],
      },
    ];
  },
};

export default nextConfig;`;

const EXAMPLES: readonly FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Désactive le filtre XSS obsolète des anciens navigateurs.
# Derrière un proxy, masque d'abord la valeur envoyée par l'application.
proxy_hide_header X-XSS-Protection;
add_header X-XSS-Protection "0" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Désactive le filtre XSS obsolète (module mod_headers) :
# retire la valeur éventuelle de l'application, puis envoie 0.
Header unset X-XSS-Protection
Header always set X-XSS-Protection "0"`,
  },
  { label: "Next.js (next.config.ts)", language: "ts", code: NEXT_CONFIG_EXAMPLE },
];

/**
 * Syntaxe acceptée par Chromium : « 0 », ou « 1 » suivi éventuellement de « ; mode=block » et de
 * « ; report=<adresse> » ; tout le reste est invalide.
 */
function parseXssProtection(value: string): XssFilterMode {
  // En-tête répété : la sonde joint les valeurs par ", " ; on analyse la première.
  const [first = ""] = value.split(",");
  const [state = "", ...directives] = first.split(";").map((part) => part.trim());
  if (state === "0") return "disabled";
  if (state !== "1") return "invalid";

  let mode: XssFilterMode = "filter";
  for (const directive of directives) {
    if (directive === "") continue; // point-virgule final toléré
    if (MODE_BLOCK.test(directive)) mode = "block";
    else if (!REPORT_URI.test(directive)) return "invalid";
  }
  return mode;
}

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

export const xssProtectionCheck: CheckDefinition = {
  id: "xss-protection",
  category: "headers",
  title: "X-XSS-Protection (obsolète)",
  description:
    "X-XSS-Protection activait le « filtre XSS » d'anciens navigateurs (Internet Explorer, anciennes versions de Chrome et de Safari). Ce filtre, facile à contourner, pouvait lui-même créer des failles et a été retiré de tous les navigateurs actuels. Il est recommandé de ne pas envoyer cet en-tête, ou de le fixer à 0, et de se protéger des XSS avec une Content Security Policy. Ce contrôle n'a aucun effet sur la note.",
  references: [
    REFS.cheatSheets.httpHeadersXxp,
    REFS.secureHeaders.xssProtection,
    REFS.top10.A02,
    REFS.wstg.CONF14,
    REFS.mdn.xXssProtection,
  ],
  scoring: Object.values(GRID).map(({ outcome, modifier }) => ({ outcome, modifier })),
  evaluate(context) {
    const response = context.response;
    if (!response) {
      // Cas théorique : sans aucune réponse, scan.ts interrompt le scan (TARGET_UNREACHABLE).
      return context.https.ok
        ? notApplicable("Aucune réponse HTTP n'a pu être analysée.")
        : probeErrorOutcome(context.https.error, "l'en-tête X-XSS-Protection");
    }

    const value = getHeader(response, "x-xss-protection");
    if (value === null) {
      return buildOutcome(
        "disabled",
        "L'en-tête X-XSS-Protection est absent : c'est le réglage recommandé, ce filtre obsolète n'existant plus dans les navigateurs actuels.",
        [],
        null,
        null,
      );
    }

    const evidence = truncateEvidence(value);
    const details = value.includes(",")
      ? [
          "L'en-tête est envoyé plusieurs fois (valeurs jointes par une virgule) : seule la première valeur est analysée.",
        ]
      : [];

    switch (parseXssProtection(value)) {
      case "disabled":
        return buildOutcome(
          "disabled",
          "L'en-tête X-XSS-Protection vaut 0 : le filtre XSS obsolète des anciens navigateurs est explicitement désactivé, comme le recommande l'OWASP.",
          details,
          evidence,
          details.length > 0 ? SINGLE_HEADER_ADVICE : null,
        );
      case "block":
        return buildOutcome(
          "enabled",
          "X-XSS-Protection: 1; mode=block active le filtre XSS des anciens navigateurs : ce filtre a été retiré des navigateurs actuels et son mode « block » pouvait provoquer des fuites d'informations.",
          [...details, BROWSER_SUPPORT_DETAIL],
          evidence,
          DISABLE_ADVICE,
        );
      case "filter":
        return buildOutcome(
          "enabled",
          "X-XSS-Protection: 1 active le filtre XSS des anciens navigateurs : ce filtre, retiré des navigateurs actuels, pouvait neutraliser des scripts légitimes et ainsi créer des failles.",
          [...details, BROWSER_SUPPORT_DETAIL],
          evidence,
          DISABLE_ADVICE,
        );
      case "invalid":
        return buildOutcome(
          "invalid",
          `La valeur de X-XSS-Protection (« ${shorten(value)} ») n'est pas valide : les valeurs possibles sont 0, 1 et 1; mode=block.`,
          details,
          evidence,
          DISABLE_ADVICE,
        );
    }
  },
};
