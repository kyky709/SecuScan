// Barème de MDN HTTP Observatory v6 (test « referrer-policy »).
import {
  getHeader,
  lookup,
  notApplicable,
  probeErrorOutcome,
  shorten,
  splitList,
  truncateEvidence,
} from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, FixExample } from "@/lib/scanner/types";

const POLICY_EFFECTS: Readonly<Record<string, string>> = {
  "no-referrer": "aucune adresse n'est jamais envoyée",
  "same-origin": "l'adresse complète n'est envoyée qu'aux pages du même site, rien aux autres",
  "strict-origin": "seule l'origine (https://site) est envoyée, et jamais vers une page en HTTP",
  "strict-origin-when-cross-origin":
    "l'adresse complète pour le même site, l'origine seule pour les autres, rien vers HTTP",
  "no-referrer-when-downgrade": "l'adresse complète est envoyée à tous les sites en HTTPS",
  origin: "l'origine est envoyée à tous les sites, même en HTTP clair",
  "origin-when-cross-origin": "l'origine est envoyée aux autres sites, même en HTTP clair",
  "unsafe-url": "l'adresse complète (chemin et paramètres) est envoyée partout, même en HTTP clair",
};

const SAFE_POLICIES: ReadonlySet<string> = new Set([
  "no-referrer",
  "same-origin",
  "strict-origin",
  "strict-origin-when-cross-origin",
]);

/** Anciens mots-clés encore acceptés par <meta name="referrer"> (spécification HTML). */
const META_LEGACY_KEYWORDS: Readonly<Record<string, string>> = {
  never: "no-referrer",
  default: "strict-origin-when-cross-origin",
  always: "unsafe-url",
  "origin-when-crossorigin": "origin-when-cross-origin",
};

const BROWSER_DEFAULT = "strict-origin-when-cross-origin";

interface HeaderAnalysis {
  policy: string | null;
  ignored: string[];
  notLowercase: string[];
}

/**
 * Referrer Policy § 8.1 : valeurs inconnues ignorées, la DERNIÈRE reconnue l'emporte (avec
 * « no-referrer, strict-origin-when-cross-origin », un navigateur ancien garde la première).
 * Casse ignorée comme chez Observatory, mais signalée.
 */
function analyzeHeader(value: string): HeaderAnalysis {
  const analysis: HeaderAnalysis = { policy: null, ignored: [], notLowercase: [] };
  for (const token of splitList(value, ",")) {
    const lower = token.toLowerCase();
    if (lookup(POLICY_EFFECTS, lower) === undefined) {
      analysis.ignored.push(token);
      continue;
    }
    if (token !== lower) analysis.notLowercase.push(token);
    analysis.policy = lower;
  }
  return analysis;
}

function parseMeta(content: string): string | null {
  const lower = content.trim().toLowerCase();
  const policy = lookup(META_LEGACY_KEYWORDS, lower) ?? lower;
  return lookup(POLICY_EFFECTS, policy) === undefined ? null : policy;
}

/** Valeur conseillée par OWASP. */
const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `add_header Referrer-Policy "strict-origin-when-cross-origin" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Module mod_headers
Header always set Referrer-Policy "strict-origin-when-cross-origin"`,
  },
  {
    label: "Next.js (next.config.ts)",
    language: "ts",
    code: `import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }],
      },
    ];
  },
};

export default nextConfig;`,
  },
  {
    label: "HTML (balise meta)",
    language: "html",
    code: `<meta name="referrer" content="strict-origin-when-cross-origin">`,
  },
];

export const referrerPolicyCheck: CheckDefinition = {
  id: "referrer-policy",
  category: "headers",
  title: "Referrer-Policy",
  description:
    "Quand un visiteur suit un lien ou qu'une ressource externe est chargée, le navigateur envoie l'adresse de la page d'origine (en-tête Referer). Cette adresse peut contenir des données personnelles ou des jetons. Referrer-Policy limite ce qui est transmis aux autres sites, par exemple l'origine seule et jamais vers une page en HTTP clair.",
  references: [
    REFS.cheatSheets.httpHeadersReferrer,
    REFS.secureHeaders.configuration,
    REFS.top10.A02,
    REFS.asvs["3.4.5"],
    REFS.wstg.CONF14,
    REFS.mdn.referrerPolicy,
    REFS.mdn.observatoryScoring,
  ],
  scoring: [
    {
      outcome:
        "Politique stricte : no-referrer, same-origin, strict-origin ou strict-origin-when-cross-origin",
      modifier: 5,
    },
    {
      outcome:
        "Politique permissive : no-referrer-when-downgrade, origin, origin-when-cross-origin ou unsafe-url",
      modifier: -5,
    },
    { outcome: "Valeur invalide", modifier: -5 },
    { outcome: "Absente (le navigateur applique strict-origin-when-cross-origin)", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    const response = context.response;
    if (!response) {
      return context.https.ok
        ? notApplicable("Aucune réponse à analyser.")
        : probeErrorOutcome(context.https.error, "l'en-tête Referrer-Policy");
    }

    const header = getHeader(response, "referrer-policy");
    const meta = context.html?.metaReferrer ?? null;
    if (header === null && meta === null) {
      return {
        status: "info",
        scoreModifier: 0,
        summary: `Aucune politique de référent n'est définie : le navigateur applique sa valeur par défaut, ${BROWSER_DEFAULT}.`,
        recommendation: `Définissez explicitement « Referrer-Policy: ${BROWSER_DEFAULT} » (ou no-referrer, same-origin) : vous ne dépendez plus du choix par défaut du navigateur.`,
        examples: EXAMPLES,
      };
    }

    const fromHeader = header === null ? null : analyzeHeader(header);
    const fromMeta = meta === null ? null : parseMeta(meta);
    // La balise <meta> est appliquée après l'en-tête, pendant la lecture du HTML : si elle est
    // valide, elle remplace la politique de l'en-tête ; invalide, elle est simplement ignorée.
    const policy = fromMeta ?? fromHeader?.policy ?? null;

    const details: string[] = [];
    if (fromHeader && fromHeader.ignored.length > 0) {
      details.push(
        `Valeur inconnue ignorée par le navigateur : ${fromHeader.ignored.map(shorten).join(", ")}.`,
      );
    }
    if (fromHeader && fromHeader.notLowercase.length > 0) {
      details.push(
        `Écrivez ${fromHeader.notLowercase.join(", ")} en minuscules : la spécification compare les valeurs à l'identique et un navigateur pourrait les ignorer.`,
      );
    }
    if (meta !== null && fromMeta === null) {
      details.push(
        `La balise <meta name="referrer"> contient une valeur invalide (« ${shorten(meta)} ») : elle est ignorée.`,
      );
    }
    if (fromMeta !== null && fromHeader?.policy && fromHeader.policy !== fromMeta) {
      details.push(
        `La balise <meta name="referrer"> (${fromMeta}) remplace l'en-tête (${fromHeader.policy}) : elle est appliquée après lui.`,
      );
    }

    const evidence = truncateEvidence(
      [
        header === null ? null : `Referrer-Policy: ${header}`,
        meta === null ? null : `<meta name="referrer" content="${meta}">`,
      ]
        .filter((line) => line !== null)
        .join("\n"),
    );

    if (policy === null) {
      return {
        status: "warning",
        scoreModifier: -5,
        summary: `La politique de référent est invalide : le navigateur l'ignore et applique ${BROWSER_DEFAULT}.`,
        details,
        evidence,
        recommendation: `Corrigez la valeur : utilisez une valeur reconnue, par exemple « ${BROWSER_DEFAULT} ».`,
        examples: EXAMPLES,
      };
    }

    const source = fromMeta === null ? "en-tête" : "balise meta";
    const summary = `La politique de référent est « ${policy} » (${source}) : ${lookup(POLICY_EFFECTS, policy)}.`;
    if (SAFE_POLICIES.has(policy)) {
      return { status: "pass", scoreModifier: 5, summary, details, evidence, recommendation: null };
    }
    return {
      status: "warning",
      scoreModifier: -5,
      summary,
      details,
      evidence,
      recommendation: `Remplacez « ${policy} » par « ${BROWSER_DEFAULT} » (ou plus strict) : l'adresse des pages, qui peut contenir des identifiants ou des données personnelles, ne fuira plus vers d'autres sites.`,
      examples: EXAMPLES,
    };
  },
};
