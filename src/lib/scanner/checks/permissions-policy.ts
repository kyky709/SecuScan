// Sans effet sur la note, comme chez Observatory. La syntaxe est validée car une erreur fait
// ignorer TOUT l'en-tête par le navigateur (spécification Permissions Policy § 9.1).
import {
  getHeader,
  notApplicable,
  probeErrorOutcome,
  truncateEvidence,
} from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, FixExample } from "@/lib/scanner/types";

// Champs structurés (RFC 8941), limités à ce qu'utilise Permissions-Policy.
/** Minuscules obligatoires : « Camera » est invalide. */
const KEY = "[a-z*][a-z0-9_.*-]*";
const TOKEN = "[A-Za-z*][!#$%&'*+.^_`|~0-9A-Za-z:/-]*";
/** ASCII imprimable, \" et \\ échappés. */
const STRING = String.raw`"(?:[ !#-\[\]-~]|\\["\\])*"`;
/** Jeton, chaîne, nombre, booléen (?1) ou suite d'octets (:base64:). */
const BARE_ITEM = String.raw`(?:${TOKEN}|${STRING}|-?\d{1,15}(?:\.\d{1,3})?|\?[01]|:[A-Za-z0-9+/=]*:)`;
const PARAMETERS = `(?:; *${KEY}(?:=${BARE_ITEM})?)*`;
const ITEM = `${BARE_ITEM}${PARAMETERS}`;
/**
 * Espaces finaux rattachés au dernier élément (« ITEM *\) ») plutôt que « (…)? *\) » : deux « * »
 * sur les mêmes espaces sont quadratiques face à « camera=(     …! » (ReDoS).
 */
const INNER_LIST = String.raw`\( *(?:${ITEM}(?: +${ITEM})* *)?\)${PARAMETERS}`;
const MEMBER = new RegExp(`^(${KEY})(?:=(${INNER_LIST}|${ITEM})|${PARAMETERS})$`);

const RECOMMENDED_VALUE = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";

interface PolicyMember {
  feature: string;
  /** undefined si la fonctionnalité est écrite seule. */
  value: string | undefined;
}

type ParseResult = { valid: true; members: PolicyMember[] } | { valid: false; invalid: string };

/**
 * Les en-têtes répétés, joints par « , », restent un dictionnaire valide (voulu par la RFC 8941).
 * Limite assumée : une virgule dans une chaîne n'est pas gérée (une origine n'en contient jamais).
 */
function parsePolicy(value: string): ParseResult {
  const members: PolicyMember[] = [];
  for (const rawMember of value.split(",")) {
    const member = rawMember.trim();
    const match = MEMBER.exec(member);
    const feature = match?.[1];
    // Un membre vide (virgule en trop) ou mal formé invalide tout le dictionnaire.
    if (!match || feature === undefined) return { valid: false, invalid: member };
    members.push({ feature, value: match[2] });
  }
  return { valid: true, members };
}

/** Jeton *, seul ou dans la liste. */
function allowsEveryOrigin(value: string | undefined): boolean {
  return value !== undefined && /(?:^|[( ])\*(?:[ );]|$)/.test(value);
}

/** « () » désactive la fonctionnalité partout. */
function isDisabled(value: string | undefined): boolean {
  return value !== undefined && /^\( *\)/.test(value);
}

function syntaxHints(value: string, invalid: string): string[] {
  const hints = [
    invalid === ""
      ? "Élément vide : une virgule est en trop (en début, en fin ou doublée)."
      : `Élément invalide : « ${truncateEvidence(invalid, 80)} ».`,
  ];
  if (/'(?:self|none|src)'/i.test(value)) {
    hints.push(
      "La valeur ressemble à l'ancienne syntaxe Feature-Policy (« camera 'none' ») ; la syntaxe actuelle est « camera=() ».",
    );
  }
  if (/[A-Z]/.test(invalid.split(/[=;]/)[0] ?? "")) {
    hints.push("Les noms de fonctionnalités doivent être écrits en minuscules.");
  }
  return hints;
}

function memberDetails(members: readonly PolicyMember[]): string[] {
  const details: string[] = [];
  const disabled = members.filter((m) => isDisabled(m.value)).map((m) => m.feature);
  if (disabled.length > 0) details.push(`Fonctionnalités désactivées : ${disabled.join(", ")}.`);
  const open = members.filter((m) => allowsEveryOrigin(m.value)).map((m) => m.feature);
  if (open.length > 0) {
    details.push(
      `Autorisées pour toutes les origines (*) : ${open.join(", ")} ; préférez self ou une liste d'origines précises.`,
    );
  }
  const features = members.map((m) => m.feature);
  const repeated = [...new Set(features.filter((f, i) => features.indexOf(f) !== i))];
  if (repeated.length > 0) {
    details.push(
      `Déclarées plusieurs fois (la dernière valeur l'emporte) : ${repeated.join(", ")}.`,
    );
  }
  details.push(
    "Permissions-Policy est appliqué par les navigateurs basés sur Chromium (Chrome, Edge…) ; Firefox et Safari ne le prennent pas encore en charge.",
  );
  return details;
}

const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `add_header Permissions-Policy "${RECOMMENDED_VALUE}" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Module mod_headers
Header always set Permissions-Policy "${RECOMMENDED_VALUE}"`,
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
        headers: [
          {
            key: "Permissions-Policy",
            value: "${RECOMMENDED_VALUE}",
          },
        ],
      },
    ];
  },
};

export default nextConfig;`,
  },
];

const ADD_ADVICE = `Ajoutez un en-tête Permissions-Policy qui désactive les fonctionnalités que le site n'utilise pas, par exemple « ${RECOMMENDED_VALUE} ».`;

function missingPolicy(
  summary: string,
  details: string[],
  evidence: string | null,
  recommendation = ADD_ADVICE,
): CheckOutcome {
  return {
    status: "warning",
    scoreModifier: 0,
    summary,
    details,
    evidence,
    recommendation,
    examples: EXAMPLES,
  };
}

export const permissionsPolicyCheck: CheckDefinition = {
  id: "permissions-policy",
  category: "headers",
  title: "Permissions-Policy",
  description:
    "Permissions-Policy indique quelles fonctionnalités sensibles du navigateur (caméra, micro, géolocalisation, paiement…) la page et les contenus qu'elle intègre ont le droit d'utiliser. Désactiver ce que le site n'utilise pas limite ce que pourrait faire un script malveillant ou une iframe tierce. Il remplace l'ancien en-tête Feature-Policy, dont la syntaxe était différente.",
  references: [
    REFS.cheatSheets.httpHeadersPermissions,
    REFS.secureHeaders.configuration,
    REFS.top10.A02,
    REFS.wstg.CONF14,
    REFS.mdn.permissionsPolicy,
  ],
  scoring: [
    { outcome: "Présent et lisible", modifier: 0 },
    { outcome: "Présent mais syntaxe invalide", modifier: 0 },
    { outcome: "Seulement l'ancien en-tête Feature-Policy", modifier: 0 },
    { outcome: "Absent", modifier: 0 },
  ],
  evaluate(context) {
    const response = context.response;
    if (!response) {
      return context.https.ok
        ? notApplicable("Aucune réponse à analyser.")
        : probeErrorOutcome(context.https.error, "l'en-tête Permissions-Policy");
    }

    const header = getHeader(response, "permissions-policy");
    const legacy = getHeader(response, "feature-policy");
    if (header === null) {
      if (legacy !== null) {
        return missingPolicy(
          "Seul l'ancien en-tête Feature-Policy est présent : il est obsolète et seuls les navigateurs basés sur Chromium le reconnaissent.",
          [],
          truncateEvidence(`Feature-Policy: ${legacy}`),
          `Remplacez Feature-Policy par Permissions-Policy, dont la syntaxe diffère : « camera 'none' » devient « camera=() ». Par exemple : « ${RECOMMENDED_VALUE} ».`,
        );
      }
      return missingPolicy(
        "L'en-tête Permissions-Policy est absent : les fonctionnalités sensibles (caméra, micro, géolocalisation…) gardent leurs autorisations par défaut.",
        [],
        null,
      );
    }

    const evidence = truncateEvidence(header);
    const details =
      legacy === null
        ? []
        : [
            "L'ancien en-tête Feature-Policy est aussi présent : Permissions-Policy est prioritaire, vous pouvez le retirer.",
          ];
    if (header.trim() === "") {
      return missingPolicy(
        "L'en-tête Permissions-Policy est présent mais vide : il ne restreint aucune fonctionnalité.",
        details,
        null,
      );
    }

    const parsed = parsePolicy(header);
    if (!parsed.valid) {
      return missingPolicy(
        "L'en-tête Permissions-Policy est présent mais sa syntaxe est invalide : le navigateur l'ignore entièrement.",
        [...syntaxHints(header, parsed.invalid), ...details],
        evidence,
        `Corrigez la syntaxe : chaque fonctionnalité s'écrit « nom=(liste) », séparées par des virgules, par exemple « ${RECOMMENDED_VALUE} » ou « geolocation=(self "https://exemple.fr") ».`,
      );
    }

    const { members } = parsed;
    const count = new Set(members.map((m) => m.feature)).size;
    const hasWildcard = members.some((m) => allowsEveryOrigin(m.value));
    return {
      status: "pass",
      scoreModifier: 0,
      summary: `L'en-tête Permissions-Policy est présent et lisible : ${count} fonctionnalité${count > 1 ? "s" : ""} encadrée${count > 1 ? "s" : ""}.`,
      details: [...memberDetails(members), ...details],
      evidence,
      recommendation: hasWildcard
        ? "Remplacez * par self ou par la liste des origines qui ont réellement besoin de ces fonctionnalités."
        : null,
    };
  },
};
