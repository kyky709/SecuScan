// Écart avec Observatory : seul COOP rapporte un bonus (pas un par en-tête), et une valeur invalide
// est pénalisée car le navigateur l'ignore en silence. Les valeurs sont des jetons sensibles à la
// casse (champs structurés) ; les paramètres (« ; report-to=… ») sont ignorés.
import {
  getHeader,
  isServedOverHttps,
  lookup,
  notApplicable,
  probeErrorOutcome,
  shorten,
  truncateEvidence,
} from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, FixExample, HttpResponse } from "@/lib/scanner/types";

interface HeaderSpec {
  name: string;
  /** Les clés sont les seules valeurs acceptées. */
  effects: Readonly<Record<string, string>>;
  whenAbsent: string;
}

const COOP: HeaderSpec = {
  name: "Cross-Origin-Opener-Policy",
  effects: {
    "unsafe-none":
      "la page partage son groupe de fenêtres avec les sites qui l'ouvrent ou qu'elle ouvre",
    "same-origin": "la page est isolée des fenêtres d'autres origines",
    "same-origin-allow-popups":
      "la page est isolée mais garde le lien avec les fenêtres qu'elle ouvre (paiement, OAuth)",
    "noopener-allow-popups":
      "la page est isolée de la fenêtre qui l'a ouverte, même de même origine",
  },
  whenAbsent: "absent, ce qui équivaut à unsafe-none",
};

const COEP: HeaderSpec = {
  name: "Cross-Origin-Embedder-Policy",
  effects: {
    "unsafe-none": "aucune exigence envers les ressources tierces (valeur par défaut)",
    "require-corp":
      "les ressources d'autres origines doivent l'autoriser explicitement (CORS ou CORP)",
    credentialless: "les ressources d'autres origines sont chargées sans cookies",
  },
  whenAbsent: "absent (facultatif, nécessaire seulement pour l'isolation complète)",
};

const CORP: HeaderSpec = {
  name: "Cross-Origin-Resource-Policy",
  effects: {
    "same-origin": "seules les pages de la même origine peuvent charger cette ressource",
    "same-site": "seules les pages du même site peuvent charger cette ressource",
    "cross-origin": "n'importe quel site peut charger cette ressource (normal pour un CDN public)",
  },
  whenAbsent: "absent, n'importe quel site peut intégrer les ressources",
};

const ISOLATING_COOP: ReadonlySet<string> = new Set([
  "same-origin",
  "same-origin-allow-popups",
  "noopener-allow-popups",
]);

const ISOLATING_COEP: ReadonlySet<string> = new Set(["require-corp", "credentialless"]);

type HeaderReading =
  | { state: "absent" }
  | { state: "invalid"; raw: string; reason: string }
  | { state: "valid"; raw: string; value: string };

/**
 * Une virgule signifie que l'en-tête a été envoyé plusieurs fois (valeurs jointes par la sonde) :
 * le navigateur l'ignore alors (spécification HTML, « fail open »).
 */
function readHeader(response: HttpResponse, spec: HeaderSpec): HeaderReading {
  const raw = getHeader(response, spec.name);
  if (raw === null) return { state: "absent" };
  if (raw.includes(",")) return { state: "invalid", raw, reason: "en-tête envoyé plusieurs fois" };
  const value = (raw.split(";")[0] ?? "").trim();
  if (lookup(spec.effects, value) !== undefined) return { state: "valid", raw, value };
  const caseHint =
    lookup(spec.effects, value.toLowerCase()) === undefined
      ? ""
      : ", les valeurs étant sensibles à la casse";
  return { state: "invalid", raw, reason: `valeur inconnue « ${shorten(value)} »${caseHint}` };
}

function describeReading(spec: HeaderSpec, reading: HeaderReading): string {
  switch (reading.state) {
    case "absent":
      return `${spec.name} : ${spec.whenAbsent}.`;
    case "invalid":
      return `${spec.name} : invalide (${reading.reason}), donc ignoré par le navigateur.`;
    case "valid":
      return `${spec.name} : « ${reading.value} », ${lookup(spec.effects, reading.value)}.`;
  }
}

/** COEP reste en option : il peut casser des intégrations tierces. */
const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `add_header Cross-Origin-Opener-Policy "same-origin" always;
add_header Cross-Origin-Resource-Policy "same-origin" always;
# Isolation complète (bloque les ressources tierces qui ne l'autorisent pas) :
# add_header Cross-Origin-Embedder-Policy "require-corp" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Module mod_headers
Header always set Cross-Origin-Opener-Policy "same-origin"
Header always set Cross-Origin-Resource-Policy "same-origin"
# Isolation complète (bloque les ressources tierces qui ne l'autorisent pas) :
# Header always set Cross-Origin-Embedder-Policy "require-corp"`,
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
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
          { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
          // Isolation complète (bloque les ressources tierces qui ne l'autorisent pas) :
          // { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
        ],
      },
    ];
  },
};

export default nextConfig;`,
  },
];

export const crossOriginIsolationCheck: CheckDefinition = {
  id: "cross-origin-isolation",
  category: "headers",
  title: "Isolation entre origines (COOP, COEP, CORP)",
  description:
    "Cross-Origin-Opener-Policy coupe le lien entre la page et les fenêtres d'autres sites, ce qui bloque des fuites d'informations entre origines (XS-Leaks). Cross-Origin-Resource-Policy empêche d'autres sites de charger vos ressources, et Cross-Origin-Embedder-Policy exige l'accord des ressources tierces. Ensemble, COOP et COEP isolent complètement la page, ce qui protège contre les attaques de type Spectre.",
  references: [
    REFS.cheatSheets.httpHeadersCoop,
    REFS.cheatSheets.httpHeadersCoep,
    REFS.cheatSheets.httpHeadersCorp,
    REFS.cheatSheets.xsLeaksCoop,
    REFS.top10.A02,
    REFS.asvs["3.4.8"],
    REFS.wstg.CONF14,
    REFS.mdn.coop,
    REFS.mdn.coep,
    REFS.mdn.corp,
  ],
  scoring: [
    {
      outcome: "Valeur invalide (inconnue ou en-tête dupliqué) pour COOP, COEP ou CORP",
      modifier: -5,
    },
    {
      outcome: "COOP isolant : same-origin, same-origin-allow-popups ou noopener-allow-popups",
      modifier: 5,
    },
    { outcome: "COOP absent ou unsafe-none", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    const response = context.response;
    if (!response) {
      return context.https.ok
        ? notApplicable("Aucune réponse à analyser.")
        : probeErrorOutcome(context.https.error, "les en-têtes COOP, COEP et CORP");
    }

    const coop = readHeader(response, COOP);
    const coep = readHeader(response, COEP);
    const corp = readHeader(response, CORP);
    const readings = [
      { spec: COOP, reading: coop },
      { spec: COEP, reading: coep },
      { spec: CORP, reading: corp },
    ];
    const details = readings.map(({ spec, reading }) => describeReading(spec, reading));
    if (
      coop.state === "valid" &&
      coop.value === "same-origin" &&
      coep.state === "valid" &&
      ISOLATING_COEP.has(coep.value)
    ) {
      details.push(
        "Isolation complète entre origines (crossOriginIsolated) : protection renforcée contre Spectre et accès à SharedArrayBuffer.",
      );
    }
    const present = readings.flatMap(({ spec, reading }) =>
      reading.state === "absent" ? [] : [`${spec.name}: ${reading.raw}`],
    );
    const evidence = present.length > 0 ? truncateEvidence(present.join("\n")) : null;

    // Le pire l'emporte : une valeur invalide est ignorée en silence par le navigateur.
    const invalid = readings.filter(({ reading }) => reading.state === "invalid");
    const [firstInvalid] = invalid;
    if (firstInvalid) {
      const names = invalid.map(({ spec }) => spec.name).join(", ");
      return {
        status: "warning",
        scoreModifier: -5,
        summary:
          invalid.length > 1
            ? `Plusieurs en-têtes d'isolation sont invalides (${names}) : le navigateur les ignore.`
            : `L'en-tête ${names} est invalide : le navigateur l'ignore.`,
        details,
        evidence,
        recommendation: invalid
          .map(
            ({ spec }) =>
              `Corrigez ${spec.name} (valeurs possibles : ${Object.keys(spec.effects).join(", ")}) et envoyez-le une seule fois.`,
          )
          .join(" "),
        examples: EXAMPLES,
      };
    }

    // COOP n'est appliqué que sur une page servie en HTTPS.
    if (coop.state === "valid" && ISOLATING_COOP.has(coop.value)) {
      if (!isServedOverHttps(response)) {
        return {
          status: "info",
          scoreModifier: 0,
          summary: `Cross-Origin-Opener-Policy vaut « ${coop.value} », mais il est ignoré car la page est servie en HTTP clair.`,
          details,
          evidence,
          recommendation: "Servez la page en HTTPS : COOP n'est appliqué que dans ce cas.",
        };
      }
      return {
        status: "pass",
        scoreModifier: 5,
        summary: `Cross-Origin-Opener-Policy vaut « ${coop.value} » : la page est isolée des fenêtres d'autres origines.`,
        details,
        evidence,
        recommendation:
          corp.state === "absent"
            ? "Ajoutez aussi « Cross-Origin-Resource-Policy: same-origin » (ou same-site) pour empêcher d'autres sites de charger vos ressources."
            : null,
        examples: corp.state === "absent" ? EXAMPLES : undefined,
      };
    }

    return {
      status: "info",
      scoreModifier: 0,
      summary:
        coop.state === "absent"
          ? "Cross-Origin-Opener-Policy est absent : la page n'est pas isolée des fenêtres d'autres origines."
          : "Cross-Origin-Opener-Policy vaut « unsafe-none » : la page n'est pas isolée des fenêtres d'autres origines.",
      details,
      evidence,
      recommendation:
        "Ajoutez « Cross-Origin-Opener-Policy: same-origin » (ou same-origin-allow-popups si le site ouvre des fenêtres de paiement ou de connexion OAuth) pour isoler la page des fenêtres d'autres origines.",
      examples: EXAMPLES,
    };
  },
};
