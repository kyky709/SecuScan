/**
 * Contrôle « HTTP Strict Transport Security (HSTS) ».
 *
 * Rôle : analyser l'en-tête Strict-Transport-Security de la réponse HTTPS finale selon la
 * grammaire de la RFC 6797 et le barème de MDN HTTP Observatory.
 *
 * Pourquoi : même avec une redirection HTTP → HTTPS, la première requête part en clair et peut
 * être détournée (attaque « SSL stripping »). HSTS demande au navigateur de n'utiliser que HTTPS
 * pour ce site pendant `max-age` secondes, sans jamais repasser par HTTP.
 *
 * Place dans l'architecture : contrôle pur de la famille « transport ». Il lit la réponse HTTPS
 * finale (`httpsResponse(context)`) et, pour un constat secondaire, la chaîne HTTP (`context.http`).
 * Le préchargement est estimé d'après l'en-tête (éligibilité) : SecuScan ne télécharge pas la
 * liste de préchargement de Chromium (écart assumé avec Observatory, voir docs/22-notation.md § 4).
 */
import { getHeader, httpsResponse, shorten, truncateEvidence } from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type {
  CheckDefinition,
  CheckOutcome,
  FixExample,
  HttpResponse,
  ScanContext,
} from "@/lib/scanner/types";

/** Durée minimale attendue : 180 jours, seuil exact de MDN HTTP Observatory. */
const MIN_MAX_AGE = 15_552_000;

/** Durée minimale exigée pour le préchargement (hstspreload.org) : 365 jours. */
const PRELOAD_MIN_MAX_AGE = 31_536_000;

/** Valeur conseillée : deux ans, sous-domaines inclus, sans preload (démarche volontaire). */
const RECOMMENDED_VALUE = "max-age=63072000; includeSubDomains";

/** Jeton HTTP (RFC 9110 § 5.6.2). */
const TOKEN = "[!#$%&'*+.^_`|~0-9A-Za-z-]+";

/** Directive HSTS (RFC 6797 § 6.1) : nom, puis éventuellement « = » et un jeton ou une chaîne. */
const DIRECTIVE = new RegExp(`^(${TOKEN})(?:\\s*=\\s*("[^"]*"|${TOKEN}))?$`);

/** Politique HSTS lue dans un en-tête valide. */
interface HstsPolicy {
  maxAge: number;
  /** max-age tel qu'écrit (chiffres), pour l'affichage : un nombre démesuré deviendrait « Infinity ». */
  maxAgeText: string;
  includeSubDomains: boolean;
  preload: boolean;
}

type HstsParseResult = { valid: true; policy: HstsPolicy } | { valid: false; reason: string };

/**
 * Analyse UN en-tête Strict-Transport-Security selon la RFC 6797 § 6.1 : directives séparées par
 * « ; », noms insensibles à la casse, chaque directive au plus une fois, max-age obligatoire
 * (éventuellement entre guillemets). Un en-tête non conforme est ignoré par les navigateurs.
 * Limite assumée : un « ; » à l'intérieur d'une valeur entre guillemets n'est pas pris en charge
 * (aucune directive connue n'en contient).
 */
function parseHsts(value: string): HstsParseResult {
  const directives = new Map<string, string | null>();
  for (const part of value.split(";")) {
    const directive = part.trim();
    // La grammaire autorise les directives vides, par exemple un « ; » final.
    if (directive === "") continue;
    const match = DIRECTIVE.exec(directive);
    const name = match?.[1]?.toLowerCase();
    if (!match || name === undefined) {
      return { valid: false, reason: `la directive « ${shorten(directive)} » est mal formée` };
    }
    if (directives.has(name)) {
      return { valid: false, reason: `la directive « ${shorten(name)} » apparaît plusieurs fois` };
    }
    const rawValue = match[2];
    directives.set(name, rawValue === undefined ? null : rawValue.replace(/^"(.*)"$/, "$1"));
  }
  const maxAge = directives.get("max-age");
  if (maxAge === undefined) {
    return { valid: false, reason: "la directive max-age, obligatoire, est absente" };
  }
  if (maxAge === null || !/^\d+$/.test(maxAge)) {
    return { valid: false, reason: "la valeur de max-age n'est pas un nombre entier de secondes" };
  }
  return {
    valid: true,
    policy: {
      maxAge: Number(maxAge),
      maxAgeText: maxAge,
      includeSubDomains: directives.has("includesubdomains"),
      preload: directives.has("preload"),
    },
  };
}

/** « 365 jours ». */
function formatDays(seconds: number): string {
  // Une valeur de plus de 309 chiffres dépasse la capacité d'un nombre JavaScript (Infinity).
  if (!Number.isFinite(seconds)) return "une durée démesurée";
  const days = Math.floor(seconds / 86_400);
  return `${days} jour${days > 1 ? "s" : ""}`;
}

/** L'en-tête remplit-il les conditions de hstspreload.org (1 an, includeSubDomains, preload) ? */
function isPreloadEligible(policy: HstsPolicy): boolean {
  return policy.maxAge >= PRELOAD_MIN_MAX_AGE && policy.includeSubDomains && policy.preload;
}

/** HSTS a-t-il été envoyé sur une réponse en HTTP clair (où il est ignoré) ? */
function sentOverCleartext(context: ScanContext): boolean {
  const chain = context.http.ok ? context.http.value.chain : (context.http.error.chain ?? []);
  return chain.some(
    (response) =>
      response.url.startsWith("http:") && getHeader(response, "strict-transport-security") !== null,
  );
}

/** Constats indépendants de la valeur de l'en-tête (HTTP clair, certificat, adresse IP). */
function contextDetails(context: ScanContext, response: HttpResponse | null): string[] {
  const details: string[] = [];
  if (sentOverCleartext(context)) {
    details.push(
      "L'en-tête HSTS est aussi envoyé en HTTP clair : les navigateurs l'y ignorent (RFC 6797 § 8.1), seul l'en-tête reçu en HTTPS compte.",
    );
  }
  if (response?.tls?.authorized === false) {
    details.push(
      "Le certificat présenté est invalide : les navigateurs ignorent HSTS tant qu'il n'est pas corrigé (pénalité déjà comptée par le contrôle du certificat).",
    );
  }
  if (context.target.isIpAddress) {
    details.push(
      "HSTS ne s'applique pas à une adresse IP (RFC 6797 § 8.1.1) : il faut accéder au site par son nom de domaine.",
    );
  }
  return details;
}

/** Constats sur la politique lue : sous-domaines et préchargement. */
function policyDetails(policy: HstsPolicy): string[] {
  const details = [
    policy.includeSubDomains
      ? "includeSubDomains est présent : les sous-domaines sont aussi protégés."
      : "includeSubDomains est absent : les sous-domaines ne sont pas protégés par HSTS.",
  ];
  if (isPreloadEligible(policy)) {
    details.push(
      "L'en-tête remplit les conditions du préchargement (max-age ≥ 31536000, includeSubDomains, preload) ; SecuScan ne consulte pas la liste des navigateurs : vérifiez l'inscription sur hstspreload.org.",
    );
  } else if (policy.preload) {
    details.push(
      "La directive preload est présente, mais le préchargement exige aussi max-age ≥ 31536000 (un an) et includeSubDomains.",
    );
  }
  return details;
}

/** Recommandation pour un en-tête valide : null s'il n'y a rien à améliorer. */
function improvementAdvice(policy: HstsPolicy): string | null {
  if (policy.maxAge < MIN_MAX_AGE) {
    return "Augmentez max-age à au moins 15552000 secondes (180 jours) ; la valeur conseillée est 63072000 (deux ans). Vous pouvez monter par paliers (une semaine, un mois, puis deux ans).";
  }
  if (!policy.includeSubDomains) {
    return "Ajoutez includeSubDomains si tous vos sous-domaines sont accessibles en HTTPS.";
  }
  if (policy.maxAge < PRELOAD_MIN_MAX_AGE) {
    return "Portez max-age à au moins un an (31536000), idéalement deux ans (63072000).";
  }
  return null;
}

/** Exemples d'en-tête HSTS (sans preload : le préchargement doit rester un choix délibéré). */
const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Dans le bloc server { listen 443 ssl; … } uniquement
add_header Strict-Transport-Security "${RECOMMENDED_VALUE}" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Dans le <VirtualHost *:443> (module mod_headers)
Header always set Strict-Transport-Security "${RECOMMENDED_VALUE}"`,
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
        headers: [{ key: "Strict-Transport-Security", value: "${RECOMMENDED_VALUE}" }],
      },
    ];
  },
};

export default nextConfig;`,
  },
];

/** Verdict « HSTS non appliqué » (absent, invalide, désactivé ou sans HTTPS) : -20. */
function notEnforced(
  summary: string,
  details: string[],
  evidence: string | null,
  recommendation = `Envoyez l'en-tête « Strict-Transport-Security: ${RECOMMENDED_VALUE} » sur toutes les réponses HTTPS (retirez includeSubDomains si certains sous-domaines ne fonctionnent pas en HTTPS).`,
): CheckOutcome {
  return {
    status: "fail",
    scoreModifier: -20,
    summary,
    details,
    evidence,
    recommendation,
    examples: EXAMPLES,
  };
}

/** Contrôle de l'en-tête HSTS. */
export const hstsCheck: CheckDefinition = {
  id: "hsts",
  category: "transport",
  title: "HTTP Strict Transport Security (HSTS)",
  description:
    "L'en-tête Strict-Transport-Security demande au navigateur de n'utiliser que HTTPS pour ce site pendant une durée donnée (max-age). Il empêche un attaquant de faire repasser la connexion en HTTP clair (attaque « SSL stripping ») et rend impossible le contournement d'une erreur de certificat. Avec includeSubDomains, la protection s'étend aux sous-domaines.",
  references: [
    REFS.cheatSheets.hsts,
    REFS.cheatSheets.httpHeadersHsts,
    REFS.top10.A04,
    REFS.asvs["3.4.1"],
    REFS.asvs["3.7.4"],
    REFS.wstg.CONF07,
    REFS.mdn.hsts,
    REFS.rfc.hsts,
    REFS.other.hstsPreload,
  ],
  scoring: [
    { outcome: "Site non accessible en HTTPS", modifier: -20 },
    { outcome: "En-tête absent", modifier: -20 },
    { outcome: "En-tête invalide ou max-age=0", modifier: -20 },
    { outcome: "max-age inférieur à 15552000 s (180 jours)", modifier: -10 },
    { outcome: "max-age d'au moins 180 jours", modifier: 0 },
    {
      outcome: "Éligible au préchargement (max-age ≥ 31536000, includeSubDomains, preload)",
      modifier: 5,
    },
  ],
  evaluate(context) {
    const response = httpsResponse(context);
    const details = contextDetails(context, response);
    if (!response) {
      return notEnforced(
        "Le site n'est pas accessible en HTTPS : HSTS ne peut pas être activé.",
        details,
        null,
        `Activez d'abord HTTPS, puis envoyez l'en-tête « Strict-Transport-Security: ${RECOMMENDED_VALUE} » sur toutes les réponses HTTPS.`,
      );
    }

    const header = getHeader(response, "strict-transport-security");
    if (header === null) {
      return notEnforced(
        "L'en-tête Strict-Transport-Security est absent de la réponse HTTPS.",
        details,
        null,
      );
    }
    const evidence = truncateEvidence(header);

    // En-tête reçu plusieurs fois : la sonde joint les valeurs par « , ». La grammaire HSTS
    // n'autorisant pas de virgule, chaque virgule sépare deux en-têtes, et seul le premier
    // compte (RFC 6797 § 8.1).
    const [first = "", ...others] = header.split(",");
    if (others.length > 0) {
      details.unshift(
        "Plusieurs valeurs séparées par des virgules ont été reçues (en-tête envoyé plusieurs fois, ou virgule écrite à la place d'un point-virgule) : seul le premier en-tête est pris en compte, n'en envoyez qu'un.",
      );
    }

    const parsed = parseHsts(first);
    if (!parsed.valid) {
      return notEnforced(
        `L'en-tête HSTS est invalide : ${parsed.reason}. Les navigateurs l'ignorent.`,
        details,
        evidence,
      );
    }
    const { policy } = parsed;
    if (policy.maxAge === 0) {
      return notEnforced(
        "L'en-tête HSTS contient max-age=0 : il demande au navigateur d'oublier la protection.",
        details,
        evidence,
      );
    }

    details.push(...policyDetails(policy));
    const summary = `L'en-tête HSTS est présent avec max-age=${shorten(policy.maxAgeText)} (${formatDays(policy.maxAge)}).`;
    const recommendation = improvementAdvice(policy);
    const examples = recommendation === null ? undefined : EXAMPLES;

    if (policy.maxAge < MIN_MAX_AGE) {
      return {
        status: "warning",
        scoreModifier: -10,
        summary: `L'en-tête HSTS est présent, mais max-age=${shorten(policy.maxAgeText)} (${formatDays(policy.maxAge)}) est inférieur aux 180 jours attendus.`,
        details,
        evidence,
        recommendation,
        examples,
      };
    }
    return {
      status: "pass",
      scoreModifier: isPreloadEligible(policy) ? 5 : 0,
      summary,
      details,
      evidence,
      recommendation,
      examples,
    };
  },
};
