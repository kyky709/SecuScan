/**
 * Contrôle « csp » : Content Security Policy.
 *
 * Rôle : vérifier que la page applique une CSP (en-tête Content-Security-Policy ou balise <meta>)
 * capable d'empêcher l'exécution de scripts injectés, et la noter selon la grille de
 * docs/22-notation.md, reprise de l'algorithme de MDN HTTP Observatory.
 *
 * Pourquoi : la CSP est la principale défense en profondeur contre les failles XSS (injection de
 * code dans la page). Même si un attaquant parvient à insérer du HTML, le navigateur refuse
 * d'exécuter un script que la politique n'autorise pas.
 *
 * Place dans l'architecture : contrôle pur `ScanContext → CheckOutcome` de la famille « headers ».
 * La lecture de la syntaxe CSP est déléguée à csp-parser.ts, partagé avec le contrôle clickjacking.
 *
 * Plusieurs politiques (plusieurs en-têtes, ou en-tête + <meta>) : le navigateur les applique
 * TOUTES, et une ressource doit être autorisée par chacune. Ajouter une politique ne peut donc que
 * renforcer la protection : la page est au moins aussi protégée que sa meilleure politique. Chaque
 * politique est notée séparément et le meilleur verdict est retenu. C'est une approximation simple
 * (on ne calcule pas l'intersection exacte des politiques) qui donne le bon résultat dans le cas
 * courant d'une politique principale complétée par une politique annexe (frame-ancestors seule…).
 */
import { REFS } from "@/lib/scanner/references";
import type {
  CheckDefinition,
  CheckOutcome,
  CheckStatus,
  FixExample,
  HttpResponse,
} from "@/lib/scanner/types";
import type { CspPolicy } from "./csp-parser";
import {
  allowsAllInline,
  effectiveSources,
  hasKeyword,
  hasNonceOrHash,
  honoredScriptSources,
  isBroadSource,
  isDataSource,
  isInsecureSchemeSource,
  isNoneSourceList,
  parseCspHeader,
  parseMetaCsp,
} from "./csp-parser";
import {
  getHeader,
  isServedOverHttps,
  notApplicable,
  probeErrorOutcome,
  truncateEvidence,
} from "./helpers";

/** Ligne de la grille de notation : résultat lisible, statut et effet sur le score. */
interface GridRow {
  outcome: string;
  status: CheckStatus;
  modifier: number;
}

/** Grille de notation du contrôle (docs/22-notation.md), du plus grave au meilleur résultat. */
const GRID = {
  notImplemented: {
    outcome:
      "Aucune CSP appliquée (ni en-tête ni balise <meta> ; une politique Report-Only seule ne compte pas)",
    status: "fail",
    modifier: -25,
  },
  invalid: {
    outcome: "CSP invalide (illisible, ou directive répétée dans une même politique)",
    status: "fail",
    modifier: -25,
  },
  unrestrictedScripts: {
    outcome:
      "Scripts non restreints : ni script-src ni default-src, 'unsafe-inline' effectif (sans nonce ni empreinte), data: ou source trop large (*, http:, https:, ftp:, https://*…) dans script-src ; ou object-src absente (sans default-src) ou trop large",
    status: "fail",
    modifier: -20,
  },
  insecureScheme: {
    outcome: "Source en schéma non sécurisé (http: ou http://…) pour les scripts ou les objets",
    status: "fail",
    modifier: -20,
  },
  unsafeEval: {
    outcome: "'unsafe-eval' dans script-src ou style-src (après repli sur default-src)",
    status: "warning",
    modifier: -10,
  },
  insecurePassiveScheme: {
    outcome:
      "Schéma non sécurisé (http:, ftp:) seulement pour du contenu passif (img-src, media-src)",
    status: "warning",
    modifier: -10,
  },
  weakStylesOnly: {
    outcome: "Seul style-src est faible ('unsafe-inline', data: ou source trop large)",
    status: "pass",
    modifier: 0,
  },
  noUnsafeSource: { outcome: "Aucune source dangereuse", status: "pass", modifier: 5 },
  defaultSrcNone: {
    outcome: "Aucune source dangereuse et default-src 'none'",
    status: "pass",
    modifier: 10,
  },
} as const satisfies Record<string, GridRow>;

/** Verdict possible du contrôle : une ligne de la grille. */
type Verdict = keyof typeof GRID;

/** Faiblesse relevée dans une politique : la ligne de grille concernée et une phrase d'explication. */
interface Finding {
  verdict: Verdict;
  message: string;
}

/** Note d'une politique : son verdict, la phrase de résumé et les autres constats. */
interface PolicyAssessment {
  verdict: Verdict;
  summary: string;
  details: string[];
}

/** Politiques observées sur la réponse analysée. */
interface ObservedPolicies {
  /** Valeur brute de l'en-tête Content-Security-Policy (null s'il est absent). */
  headerValue: string | null;
  /** Valeur brute de l'en-tête Content-Security-Policy-Report-Only (null s'il est absent). */
  reportOnlyValue: string | null;
  /** Contenu brut des balises <meta http-equiv="Content-Security-Policy">. */
  metaContents: readonly string[];
  /** Politiques que le navigateur applique (en-tête et <meta>), sans les politiques vides. */
  enforced: CspPolicy[];
  /** Politiques des balises <meta>, même vides (pour signaler les directives ignorées). */
  meta: CspPolicy[];
}

/** Directive de durcissement manquante : la directive conseillée et l'explication du risque. */
interface HardeningGap {
  directive: string;
  detail: string;
}

const STRICT_CSP_ADVICE =
  "Adoptez une CSP stricte fondée sur un nonce : à chaque réponse, le serveur tire une valeur aléatoire et imprévisible (le nonce), l'ajoute à ses propres balises <script nonce=\"…\"> et l'annonce dans l'en-tête avec script-src 'nonce-…' 'strict-dynamic'. Un script injecté par un attaquant ne connaît pas cette valeur : le navigateur refuse de l'exécuter. Ajoutez object-src 'none' et base-uri 'none', et déployez d'abord la politique en Content-Security-Policy-Report-Only pour repérer ce qu'elle bloquerait. Pour un site statique, sans code côté serveur, limitez plutôt script-src à 'self' et autorisez les rares scripts en ligne par leur empreinte ('sha256-…').";

const REPORT_ONLY_ADVICE =
  "Votre politique Report-Only peut servir de point de départ : une fois les violations signalées corrigées, envoyez-la dans l'en-tête Content-Security-Policy pour qu'elle soit appliquée.";

const UNREADABLE_ADVICE =
  "Corrigez la syntaxe de l'en-tête : des directives séparées par « ; », chacune suivie de ses sources séparées par des espaces (ex. default-src 'self'; object-src 'none').";

const DUPLICATE_ADVICE =
  "Déclarez chaque directive une seule fois par politique, en regroupant toutes ses sources : le navigateur ignore les répétitions. Pour restreindre davantage, ajoutez plutôt un second en-tête Content-Security-Policy, qui s'applique en plus du premier.";

const UNRESTRICTED_SCRIPTS_ADVICE =
  "Retirez de script-src (et de default-src) 'unsafe-inline', data: et les sources trop larges, et définissez object-src 'none'.";

const INSECURE_SCHEME_ADVICE =
  "Remplacez les sources en http:// (ou ftp://) de script-src, object-src et default-src par leur équivalent en https://.";

const UNSAFE_EVAL_ADVICE =
  "Retirez 'unsafe-eval' : remplacez eval(), new Function() et setTimeout() appelé avec une chaîne par du code ordinaire ; si une bibliothèque l'exige, cherchez une version compatible avec la CSP.";

const PASSIVE_SCHEME_ADVICE =
  "Remplacez les sources en http:// de img-src et media-src (ou default-src) par https://, ou ajoutez la directive upgrade-insecure-requests.";

const WEAK_STYLES_ADVICE =
  "Pour aller plus loin, retirez 'unsafe-inline' de style-src en autorisant vos balises <style> par un nonce ou une empreinte, et limitez les sources de styles à vos propres domaines.";

const STRICT_DYNAMIC_DETAIL =
  "'strict-dynamic' est utilisé : seuls les scripts portant le nonce ou l'empreinte sont autorisés, et ils peuvent charger d'autres scripts ; les navigateurs récents ignorent alors les sources d'hôtes et de schémas.";

const STRICT_DYNAMIC_WITHOUT_NONCE_DETAIL =
  "'strict-dynamic' est utilisé sans nonce ni empreinte : les navigateurs récents bloquent alors tous les scripts de la page.";

const NEUTRALIZED_UNSAFE_INLINE_DETAIL =
  "'unsafe-inline' est ignoré par les navigateurs récents, car script-src contient un nonce, une empreinte ou 'strict-dynamic' : il ne sert que de repli pour les anciens navigateurs.";

/** Politique de départ pour un site sans script en ligne : tout vient du site lui-même. */
const STATIC_SITE_POLICY =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests";

/** Exemple Next.js 16, adapté du guide officiel « Content Security Policy » (fichier proxy.ts). */
const NEXT_PROXY_EXAMPLE = `// proxy.ts : un nonce aléatoire est tiré à chaque requête. Next.js le lit dans
// l'en-tête de la requête et l'ajoute à ses propres scripts. Les pages doivent être
// rendues dynamiquement (ex. await connection()) pour que le nonce change à chaque fois.
import { type NextRequest, NextResponse } from "next/server";

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  // En développement uniquement, React a besoin de 'unsafe-eval'.
  const isDev = process.env.NODE_ENV === "development";
  const csp = [
    "default-src 'self'",
    \`script-src 'self' 'nonce-\${nonce}' 'strict-dynamic'\${isDev ? " 'unsafe-eval'" : ""}\`,
    \`style-src 'self' 'nonce-\${nonce}'\`,
    "img-src 'self' blob: data:",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "upgrade-insecure-requests",
  ].join("; ");

  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}`;

const CSP_EXAMPLES: readonly FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: [
      "# Site sans script en ligne : point de départ à adapter (CDN, API…).",
      "# Script en ligne indispensable ? Autorisez son empreinte : script-src 'self' 'sha256-…'.",
      "# Testez d'abord la politique avec l'en-tête Content-Security-Policy-Report-Only.",
      `add_header Content-Security-Policy "${STATIC_SITE_POLICY}" always;`,
    ].join("\n"),
  },
  {
    label: "Apache",
    language: "apache",
    code: [
      "# Site sans script en ligne : point de départ à adapter (CDN, API…), module mod_headers.",
      "# Script en ligne indispensable ? Autorisez son empreinte : script-src 'self' 'sha256-…'.",
      "# Testez d'abord la politique avec l'en-tête Content-Security-Policy-Report-Only.",
      `Header always set Content-Security-Policy "${STATIC_SITE_POLICY}"`,
    ].join("\n"),
  },
  { label: "Next.js (proxy.ts)", language: "ts", code: NEXT_PROXY_EXAMPLE },
];

/** Élimine les doublons en conservant l'ordre. */
function unique<T>(items: readonly T[]): T[] {
  return [...new Set(items)];
}

/** Lit l'en-tête CSP, l'en-tête Report-Only et les balises <meta> de la réponse analysée. */
function readPolicies(response: HttpResponse, metaContents: readonly string[]): ObservedPolicies {
  const headerValue = getHeader(response, "content-security-policy");
  const headerPolicies = headerValue === null ? [] : parseCspHeader(headerValue, "header");
  const meta = metaContents.map((content) => parseMetaCsp(content));
  return {
    headerValue,
    reportOnlyValue: getHeader(response, "content-security-policy-report-only"),
    metaContents,
    enforced: [...headerPolicies, ...meta.filter((policy) => policy.directives.size > 0)],
    meta,
  };
}

/** Preuve affichée : chaque politique observée, précédée de sa provenance. */
function describeEvidence(observed: ObservedPolicies): string | null {
  const lines = [
    ...(observed.headerValue === null ? [] : [`Content-Security-Policy: ${observed.headerValue}`]),
    ...observed.metaContents.map(
      (content) => `<meta http-equiv="Content-Security-Policy" content="${content}">`,
    ),
    ...(observed.reportOnlyValue === null
      ? []
      : [`Content-Security-Policy-Report-Only: ${observed.reportOnlyValue}`]),
  ];
  return lines.length === 0 ? null : truncateEvidence(lines.join("\n"));
}

/** Scripts : la politique empêche-t-elle l'exécution d'un script injecté ? */
function scriptFindings(policy: CspPolicy): Finding[] {
  const sources = effectiveSources(policy, "script-src");
  if (sources === null) {
    return [
      {
        verdict: "unrestrictedScripts",
        message:
          "La CSP ne restreint pas les scripts : elle ne contient ni script-src ni default-src.",
      },
    ];
  }

  const findings: Finding[] = [];
  if (allowsAllInline(sources, "script")) {
    findings.push({
      verdict: "unrestrictedScripts",
      message:
        "La CSP autorise tous les scripts en ligne ('unsafe-inline' sans nonce ni empreinte) : un script injecté dans la page serait exécuté.",
    });
  }
  // Avec 'strict-dynamic', les hôtes et les schémas sont ignorés : seules les sources honorées comptent.
  const honored = honoredScriptSources(sources);
  if (honored.some(isDataSource)) {
    findings.push({
      verdict: "unrestrictedScripts",
      message:
        "La CSP autorise les scripts en data: : un attaquant peut fournir le code du script dans l'adresse elle-même.",
    });
  }
  const broad = honored.filter(isBroadSource);
  if (broad.length > 0) {
    findings.push({
      verdict: "unrestrictedScripts",
      message: `La CSP autorise des scripts venant de sources trop larges (${broad.join(", ")}) : n'importe quel site peut fournir un script.`,
    });
  }
  return findings;
}

/** Plugins (<object>, <embed>) : une source absente ou trop large équivaut à tout autoriser. */
function objectFindings(policy: CspPolicy): Finding[] {
  const sources = effectiveSources(policy, "object-src");
  if (sources === null) {
    return [
      {
        verdict: "unrestrictedScripts",
        message:
          "La CSP ne restreint pas les plugins (<object>, <embed>) : elle ne contient ni object-src ni default-src.",
      },
    ];
  }
  const broad = sources.filter(isBroadSource);
  if (broad.length === 0) return [];
  return [
    {
      verdict: "unrestrictedScripts",
      message: `La CSP autorise des plugins (<object>, <embed>) venant de sources trop larges (${broad.join(", ")}).`,
    },
  ];
}

/** Scripts et objets transmis en clair (http://, ftp://), modifiables par un attaquant réseau. */
function insecureSchemeFindings(policy: CspPolicy): Finding[] {
  const scripts = honoredScriptSources(effectiveSources(policy, "script-src") ?? []);
  const objects = effectiveSources(policy, "object-src") ?? [];
  // Une source à la fois trop large et non chiffrée (http:) est déjà signalée comme trop large.
  const insecure = unique(
    [...scripts, ...objects].filter(
      (source) => isInsecureSchemeSource(source) && !isBroadSource(source),
    ),
  );
  if (insecure.length === 0) return [];
  return [
    {
      verdict: "insecureScheme",
      message: `La CSP autorise des scripts ou des objets transmis en clair (${insecure.join(", ")}) : un attaquant placé sur le réseau pourrait les modifier.`,
    },
  ];
}

/** 'unsafe-eval' : permet de transformer une chaîne de caractères en code exécuté. */
function unsafeEvalFindings(policy: CspPolicy): Finding[] {
  const allowsEval = ["script-src", "style-src"].some((directive) =>
    hasKeyword(effectiveSources(policy, directive) ?? [], "'unsafe-eval'"),
  );
  if (!allowsEval) return [];
  return [
    {
      verdict: "unsafeEval",
      message:
        "La CSP autorise 'unsafe-eval' : eval() et new Function() peuvent transformer du texte en code exécuté, ce qui facilite l'exploitation d'une injection.",
    },
  ];
}

/** Contenu passif (images, médias) transmis en clair : risque plus faible que pour les scripts. */
function passiveSchemeFindings(policy: CspPolicy): Finding[] {
  const passive = [
    ...(effectiveSources(policy, "img-src") ?? []),
    ...(effectiveSources(policy, "media-src") ?? []),
  ];
  const insecure = unique(passive.filter(isInsecureSchemeSource));
  if (insecure.length === 0) return [];
  return [
    {
      verdict: "insecurePassiveScheme",
      message: `La CSP autorise des images ou des médias transmis en clair (${insecure.join(", ")}) : ils peuvent être lus ou remplacés sur le réseau.`,
    },
  ];
}

/** Styles : une faiblesse ici ne permet pas d'exécuter de script, d'où une note neutre. */
function styleFindings(policy: CspPolicy): Finding[] {
  const sources = effectiveSources(policy, "style-src");
  if (sources === null) {
    return [
      {
        verdict: "weakStylesOnly",
        message:
          "Les styles ne sont pas restreints (ni style-src ni default-src) : une injection de CSS reste possible, un risque bien moindre que l'exécution de scripts.",
      },
    ];
  }
  const weaknesses = [
    ...(allowsAllInline(sources, "style") ? ["'unsafe-inline'"] : []),
    ...sources.filter((source) => isDataSource(source) || isBroadSource(source)),
  ];
  if (weaknesses.length === 0) return [];
  return [
    {
      verdict: "weakStylesOnly",
      message: `La directive style-src est permissive (${weaknesses.join(", ")}) : une injection de CSS reste possible, un risque bien moindre que l'exécution de scripts.`,
    },
  ];
}

/** Toutes les faiblesses d'une politique, de la plus grave à la moins grave. */
function findWeaknesses(policy: CspPolicy, overHttps: boolean): Finding[] {
  const findings = [
    ...scriptFindings(policy),
    ...objectFindings(policy),
    // Comme Observatory, les schémas non chiffrés ne comptent que pour une page servie en HTTPS :
    // une page en HTTP circule déjà entièrement en clair.
    ...(overHttps ? insecureSchemeFindings(policy) : []),
    ...unsafeEvalFindings(policy),
    ...(overHttps ? passiveSchemeFindings(policy) : []),
    ...styleFindings(policy),
  ];
  // Tri stable : le constat le plus grave d'abord, l'ordre de la grille à gravité égale.
  return findings.sort((a, b) => GRID[a.verdict].modifier - GRID[b.verdict].modifier);
}

/** Note une politique seule : son constat le plus grave, ou un bonus si elle n'a aucune faiblesse. */
function assessPolicy(policy: CspPolicy, overHttps: boolean): PolicyAssessment {
  const [worst, ...others] = findWeaknesses(policy, overHttps);
  if (worst !== undefined) {
    return {
      verdict: worst.verdict,
      summary: worst.message,
      details: others.map((f) => f.message),
    };
  }
  const defaultSources = policy.directives.get("default-src");
  if (defaultSources !== undefined && isNoneSourceList(defaultSources)) {
    return {
      verdict: "defaultSrcNone",
      summary:
        "La CSP part de default-src 'none' (tout est interdit sauf ce qui est explicitement permis) et n'autorise aucune source dangereuse.",
      details: [],
    };
  }
  return {
    verdict: "noUnsafeSource",
    summary:
      "La CSP n'autorise aucune source dangereuse pour les scripts, les plugins et les styles.",
    details: [],
  };
}

/**
 * Meilleure note parmi les politiques appliquées : comme le navigateur les applique toutes, la page
 * est au moins aussi protégée que la plus stricte d'entre elles. `policies` n'est jamais vide.
 */
function bestAssessment(policies: readonly CspPolicy[], overHttps: boolean): PolicyAssessment {
  return policies
    .map((policy) => assessPolicy(policy, overHttps))
    .reduce((best, candidate) =>
      GRID[candidate.verdict].modifier > GRID[best.verdict].modifier ? candidate : best,
    );
}

/**
 * Directives de durcissement absentes de toutes les politiques. base-uri, form-action et
 * frame-ancestors n'héritent pas de default-src : leur absence autorise tout.
 */
function hardeningGaps(enforced: readonly CspPolicy[]): HardeningGap[] {
  const declares = (name: string) => enforced.some((policy) => policy.directives.has(name));
  const objectLists = enforced
    .map((policy) => effectiveSources(policy, "object-src"))
    .filter((sources): sources is readonly string[] => sources !== null);

  const gaps: HardeningGap[] = [];
  // Sans aucune liste object-src, le verdict signale déjà les plugins non restreints.
  if (objectLists.length > 0 && !objectLists.some(isNoneSourceList)) {
    gaps.push({
      directive: "object-src 'none'",
      detail:
        "object-src n'est pas 'none' : l'OWASP (ASVS 3.4.3) recommande object-src 'none', les plugins (<object>, <embed>) étant devenus inutiles sur le Web moderne.",
    });
  }
  if (!declares("base-uri")) {
    gaps.push({
      directive: "base-uri 'none'",
      detail:
        "base-uri est absente (elle n'hérite pas de default-src) : une balise <base> injectée pourrait détourner les scripts chargés par des chemins relatifs.",
    });
  }
  if (!declares("form-action")) {
    gaps.push({
      directive: "form-action 'self'",
      detail:
        "form-action est absente (elle n'hérite pas de default-src) : un formulaire injecté pourrait envoyer les données saisies vers un autre site.",
    });
  }
  // Les politiques <meta> n'ont plus de frame-ancestors (retirée à l'analyse) : seul l'en-tête compte.
  if (!declares("frame-ancestors")) {
    gaps.push({
      directive: "frame-ancestors 'none'",
      detail:
        "frame-ancestors est absente de l'en-tête : la CSP ne protège pas contre le clickjacking (voir le contrôle dédié).",
    });
  }
  return gaps;
}

/** Constats sur les mots-clés de script ('strict-dynamic', 'unsafe-inline' neutralisé). */
function scriptKeywordDetails(enforced: readonly CspPolicy[]): string[] {
  const details = new Set<string>();
  for (const policy of enforced) {
    const sources = effectiveSources(policy, "script-src") ?? [];
    if (hasKeyword(sources, "'strict-dynamic'")) {
      details.add(
        hasNonceOrHash(sources) ? STRICT_DYNAMIC_DETAIL : STRICT_DYNAMIC_WITHOUT_NONCE_DETAIL,
      );
    }
    if (hasKeyword(sources, "'unsafe-inline'") && !allowsAllInline(sources, "script")) {
      details.add(NEUTRALIZED_UNSAFE_INLINE_DETAIL);
    }
  }
  return [...details];
}

/** Constats sur la provenance des politiques (<meta>, Report-Only, en-tête vide, pluralité). */
function sourceDetails(observed: ObservedPolicies): string[] {
  const { enforced } = observed;
  const details: string[] = [];
  const headerApplied = enforced.some((policy) => policy.source === "header");
  if (observed.headerValue !== null && !headerApplied && enforced.length > 0) {
    details.push(
      "L'en-tête Content-Security-Policy ne contient aucune directive lisible : il est sans effet.",
    );
  }
  if (enforced.some((policy) => policy.source === "meta")) {
    details.push(
      "Une CSP est déclarée dans une balise <meta> : elle ne protège que le contenu placé après la balise, et frame-ancestors, report-uri et sandbox y sont sans effet.",
    );
  }
  const ignored = unique(observed.meta.flatMap((policy) => policy.ignored));
  if (ignored.length > 0) {
    details.push(
      `Directives ignorées par le navigateur dans la balise <meta> : ${ignored.join(", ")}.`,
    );
  }
  if (observed.reportOnlyValue !== null && enforced.length > 0) {
    details.push(
      "Une politique Content-Security-Policy-Report-Only est aussi présente : elle signale les violations sans rien bloquer (pratique pour tester une politique plus stricte).",
    );
  }
  if (enforced.length > 1) {
    details.push(
      `${enforced.length} politiques CSP sont appliquées en même temps : une ressource doit être autorisée par chacune, le verdict retient donc la plus protectrice.`,
    );
  }
  return details;
}

/** Recommandation adaptée au verdict (null si la politique est déjà complète). */
function recommendationFor(verdict: Verdict, observed: ObservedPolicies): string | null {
  switch (verdict) {
    case "notImplemented":
      return observed.reportOnlyValue === null
        ? STRICT_CSP_ADVICE
        : `${REPORT_ONLY_ADVICE} ${STRICT_CSP_ADVICE}`;
    case "invalid":
      return `${UNREADABLE_ADVICE} ${STRICT_CSP_ADVICE}`;
    case "unrestrictedScripts":
      return `${UNRESTRICTED_SCRIPTS_ADVICE} ${STRICT_CSP_ADVICE}`;
    case "insecureScheme":
      return INSECURE_SCHEME_ADVICE;
    case "unsafeEval":
      return UNSAFE_EVAL_ADVICE;
    case "insecurePassiveScheme":
      return PASSIVE_SCHEME_ADVICE;
    case "weakStylesOnly":
      return WEAK_STYLES_ADVICE;
    case "noUnsafeSource":
    case "defaultSrcNone": {
      const missing = hardeningGaps(observed.enforced).map((gap) => gap.directive);
      return missing.length === 0
        ? null
        : `Pour renforcer encore la politique, ajoutez : ${missing.join("; ")}.`;
    }
  }
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
    examples: recommendation === null ? [] : [...CSP_EXAMPLES],
  };
}

/** Verdict quand aucune politique n'est appliquée : CSP absente, ou présente mais illisible. */
function withoutEnforcedPolicy(observed: ObservedPolicies, evidence: string | null): CheckOutcome {
  const details = sourceDetails(observed);
  if (observed.headerValue !== null) {
    // L'en-tête existe mais aucune directive n'a pu en être lue : c'est une erreur de syntaxe.
    return buildOutcome(
      "invalid",
      "L'en-tête Content-Security-Policy est présent mais ne contient aucune directive lisible : le navigateur n'applique aucune restriction.",
      details,
      evidence,
      recommendationFor("invalid", observed),
    );
  }

  let summary =
    "Aucune Content Security Policy n'est appliquée : ni en-tête Content-Security-Policy, ni balise <meta>.";
  if (observed.reportOnlyValue !== null) {
    summary =
      "Aucune CSP n'est appliquée : seule une politique Content-Security-Policy-Report-Only est présente, et elle signale les violations sans rien bloquer.";
  } else if (observed.meta.length > 0) {
    summary =
      "Aucune CSP n'est appliquée : la balise <meta> ne contient aucune directive applicable (frame-ancestors, report-uri et sandbox y sont ignorées).";
  }
  return buildOutcome(
    "notImplemented",
    summary,
    details,
    evidence,
    recommendationFor("notImplemented", observed),
  );
}

export const cspCheck: CheckDefinition = {
  id: "csp",
  category: "headers",
  title: "Content Security Policy (CSP)",
  description:
    "La Content Security Policy (CSP) indique au navigateur d'où la page a le droit de charger ou d'exécuter des scripts, des styles, des plugins… Bien configurée (scripts autorisés par un nonce ou une empreinte, object-src 'none'), elle empêche l'exécution d'un script injecté par un attaquant (XSS), même si une faille existe dans le code. C'est une défense en profondeur : elle ne remplace ni la validation des entrées ni l'échappement des données affichées.",
  references: [
    REFS.cheatSheets.csp,
    REFS.cheatSheets.httpHeadersCsp,
    REFS.secureHeaders.configuration,
    REFS.top10.A05,
    REFS.top10.A02,
    REFS.asvs["3.4.3"],
    REFS.wstg.CONF12,
    REFS.mdn.csp,
    REFS.mdn.observatoryScoring,
    REFS.other.strictCsp,
  ],
  scoring: Object.values(GRID).map(({ outcome, modifier }) => ({ outcome, modifier })),
  evaluate(context) {
    const response = context.response;
    if (!response) {
      // Cas théorique : sans aucune réponse, scan.ts interrompt le scan (TARGET_UNREACHABLE).
      return context.https.ok
        ? notApplicable("Aucune réponse HTTP n'a pu être analysée.")
        : probeErrorOutcome(context.https.error, "la Content Security Policy");
    }

    const observed = readPolicies(response, context.html?.metaCsp ?? []);
    const evidence = describeEvidence(observed);
    if (observed.enforced.length === 0) return withoutEnforcedPolicy(observed, evidence);

    const best = bestAssessment(observed.enforced, isServedOverHttps(response));
    const details = [
      ...best.details,
      ...hardeningGaps(observed.enforced).map((gap) => gap.detail),
      ...scriptKeywordDetails(observed.enforced),
      ...sourceDetails(observed),
    ];

    // Une directive répétée est une erreur de configuration (la répétition est ignorée par le
    // navigateur, sans doute à l'insu de l'auteur) : comme Observatory, la CSP est jugée invalide.
    const duplicates = unique(observed.enforced.flatMap((policy) => policy.duplicates));
    if (duplicates.length > 0) {
      return buildOutcome(
        "invalid",
        `La CSP est invalide : directive répétée dans une même politique (${duplicates.join(", ")}) ; le navigateur ne garde que la première occurrence, ce qui n'est sans doute pas l'effet voulu.`,
        [best.summary, ...details],
        evidence,
        DUPLICATE_ADVICE,
      );
    }

    return buildOutcome(
      best.verdict,
      best.summary,
      details,
      evidence,
      recommendationFor(best.verdict, observed),
    );
  },
};
