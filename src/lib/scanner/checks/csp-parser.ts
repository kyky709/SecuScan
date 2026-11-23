// Lecture des CSP selon l'algorithme du navigateur (CSP3), partagée par les contrôles `csp` et
// `clickjacking` pour qu'ils en aient une seule interprétation.

export type CspSource = "header" | "report-only" | "meta";

export interface CspPolicy {
  source: CspSource;
  raw: string;
  /** Nom en minuscules → expressions de source (casse d'origine conservée). */
  directives: ReadonlyMap<string, readonly string[]>;
  /** Directives répétées : le navigateur ne garde que leur première occurrence. */
  duplicates: readonly string[];
  /** Retirées car sans effet dans une balise <meta>. */
  ignored: readonly string[];
}

/** CSP3 § 2.3.1. */
export type SourceKind =
  | "none"
  /** 'self', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic'… */
  | "keyword"
  | "nonce"
  /** 'sha256-…' (ou sha384, sha512). */
  | "hash"
  /** * seul. */
  | "wildcard"
  /** Schéma seul : https:, data:, blob:… */
  | "scheme"
  /** Hôte, avec schéma, port ou chemin éventuels : cdn.example.com, https://*.example.com… */
  | "host";

/** Retirées par le navigateur dans une balise <meta> (CSP3 § 3.3, HTML). */
export const META_IGNORED_DIRECTIVES: readonly string[] = [
  "frame-ancestors",
  "report-uri",
  "sandbox",
];

const ASCII_WHITESPACE = /[\t\n\f\r ]+/;
const ASCII_ONLY = /^\p{ASCII}*$/u;

const HASH_SOURCE = /^'sha(?:256|384|512)-/;
const SCHEME_ONLY_SOURCE = /^[a-z][a-z0-9+.-]*:$/;
const SCHEME_PREFIX = /^([a-z][a-z0-9+.-]*):(?:\/\/|$)/;
const SCHEME_AND_SLASHES = /^[a-z][a-z0-9+.-]*:\/\//;

const BROAD_SCHEMES: ReadonlySet<string> = new Set(["http", "https", "ftp"]);
const INSECURE_SCHEMES: ReadonlySet<string> = new Set(["http", "ftp"]);
const IGNORED_WITH_STRICT_DYNAMIC: ReadonlySet<string> = new Set(["'self'", "'unsafe-inline'"]);

/**
 * Replis des directives de récupération (CSP3 § 6.8.3). Les directives absentes de ce tableau
 * (base-uri, form-action, frame-ancestors, sandbox…) n'ont AUCUN repli : leur absence autorise
 * tout, même avec default-src 'none'.
 */
const FALLBACK_CHAINS: Readonly<Record<string, readonly string[]>> = {
  "script-src": ["script-src", "default-src"],
  "script-src-elem": ["script-src-elem", "script-src", "default-src"],
  "script-src-attr": ["script-src-attr", "script-src", "default-src"],
  "style-src": ["style-src", "default-src"],
  "style-src-elem": ["style-src-elem", "style-src", "default-src"],
  "style-src-attr": ["style-src-attr", "style-src", "default-src"],
  "worker-src": ["worker-src", "child-src", "script-src", "default-src"],
  "child-src": ["child-src", "default-src"],
  "frame-src": ["frame-src", "child-src", "default-src"],
  "connect-src": ["connect-src", "default-src"],
  "font-src": ["font-src", "default-src"],
  "img-src": ["img-src", "default-src"],
  "manifest-src": ["manifest-src", "default-src"],
  "media-src": ["media-src", "default-src"],
  "object-src": ["object-src", "default-src"],
};

/**
 * Blancs ASCII seulement (`trim()` retirerait aussi les espaces Unicode). Boucles plutôt que
 * `/^\s+|\s+$/g`, quadratique sur une longue suite d'espaces : 80 000 espaces bloquent le serveur
 * plusieurs secondes, un site malveillant pourrait s'en servir (ReDoS).
 */
function stripAsciiWhitespace(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && isAsciiWhitespace(text.charCodeAt(start))) start += 1;
  while (end > start && isAsciiWhitespace(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

function isAsciiWhitespace(code: number): boolean {
  return code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d || code === 0x20;
}

/**
 * UNE politique (CSP3 § 2.2.1). Comme le navigateur, on ignore un morceau vide ou non ASCII et une
 * directive répétée ; celle-ci est notée dans `duplicates`, c'est presque toujours une erreur.
 */
export function parseSerializedPolicy(serialized: string, source: CspSource): CspPolicy {
  const directives = new Map<string, readonly string[]>();
  const duplicates: string[] = [];

  for (const token of serialized.split(";")) {
    const directive = stripAsciiWhitespace(token);
    if (directive === "" || !ASCII_ONLY.test(directive)) continue;

    const [rawName = "", ...sources] = directive.split(ASCII_WHITESPACE);
    const name = rawName.toLowerCase();
    if (directives.has(name)) {
      duplicates.push(name);
      continue;
    }
    directives.set(name, sources);
  }

  // Le navigateur analyse d'abord la balise <meta> comme un en-tête, puis retire ces directives.
  const ignored: string[] = [];
  if (source === "meta") {
    for (const name of META_IGNORED_DIRECTIVES) {
      if (directives.delete(name)) ignored.push(name);
    }
  }

  return { source, raw: stripAsciiWhitespace(serialized), directives, duplicates, ignored };
}

/**
 * L'en-tête est une LISTE de politiques séparées par des virgules (CSP3 § 3.1), et la sonde joint
 * les en-têtes répétés par ", " : chaque morceau est une politique qui s'ajoute aux autres. Les
 * politiques vides sont écartées, comme le fait le navigateur.
 */
export function parseCspHeader(value: string, source: "header" | "report-only"): CspPolicy[] {
  return value
    .split(",")
    .map((serialized) => parseSerializedPolicy(serialized, source))
    .filter((policy) => policy.directives.size > 0);
}

/**
 * Contrairement à l'en-tête, UNE seule politique (pas de découpage sur la virgule). Peut être vide,
 * par exemple si la balise ne contenait que frame-ancestors.
 */
export function parseMetaCsp(content: string): CspPolicy {
  return parseSerializedPolicy(content, "meta");
}

/** Après repli (object-src absente → default-src) ; null si rien ne restreint la directive. */
export function effectiveSources(policy: CspPolicy, directive: string): readonly string[] | null {
  const chain = FALLBACK_CHAINS[directive] ?? [directive];
  for (const name of chain) {
    const sources = policy.directives.get(name);
    if (sources !== undefined) return sources;
  }
  return null;
}

export function classifySource(expression: string): SourceKind {
  const source = expression.toLowerCase();
  if (source === "'none'") return "none";
  if (source.startsWith("'nonce-")) return "nonce";
  if (HASH_SOURCE.test(source)) return "hash";
  if (source.startsWith("'")) return "keyword";
  if (source === "*") return "wildcard";
  if (SCHEME_ONLY_SOURCE.test(source)) return "scheme";
  return "host";
}

/** « https » pour https: comme pour https://a.fr. */
export function sourceScheme(expression: string): string | null {
  return SCHEME_PREFIX.exec(expression.toLowerCase())?.[1] ?? null;
}

function sourceHost(expression: string): string {
  const withoutScheme = expression.toLowerCase().replace(SCHEME_AND_SLASHES, "");
  return withoutScheme.split(/[:/]/)[0] ?? "";
}

/**
 * Liste de MDN HTTP Observatory : *, un schéma seul (https:, http:, ftp:) ou un hôte joker
 * (https://*). Un joker de sous-domaine (https://*.example.com) reste limité à un domaine.
 */
export function isBroadSource(expression: string): boolean {
  switch (classifySource(expression)) {
    case "wildcard":
      return true;
    case "scheme":
      return BROAD_SCHEMES.has(sourceScheme(expression) ?? "");
    case "host":
      return sourceHost(expression) === "*";
    default:
      return false;
  }
}

export function isInsecureSchemeSource(expression: string): boolean {
  const scheme = sourceScheme(expression);
  return scheme !== null && INSECURE_SCHEMES.has(scheme);
}

export function isDataSource(expression: string): boolean {
  return classifySource(expression) === "scheme" && sourceScheme(expression) === "data";
}

/** `keyword` en minuscules, ex. "'unsafe-inline'". */
export function hasKeyword(sources: readonly string[], keyword: string): boolean {
  return sources.some((source) => source.toLowerCase() === keyword);
}

export function hasNonceOrHash(sources: readonly string[]): boolean {
  return sources.some((source) => {
    const kind = classifySource(source);
    return kind === "nonce" || kind === "hash";
  });
}

/**
 * Vrai aussi pour une liste vide (« script-src; » n'autorise rien). 'none' accompagné d'autres
 * sources est ignoré par le navigateur.
 */
export function isNoneSourceList(sources: readonly string[]): boolean {
  return sources.every((source) => classifySource(source) === "none");
}

/**
 * CSP3 § 6.7.3.2 : 'unsafe-inline' est ignoré en présence d'un nonce, d'une empreinte ou (scripts)
 * de 'strict-dynamic' ; il ne sert plus alors que de repli pour les très anciens navigateurs.
 */
export function allowsAllInline(sources: readonly string[], type: "script" | "style"): boolean {
  if (hasNonceOrHash(sources)) return false;
  if (type === "script" && hasKeyword(sources, "'strict-dynamic'")) return false;
  return hasKeyword(sources, "'unsafe-inline'");
}

/**
 * Avec 'strict-dynamic' (CSP3 § 8.2), hôtes, schémas, 'self' et 'unsafe-inline' sont ignorés par
 * un navigateur récent : seuls les nonces et empreintes comptent. Une source large (https:) placée
 * à côté ne sert que de repli pour les anciens navigateurs.
 */
export function honoredScriptSources(sources: readonly string[]): readonly string[] {
  if (!hasKeyword(sources, "'strict-dynamic'")) return sources;
  return sources.filter((source) => {
    const kind = classifySource(source);
    if (kind === "host" || kind === "scheme" || kind === "wildcard") return false;
    return !IGNORED_WITH_STRICT_DYNAMIC.has(source.toLowerCase());
  });
}
