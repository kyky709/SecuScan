/**
 * Analyse syntaxique des Content Security Policy (CSP niveau 3).
 *
 * Rôle : transformer le texte d'une CSP (en-tête HTTP ou balise <meta>) en une structure simple
 * « directive → liste de sources », en suivant l'algorithme du navigateur décrit par la
 * spécification CSP3 (§ 2.2.1, « parse a serialized CSP »), puis fournir de petites fonctions pour
 * raisonner sur ces sources : type d'une source, repli sur default-src, effet d'un nonce ou de
 * 'strict-dynamic'…
 *
 * Pourquoi un module à part : la syntaxe CSP est piégeuse (plusieurs politiques dans un même
 * en-tête, directive répétée ignorée, repli d'une directive sur une autre) et elle sert à deux
 * contrôles : `csp` (protection contre les XSS) et `clickjacking` (directive frame-ancestors).
 * La regrouper ici garantit une seule interprétation, testée isolément.
 *
 * Place dans l'architecture : fonctions pures, sans dépendance, utilisées par checks/csp.ts et
 * checks/clickjacking.ts.
 */

/** Provenance d'une politique : en-tête appliqué, en-tête Report-Only (signalement seul) ou <meta>. */
export type CspSource = "header" | "report-only" | "meta";

/** Une politique CSP analysée. */
export interface CspPolicy {
  /** Provenance de la politique. */
  source: CspSource;
  /** Texte de la politique, sans les blancs de début et de fin. */
  raw: string;
  /** Directives retenues : nom en minuscules → expressions de source (casse d'origine conservée). */
  directives: ReadonlyMap<string, readonly string[]>;
  /** Noms des directives répétées : le navigateur ne garde que leur première occurrence. */
  duplicates: readonly string[];
  /** Directives retirées car sans effet dans une balise <meta> (frame-ancestors, report-uri, sandbox). */
  ignored: readonly string[];
}

/** Type d'une expression de source (CSP3 § 2.3.1). */
export type SourceKind =
  /** 'none' : n'autorise rien. */
  | "none"
  /** Mot-clé entre apostrophes : 'self', 'unsafe-inline', 'unsafe-eval', 'strict-dynamic'… */
  | "keyword"
  /** 'nonce-…' : jeton aléatoire que doit porter la balise <script> ou <style>. */
  | "nonce"
  /** 'sha256-…' (ou sha384, sha512) : empreinte du code autorisé. */
  | "hash"
  /** * seul : n'importe quel hôte. */
  | "wildcard"
  /** Schéma seul : https:, data:, blob:… */
  | "scheme"
  /** Hôte, avec schéma, port ou chemin éventuels : cdn.example.com, https://*.example.com… */
  | "host";

/** Directives sans effet dans une balise <meta> : le navigateur les retire (CSP3 § 3.3, HTML). */
export const META_IGNORED_DIRECTIVES: readonly string[] = [
  "frame-ancestors",
  "report-uri",
  "sandbox",
];

/** Blancs ASCII au sens de la spécification : tabulation, sauts de ligne et de page, espace. */
const ASCII_WHITESPACE = /[\t\n\f\r ]+/;
const ASCII_ONLY = /^\p{ASCII}*$/u;

const HASH_SOURCE = /^'sha(?:256|384|512)-/;
const SCHEME_ONLY_SOURCE = /^[a-z][a-z0-9+.-]*:$/;
const SCHEME_PREFIX = /^([a-z][a-z0-9+.-]*):(?:\/\/|$)/;
const SCHEME_AND_SLASHES = /^[a-z][a-z0-9+.-]*:\/\//;

/** Schémas « trop larges » : seuls, ils autorisent n'importe quel site qui les utilise. */
const BROAD_SCHEMES: ReadonlySet<string> = new Set(["http", "https", "ftp"]);

/** Schémas non chiffrés : un attaquant placé sur le réseau peut lire ou modifier la ressource. */
const INSECURE_SCHEMES: ReadonlySet<string> = new Set(["http", "ftp"]);

/** Mots-clés que le navigateur ignore pour les scripts quand 'strict-dynamic' est présent. */
const IGNORED_WITH_STRICT_DYNAMIC: ReadonlySet<string> = new Set(["'self'", "'unsafe-inline'"]);

/**
 * Chaînes de repli des directives de récupération (CSP3 § 6.8.3) : quand une directive est
 * absente, le navigateur applique la suivante de la liste, jusqu'à default-src. script-src et
 * style-src se replient sur default-src (comme leurs variantes -elem et -attr).
 * Les directives absentes de ce tableau (base-uri, form-action, frame-ancestors, sandbox…) n'ont
 * AUCUN repli : leur absence autorise tout, même avec default-src 'none'.
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
 * Retire les blancs ASCII de début et de fin (`trim()` retirerait aussi les espaces Unicode).
 *
 * Écrit avec deux boucles plutôt qu'avec l'expression `/^\s+|\s+$/g` : face à une longue suite
 * d'espaces suivie d'un autre caractère, le moteur d'expressions régulières essaie chaque position
 * de départ et chaque longueur, soit un coût quadratique (80 000 espaces = plusieurs secondes de
 * calcul qui bloquent le serveur). Un site malveillant pourrait s'en servir pour saturer SecuScan
 * (déni de service par expression régulière, « ReDoS »). Les boucles sont linéaires.
 */
function stripAsciiWhitespace(text: string): string {
  let start = 0;
  let end = text.length;
  while (start < end && isAsciiWhitespace(text.charCodeAt(start))) start += 1;
  while (end > start && isAsciiWhitespace(text.charCodeAt(end - 1))) end -= 1;
  return text.slice(start, end);
}

/** Blanc ASCII au sens de la spécification Infra : tabulation, LF, FF, CR, espace. */
function isAsciiWhitespace(code: number): boolean {
  return code === 0x09 || code === 0x0a || code === 0x0c || code === 0x0d || code === 0x20;
}

/**
 * Analyse UNE politique sérialisée (CSP3 § 2.2.1) : directives séparées par « ; », chacune formée
 * d'un nom puis de sources séparées par des blancs.
 * - Les noms de directive sont insensibles à la casse : ils sont mis en minuscules.
 * - Un morceau vide ou contenant un caractère non ASCII est ignoré, comme dans le navigateur.
 * - Une directive répétée est ignorée (la première l'emporte) ; on la note dans `duplicates`, car
 *   c'est presque toujours une erreur de configuration (la seconde ligne n'a aucun effet).
 * - Dans une balise <meta>, frame-ancestors, report-uri et sandbox sont retirées (sans effet).
 *
 * @param serialized texte de la politique, ex. "default-src 'self'; object-src 'none'"
 * @param source     provenance de la politique
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
 * Analyse la valeur d'un en-tête Content-Security-Policy ou Content-Security-Policy-Report-Only.
 * Sa grammaire est une LISTE de politiques séparées par des virgules (CSP3 § 3.1) ; la sonde HTTP
 * joint d'ailleurs par ", " les en-têtes répétés. Chaque morceau est donc une politique distincte,
 * que le navigateur applique en plus des autres. Les politiques sans aucune directive sont
 * écartées, comme le fait le navigateur.
 */
export function parseCspHeader(value: string, source: "header" | "report-only"): CspPolicy[] {
  return value
    .split(",")
    .map((serialized) => parseSerializedPolicy(serialized, source))
    .filter((policy) => policy.directives.size > 0);
}

/**
 * Analyse le contenu d'une balise <meta http-equiv="Content-Security-Policy">.
 * Contrairement à l'en-tête, ce contenu forme UNE seule politique (pas de découpage sur la
 * virgule). La politique renvoyée peut être vide, par exemple si la balise ne contenait que
 * frame-ancestors : elle n'a alors aucun effet.
 */
export function parseMetaCsp(content: string): CspPolicy {
  return parseSerializedPolicy(content, "meta");
}

/**
 * Sources qui s'appliquent réellement à `directive` dans une politique, après repli
 * (ex. object-src absente → default-src). Renvoie null si rien ne la restreint : tout est permis.
 */
export function effectiveSources(policy: CspPolicy, directive: string): readonly string[] | null {
  const chain = FALLBACK_CHAINS[directive] ?? [directive];
  for (const name of chain) {
    const sources = policy.directives.get(name);
    if (sources !== undefined) return sources;
  }
  return null;
}

/** Détermine le type d'une expression de source (sans tenir compte de la casse). */
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

/** Schéma explicite d'une source, en minuscules (« https » pour https: ou https://a.fr), sinon null. */
export function sourceScheme(expression: string): string | null {
  return SCHEME_PREFIX.exec(expression.toLowerCase())?.[1] ?? null;
}

/** Hôte d'une source de type hôte : « * », « *.example.com », « cdn.example.com »… */
function sourceHost(expression: string): string {
  const withoutScheme = expression.toLowerCase().replace(SCHEME_AND_SLASHES, "");
  return withoutScheme.split(/[:/]/)[0] ?? "";
}

/**
 * La source est-elle « trop large » (liste de MDN HTTP Observatory) ? Elle autorise alors
 * n'importe quel site, donc n'importe quel attaquant capable d'y héberger un fichier : *, un schéma
 * seul (https:, http:, ftp:) ou un hôte joker (https://*). Un joker de sous-domaine
 * (https://*.example.com) reste limité à un domaine : il n'est pas considéré comme trop large.
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

/** La source utilise-t-elle un schéma non chiffré (http:, http://…, ftp:, ftp://…) ? */
export function isInsecureSchemeSource(expression: string): boolean {
  const scheme = sourceScheme(expression);
  return scheme !== null && INSECURE_SCHEMES.has(scheme);
}

/** La source est-elle le schéma data: (contenu fourni directement dans l'adresse) ? */
export function isDataSource(expression: string): boolean {
  return classifySource(expression) === "scheme" && sourceScheme(expression) === "data";
}

/** La liste contient-elle ce mot-clé (ex. "'unsafe-inline'"), sans tenir compte de la casse ? */
export function hasKeyword(sources: readonly string[], keyword: string): boolean {
  return sources.some((source) => source.toLowerCase() === keyword);
}

/** La liste contient-elle un nonce ou une empreinte (hash) ? */
export function hasNonceOrHash(sources: readonly string[]): boolean {
  return sources.some((source) => {
    const kind = classifySource(source);
    return kind === "nonce" || kind === "hash";
  });
}

/**
 * La liste n'autorise-t-elle rien ? C'est le cas de 'none' seul, mais aussi d'une liste vide
 * (« script-src; » ne correspond à aucune adresse). 'none' accompagné d'autres sources est ignoré
 * par le navigateur : la liste n'est alors pas vide de sens.
 */
export function isNoneSourceList(sources: readonly string[]): boolean {
  return sources.every((source) => classifySource(source) === "none");
}

/**
 * La liste autorise-t-elle TOUT le code en ligne (CSP3 § 6.7.3.2) ?
 * 'unsafe-inline' n'a d'effet qu'en l'absence de nonce et d'empreinte (et, pour les scripts, de
 * 'strict-dynamic') : sinon les navigateurs récents l'ignorent, et il ne sert plus que de repli
 * pour les très anciens navigateurs qui ne comprennent pas les nonces.
 */
export function allowsAllInline(sources: readonly string[], type: "script" | "style"): boolean {
  if (hasNonceOrHash(sources)) return false;
  if (type === "script" && hasKeyword(sources, "'strict-dynamic'")) return false;
  return hasKeyword(sources, "'unsafe-inline'");
}

/**
 * Sources de script réellement honorées par un navigateur récent. Avec 'strict-dynamic'
 * (CSP3 § 8.2), les hôtes, les schémas, 'self' et 'unsafe-inline' sont ignorés : seuls les nonces
 * et les empreintes autorisent un script, qui peut ensuite en charger d'autres. Une source large
 * (https:) placée à côté ne sert donc que de repli pour les anciens navigateurs.
 */
export function honoredScriptSources(sources: readonly string[]): readonly string[] {
  if (!hasKeyword(sources, "'strict-dynamic'")) return sources;
  return sources.filter((source) => {
    const kind = classifySource(source);
    if (kind === "host" || kind === "scheme" || kind === "wildcard") return false;
    return !IGNORED_WITH_STRICT_DYNAMIC.has(source.toLowerCase());
  });
}
