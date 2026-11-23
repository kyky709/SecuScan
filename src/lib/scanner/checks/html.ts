/**
 * Extraction des éléments utiles du HTML de la page analysée.
 *
 * Rôle : transformer le corps HTML de la réponse en une liste de faits (`HtmlInfo`) : scripts,
 * feuilles de style, autres ressources chargées, formulaires, CSP et Referrer-Policy en <meta>.
 * Pourquoi : plusieurs contrôles (SRI, contenu mixte, CSP, Referrer-Policy) ont besoin des mêmes
 * informations ; on analyse donc la page une seule fois, avec les règles du navigateur (URL résolues
 * par rapport au <base href>, types de scripts réellement exécutés…).
 * Place dans l'architecture : appelé par l'orchestrateur (scan.ts, étape 4) quand la réponse est du
 * HTML ; le résultat est rangé dans `ScanContext.html`, lu ensuite par les contrôles purs.
 *
 * Le HTML vient d'un site quelconque : il peut être mal formé, énorme ou piégé. L'analyse ne doit
 * jamais lever d'exception (filet de sécurité final dans `extractHtmlInfo`) et le parcours de
 * l'arbre est itératif (une imbrication très profonde ne fait pas déborder la pile d'appels).
 */
import { type HTMLElement, type Options, parse } from "node-html-parser";
import type { HtmlInfo, HtmlResource } from "../types";
import { splitList } from "./helpers";

/**
 * Options de node-html-parser.
 * - `blockTextElements` : éléments dont le contenu est du texte brut et non du HTML, comme dans un
 *   navigateur (`true` = texte conservé, `false` = texte ignoré). On garde le texte des scripts (pour
 *   compter les scripts en ligne non vides). Le contenu de <noscript> est ignoré, comme dans un
 *   navigateur où JavaScript est actif. <pre>, traité en texte par défaut par la bibliothèque, est
 *   volontairement absent : son contenu est du HTML normal.
 * - `parseNoneClosedTags` : conserve les éléments jamais fermés (un navigateur les garde, alors que
 *   la bibliothèque les supprime par défaut, ce qui ferait disparaître un <iframe> non fermé).
 */
const PARSE_OPTIONS: Partial<Options> = {
  parseNoneClosedTags: true,
  blockTextElements: {
    script: true,
    style: false,
    noscript: false,
    textarea: false,
    title: false,
    xmp: false,
    iframe: false,
    noembed: false,
    noframes: false,
  },
};

/** Schémas qui ne déclenchent aucun chargement depuis un serveur (contenu en ligne ou local). */
const IGNORED_SCHEMES: ReadonlySet<string> = new Set(["javascript:", "data:", "about:", "blob:"]);

/** Types MIME JavaScript reconnus par la spécification HTML (« JavaScript MIME type essence »). */
const JAVASCRIPT_MIME_TYPES: ReadonlySet<string> = new Set([
  "application/ecmascript",
  "application/javascript",
  "application/x-ecmascript",
  "application/x-javascript",
  "text/ecmascript",
  "text/javascript",
  "text/javascript1.0",
  "text/javascript1.1",
  "text/javascript1.2",
  "text/javascript1.3",
  "text/javascript1.4",
  "text/javascript1.5",
  "text/jscript",
  "text/livescript",
  "text/x-ecmascript",
  "text/x-javascript",
]);

/** Valeurs de <link rel> qui chargent une ressource autre qu'une feuille de style. */
const LOADING_LINK_RELS: ReadonlySet<string> = new Set(["preload", "modulepreload", "icon"]);

/**
 * Attributs d'URL des autres balises qui chargent une ressource.
 * Une Map (et non un objet littéral) : le nom de balise vient de la page, et une balise nommée
 * `<constructor>` ne doit pas retrouver une propriété héritée d'Object.prototype.
 */
const URL_ATTRIBUTES: ReadonlyMap<string, readonly string[]> = new Map([
  ["img", ["src"]],
  ["audio", ["src"]],
  ["video", ["src", "poster"]],
  ["source", ["src"]],
  ["track", ["src"]],
  ["iframe", ["src"]],
  ["frame", ["src"]],
  ["object", ["data"]],
  ["embed", ["src"]],
]);

/** Balises dont l'attribut srcset liste des images candidates. */
const SRCSET_TAGS: ReadonlySet<string> = new Set(["img", "source"]);

/**
 * Analyse le HTML d'une page et en extrait les ressources, formulaires et politiques déclarées.
 *
 * @param html    corps de la réponse (éventuellement tronqué ou mal formé)
 * @param pageUrl URL finale de la page, pour résoudre les URL relatives
 * @returns les informations extraites ; jamais d'exception (au pire, une page vide)
 */
export function extractHtmlInfo(html: string, pageUrl: string): HtmlInfo {
  try {
    return extract(html, pageUrl);
  } catch {
    // Filet de sécurité : un HTML pathologique ne doit jamais faire échouer tout le scan.
    return emptyHtmlInfo(null);
  }
}

function extract(html: string, pageUrl: string): HtmlInfo {
  const elements = listElements(html);
  const baseHref = findBaseHref(elements, pageUrl);
  const baseUrl = baseHref ?? pageUrl;
  const info = emptyHtmlInfo(baseHref);
  for (const element of elements) {
    collectElement(element, baseUrl, info);
  }
  return info;
}

function emptyHtmlInfo(baseHref: string | null): HtmlInfo {
  return {
    scripts: [],
    inlineScriptCount: 0,
    stylesheets: [],
    otherResources: [],
    forms: [],
    metaCsp: [],
    metaReferrer: null,
    baseHref,
  };
}

/**
 * Tous les éléments de la page, dans l'ordre du document (parcours en profondeur avec une pile
 * explicite plutôt que par récursion). Le contenu d'un <template> est inerte (rien n'y est chargé ni
 * exécuté) : on n'y descend pas.
 */
function listElements(html: string): HTMLElement[] {
  const root = parse(html, PARSE_OPTIONS);
  const elements: HTMLElement[] = [];
  const stack: HTMLElement[] = [...root.children].reverse();
  let element = stack.pop();
  while (element !== undefined) {
    elements.push(element);
    if (tagOf(element) !== "template") {
      // Enfants empilés à l'envers : le premier enfant est traité en premier.
      for (const child of [...element.children].reverse()) stack.push(child);
    }
    element = stack.pop();
  }
  return elements;
}

/** Nom de balise en minuscules (la bibliothèque conserve la casse écrite dans la page). */
function tagOf(element: HTMLElement): string {
  return element.rawTagName?.toLowerCase() ?? "";
}

/** Valeur d'un attribut (nom insensible à la casse) ; "" pour un attribut sans valeur, null s'il est absent. */
function attribute(element: HTMLElement, name: string): string | null {
  return element.hasAttribute(name) ? (element.getAttribute(name) ?? "") : null;
}

/**
 * URL de base du document : celle du premier <base href> (spécification HTML, « frozen base URL »).
 * Si cette URL est illisible, ou en data: ou javascript:, le navigateur l'ignore et garde l'URL de
 * la page : on renvoie alors null.
 */
function findBaseHref(elements: HTMLElement[], pageUrl: string): string | null {
  const base = elements.find(
    (element) => tagOf(element) === "base" && element.hasAttribute("href"),
  );
  if (base === undefined) return null;
  try {
    const url = new URL(attribute(base, "href") ?? "", pageUrl);
    return url.protocol === "data:" || url.protocol === "javascript:" ? null : url.href;
  } catch {
    return null;
  }
}

/**
 * Résout l'URL d'une ressource. Renvoie null si l'attribut est absent ou vide (aucun chargement),
 * si l'URL est illisible, ou si son schéma ne charge rien depuis un serveur (javascript:, data:…).
 */
function resolveResourceUrl(raw: string | null, baseUrl: string): string | null {
  if (raw === null || raw.trim() === "") return null;
  try {
    const url = new URL(raw, baseUrl);
    return IGNORED_SCHEMES.has(url.protocol) ? null : url.href;
  } catch {
    return null;
  }
}

function makeResource(
  element: HTMLElement,
  tag: string,
  url: string,
  rel: string | null = null,
): HtmlResource {
  return {
    tag,
    url,
    integrity: attribute(element, "integrity"),
    crossorigin: attribute(element, "crossorigin"),
    rel,
  };
}

/** Range un élément dans la bonne catégorie de `info`. */
function collectElement(element: HTMLElement, baseUrl: string, info: HtmlInfo): void {
  const tag = tagOf(element);
  switch (tag) {
    case "script":
      collectScript(element, baseUrl, info);
      break;
    case "link":
      collectLink(element, baseUrl, info);
      break;
    case "form":
      collectForm(element, baseUrl, info);
      break;
    case "meta":
      collectMeta(element, info);
      break;
    default:
      collectOtherResource(element, tag, baseUrl, info);
  }
}

/**
 * Le navigateur exécute-t-il ce <script> ? Algorithme « prepare the script element » de la
 * spécification HTML : sans type (ou type vide), c'est du JavaScript ; sinon, seuls un type MIME
 * JavaScript ou « module » sont exécutés. JSON, ld+json, importmap… sont des blocs de données.
 */
function isExecutableScript(element: HTMLElement): boolean {
  const type = attribute(element, "type");
  const language = attribute(element, "language");
  let typeString: string;
  if (type !== null) {
    typeString = type === "" ? "text/javascript" : type.trim();
  } else {
    typeString = language ? `text/${language}` : "text/javascript";
  }
  const normalized = typeString.toLowerCase();
  return JAVASCRIPT_MIME_TYPES.has(normalized) || normalized === "module";
}

function collectScript(element: HTMLElement, baseUrl: string, info: HtmlInfo): void {
  if (!isExecutableScript(element)) return;
  if (element.hasAttribute("src")) {
    // Un src vide ou illisible déclenche une erreur sans rien charger ni exécuter.
    const url = resolveResourceUrl(attribute(element, "src"), baseUrl);
    if (url !== null) info.scripts.push(makeResource(element, "script", url));
  } else if (element.rawText.trim() !== "") {
    // Un script en ligne vide n'exécute rien : on ne le compte pas.
    info.inlineScriptCount += 1;
  }
}

/** <link> : rel est une liste de mots-clés séparés par des espaces, insensibles à la casse. */
function collectLink(element: HTMLElement, baseUrl: string, info: HtmlInfo): void {
  const relTokens = splitList(attribute(element, "rel")?.toLowerCase() ?? "", /\s+/);
  const url = resolveResourceUrl(attribute(element, "href"), baseUrl);
  if (url === null) return;
  const rel = relTokens.join(" ");
  if (relTokens.includes("stylesheet")) {
    info.stylesheets.push(makeResource(element, "link", url, rel));
  } else if (relTokens.some((token) => LOADING_LINK_RELS.has(token))) {
    info.otherResources.push(makeResource(element, "link", url, rel));
  }
}

/** Images, médias, cadres et objets : une ressource par attribut d'URL (et par entrée de srcset). */
function collectOtherResource(
  element: HTMLElement,
  tag: string,
  baseUrl: string,
  info: HtmlInfo,
): void {
  const rawUrls = (URL_ATTRIBUTES.get(tag) ?? []).map((name) => attribute(element, name));
  const srcset = SRCSET_TAGS.has(tag) ? attribute(element, "srcset") : null;
  if (srcset !== null) rawUrls.push(...parseSrcset(srcset));
  for (const raw of rawUrls) {
    const url = resolveResourceUrl(raw, baseUrl);
    if (url !== null) info.otherResources.push(makeResource(element, tag, url));
  }
}

/**
 * URL d'un attribut srcset (« a.jpg 1x, b.jpg 2x »), selon l'algorithme de la spécification HTML :
 * une URL est une suite de caractères sans espace (elle peut contenir des virgules) ; des virgules
 * finales la terminent, sinon ses descripteurs (« 2x », « 300w ») vont jusqu'à la virgule suivante.
 */
function parseSrcset(value: string): string[] {
  const urls: string[] = [];
  const isSpace = (char: string) => /\s/.test(char);
  let position = 0;
  while (position < value.length) {
    // Espaces et virgules séparent les candidats.
    while (
      position < value.length &&
      (isSpace(value.charAt(position)) || value.charAt(position) === ",")
    ) {
      position += 1;
    }
    const start = position;
    while (position < value.length && !isSpace(value.charAt(position))) position += 1;
    const url = value.slice(start, position);
    if (url.endsWith(",")) {
      urls.push(withoutTrailingCommas(url));
      continue;
    }
    // Descripteurs : jusqu'à la prochaine virgule qui n'est pas entre parenthèses.
    let depth = 0;
    while (position < value.length) {
      const char = value.charAt(position);
      if (char === "," && depth === 0) break;
      if (char === "(") depth += 1;
      if (char === ")" && depth > 0) depth -= 1;
      position += 1;
    }
    if (url !== "") urls.push(url);
  }
  return urls;
}

/**
 * Retire les virgules finales. Une boucle plutôt que `replace(/,+$/, "")` : sur une longue suite de
 * virgules suivie d'un autre caractère, cette expression a un coût quadratique (80 000 virgules =
 * plusieurs secondes de calcul), exploitable par une page piégée pour bloquer le serveur (ReDoS).
 */
function withoutTrailingCommas(text: string): string {
  let end = text.length;
  while (end > 0 && text.charAt(end - 1) === ",") end -= 1;
  return text.slice(0, end);
}

/**
 * Formulaire : action résolue (null si absente ou vide : le formulaire est envoyé à l'URL de la
 * page elle-même) et méthode. La méthode est un attribut énuméré : une valeur inconnue vaut "get" ;
 * "dialog" ferme une boîte de dialogue sans rien envoyer. Une action illisible empêche l'envoi : le
 * formulaire est alors ignoré.
 * Limite connue : l'attribut formaction des boutons, qui remplace l'action, n'est pas analysé.
 */
function collectForm(element: HTMLElement, baseUrl: string, info: HtmlInfo): void {
  const rawMethod = attribute(element, "method")?.toLowerCase();
  const method = rawMethod === "post" || rawMethod === "dialog" ? rawMethod : "get";
  const rawAction = attribute(element, "action")?.trim() ?? "";
  if (rawAction === "") {
    info.forms.push({ action: null, method });
    return;
  }
  try {
    info.forms.push({ action: new URL(rawAction, baseUrl).href, method });
  } catch {
    // Action illisible : le navigateur n'envoie pas le formulaire.
  }
}

/**
 * <meta http-equiv="Content-Security-Policy"> : chaque balise ajoute une politique. Le navigateur
 * ignore une telle balise hors de <head> ; faute d'arbre aussi fidèle que celui d'un navigateur
 * (balises <head> souvent omises), on écarte seulement celles placées dans <body>.
 * <meta name="referrer"> : chaque balise remplace la précédente, la dernière non vide est retenue.
 */
function collectMeta(element: HTMLElement, info: HtmlInfo): void {
  const content = attribute(element, "content");
  if (content === null || content.trim() === "") return;
  const httpEquiv = attribute(element, "http-equiv")?.toLowerCase();
  if (httpEquiv === "content-security-policy" && !isInsideBody(element)) {
    info.metaCsp.push(content);
  }
  if (attribute(element, "name")?.toLowerCase() === "referrer") {
    info.metaReferrer = content.trim();
  }
}

function isInsideBody(element: HTMLElement): boolean {
  for (let node = element.parentNode; node !== null; node = node.parentNode) {
    if (node.rawTagName?.toLowerCase() === "body") return true;
  }
  return false;
}
