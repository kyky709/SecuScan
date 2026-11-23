// Analyse unique de la page pour les contrôles SRI, contenu mixte, CSP et Referrer-Policy. Le HTML
// vient d'un site quelconque (mal formé, énorme ou piégé) : jamais d'exception, et un parcours
// itératif pour qu'une imbrication très profonde ne fasse pas déborder la pile.
import { type HTMLElement, type Options, parse } from "node-html-parser";
import type { HtmlInfo, HtmlResource } from "../types";
import { splitList } from "./helpers";

/**
 * Comme un navigateur où JavaScript est actif : texte des scripts conservé (pour compter les
 * scripts en ligne), <noscript> ignoré. <pre>, traité en texte par défaut par la bibliothèque, est
 * absent exprès : son contenu est du HTML. `parseNoneClosedTags` garde les éléments jamais fermés,
 * que la bibliothèque supprime par défaut (un <iframe> non fermé disparaîtrait).
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

/** Aucun chargement depuis un serveur. */
const IGNORED_SCHEMES: ReadonlySet<string> = new Set(["javascript:", "data:", "about:", "blob:"]);

/** Spécification HTML, « JavaScript MIME type essence ». */
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

const LOADING_LINK_RELS: ReadonlySet<string> = new Set(["preload", "modulepreload", "icon"]);

/** Une Map, pas un objet : une balise `<constructor>` ne doit pas trouver de propriété héritée. */
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

const SRCSET_TAGS: ReadonlySet<string> = new Set(["img", "source"]);

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

/** Le contenu d'un <template> est inerte (rien n'y est chargé ni exécuté) : on n'y descend pas. */
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

/** La bibliothèque conserve la casse écrite dans la page. */
function tagOf(element: HTMLElement): string {
  return element.rawTagName?.toLowerCase() ?? "";
}

/** "" pour un attribut sans valeur, null s'il est absent. */
function attribute(element: HTMLElement, name: string): string | null {
  return element.hasAttribute(name) ? (element.getAttribute(name) ?? "") : null;
}

/**
 * Premier <base href> (HTML, « frozen base URL ») ; illisible, en data: ou javascript:, il est
 * ignoré et le navigateur garde l'URL de la page.
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
 * HTML, « prepare the script element » : sans type, c'est du JavaScript ; sinon seuls un type MIME
 * JavaScript ou « module » s'exécutent (JSON, importmap… sont des blocs de données).
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
    info.inlineScriptCount += 1;
  }
}

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
 * Algorithme HTML : une URL est une suite sans espace (elle peut contenir des virgules) ; des
 * virgules finales la terminent, sinon ses descripteurs (« 2x ») vont jusqu'à la virgule suivante.
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
 * Une boucle plutôt que `replace(/,+$/, "")`, quadratique sur une longue suite de virgules :
 * exploitable par une page piégée pour bloquer le serveur (ReDoS).
 */
function withoutTrailingCommas(text: string): string {
  let end = text.length;
  while (end > 0 && text.charAt(end - 1) === ",") end -= 1;
  return text.slice(0, end);
}

/**
 * Action absente ou vide (null) : envoi à l'URL de la page. method est énuméré : valeur inconnue =
 * "get", "dialog" n'envoie rien. Limite connue : formaction sur les boutons n'est pas analysé.
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
 * Le navigateur ignore une CSP en <meta> hors de <head> ; faute d'arbre aussi fidèle (<head>
 * souvent omis), on n'écarte que celles placées dans <body>. Pour referrer, la dernière non vide
 * l'emporte.
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
