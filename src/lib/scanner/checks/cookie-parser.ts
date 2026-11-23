/**
 * Analyseur des en-têtes Set-Cookie, écrit à la main d'après RFC 6265bis (draft 22, § 5.6).
 *
 * Rôle : transformer « nom=valeur; Attr; Attr=Val » en objet typé, comme le ferait un navigateur
 * (noms d'attributs insensibles à la casse, dernière occurrence retenue, valeurs inconnues ignorées).
 * Pourquoi un analyseur maison : il est court, sans dépendance, et chaque règle de sécurité utile au
 * contrôle « cookies » y est explicite et testée. Il ne sert qu'à la lecture : aucune valeur de cookie
 * n'est jamais affichée (voir `maskCookie`).
 * Place dans l'architecture : utilisé par le contrôle pur `cookies.ts`.
 *
 * Simplification assumée : les limites de taille (4096 octets pour nom + valeur, 1024 par attribut)
 * ne sont pas appliquées ; elles n'ont pas d'effet sur les attributs de sécurité.
 */

/** Valeur de SameSite : "invalid" = valeur inconnue ou vide, que le navigateur ignore. */
export type SameSiteValue = "strict" | "lax" | "none" | "invalid";

/** Cookie décrit par un en-tête Set-Cookie. */
export interface ParsedCookie {
  /** Nom du cookie ("" pour un cookie sans nom, autorisé par la norme). */
  name: string;
  /** Valeur : ne jamais l'afficher (elle peut être un identifiant de session). */
  value: string;
  secure: boolean;
  httpOnly: boolean;
  /** Dernière valeur de SameSite, null si l'attribut est absent. */
  sameSite: SameSiteValue | null;
  /** Domaine (minuscules, sans point initial), null si absent : cookie limité à l'hôte. */
  domain: string | null;
  /** Valeur du dernier attribut Path, null si absent. */
  path: string | null;
  /** Durée de vie en secondes (dernier Max-Age valide), null si absent. */
  maxAge: number | null;
  /** Date d'expiration (horodatage en ms du dernier Expires lisible), null si absente. */
  expires: number | null;
  /** Attributs tels qu'écrits par le serveur (pour l'affichage). */
  attributes: string[];
}

/**
 * Analyse un en-tête Set-Cookie.
 *
 * @returns le cookie, ou null si le navigateur ignorerait entièrement l'en-tête (caractère de
 *          contrôle, nom et valeur vides)
 */
export function parseSetCookie(header: string): ParsedCookie | null {
  // RFC 6265bis § 5.6, étape 1 : un caractère de contrôle (hors tabulation) invalide tout l'en-tête.
  if (hasForbiddenControlCharacter(header)) return null;

  const [pair = "", ...rawAttributes] = header.split(";");
  const separator = pair.indexOf("=");
  // Sans « = », la chaîne entière est la valeur d'un cookie sans nom.
  const name = (separator === -1 ? "" : pair.slice(0, separator)).trim();
  const value = (separator === -1 ? pair : pair.slice(separator + 1)).trim();
  if (name === "" && value === "") return null;

  const cookie: ParsedCookie = {
    name,
    value,
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    maxAge: null,
    expires: null,
    attributes: [],
  };
  for (const rawAttribute of rawAttributes) {
    applyAttribute(cookie, rawAttribute);
  }
  return cookie;
}

/**
 * Représentation affichable d'un cookie, valeur masquée : « nom=***; Path=/; Secure ».
 * La valeur peut être un identifiant de session : la montrer dans un rapport partagé la divulguerait.
 */
export function maskCookie(cookie: ParsedCookie): string {
  return [`${cookie.name || "(sans nom)"}=***`, ...cookie.attributes].join("; ");
}

/** Caractères %x00-08, %x0A-1F et %x7F (caractères de contrôle, tabulation exceptée). */
function hasForbiddenControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x08 || (code >= 0x0a && code <= 0x1f) || code === 0x7f) return true;
  }
  return false;
}

/**
 * Applique un attribut « Nom » ou « Nom=Valeur ». Les attributs inconnus sont conservés pour
 * l'affichage mais n'ont aucun effet. Un attribut répété : la dernière occurrence l'emporte.
 */
function applyAttribute(cookie: ParsedCookie, rawAttribute: string): void {
  const text = rawAttribute.trim();
  if (text === "") return;
  cookie.attributes.push(text);

  const separator = text.indexOf("=");
  const name = (separator === -1 ? text : text.slice(0, separator)).trim().toLowerCase();
  const value = separator === -1 ? "" : text.slice(separator + 1).trim();
  switch (name) {
    // Secure et HttpOnly ne dépendent que du nom : « Secure=false » active quand même Secure.
    case "secure":
      cookie.secure = true;
      break;
    case "httponly":
      cookie.httpOnly = true;
      break;
    case "samesite":
      cookie.sameSite = parseSameSite(value);
      break;
    case "domain":
      // Un Domain vide est ignoré ; le point initial (« .example.com ») n'a pas de sens.
      if (value !== "") cookie.domain = value.replace(/^\./, "").toLowerCase();
      break;
    case "path":
      cookie.path = value;
      break;
    case "max-age":
      // Seul un entier (éventuellement négatif) est valide ; sinon l'attribut est ignoré.
      if (/^-?\d+$/.test(value)) cookie.maxAge = Number(value);
      break;
    case "expires": {
      const time = Date.parse(value);
      if (!Number.isNaN(time)) cookie.expires = time;
      break;
    }
  }
}

/** SameSite : comparaison insensible à la casse avec Strict, Lax et None ; le reste est invalide. */
function parseSameSite(value: string): SameSiteValue {
  const normalized = value.toLowerCase();
  return normalized === "strict" || normalized === "lax" || normalized === "none"
    ? normalized
    : "invalid";
}
