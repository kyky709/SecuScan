// Lecture de Set-Cookie selon RFC 6265bis (draft 22, § 5.6). Les limites de taille (4096 octets
// pour nom + valeur, 1024 par attribut) ne sont pas appliquées : sans effet sur la sécurité.

/** "invalid" = valeur inconnue ou vide, que le navigateur ignore. */
export type SameSiteValue = "strict" | "lax" | "none" | "invalid";

export interface ParsedCookie {
  /** "" pour un cookie sans nom, autorisé par la norme. */
  name: string;
  /** À ne jamais afficher : peut être un identifiant de session. */
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: SameSiteValue | null;
  /** Minuscules, sans point initial ; null = cookie limité à l'hôte. */
  domain: string | null;
  path: string | null;
  /** En secondes. */
  maxAge: number | null;
  /** Horodatage en ms. */
  expires: number | null;
  /** Tels qu'écrits par le serveur, pour l'affichage. */
  attributes: string[];
}

/** null si le navigateur ignorerait entièrement l'en-tête. */
export function parseSetCookie(header: string): ParsedCookie | null {
  // RFC 6265bis § 5.6, étape 1 : un caractère de contrôle (sauf tabulation) invalide l'en-tête.
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

/** « nom=***; Path=/; Secure » : la valeur ne doit jamais apparaître dans un rapport partagé. */
export function maskCookie(cookie: ParsedCookie): string {
  return [`${cookie.name || "(sans nom)"}=***`, ...cookie.attributes].join("; ");
}

function hasForbiddenControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x08 || (code >= 0x0a && code <= 0x1f) || code === 0x7f) return true;
  }
  return false;
}

/** Attribut inconnu : affiché mais sans effet. Attribut répété : le dernier l'emporte. */
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
      if (/^-?\d+$/.test(value)) cookie.maxAge = Number(value);
      break;
    case "expires": {
      const time = Date.parse(value);
      if (!Number.isNaN(time)) cookie.expires = time;
      break;
    }
  }
}

function parseSameSite(value: string): SameSiteValue {
  const normalized = value.toLowerCase();
  return normalized === "strict" || normalized === "lax" || normalized === "none"
    ? normalized
    : "invalid";
}
