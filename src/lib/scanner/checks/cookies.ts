// Grille reprise de MDN HTTP Observatory.
import { REFS } from "../references";
import type {
  CheckDefinition,
  CheckStatus,
  FetchSuccess,
  FixExample,
  HttpResponse,
  Result,
  ScanContext,
} from "../types";
import { maskCookie, type ParsedCookie, parseSetCookie } from "./cookie-parser";
import {
  hasEffectiveHsts,
  httpsResponse,
  isServedOverHttps,
  notApplicable,
  shorten,
  truncateEvidence,
} from "./helpers";

const SESSION_COOKIE_PATTERN =
  /sess|sid|auth|token|login|jwt|connect\.sid|phpsessid|jsessionid|asp\.net_sessionid|remember/i;

const ANTI_CSRF_PATTERN = /csrf|xsrf/i;

/**
 * Un cookie anti-CSRF (« XSRF-TOKEN ») contient souvent « token » sans être un cookie de session :
 * en double soumission (Angular, Laravel…), JavaScript doit le lire. Exiger HttpOnly casserait la
 * protection CSRF du site.
 */
function isSessionCookieName(name: string): boolean {
  return SESSION_COOKIE_PATTERN.test(name) && !ANTI_CSRF_PATTERN.test(name);
}

const MAX_LISTED_NAMES = 5;

interface ObservedCookie {
  cookie: ParsedCookie;
  overHttp: boolean;
  isSession: boolean;
  isAntiCsrf: boolean;
  /** Non null : le navigateur rejette le cookie. */
  prefixViolation: string | null;
}

interface CookieRule {
  id: string;
  outcome: string;
  status: CheckStatus;
  modifier: number;
  appliesTo(observed: ObservedCookie, hsts: boolean): boolean;
  describe(cookies: ObservedCookie[]): string;
  fix: string;
}

function displayName(cookie: ParsedCookie): string {
  return cookie.name === "" ? "(sans nom)" : shorten(cookie.name);
}

function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** « a », « a et b », « a, b et c », « a, b, c, d, e et 2 autres ». */
function joinList(items: string[]): string {
  const shown = items.slice(0, MAX_LISTED_NAMES);
  const hidden = items.length - shown.length;
  if (hidden > 0) return `${shown.join(", ")} et ${hidden} ${hidden > 1 ? "autres" : "autre"}`;
  return shown.length > 1 ? `${shown.slice(0, -1).join(", ")} et ${shown.at(-1)}` : items.join("");
}

function uniqueNames(cookies: ObservedCookie[]): string[] {
  return [...new Set(cookies.map(({ cookie }) => `« ${displayName(cookie)} »`))];
}

function isPlural(cookies: ObservedCookie[]): boolean {
  return uniqueNames(cookies).length > 1;
}

/** Sujet et verbe accordés : « le cookie « a » n'a » / « les cookies « a » et « b » n'ont ». */
function subject(cookies: ObservedCookie[], kind: string, singular: string, plural: string) {
  const many = isPlural(cookies);
  return `${many ? "les cookies" : "le cookie"}${kind} ${joinList(uniqueNames(cookies))} ${
    many ? plural : singular
  }`;
}

const ADD_SECURE = "Ajoutez l'attribut Secure à tous les cookies : ils ne circuleront qu'en HTTPS.";

/**
 * De la plus grave à la moins grave : la première enfreinte fixe le verdict (les pénalités ne se
 * cumulent pas), les autres deviennent des détails.
 */
const COOKIE_RULES: readonly CookieRule[] = [
  {
    id: "session-secure",
    outcome: "Cookie de session sans Secure",
    status: "fail",
    modifier: -40,
    appliesTo: (observed, hsts) => observed.isSession && !observed.cookie.secure && !hsts,
    describe: (cookies) =>
      `${capitalize(subject(cookies, " de session", "n'a", "n'ont"))} pas l'attribut Secure et aucun HSTS ne compense : la session peut être interceptée sur une connexion non chiffrée.`,
    fix: ADD_SECURE,
  },
  {
    id: "session-httponly",
    outcome: "Cookie de session sans HttpOnly",
    status: "fail",
    modifier: -30,
    appliesTo: (observed) => observed.isSession && !observed.cookie.httpOnly,
    describe: (cookies) =>
      `${capitalize(subject(cookies, " de session", "n'a", "n'ont"))} pas l'attribut HttpOnly : un script injecté (XSS) peut lire et voler la session.`,
    fix: "Ajoutez HttpOnly aux cookies de session : JavaScript n'a pas besoin de les lire.",
  },
  {
    id: "secure",
    outcome: "Cookie sans Secure",
    status: "fail",
    modifier: -20,
    // Les cookies de session ont leurs propres règles, plus sévères.
    appliesTo: (observed, hsts) => !observed.isSession && !observed.cookie.secure && !hsts,
    describe: (cookies) =>
      `${capitalize(subject(cookies, "", "n'a", "n'ont"))} pas l'attribut Secure et aucun HSTS ne compense : ${
        isPlural(cookies) ? "leur" : "sa"
      } valeur peut circuler en clair sur le réseau.`,
    fix: ADD_SECURE,
  },
  {
    id: "samesite",
    outcome: "SameSite invalide, ou SameSite=None sans Secure",
    status: "fail",
    modifier: -20,
    appliesTo: ({ cookie }) =>
      cookie.sameSite === "invalid" || (cookie.sameSite === "none" && !cookie.secure),
    describe: (cookies) => {
      const invalid = cookies.filter(({ cookie }) => cookie.sameSite === "invalid");
      const noneWithoutSecure = cookies.filter(({ cookie }) => cookie.sameSite === "none");
      const clauses: string[] = [];
      if (invalid.length > 0) {
        clauses.push(
          `${subject(invalid, "", "a", "ont")} une valeur SameSite invalide, que le navigateur ignore`,
        );
      }
      if (noneWithoutSecure.length > 0) {
        clauses.push(
          `${subject(noneWithoutSecure, "", "utilise", "utilisent")} SameSite=None sans Secure, combinaison rejetée par Chrome et Firefox`,
        );
      }
      return `${capitalize(clauses.join(" ; "))}.`;
    },
    fix: "Utilisez une valeur SameSite valide (Strict, Lax ou None) et réservez None aux cookies Secure.",
  },
  {
    id: "anti-csrf",
    outcome: "Cookie anti-CSRF sans SameSite",
    status: "fail",
    modifier: -20,
    appliesTo: ({ isAntiCsrf, cookie }) => isAntiCsrf && cookie.sameSite === null,
    describe: (cookies) =>
      `${capitalize(subject(cookies, " anti-CSRF", "n'a", "n'ont"))} pas d'attribut SameSite : la protection contre la falsification de requêtes (CSRF) dépend du comportement par défaut du navigateur.`,
    fix: "Ajoutez SameSite=Strict (ou Lax) au cookie anti-CSRF.",
  },
  {
    id: "session-secure-hsts",
    outcome: "Cookie de session sans Secure mais protégé par HSTS",
    status: "fail",
    modifier: -10,
    appliesTo: (observed, hsts) => observed.isSession && !observed.cookie.secure && hsts,
    describe: (cookies) =>
      `${capitalize(subject(cookies, " de session", "n'a", "n'ont"))} pas l'attribut Secure : HSTS limite le risque, mais la session reste exposée tant que le navigateur ne connaît pas encore HSTS (première visite).`,
    fix: ADD_SECURE,
  },
  {
    id: "secure-hsts",
    outcome: "Cookie sans Secure mais protégé par HSTS",
    status: "warning",
    modifier: -5,
    appliesTo: (observed, hsts) => !observed.isSession && !observed.cookie.secure && hsts,
    describe: (cookies) =>
      `${capitalize(subject(cookies, "", "n'a", "n'ont"))} pas l'attribut Secure ; HSTS compense en grande partie ce manque.`,
    fix: ADD_SECURE,
  },
  {
    id: "prefix",
    outcome:
      "Préfixe __Secure-/__Host- dont les règles ne sont pas respectées (cookie rejeté par les navigateurs)",
    status: "warning",
    modifier: -5,
    appliesTo: (observed) => observed.prefixViolation !== null,
    describe: (cookies) => {
      const reasons = cookies.map(
        ({ cookie, prefixViolation }) => `« ${displayName(cookie)} » (${prefixViolation})`,
      );
      return `Règles de préfixe non respectées, les navigateurs rejettent ${
        isPlural(cookies) ? "ces cookies" : "ce cookie"
      } : ${joinList([...new Set(reasons)])}.`;
    },
    fix: "Respectez les règles des préfixes : __Secure- exige Secure et un dépôt en HTTPS ; __Host- exige en plus Path=/ et aucun attribut Domain.",
  },
];

/** RFC 6265bis § 4.1.3 ; __Http- et __Host-Http- d'après MDN. Préfixes insensibles à la casse. */
function prefixViolation(cookie: ParsedCookie, overHttp: boolean): string | null {
  const name = cookie.name.toLowerCase();
  // Un cookie sans nom dont la valeur commence par un préfixe est rejeté : il l'imiterait.
  if (name === "" && /^__(secure|host)-/i.test(cookie.value)) return "sans nom, imite un préfixe";
  if (!["__secure-", "__host-", "__http-"].some((prefix) => name.startsWith(prefix))) return null;
  if (!cookie.secure) return "Secure obligatoire";
  if (overHttp) return "dépôt en HTTPS obligatoire";
  if (name.startsWith("__host-") && cookie.domain !== null) return "Domain interdit";
  if (name.startsWith("__host-") && cookie.path !== "/") return "Path=/ obligatoire";
  const needsHttpOnly = name.startsWith("__http-") || name.startsWith("__host-http-");
  if (needsHttpOnly && !cookie.httpOnly) return "HttpOnly obligatoire";
  return null;
}

function cookiesBreaking(
  rule: CookieRule,
  cookies: ObservedCookie[],
  hsts: boolean,
): ObservedCookie[] {
  // Un cookie au préfixe invalide est rejeté par le navigateur : ses autres attributs n'exposent
  // rien, seule la règle du préfixe le concerne.
  return cookies.filter(
    (observed) =>
      (rule.id === "prefix" || observed.prefixViolation === null) && rule.appliesTo(observed, hsts),
  );
}

/** Y compris les réponses obtenues avant une erreur (redirections). */
function responsesOf(result: Result<FetchSuccess>): HttpResponse[] {
  return result.ok ? result.value.chain : (result.error.chain ?? []);
}

/** Max-Age l'emporte sur Expires. Un cookie supprimé n'est pas conservé : attributs sans enjeu. */
function isDeletion(cookie: ParsedCookie, now: number): boolean {
  if (cookie.maxAge !== null) return cookie.maxAge <= 0;
  return cookie.expires !== null && cookie.expires <= now;
}

interface CookieInventory {
  cookies: ObservedCookie[];
  invalidCount: number;
  deletedNames: string[];
}

/** La réponse HTTPS finale figure souvent dans les deux chaînes : dédoublonnage par transport. */
function inventoryCookies(context: ScanContext, now: number): CookieInventory {
  const headers = new Map<string, { header: string; overHttp: boolean }>();
  for (const response of [...responsesOf(context.https), ...responsesOf(context.http)]) {
    const overHttp = !isServedOverHttps(response);
    for (const header of response.setCookies) {
      headers.set(`${overHttp ? "http" : "https"} ${header}`, { header, overHttp });
    }
  }

  const inventory: CookieInventory = { cookies: [], invalidCount: 0, deletedNames: [] };
  for (const { header, overHttp } of headers.values()) {
    const cookie = parseSetCookie(header);
    if (cookie === null) {
      inventory.invalidCount += 1;
    } else if (isDeletion(cookie, now)) {
      inventory.deletedNames.push(`« ${displayName(cookie)} »`);
    } else {
      inventory.cookies.push({
        cookie,
        overHttp,
        isSession: isSessionCookieName(cookie.name),
        isAntiCsrf: ANTI_CSRF_PATTERN.test(cookie.name),
        prefixViolation: prefixViolation(cookie, overHttp),
      });
    }
  }
  return inventory;
}

/** Constats sans effet sur la note. */
function inventoryNotes({ cookies, invalidCount, deletedNames }: CookieInventory): string[] {
  const notes: string[] = [];
  const overHttp = cookies.filter((observed) => observed.overHttp);
  if (overHttp.length > 0) {
    notes.push(
      `${capitalize(subject(overHttp, "", "est déposé", "sont déposés"))} par une réponse en HTTP clair : ${
        isPlural(overHttp) ? "leur" : "sa"
      } valeur circule sans chiffrement.`,
    );
  }
  if (invalidCount > 0) {
    notes.push(
      invalidCount > 1
        ? `${invalidCount} en-têtes Set-Cookie invalides ont été ignorés, comme le ferait un navigateur.`
        : "Un en-tête Set-Cookie invalide a été ignoré, comme le ferait un navigateur.",
    );
  }
  if (deletedNames.length > 0) {
    notes.push(
      `Cookies supprimés par le serveur (expiration passée), non évalués : ${joinList([
        ...new Set(deletedNames),
      ])}.`,
    );
  }
  return notes;
}

const COOKIE_EXAMPLES: FixExample[] = [
  {
    label: "En-tête attendu (cookie de session)",
    language: "http",
    code: "Set-Cookie: __Host-session=<valeur>; Path=/; Secure; HttpOnly; SameSite=Lax",
  },
  {
    label: "Nginx (≥ 1.19.3, devant l'application)",
    language: "nginx",
    code: `location / {
    proxy_pass http://127.0.0.1:3000;
    # Ajoute Secure, HttpOnly et SameSite=Lax aux cookies émis par l'application.
    # Retirez httponly si un script doit lire certains cookies.
    proxy_cookie_flags ~ secure httponly samesite=lax;
}`,
  },
  {
    label: "Apache (mod_headers)",
    language: "apache",
    code: `# Ajoute les attributs manquants aux cookies émis par l'application
Header edit Set-Cookie "^((?!.*;\\s*[Ss]ecure).*)$" "$1; Secure"
Header edit Set-Cookie "^((?!.*;\\s*[Hh]ttp[Oo]nly).*)$" "$1; HttpOnly"
Header edit Set-Cookie "^((?!.*;\\s*[Ss]ame[Ss]ite).*)$" "$1; SameSite=Lax"`,
  },
  {
    label: "Next.js (Route Handler)",
    language: "ts",
    code: `// app/api/login/route.ts : dépôt d'un cookie de session
import { cookies } from "next/headers";

export async function POST() {
  const sessionId = crypto.randomUUID(); // à associer à la session côté serveur
  const cookieStore = await cookies();
  cookieStore.set("__Host-session", sessionId, {
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    path: "/",
  });
  return Response.json({ ok: true });
}`,
  },
];

const MISSING_SAMESITE_FIX =
  "Ajoutez SameSite=Lax (ou Strict) à chaque cookie plutôt que de dépendre du comportement par défaut, qui varie d'un navigateur à l'autre.";

export const cookiesCheck: CheckDefinition = {
  id: "cookies",
  category: "cookies",
  title: "Attributs des cookies",
  description:
    "Les cookies transportent souvent l'identifiant de session. L'attribut Secure empêche leur envoi en clair, HttpOnly les rend illisibles par JavaScript (vol par XSS) et SameSite limite leur envoi par des requêtes venues d'autres sites (CSRF). Les préfixes __Secure- et __Host- font vérifier ces règles par le navigateur.",
  references: [
    REFS.cheatSheets.sessionCookies,
    REFS.cheatSheets.tlsSecureCookies,
    REFS.cheatSheets.csrfSameSite,
    REFS.top10.A02,
    REFS.asvs["3.3.1"],
    REFS.asvs["3.3.2"],
    REFS.asvs["3.3.3"],
    REFS.asvs["3.3.4"],
    REFS.wstg.SESS02,
    REFS.mdn.setCookie,
    REFS.mdn.cookies,
  ],
  scoring: [
    { outcome: "Aucun cookie", modifier: 0 },
    ...COOKIE_RULES.map(({ outcome, modifier }) => ({ outcome, modifier })),
    { outcome: "Tous Secure, sessions HttpOnly, mais SameSite manquant sur certains", modifier: 0 },
    { outcome: "Tous Secure, sessions HttpOnly, tous avec SameSite valide", modifier: 5 },
  ],
  evaluate(context) {
    const inventory = inventoryCookies(context, Date.now());
    const { cookies } = inventory;
    const notes = inventoryNotes(inventory);
    if (cookies.length === 0) {
      return notApplicable("Le site ne dépose aucun cookie.", notes.length > 0 ? notes : undefined);
    }

    const hsts = hasEffectiveHsts(httpsResponse(context));
    const evidence = truncateEvidence(
      [...new Set(cookies.map(({ cookie }) => maskCookie(cookie)))].join("\n"),
    );
    const findings = COOKIE_RULES.map((rule) => ({
      rule,
      cookies: cookiesBreaking(rule, cookies, hsts),
    })).filter((finding) => finding.cookies.length > 0);

    const [worst, ...others] = findings;
    if (worst !== undefined) {
      return {
        status: worst.rule.status,
        scoreModifier: worst.rule.modifier,
        summary: worst.rule.describe(worst.cookies),
        details: [...others.map((finding) => finding.rule.describe(finding.cookies)), ...notes],
        evidence,
        recommendation: [...new Set(findings.map((finding) => finding.rule.fix))].join(" "),
        examples: COOKIE_EXAMPLES,
      };
    }

    const withoutSameSite = cookies.filter(({ cookie }) => cookie.sameSite === null);
    if (withoutSameSite.length > 0) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary: `Secure et HttpOnly sont bien utilisés, mais ${subject(withoutSameSite, "", "n'a", "n'ont")} pas d'attribut SameSite : le navigateur applique alors son comportement par défaut.`,
        details: notes,
        evidence,
        recommendation: MISSING_SAMESITE_FIX,
        examples: COOKIE_EXAMPLES,
      };
    }

    return {
      status: "pass",
      scoreModifier: 5,
      summary: `${capitalize(subject(cookies, "", "a", "ont"))} les attributs attendus : Secure, HttpOnly pour les sessions et une valeur SameSite valide.`,
      details: notes,
      evidence,
      recommendation: null,
    };
  },
};
