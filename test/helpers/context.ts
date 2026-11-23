/**
 * Fabriques de données de test.
 *
 * Les contrôles sont des fonctions pures `ScanContext → CheckOutcome` : pour les tester, il suffit
 * de construire un contexte. Ces fabriques donnent un contexte « site exemplaire par défaut »
 * (HTTPS valide, redirection HTTP → HTTPS) que chaque test modifie selon le cas étudié.
 */
import type {
  CaaInfo,
  FetchSuccess,
  HtmlInfo,
  HttpResponse,
  NetworkError,
  NetworkErrorCode,
  Result,
  ScanContext,
  ScanTarget,
  TlsInfo,
} from "@/lib/scanner/types";

/** Résultat réussi. */
export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

/** Résultat en échec. */
export function failure<T = never>(
  code: NetworkErrorCode = "CONNECTION_REFUSED",
  message = "Connexion refusée par le serveur.",
  extra: Partial<NetworkError> = {},
): Result<T> {
  return { ok: false, error: { code, message, ...extra } };
}

/** Met les noms d'en-têtes en minuscules, comme le fait la sonde HTTP. */
function lowercaseKeys(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

/** Réponse HTTP de test (HTML en HTTPS, statut 200 par défaut). */
export function makeResponse(overrides: Partial<HttpResponse> = {}): HttpResponse {
  const url = overrides.url ?? "https://example.com/";
  const headers = lowercaseKeys(
    overrides.headers ?? { "content-type": "text/html; charset=utf-8" },
  );
  const isHttps = url.startsWith("https:");
  return {
    status: 200,
    rawHeaders: Object.entries(headers),
    setCookies: [],
    body: null,
    bodyTruncated: false,
    remoteAddress: "93.184.215.14",
    tls: isHttps ? { authorized: true, authorizationError: null, protocol: "TLSv1.3" } : null,
    durationMs: 42,
    ...overrides,
    url,
    headers,
  };
}

/** Réponse de redirection (301 par défaut) vers `location`. */
export function makeRedirect(url: string, location: string, status = 301): HttpResponse {
  return makeResponse({ url, status, headers: { location }, body: null });
}

/** Résultat de requête réussi : `chain` = redirections éventuelles + réponse finale. */
export function fetched(
  response: HttpResponse,
  redirects: HttpResponse[] = [],
): Result<FetchSuccess> {
  return ok({ response, chain: [...redirects, response] });
}

/** Informations TLS de test : certificat valide, TLS 1.3, 60 jours restants. */
export function makeTlsInfo(overrides: Partial<TlsInfo> = {}): TlsInfo {
  return {
    hostname: "example.com",
    address: "93.184.215.14",
    port: 443,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    alpnProtocol: "h2",
    authorized: true,
    authorizationError: null,
    certificate: {
      subject: "example.com",
      subjectAltNames: ["example.com", "www.example.com"],
      issuer: "Let's Encrypt",
      validFrom: "2026-10-01T00:00:00.000Z",
      validTo: "2026-12-30T00:00:00.000Z",
      daysRemaining: 60,
      serialNumber: "04A1B2C3D4E5F6",
      fingerprint256: "AA:BB:CC:DD",
      keyType: "EC",
      keyBits: 256,
      selfSigned: false,
    },
    chain: [
      { subject: "example.com", issuer: "E7" },
      { subject: "E7", issuer: "ISRG Root X1" },
    ],
    legacyProtocols: { tls10: false, tls11: false },
    ...overrides,
  };
}

/** Page HTML de test sans aucune ressource. */
export function makeHtmlInfo(overrides: Partial<HtmlInfo> = {}): HtmlInfo {
  return {
    scripts: [],
    inlineScriptCount: 0,
    stylesheets: [],
    otherResources: [],
    forms: [],
    metaCsp: [],
    metaReferrer: null,
    baseHref: null,
    ...overrides,
  };
}

/** Cible de test. */
export function makeTarget(overrides: Partial<ScanTarget> = {}): ScanTarget {
  return {
    input: "example.com",
    url: "https://example.com/",
    hostname: "example.com",
    isIpAddress: false,
    ...overrides,
  };
}

export interface ContextOptions extends Partial<ScanContext> {
  /** En-têtes de la réponse HTTPS finale (raccourci le plus courant). */
  headers?: Record<string, string>;
  /** En-têtes Set-Cookie de la réponse HTTPS finale. */
  setCookies?: string[];
}

/**
 * Contexte de scan de test. Par défaut :
 * - HTTPS répond 200 avec les en-têtes fournis (`headers`) ;
 * - HTTP redirige en 301 vers https://example.com/ ;
 * - TLS valide (TLS 1.3), pas de security.txt (404), pas d'enregistrement CAA ;
 * - `response` = réponse HTTPS finale, `html` = page vide.
 * Toute propriété de `ScanContext` peut être remplacée.
 */
export function makeContext(options: ContextOptions = {}): ScanContext {
  const { headers, setCookies, ...overrides } = options;
  const httpsResponse = makeResponse({
    headers: { "content-type": "text/html; charset=utf-8", ...(headers ?? {}) },
    setCookies: setCookies ?? [],
  });
  const https = overrides.https ?? fetched(httpsResponse);
  const http =
    overrides.http ??
    fetched(httpsResponse, [makeRedirect("http://example.com/", "https://example.com/")]);
  const caa: Result<CaaInfo> = ok({ domain: null, records: [] });
  const base: ScanContext = {
    target: makeTarget(),
    https,
    http,
    tls: ok(makeTlsInfo()),
    securityTxt: fetched(
      makeResponse({
        url: "https://example.com/.well-known/security.txt",
        status: 404,
        headers: { "content-type": "text/html" },
      }),
    ),
    cors: https,
    caa,
    response: https.ok ? https.value.response : http.ok ? http.value.response : null,
    html: makeHtmlInfo(),
  };
  return { ...base, ...overrides };
}
