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

export function ok<T>(value: T): Result<T> {
  return { ok: true, value };
}

export function failure<T = never>(
  code: NetworkErrorCode = "CONNECTION_REFUSED",
  message = "Connexion refusée par le serveur.",
  extra: Partial<NetworkError> = {},
): Result<T> {
  return { ok: false, error: { code, message, ...extra } };
}

/** En minuscules, comme le fait la sonde HTTP. */
function lowercaseKeys(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

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

export function makeRedirect(url: string, location: string, status = 301): HttpResponse {
  return makeResponse({ url, status, headers: { location }, body: null });
}

export function fetched(
  response: HttpResponse,
  redirects: HttpResponse[] = [],
): Result<FetchSuccess> {
  return ok({ response, chain: [...redirects, response] });
}

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
  headers?: Record<string, string>;
  setCookies?: string[];
}

/**
 * Par défaut, un site exemplaire : HTTPS 200 avec `headers`, HTTP redirigé en 301 vers HTTPS, TLS
 * 1.3 valide, ni security.txt ni enregistrement CAA. Toute propriété de `ScanContext` peut être
 * remplacée.
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
