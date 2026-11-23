// Toutes les dépendances du scan sont injectées, et les modules des autres couches remplacés avec
// `vi.mock` : ces tests ne vérifient que l'orchestration.

import {
  failure,
  fetched,
  makeHtmlInfo,
  makeRedirect,
  makeResponse,
  makeTlsInfo,
  ok,
} from "@test/helpers/context";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  CORS_PROBE_ORIGIN,
  MAX_BODY_BYTES,
  MAX_SECURITY_TXT_BYTES,
  SCANNER_NAME,
  SCANNER_VERSION,
} from "@/lib/config";
import type { HostResolver, ScanDependencies } from "@/lib/scanner/scan";
import { scanSite } from "@/lib/scanner/scan";
import type {
  CaaResolver,
  CheckDefinition,
  CheckId,
  CheckOutcome,
  CheckStatus,
  Fetcher,
  FetchSuccess,
  Result,
  ScanContext,
  TlsProber,
} from "@/lib/scanner/types";

const doubles = vi.hoisted(() => ({
  extractHtmlInfo: vi.fn(),
  // Testée par ailleurs : ici, toute adresse est publique.
  checkAddress: vi.fn((address: string) => ({
    allowed: true,
    address,
    family: address.includes(":") ? 6 : 4,
  })),
}));

vi.mock("@/lib/scanner/checks", () => ({ CHECKS: [] }));
vi.mock("@/lib/scanner/checks/html", () => ({ extractHtmlInfo: doubles.extractHtmlInfo }));
vi.mock("@/lib/scanner/network", () => ({
  safeFetch: vi.fn(),
  probeTls: vi.fn(),
  resolveCaa: vi.fn(),
  resolveHost: vi.fn(),
}));
vi.mock("@/lib/scanner/network/ip", () => ({ checkAddress: doubles.checkAddress }));

const START = Date.UTC(2026, 10, 16, 10, 0, 0);

const PAGE_HTML = "<!doctype html><html><head><title>Exemple</title></head><body></body></html>";

interface HttpProbeResults {
  https: Result<FetchSuccess>;
  http: Result<FetchSuccess>;
  securityTxt: Result<FetchSuccess>;
  cors: Result<FetchSuccess>;
}

function exemplarySite(): HttpProbeResults {
  const page = makeResponse({ body: PAGE_HTML });
  return {
    https: fetched(page),
    http: fetched(page, [makeRedirect("http://example.com/", "https://example.com/")]),
    securityTxt: fetched(
      makeResponse({ url: "https://example.com/.well-known/security.txt", status: 404 }),
    ),
    cors: fetched(makeResponse()),
  };
}

// Reconnaît la sonde d'après l'URL et les en-têtes demandés.
function fakeFetch(overrides: Partial<HttpProbeResults> = {}) {
  const results = { ...exemplarySite(), ...overrides };
  return vi.fn<Fetcher>(async (url, options) => {
    if (url.endsWith("/.well-known/security.txt")) return results.securityTxt;
    if (url.startsWith("http:")) return results.http;
    if (options?.headers?.Origin !== undefined) return results.cors;
    return results.https;
  });
}

function steppingClock(start: number, stepMs: number): () => number {
  let current = start - stepMs;
  return () => {
    current += stepMs;
    return current;
  };
}

function fakeDependencies(overrides: Partial<ScanDependencies> = {}): ScanDependencies {
  return {
    fetch: fakeFetch(),
    probeTls: vi.fn<TlsProber>(async () => ok(makeTlsInfo())),
    resolveCaa: vi.fn<CaaResolver>(async () =>
      ok({
        domain: "example.com",
        records: [{ critical: 0, tag: "issue", value: "letsencrypt.org" }],
      }),
    ),
    resolveHost: vi.fn<HostResolver>(async () => ok([{ address: "93.184.215.14", family: 4 }])),
    checks: [],
    now: steppingClock(START, 250),
    ...overrides,
  };
}

function fakeCheck(id: CheckId, evaluate: (context: ScanContext) => CheckOutcome): CheckDefinition {
  return {
    id,
    category: "headers",
    title: `Contrôle ${id}`,
    description: `Description du contrôle ${id}.`,
    references: [],
    scoring: [],
    evaluate,
  };
}

function verdict(status: CheckStatus, scoreModifier: number): CheckOutcome {
  return { status, scoreModifier, summary: `Verdict ${status} (${scoreModifier}).` };
}

// Mémorise le contexte reçu, pour vérifier ce que voient les contrôles.
function capturingCheck(): { check: CheckDefinition; context: () => ScanContext } {
  const evaluate = vi.fn((_context: ScanContext) => verdict("info", 0));
  return {
    check: fakeCheck("caa", evaluate),
    context: () => {
      const context = evaluate.mock.calls[0]?.[0];
      if (context === undefined) throw new Error("Le contrôle n'a pas été évalué.");
      return context;
    },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  doubles.extractHtmlInfo.mockReturnValue(makeHtmlInfo());
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("scanSite — rapport", () => {
  it("produit un rapport complet, contrôles dans l'ordre et champs facultatifs remplis", async () => {
    const example = { label: "Nginx", language: "nginx", code: "add_header X-Exemple 1;" };
    const deps = fakeDependencies({
      checks: [
        fakeCheck("hsts", () => ({
          ...verdict("pass", 5),
          details: ["Préchargement possible."],
          evidence: "max-age=63072000; includeSubDomains; preload",
          examples: [example],
        })),
        fakeCheck("csp", () => verdict("warning", -5)),
      ],
    });

    const report = await scanSite("  Example.com  ", deps);

    expect(report).toEqual({
      schemaVersion: 1,
      scanner: { name: SCANNER_NAME, version: SCANNER_VERSION },
      target: {
        input: "Example.com",
        url: "https://example.com/",
        hostname: "example.com",
        finalUrl: "https://example.com/",
        ip: "93.184.215.14",
      },
      scannedAt: "2026-11-16T10:00:00.000Z",
      durationMs: 250,
      score: {
        base: 100,
        penalties: -5,
        bonuses: 5,
        bonusesApplied: true,
        score: 100,
        grade: "A+",
      },
      summary: { pass: 1, warning: 1, fail: 0, info: 0, error: 0 },
      checks: [
        {
          id: "hsts",
          category: "headers",
          title: "Contrôle hsts",
          description: "Description du contrôle hsts.",
          references: [],
          status: "pass",
          scoreModifier: 5,
          summary: "Verdict pass (5).",
          details: ["Préchargement possible."],
          evidence: "max-age=63072000; includeSubDomains; preload",
          recommendation: null,
          examples: [example],
        },
        {
          id: "csp",
          category: "headers",
          title: "Contrôle csp",
          description: "Description du contrôle csp.",
          references: [],
          status: "warning",
          scoreModifier: -5,
          summary: "Verdict warning (-5).",
          details: [],
          evidence: null,
          recommendation: null,
          examples: [],
        },
      ],
      redirects: {
        fromHttp: [
          { url: "http://example.com/", status: 301, location: "https://example.com/" },
          { url: "https://example.com/", status: 200, location: null },
        ],
        fromHttps: [{ url: "https://example.com/", status: 200, location: null }],
      },
      response: { status: 200, headers: [["content-type", "text/html; charset=utf-8"]] },
      tls: makeTlsInfo(),
      probeErrors: [],
    });
  });

  it("note le site même quand la réponse finale est une erreur HTTP (404)", async () => {
    const deps = fakeDependencies({
      fetch: fakeFetch({ https: fetched(makeResponse({ status: 404 })) }),
      checks: [fakeCheck("hsts", () => verdict("fail", -20))],
    });
    const report = await scanSite("example.com", deps);
    expect(report.response?.status).toBe(404);
    expect(report.score).toMatchObject({ score: 80, grade: "B" });
  });
});

describe("scanSite — sondes", () => {
  it("lance les six sondes avec les options prévues et un délai global commun", async () => {
    const deps = fakeDependencies();
    await scanSite("example.com", deps);

    const signal = expect.any(AbortSignal);
    expect(deps.resolveHost).toHaveBeenCalledWith("example.com");
    expect(deps.fetch).toHaveBeenCalledTimes(4);
    expect(deps.fetch).toHaveBeenCalledWith("https://example.com/", {
      signal,
      maxBodyBytes: MAX_BODY_BYTES,
    });
    expect(deps.fetch).toHaveBeenCalledWith("http://example.com/", { signal, maxBodyBytes: 0 });
    expect(deps.fetch).toHaveBeenCalledWith("https://example.com/.well-known/security.txt", {
      signal,
      maxRedirects: 3,
      maxBodyBytes: MAX_SECURITY_TXT_BYTES,
    });
    expect(deps.fetch).toHaveBeenCalledWith("https://example.com/", {
      signal,
      headers: { Origin: CORS_PROBE_ORIGIN },
      maxBodyBytes: 0,
    });
    expect(deps.probeTls).toHaveBeenCalledWith("example.com", { port: 443, signal });
    expect(deps.resolveCaa).toHaveBeenCalledWith("example.com", { signal });

    // Un seul signal d'annulation (délai global du scan), pas encore déclenché.
    const signals = new Set([
      ...vi.mocked(deps.fetch).mock.calls.map(([, options]) => options?.signal),
      vi.mocked(deps.probeTls).mock.calls[0]?.[1]?.signal,
      vi.mocked(deps.resolveCaa).mock.calls[0]?.[1]?.signal,
    ]);
    expect(signals.size).toBe(1);
    expect([...signals][0]?.aborted).toBe(false);
  });

  it("garde le chemin et la requête de l'adresse, mais cherche security.txt à la racine", async () => {
    const deps = fakeDependencies();
    await scanSite("https://example.com/blog/?page=2#commentaires", deps);
    const urls = vi.mocked(deps.fetch).mock.calls.map(([url]) => url);
    expect(urls).toEqual([
      "https://example.com/blog/?page=2",
      "http://example.com/blog/?page=2",
      "https://example.com/.well-known/security.txt",
      "https://example.com/blog/?page=2",
    ]);
  });

  it("ne cherche pas d'enregistrement CAA pour une adresse IP", async () => {
    const spy = capturingCheck();
    const deps = fakeDependencies({ checks: [spy.check] });
    const report = await scanSite("1.1.1.1", deps);

    expect(deps.resolveCaa).not.toHaveBeenCalled();
    expect(deps.resolveHost).toHaveBeenCalledWith("1.1.1.1");
    expect(deps.probeTls).toHaveBeenCalledWith("1.1.1.1", expect.anything());
    expect(spy.context().target.isIpAddress).toBe(true);
    expect(spy.context().caa).toEqual(ok({ domain: null, records: [] }));
    expect(report.probeErrors).toEqual([]);
  });
});

describe("scanSite — erreurs bloquantes", () => {
  it("refuse une saisie invalide sans rien contacter", async () => {
    const deps = fakeDependencies();
    await expect(scanSite("javascript:alert(1)", deps)).rejects.toMatchObject({
      name: "ScanError",
      code: "UNSUPPORTED_PROTOCOL",
    });
    expect(deps.resolveHost).not.toHaveBeenCalled();
    expect(deps.fetch).not.toHaveBeenCalled();
  });

  it("lève DNS_FAILURE quand le nom ne se résout pas, avant toute connexion", async () => {
    const deps = fakeDependencies({
      resolveHost: vi.fn<HostResolver>(async () =>
        failure("DNS_FAILURE", "Nom de domaine introuvable."),
      ),
    });
    await expect(scanSite("inexistant.example.com", deps)).rejects.toMatchObject({
      code: "DNS_FAILURE",
    });
    expect(deps.fetch).not.toHaveBeenCalled();
    expect(deps.probeTls).not.toHaveBeenCalled();
  });

  it("lève TARGET_NOT_ALLOWED quand le nom pointe vers une adresse privée", async () => {
    const deps = fakeDependencies({
      resolveHost: vi.fn<HostResolver>(async () => failure("BLOCKED_ADDRESS", "Réseau privé.")),
    });
    await expect(scanSite("intranet.example.com", deps)).rejects.toMatchObject({
      code: "TARGET_NOT_ALLOWED",
    });
    expect(deps.fetch).not.toHaveBeenCalled();
  });

  it("lève TARGET_UNREACHABLE quand ni HTTPS ni HTTP ne répondent, en citant les deux causes", async () => {
    const deps = fakeDependencies({
      fetch: fakeFetch({
        https: failure("CONNECTION_REFUSED", "Connexion refusée (HTTPS)."),
        http: failure("CONNECTION_RESET", "Connexion interrompue (HTTP)."),
      }),
    });
    const scan = scanSite("example.com", deps);
    await expect(scan).rejects.toMatchObject({ code: "TARGET_UNREACHABLE" });
    await expect(scan).rejects.toThrow(
      /Connexion refusée \(HTTPS\)\..*Connexion interrompue \(HTTP\)\./,
    );
  });

  it("lève TIMEOUT quand HTTPS et HTTP dépassent tous deux le délai", async () => {
    const deps = fakeDependencies({
      fetch: fakeFetch({
        https: failure("TIMEOUT", "Délai dépassé."),
        http: failure("TIMEOUT", "Délai dépassé."),
      }),
    });
    const scan = scanSite("example.com", deps);
    await expect(scan).rejects.toMatchObject({ code: "TIMEOUT" });
    await expect(scan).rejects.toThrow("20 secondes");
  });

  it("parle de site injoignable quand une seule des deux sondes a dépassé le délai", async () => {
    const deps = fakeDependencies({
      fetch: fakeFetch({
        https: failure("TIMEOUT", "Délai dépassé."),
        http: failure("CONNECTION_REFUSED", "Connexion refusée."),
      }),
    });
    await expect(scanSite("example.com", deps)).rejects.toMatchObject({
      code: "TARGET_UNREACHABLE",
    });
  });

  it("lève TARGET_NOT_ALLOWED quand la protection anti-SSRF bloque la connexion (DNS rebinding)", async () => {
    const deps = fakeDependencies({
      fetch: fakeFetch({
        https: failure("BLOCKED_ADDRESS", "Adresse de bouclage."),
        http: failure("BLOCKED_ADDRESS", "Adresse de bouclage."),
      }),
    });
    await expect(scanSite("example.com", deps)).rejects.toMatchObject({
      code: "TARGET_NOT_ALLOWED",
    });
  });
});

describe("scanSite — sondes en échec et pannes isolées", () => {
  it("analyse la réponse HTTP quand HTTPS est indisponible", async () => {
    const plainPage = makeResponse({ url: "http://example.com/" });
    const refused = failure<FetchSuccess>(
      "CONNECTION_REFUSED",
      "Connexion refusée par le serveur.",
    );
    const spy = capturingCheck();
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        fetch: fakeFetch({ https: refused, http: fetched(plainPage), cors: refused }),
        checks: [spy.check],
      }),
    );

    expect(spy.context().response).toBe(plainPage);
    expect(report.target.finalUrl).toBe("http://example.com/");
    expect(report.redirects.fromHttps).toEqual([]);
    expect(report.probeErrors).toEqual([
      { probe: "https", code: "CONNECTION_REFUSED", message: "Connexion refusée par le serveur." },
      { probe: "cors", code: "CONNECTION_REFUSED", message: "Connexion refusée par le serveur." },
    ]);
  });

  it("liste chaque sonde en échec dans probeErrors sans bloquer le rapport", async () => {
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        fetch: fakeFetch({ securityTxt: failure("TIMEOUT", "Délai dépassé.") }),
        probeTls: vi.fn<TlsProber>(async () => failure("TLS_ERROR", "Négociation TLS impossible.")),
        resolveCaa: vi.fn<CaaResolver>(async () =>
          failure("DNS_FAILURE", "Serveur DNS injoignable."),
        ),
      }),
    );
    expect(report.tls).toBeNull();
    expect(report.probeErrors).toEqual([
      { probe: "tls", code: "TLS_ERROR", message: "Négociation TLS impossible." },
      { probe: "securityTxt", code: "TIMEOUT", message: "Délai dépassé." },
      { probe: "caa", code: "DNS_FAILURE", message: "Serveur DNS injoignable." },
    ]);
  });

  it("transforme l'exception d'une sonde en échec UNKNOWN", async () => {
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        probeTls: vi.fn<TlsProber>(async () => {
          throw new Error("bogue de la sonde");
        }),
      }),
    );
    expect(report.probeErrors).toEqual([
      { probe: "tls", code: "UNKNOWN", message: expect.any(String) },
    ]);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('"event":"probe-error"'));
  });

  it("isole un contrôle qui lève une exception : statut error, sans effet sur la note", async () => {
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        checks: [
          fakeCheck("csp", () => {
            throw new TypeError("Cannot read properties of undefined");
          }),
          fakeCheck("hsts", () => verdict("warning", -10)),
        ],
      }),
    );
    expect(
      report.checks.map(({ id, status, scoreModifier }) => [id, status, scoreModifier]),
    ).toEqual([
      ["csp", "error", 0],
      ["hsts", "warning", -10],
    ]);
    expect(report.checks[0]?.summary).toContain("erreur interne");
    expect(report.summary).toMatchObject({ error: 1, warning: 1 });
    expect(report.score).toMatchObject({ score: 90, grade: "A" });
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('"check":"csp"'));
  });

  it("résout les redirections relatives et garde la chaîne d'une sonde en échec", async () => {
    const loop = [
      makeRedirect("http://example.com/", "/fr/", 302),
      makeRedirect("http://example.com/fr/", "http://example.com/", 302),
    ];
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        fetch: fakeFetch({
          http: failure("TOO_MANY_REDIRECTS", "Trop de redirections.", { chain: loop }),
        }),
      }),
    );
    expect(report.redirects.fromHttp).toEqual([
      { url: "http://example.com/", status: 302, location: "http://example.com/fr/" },
      { url: "http://example.com/fr/", status: 302, location: "http://example.com/" },
    ]);
  });

  it("garde tel quel un en-tête Location illisible", async () => {
    const broken = makeRedirect("https://example.com/", "http://[::1", 301);
    const report = await scanSite(
      "example.com",
      fakeDependencies({
        fetch: fakeFetch({
          https: failure("INVALID_REDIRECT", "Redirection invalide.", { chain: [broken] }),
        }),
      }),
    );
    expect(report.redirects.fromHttps).toEqual([
      { url: "https://example.com/", status: 301, location: "http://[::1" },
    ]);
  });
});

describe("scanSite — extraction HTML", () => {
  it("extrait le HTML de la réponse analysée et le transmet aux contrôles", async () => {
    const html = makeHtmlInfo({ inlineScriptCount: 2 });
    doubles.extractHtmlInfo.mockReturnValue(html);
    const spy = capturingCheck();
    await scanSite("example.com", fakeDependencies({ checks: [spy.check] }));

    expect(doubles.extractHtmlInfo).toHaveBeenCalledWith(PAGE_HTML, "https://example.com/");
    expect(spy.context().html).toBe(html);
  });

  it.each([
    [
      "une réponse JSON",
      makeResponse({ headers: { "content-type": "application/json" }, body: "{}" }),
    ],
    ["une réponse dont le corps n'a pas été lu", makeResponse({ body: null })],
  ])("ne cherche pas de HTML dans %s", async (_label, response) => {
    const spy = capturingCheck();
    await scanSite(
      "example.com",
      fakeDependencies({ fetch: fakeFetch({ https: fetched(response) }), checks: [spy.check] }),
    );
    expect(doubles.extractHtmlInfo).not.toHaveBeenCalled();
    expect(spy.context().html).toBeNull();
  });

  it("poursuit le scan quand l'extraction HTML échoue", async () => {
    doubles.extractHtmlInfo.mockImplementation(() => {
      throw new RangeError("HTML trop imbriqué");
    });
    const spy = capturingCheck();
    const report = await scanSite("example.com", fakeDependencies({ checks: [spy.check] }));

    expect(spy.context().html).toBeNull();
    expect(report.checks).toHaveLength(1);
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining('"event":"html-error"'));
  });
});

describe("scanSite — nouvelle tentative après une connexion coupée", () => {
  const reset = () => failure<FetchSuccess>("CONNECTION_RESET", "La connexion a été interrompue.");

  it("réessaie une fois une sonde coupée par le serveur, et garde le second résultat", async () => {
    const page = makeResponse({ body: PAGE_HTML });
    const fetch = fakeFetch();
    const https = vi.fn<Fetcher>().mockResolvedValueOnce(reset()).mockResolvedValue(fetched(page));
    const deps = fakeDependencies({
      fetch: async (url, options) =>
        url === "https://example.com/" && options?.headers?.Origin === undefined
          ? https(url, options)
          : fetch(url, options),
    });
    const report = await scanSite("example.com", deps);
    expect(https).toHaveBeenCalledTimes(2);
    expect(report.probeErrors).toEqual([]);
  });

  it("n'essaie que deux fois quand la coupure persiste", async () => {
    const probeTls = vi.fn<TlsProber>(async () => failure("CONNECTION_RESET", "Coupé."));
    const report = await scanSite("example.com", fakeDependencies({ probeTls }));
    expect(probeTls).toHaveBeenCalledTimes(2);
    expect(report.probeErrors).toEqual([
      { probe: "tls", code: "CONNECTION_RESET", message: "Coupé." },
    ]);
  });

  it.each([
    "TIMEOUT",
    "CONNECTION_REFUSED",
    "TLS_ERROR",
  ] as const)("ne réessaie pas un échec stable (%s)", async (code) => {
    const probeTls = vi.fn<TlsProber>(async () => failure(code, "Échec."));
    await scanSite("example.com", fakeDependencies({ probeTls }));
    expect(probeTls).toHaveBeenCalledTimes(1);
  });
});
