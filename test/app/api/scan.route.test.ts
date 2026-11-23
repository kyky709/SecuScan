/**
 * Tests de la route POST /api/scan, avec de vraies requêtes `Request` (API Web standard).
 *
 * Le moteur d'analyse est remplacé par une doublure de `scanSite` : on vérifie ici la « coquille »
 * HTTP (origine, taille et forme du corps, limites de débit, conversion des erreurs en réponses
 * JSON, journal), pas l'analyse elle-même (voir test/lib/scanner/scan.test.ts). La normalisation
 * de l'adresse et les limiteurs en mémoire sont les vrais.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { maxDuration, POST } from "@/app/api/scan/route";
import { RATE_LIMIT_PER_CLIENT, RATE_LIMIT_PER_TARGET } from "@/lib/config";
import type { RateLimiters } from "@/lib/rate-limit";
import { createMemoryRateLimiter, getRateLimiters, hashKey } from "@/lib/rate-limit";
import { scanSite } from "@/lib/scanner";
import type { ApiErrorBody, ScanErrorCode } from "@/lib/scanner/errors";
import { ScanError } from "@/lib/scanner/errors";
import type { ScanReport } from "@/lib/scanner/types";

// Politique d'adresses IP (network/ip.ts, testée par ailleurs) : toute adresse est publique ici.
vi.mock("@/lib/scanner/network/ip", () => ({
  checkAddress: (address: string) => ({
    allowed: true,
    address,
    family: address.includes(":") ? 6 : 4,
  }),
}));

// Moteur : vraies erreurs et vraie normalisation, mais scan simulé (aucun accès réseau).
vi.mock("@/lib/scanner", async () => {
  const errors = await import("@/lib/scanner/errors");
  const { normalizeTarget } = await import("@/lib/scanner/target");
  return { ...errors, normalizeTarget, scanSite: vi.fn() };
});

// Limiteurs : vraies fonctions, mais `getRateLimiters` renvoie des limiteurs neufs à chaque test.
vi.mock("@/lib/rate-limit", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/lib/rate-limit")>()),
  getRateLimiters: vi.fn(),
}));

/** Origine du site SecuScan dans les tests (serveur de développement). */
const APP_ORIGIN = "http://localhost:3000";

/** Adresse IP du visiteur (plage réservée à la documentation, RFC 5737). */
const CLIENT_IP = "203.0.113.7";

/** Rapport renvoyé par la doublure de `scanSite`. */
function sampleReport(): ScanReport {
  return {
    schemaVersion: 1,
    scanner: { name: "SecuScan", version: "1.0.0" },
    target: {
      input: "example.com",
      url: "https://example.com/",
      hostname: "example.com",
      finalUrl: "https://example.com/",
      ip: "93.184.215.14",
    },
    scannedAt: "2026-11-16T10:00:00.000Z",
    durationMs: 1234,
    score: { base: 100, penalties: -10, bonuses: 5, bonusesApplied: true, score: 95, grade: "A" },
    summary: { pass: 1, warning: 1, fail: 0, info: 0, error: 0 },
    checks: [],
    redirects: { fromHttp: [], fromHttps: [] },
    response: { status: 200, headers: [["content-type", "text/html"]] },
    tls: null,
    probeErrors: [],
  };
}

interface ScanRequestOptions {
  /** Corps brut (par défaut {"url":"example.com"}). */
  body?: string;
  /** En-tête Origin ; null pour l'omettre (client en ligne de commande). */
  origin?: string | null;
  /** Adresse IP du client (en-tête x-real-ip, écrit par Vercel). */
  ip?: string;
  /** En-têtes supplémentaires. */
  headers?: Record<string, string>;
}

/** Requête POST /api/scan, envoyée par défaut depuis la page de SecuScan. */
function scanRequest(options: ScanRequestOptions = {}): Request {
  const { body = urlBody("example.com"), origin = APP_ORIGIN, ip = CLIENT_IP } = options;
  const headers = new Headers({
    "content-type": "application/json",
    "x-real-ip": ip,
    ...options.headers,
  });
  if (origin !== null) headers.set("origin", origin);
  return new Request(`${APP_ORIGIN}/api/scan`, { method: "POST", headers, body });
}

/** Corps JSON `{"url": …}`. */
function urlBody(url: unknown): string {
  return JSON.stringify({ url });
}

/** Installe des limiteurs en mémoire neufs (limites de config.ts par défaut). */
function useLimiters(
  client: { limit: number; windowMs: number } = RATE_LIMIT_PER_CLIENT,
  target: { limit: number; windowMs: number } = RATE_LIMIT_PER_TARGET,
): RateLimiters {
  const limiters = {
    client: createMemoryRateLimiter(client),
    target: createMemoryRateLimiter(target),
  };
  vi.mocked(getRateLimiters).mockReturnValue(limiters);
  return limiters;
}

/** Vérifie le statut et le code d'une réponse d'erreur, puis renvoie son corps. */
async function expectApiError(
  response: Response,
  status: number,
  code: ScanErrorCode,
): Promise<ApiErrorBody> {
  expect(response.status).toBe(status);
  const body = (await response.json()) as ApiErrorBody;
  expect(body.error.code).toBe(code);
  expect(body.error.message.length).toBeGreaterThan(0);
  return body;
}

beforeEach(() => {
  vi.clearAllMocks();
  useLimiters();
  vi.mocked(scanSite).mockResolvedValue(sampleReport());
  vi.spyOn(console, "info").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("POST /api/scan — succès", () => {
  it("accorde 30 secondes d'exécution à la fonction", () => {
    expect(maxDuration).toBe(30);
  });

  it("lance le scan avec la saisie brute et renvoie le rapport (200) avec les en-têtes RateLimit-*", async () => {
    const response = await POST(scanRequest({ body: urlBody("  Example.com  ") }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(sampleReport());
    expect(scanSite).toHaveBeenCalledWith("  Example.com  ");
    expect(response.headers.get("ratelimit-limit")).toBe(String(RATE_LIMIT_PER_CLIENT.limit));
    expect(response.headers.get("ratelimit-remaining")).toBe(
      String(RATE_LIMIT_PER_CLIENT.limit - 1),
    );
    expect(response.headers.get("ratelimit-reset")).toBe("60");
    expect(response.headers.get("retry-after")).toBeNull();
  });

  it("journalise une ligne JSON minimale, sans adresse IP", async () => {
    await POST(scanRequest());

    expect(console.info).toHaveBeenCalledTimes(1);
    const line = String(vi.mocked(console.info).mock.calls[0]?.[0]);
    expect(JSON.parse(line)).toEqual({
      event: "scan",
      host: "example.com",
      grade: "A",
      score: 95,
      durationMs: 1234,
    });
    expect(line).not.toContain(CLIENT_IP);
  });
});

describe("POST /api/scan — origine de la requête", () => {
  it("refuse une requête venant d'un autre site (403), sans consommer le quota", async () => {
    const response = await POST(scanRequest({ origin: "https://evil.example.org" }));

    await expectApiError(response, 403, "FORBIDDEN_ORIGIN");
    expect(response.headers.get("ratelimit-limit")).toBeNull();
    expect(scanSite).not.toHaveBeenCalled();
    const next = await POST(scanRequest());
    expect(next.headers.get("ratelimit-remaining")).toBe(String(RATE_LIMIT_PER_CLIENT.limit - 1));
  });

  it("refuse l'origine opaque « null » (iframe isolée, fichier local)", async () => {
    await expectApiError(await POST(scanRequest({ origin: "null" })), 403, "FORBIDDEN_ORIGIN");
  });

  it("accepte une requête sans en-tête Origin (client en ligne de commande)", async () => {
    expect((await POST(scanRequest({ origin: null }))).status).toBe(200);
  });

  it("compare l'origine à l'en-tête Host, pas à l'URL interne de Next.js", async () => {
    const response = await POST(
      scanRequest({ origin: "http://127.0.0.1:3000", headers: { host: "127.0.0.1:3000" } }),
    );
    expect(response.status).toBe(200);
  });

  it("derrière un proxy, compare l'origine à X-Forwarded-Host", async () => {
    const proxied = { host: "localhost:3000", "x-forwarded-host": "secuscan.example.com" };
    const accepted = await POST(
      scanRequest({ origin: "https://secuscan.example.com", headers: proxied }),
    );
    expect(accepted.status).toBe(200);

    const refused = await POST(scanRequest({ origin: APP_ORIGIN, headers: proxied }));
    await expectApiError(refused, 403, "FORBIDDEN_ORIGIN");
  });
});

describe("POST /api/scan — corps de la requête", () => {
  it("refuse un corps de plus de 4 Kio, même sans Content-Length (413)", async () => {
    const response = await POST(scanRequest({ body: urlBody(`example.com/${"a".repeat(5_000)}`) }));
    await expectApiError(response, 413, "PAYLOAD_TOO_LARGE");
    expect(scanSite).not.toHaveBeenCalled();
  });

  it("refuse d'emblée un Content-Length annoncé trop grand (413)", async () => {
    const response = await POST(scanRequest({ headers: { "content-length": "100000" } }));
    await expectApiError(response, 413, "PAYLOAD_TOO_LARGE");
  });

  it("accepte un corps de 4 Kio exactement", async () => {
    const body = urlBody("example.com").padEnd(4 * 1024, " ");
    expect(new TextEncoder().encode(body).byteLength).toBe(4 * 1024);
    expect((await POST(scanRequest({ body }))).status).toBe(200);
  });

  it.each([
    ["un corps vide", ""],
    ["du texte", "example.com"],
    ["du JSON tronqué", '{"url": "example.com"'],
    ["du pseudo-JSON", "{url: example.com}"],
  ])("refuse %s (400 INVALID_REQUEST)", async (_label, body) => {
    await expectApiError(await POST(scanRequest({ body })), 400, "INVALID_REQUEST");
    expect(scanSite).not.toHaveBeenCalled();
  });

  it.each([
    ["un objet vide", "{}"],
    ["une URL numérique", '{"url": 42}'],
    ["un champ mal nommé", '{"adresse": "example.com"}'],
    ["un tableau", '["example.com"]'],
    ["une chaîne seule", '"example.com"'],
    ["null", "null"],
  ])("refuse %s : pas de champ « url » textuel (400 INVALID_URL)", async (_label, body) => {
    await expectApiError(await POST(scanRequest({ body })), 400, "INVALID_URL");
    expect(scanSite).not.toHaveBeenCalled();
  });
});

describe("POST /api/scan — limites de débit", () => {
  it("refuse au-delà de la limite par client (429 + Retry-After)", async () => {
    useLimiters({ limit: 1, windowMs: 60_000 });
    expect((await POST(scanRequest())).status).toBe(200);

    const response = await POST(scanRequest());
    const body = await expectApiError(response, 429, "RATE_LIMITED");

    expect(response.headers.get("retry-after")).toBe("60");
    expect(response.headers.get("ratelimit-remaining")).toBe("0");
    expect(body.error.retryAfterSeconds).toBe(60);
    expect(body.error.message).toBe(
      "Vous avez lancé trop d'analyses en peu de temps : réessayez dans 60 secondes.",
    );
    expect(scanSite).toHaveBeenCalledTimes(1);
  });

  it("identifie le client par le condensat de son adresse IP, jamais par l'adresse en clair", async () => {
    const limiters = useLimiters({ limit: 1, windowMs: 60_000 });
    const limit = vi.spyOn(limiters.client, "limit");

    expect((await POST(scanRequest({ ip: CLIENT_IP }))).status).toBe(200);
    expect((await POST(scanRequest({ ip: "198.51.100.9" }))).status).toBe(200);
    expect(limit).toHaveBeenNthCalledWith(1, hashKey(CLIENT_IP));
    expect(limit).toHaveBeenNthCalledWith(2, hashKey("198.51.100.9"));
  });

  it("refuse au-delà de la limite par site, quel que soit le client (429)", async () => {
    useLimiters(RATE_LIMIT_PER_CLIENT, { limit: 1, windowMs: 60_000 });
    const first = await POST(scanRequest({ ip: CLIENT_IP, body: urlBody("example.com") }));
    expect(first.status).toBe(200);

    // Même hôte une fois normalisé, depuis un autre client.
    const second = await POST(
      scanRequest({ ip: "198.51.100.9", body: urlBody("https://EXAMPLE.com/autre-page") }),
    );
    const body = await expectApiError(second, 429, "RATE_LIMITED");
    expect(second.headers.get("retry-after")).toBe("60");
    expect(body.error.message).toContain("Ce site a déjà été analysé plusieurs fois");

    // Un autre site reste analysable.
    const other = await POST(scanRequest({ ip: "198.51.100.9", body: urlBody("example.org") }));
    expect(other.status).toBe(200);
  });

  it("vérifie le quota du client avant l'adresse : une saisie refusée le consomme aussi", async () => {
    useLimiters({ limit: 1, windowMs: 60_000 });
    const invalid = await POST(scanRequest({ body: urlBody("javascript:alert(1)") }));
    await expectApiError(invalid, 400, "UNSUPPORTED_PROTOCOL");
    expect(invalid.headers.get("ratelimit-remaining")).toBe("0");

    await expectApiError(await POST(scanRequest()), 429, "RATE_LIMITED");
  });
});

describe("POST /api/scan — erreurs du moteur", () => {
  it.each<[input: string, status: number, code: ScanErrorCode]>([
    ["", 400, "INVALID_URL"],
    ["javascript:alert(1)", 400, "UNSUPPORTED_PROTOCOL"],
    ["https://example.com:8443/", 400, "FORBIDDEN_PORT"],
    ["https://user:pass@example.com/", 400, "CREDENTIALS_IN_URL"],
    ["localhost", 422, "TARGET_NOT_ALLOWED"],
  ])("adresse « %s » refusée avant le scan → %i %s", async (input, status, code) => {
    const response = await POST(scanRequest({ body: urlBody(input) }));
    await expectApiError(response, status, code);
    expect(scanSite).not.toHaveBeenCalled();
    expect(response.headers.get("ratelimit-limit")).toBe(String(RATE_LIMIT_PER_CLIENT.limit));
  });

  it.each<[code: ScanErrorCode, status: number]>([
    ["DNS_FAILURE", 422],
    ["TARGET_NOT_ALLOWED", 422],
    ["TARGET_UNREACHABLE", 502],
    ["TIMEOUT", 504],
  ])("ScanError %s levée par le scan → %i, message transmis tel quel", async (code, status) => {
    vi.mocked(scanSite).mockRejectedValue(new ScanError(code, "Message en français."));
    const body = await expectApiError(await POST(scanRequest()), status, code);
    expect(body.error.message).toBe("Message en français.");
    expect(console.info).not.toHaveBeenCalled();
  });

  it("masque le détail d'une erreur inattendue (500) et le garde dans le journal", async () => {
    vi.mocked(scanSite).mockRejectedValue(new Error("détail interne : pile d'appels"));
    const body = await expectApiError(await POST(scanRequest()), 500, "INTERNAL_ERROR");

    expect(body.error.message).not.toContain("détail interne");
    expect(console.error).toHaveBeenCalledWith(expect.stringContaining("détail interne"));
  });
});
