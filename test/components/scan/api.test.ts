/**
 * Tests du client de l'API d'analyse (src/components/scan/api.ts) : `fetch` est remplacé par une
 * fonction de test, aucune requête ne part sur le réseau.
 */
import { sampleReport } from "@test/fixtures/sample-report";
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest";
import { NETWORK_ERROR_MESSAGE, requestScan, SCAN_ENDPOINT } from "@/components/scan/api";

/** Réponse JSON de test. */
function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "Content-Type": "application/json", ...init.headers },
  });
}

/** Corps d'erreur au format de l'API. */
function apiError(code: string, message: string, extra: Record<string, unknown> = {}) {
  return { error: { code, message, ...extra } };
}

let fetchMock: Mock<typeof fetch>;

beforeEach(() => {
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("requestScan", () => {
  it("envoie l'adresse en JSON à l'API et renvoie le rapport", async () => {
    fetchMock.mockResolvedValue(jsonResponse(sampleReport));
    const controller = new AbortController();

    const result = await requestScan("example.com", controller.signal);

    expect(result).toEqual({ ok: true, report: sampleReport });
    expect(fetchMock).toHaveBeenCalledWith(SCAN_ENDPOINT, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: "example.com" }),
      signal: controller.signal,
    });
  });

  it("transmet le message d'erreur de l'API", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(apiError("INVALID_URL", "L'adresse saisie est invalide."), { status: 400 }),
    );

    expect(await requestScan("pas une adresse")).toEqual({
      ok: false,
      code: "INVALID_URL",
      message: "L'adresse saisie est invalide.",
    });
  });

  it("précise quand réessayer après une limitation de débit (corps de la réponse)", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        apiError("RATE_LIMITED", "Trop d'analyses en peu de temps.", { retryAfterSeconds: 42 }),
        { status: 429, headers: { "Retry-After": "10" } },
      ),
    );

    const result = await requestScan("example.com");
    expect(result).toEqual({
      ok: false,
      code: "RATE_LIMITED",
      message: "Trop d'analyses en peu de temps. Vous pourrez réessayer dans 42 secondes.",
    });
  });

  it("lit l'en-tête Retry-After à défaut d'indication dans le corps", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(apiError("RATE_LIMITED", "Trop d'analyses en peu de temps."), {
        status: 429,
        headers: { "Retry-After": "180" },
      }),
    );

    const result = await requestScan("example.com");
    expect(result.ok ? null : result.message).toBe(
      "Trop d'analyses en peu de temps. Vous pourrez réessayer dans 3 minutes.",
    );
  });

  it("garde le message seul quand le délai est inconnu ou illisible", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(apiError("RATE_LIMITED", "Trop d'analyses en peu de temps."), {
        status: 429,
        headers: { "Retry-After": "bientôt" },
      }),
    );

    const result = await requestScan("example.com");
    expect(result.ok ? null : result.message).toBe("Trop d'analyses en peu de temps.");
  });

  it("signale une réponse qui n'est pas du JSON (page d'erreur d'un intermédiaire)", async () => {
    fetchMock.mockResolvedValue(new Response("<h1>Bad Gateway</h1>", { status: 502 }));

    const result = await requestScan("example.com");
    expect(result.ok).toBe(false);
    expect(result.ok ? null : result.code).toBe("UNEXPECTED_RESPONSE");
    expect(result.ok ? null : result.message).toContain("code HTTP 502");
  });

  it("refuse un JSON qui n'a pas la forme d'un rapport", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ bonjour: "le monde" }));

    const result = await requestScan("example.com");
    expect(result.ok ? null : result.code).toBe("UNEXPECTED_RESPONSE");
  });

  it("refuse un rapport renvoyé avec un statut d'erreur", async () => {
    fetchMock.mockResolvedValue(jsonResponse(sampleReport, { status: 500 }));

    const result = await requestScan("example.com");
    expect(result.ok ? null : result.code).toBe("UNEXPECTED_RESPONSE");
  });

  it("signale une panne réseau sans lever d'exception", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));

    expect(await requestScan("example.com")).toEqual({
      ok: false,
      code: "NETWORK_ERROR",
      message: NETWORK_ERROR_MESSAGE,
    });
  });

  it("traite une requête annulée comme un échec réseau (l'appelant l'ignore)", async () => {
    fetchMock.mockRejectedValue(new DOMException("Requête annulée", "AbortError"));
    const controller = new AbortController();
    controller.abort();

    const result = await requestScan("example.com", controller.signal);
    expect(result.ok ? null : result.code).toBe("NETWORK_ERROR");
  });
});
