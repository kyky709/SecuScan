// Les contrôles vont du moins coûteux au plus coûteux (origine, corps, quota du client, cible,
// quota par site) : une requête abusive est refusée avant d'avoir consommé des ressources.
import { z } from "zod";
import type { RateLimitResult } from "@/lib/rate-limit";
import { getClientIp, getRateLimiters, hashKey } from "@/lib/rate-limit";
import type { ApiErrorBody, ScanReport } from "@/lib/scanner";
import { isScanError, normalizeTarget, ScanError, scanSite } from "@/lib/scanner";

// Le scan est borné à 20 s (`SCAN_TIMEOUT_MS`) ; la marge couvre la validation, les limites de
// débit et la réponse.
export const maxDuration = 30;

const MAX_REQUEST_BYTES = 4 * 1024;

const scanRequestSchema = z.object({ url: z.string() });

type ScanRequest = z.infer<typeof scanRequestSchema>;

export async function POST(request: Request): Promise<Response> {
  // Déclarés hors du try : une fois le quota du client connu, les en-têtes RateLimit-*
  // accompagnent toutes les réponses, succès comme erreur.
  const headers = new Headers();
  try {
    assertSameOrigin(request);
    const { url } = parseScanRequest(await readJsonBody(request));
    const limiters = getRateLimiters();

    // La clé est un condensat de l'adresse IP : les compteurs ne contiennent jamais d'IP en clair.
    const clientQuota = await limiters.client.limit(hashKey(getClientIp(request.headers)));
    setRateLimitHeaders(headers, clientQuota);
    if (!clientQuota.success) {
      return rateLimitedResponse(
        headers,
        clientQuota,
        "Vous avez lancé trop d'analyses en peu de temps",
      );
    }

    // Normaliser avant la limite par site : « EXAMPLE.com » et « https://example.com/page »
    // désignent le même hôte et partagent donc le même compteur.
    const target = normalizeTarget(url);
    const targetQuota = await limiters.target.limit(hashKey(target.hostname));
    if (!targetQuota.success) {
      return rateLimitedResponse(
        headers,
        targetQuota,
        "Ce site a déjà été analysé plusieurs fois en peu de temps (SecuScan ne doit pas le surcharger)",
      );
    }

    const report = await scanSite(url);
    logScan(report);
    return Response.json(report, { headers });
  } catch (error) {
    return errorResponse(toScanError(error), headers);
  }
}

/**
 * Protection CSRF : un navigateur joint l'en-tête Origin à toute requête POST et une page ne peut
 * pas le falsifier. Sans ce contrôle, n'importe quel site pourrait faire lancer des scans par les
 * navigateurs de ses visiteurs, sur leur quota (un formulaire ou un fetch en text/plain échappe au
 * preflight CORS). Sans Origin (curl, script), il n'y a pas de visiteur à protéger.
 */
function assertSameOrigin(request: Request): void {
  const origin = request.headers.get("origin");
  if (origin === null) return;
  // L'origine opaque « null » (iframe isolée, fichier local) n'est pas une URL : elle est refusée.
  if (URL.parse(origin)?.host === targetHost(request)) return;
  throw new ScanError(
    "FORBIDDEN_ORIGIN",
    "Les analyses ne peuvent être lancées que depuis le site SecuScan lui-même.",
  );
}

/**
 * Méthode de l'OWASP CSRF Prevention Cheat Sheet : X-Forwarded-Host derrière un proxy, sinon Host.
 * `request.url` ne convient pas : hors de Vercel, Next.js y écrit le nom de son propre serveur
 * (« localhost:3000 »), pas l'adresse utilisée par le visiteur.
 */
function targetHost(request: Request): string | null {
  const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
  const host = forwardedHost || request.headers.get("host") || URL.parse(request.url)?.host;
  return host ? host.toLowerCase() : null;
}

async function readJsonBody(request: Request): Promise<unknown> {
  const text = await readBodyText(request);
  try {
    return JSON.parse(text);
  } catch {
    throw new ScanError(
      "INVALID_REQUEST",
      'Le corps de la requête doit être du JSON de la forme {"url": "example.com"}.',
    );
  }
}

// Lecture par morceaux : un envoi énorme n'est jamais chargé entièrement en mémoire.
// Content-Length peut manquer (envoi « chunked »), d'où le comptage des octets.
async function readBodyText(request: Request): Promise<string> {
  if (Number(request.headers.get("content-length")) > MAX_REQUEST_BYTES) throw payloadTooLarge();
  if (request.body === null) return "";

  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let text = "";
  let size = 0;
  let chunk = await reader.read();
  while (!chunk.done) {
    size += chunk.value.byteLength;
    if (size > MAX_REQUEST_BYTES) {
      await reader.cancel();
      throw payloadTooLarge();
    }
    // `stream: true` : un caractère UTF-8 de plusieurs octets peut être coupé entre deux morceaux.
    text += decoder.decode(chunk.value, { stream: true });
    chunk = await reader.read();
  }
  return text + decoder.decode();
}

function payloadTooLarge(): ScanError {
  return new ScanError(
    "PAYLOAD_TOO_LARGE",
    `La requête est trop volumineuse (${MAX_REQUEST_BYTES / 1024} Kio au maximum).`,
  );
}

function parseScanRequest(body: unknown): ScanRequest {
  const parsed = scanRequestSchema.safeParse(body);
  if (parsed.success) return parsed.data;
  throw new ScanError(
    "INVALID_URL",
    "Indiquez l'adresse du site à analyser dans le champ « url » (une chaîne de caractères).",
  );
}

// Brouillon IETF « RateLimit header fields for HTTP ».
function setRateLimitHeaders(headers: Headers, quota: RateLimitResult): void {
  headers.set("RateLimit-Limit", String(quota.limit));
  headers.set("RateLimit-Remaining", String(quota.remaining));
  headers.set("RateLimit-Reset", String(secondsUntil(quota.reset)));
}

function rateLimitedResponse(headers: Headers, quota: RateLimitResult, reason: string): Response {
  // Au moins 1 s : « 0 » inviterait à réessayer aussitôt, pour un nouveau refus.
  const retryAfterSeconds = Math.max(1, secondsUntil(quota.reset));
  headers.set("Retry-After", String(retryAfterSeconds));
  const message = `${reason} : réessayez dans ${formatSeconds(retryAfterSeconds)}.`;
  return errorResponse(new ScanError("RATE_LIMITED", message), headers, retryAfterSeconds);
}

function secondsUntil(timestampMs: number): number {
  return Math.max(0, Math.ceil((timestampMs - Date.now()) / 1000));
}

function formatSeconds(seconds: number): string {
  return seconds > 1 ? `${seconds} secondes` : `${seconds} seconde`;
}

function errorResponse(error: ScanError, headers: Headers, retryAfterSeconds?: number): Response {
  const body: ApiErrorBody = { error: { code: error.code, message: error.message } };
  if (retryAfterSeconds !== undefined) body.error.retryAfterSeconds = retryAfterSeconds;
  return Response.json(body, { status: error.httpStatus, headers });
}

// Toute exception autre qu'une `ScanError` est un bogue : son détail va dans le journal du
// serveur, jamais dans la réponse, où il pourrait révéler le fonctionnement interne.
function toScanError(error: unknown): ScanError {
  if (isScanError(error)) return error;
  const message = error instanceof Error ? error.message : String(error);
  console.error(JSON.stringify({ event: "scan-internal-error", message }));
  return new ScanError(
    "INTERNAL_ERROR",
    "Une erreur inattendue est survenue pendant l'analyse. Réessayez dans quelques instants.",
    { cause: error },
  );
}

// Ni adresse IP (donnée personnelle) ni URL complète (sa requête peut contenir un jeton).
function logScan(report: ScanReport): void {
  const { grade, score } = report.score;
  const host = report.target.hostname;
  console.info(
    JSON.stringify({ event: "scan", host, grade, score, durationMs: report.durationMs }),
  );
}
