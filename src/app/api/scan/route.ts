/**
 * Route POST /api/scan : la porte d'entrée HTTP du scanner.
 *
 * Elle ne contient aucune logique d'analyse (confiée à `scanSite`) : elle filtre, limite et
 * traduit. Les étapes vont de la moins coûteuse à la plus coûteuse, pour qu'une requête abusive
 * soit refusée avant d'avoir consommé des ressources :
 *   1. origine de la requête (403) : depuis un navigateur, seul le site SecuScan lance un scan ;
 *   2. corps JSON de 4 Kio au plus (413), bien formé (400) et de la forme { "url": "…" } (400) ;
 *   3. limite de débit par client (429) ;
 *   4. normalisation de l'adresse : schéma, port, cible interdite… (400 ou 422) ;
 *   5. limite de débit par site analysé (429) ;
 *   6. scan, puis 200 avec le rapport (`ScanReport`).
 *
 * Toute erreur devient une réponse JSON `{ error: { code, message } }` (`ApiErrorBody`), dont le
 * statut HTTP découle du code (errors.ts). Les en-têtes RateLimit-* décrivent le quota du client ;
 * toute réponse 429 indique en plus quand réessayer (`Retry-After`).
 */
import { z } from "zod";
import type { RateLimitResult } from "@/lib/rate-limit";
import { getClientIp, getRateLimiters, hashKey } from "@/lib/rate-limit";
import type { ApiErrorBody, ScanReport } from "@/lib/scanner";
import { isScanError, normalizeTarget, ScanError, scanSite } from "@/lib/scanner";

/**
 * Durée maximale d'exécution de la fonction sur Vercel, en secondes. Le scan lui-même est borné à
 * 20 s (`SCAN_TIMEOUT_MS`) : la marge couvre la validation, les limites de débit et la réponse.
 */
export const maxDuration = 30;

/** Taille maximale du corps de la requête : `{"url": "…"}` y tient très largement. */
const MAX_REQUEST_BYTES = 4 * 1024;

/** Forme attendue du corps de la requête (les champs supplémentaires sont ignorés). */
const scanRequestSchema = z.object({ url: z.string() });

/** Corps de requête validé. */
type ScanRequest = z.infer<typeof scanRequestSchema>;

/**
 * Analyse le site indiqué dans le corps `{ "url": "…" }` et renvoie son rapport.
 *
 * @returns 200 et le `ScanReport`, ou une erreur JSON (`ApiErrorBody`) : 400, 403, 413, 422, 429,
 *   500, 502 ou 504 selon le code de l'erreur
 */
export async function POST(request: Request): Promise<Response> {
  // Les en-têtes RateLimit-* sont connus une fois le quota du client vérifié ; ils accompagnent
  // ensuite toutes les réponses, succès comme erreur.
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
 * Refuse une requête envoyée depuis un autre site (protection contre la falsification de requête
 * intersite, CSRF). Un navigateur joint l'en-tête Origin à toute requête POST, et une page ne peut
 * pas le falsifier. Sans ce contrôle, n'importe quel site pourrait faire lancer des scans par les
 * navigateurs de ses visiteurs, en consommant leur quota : un formulaire ou un fetch en text/plain
 * échappe à la vérification CORS préalable. Sans en-tête Origin (curl, script), il n'y a pas de
 * visiteur à protéger : la requête passe, soumise comme les autres aux limites de débit.
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
 * Hôte auquel le navigateur a envoyé la requête, comparé à celui de l'en-tête Origin (méthode de
 * l'OWASP CSRF Prevention Cheat Sheet) : X-Forwarded-Host derrière un proxy (Vercel ; Next.js le
 * remplit aussi à partir de Host), sinon Host. `request.url` ne convient pas : hors de Vercel,
 * Next.js y écrit le nom de son propre serveur (« localhost:3000 »), pas l'adresse utilisée par
 * le visiteur. Une page malveillante ne peut pas modifier ces en-têtes sans déclencher une
 * vérification CORS préalable, que cette route n'accepte jamais.
 */
function targetHost(request: Request): string | null {
  const forwardedHost = request.headers.get("x-forwarded-host")?.split(",")[0]?.trim();
  const host = forwardedHost || request.headers.get("host") || URL.parse(request.url)?.host;
  return host ? host.toLowerCase() : null;
}

/**
 * Lit le corps de la requête et l'analyse en JSON.
 *
 * @throws {ScanError} PAYLOAD_TOO_LARGE au-delà de 4 Kio, INVALID_REQUEST si ce n'est pas du JSON
 */
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

/**
 * Lit le corps morceau par morceau et abandonne dès que la limite est dépassée : un envoi énorme
 * n'est jamais chargé entièrement en mémoire. Content-Length, quand il est annoncé, permet de
 * refuser avant même de lire ; il peut manquer (envoi « chunked »), d'où le comptage des octets.
 */
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

/** Erreur renvoyée pour un corps de requête trop volumineux. */
function payloadTooLarge(): ScanError {
  return new ScanError(
    "PAYLOAD_TOO_LARGE",
    `La requête est trop volumineuse (${MAX_REQUEST_BYTES / 1024} Kio au maximum).`,
  );
}

/**
 * Vérifie la forme du corps avec zod : un objet dont le champ `url` est une chaîne.
 *
 * @throws {ScanError} INVALID_URL si le champ manque ou n'est pas une chaîne
 */
function parseScanRequest(body: unknown): ScanRequest {
  const parsed = scanRequestSchema.safeParse(body);
  if (parsed.success) return parsed.data;
  throw new ScanError(
    "INVALID_URL",
    "Indiquez l'adresse du site à analyser dans le champ « url » (une chaîne de caractères).",
  );
}

/**
 * En-têtes RateLimit-* (brouillon IETF « RateLimit header fields for HTTP ») : taille du quota,
 * requêtes restantes, et secondes avant qu'une place se libère.
 */
function setRateLimitHeaders(headers: Headers, quota: RateLimitResult): void {
  headers.set("RateLimit-Limit", String(quota.limit));
  headers.set("RateLimit-Remaining", String(quota.remaining));
  headers.set("RateLimit-Reset", String(secondsUntil(quota.reset)));
}

/**
 * Réponse 429. `Retry-After` (en-tête standard) et `retryAfterSeconds` (corps JSON, pour
 * l'interface) indiquent quand réessayer, d'après la limite qui a refusé la requête.
 *
 * @param reason début du message, complété par le délai d'attente
 */
function rateLimitedResponse(headers: Headers, quota: RateLimitResult, reason: string): Response {
  // Au moins 1 s : « 0 » inviterait à réessayer aussitôt, pour un nouveau refus.
  const retryAfterSeconds = Math.max(1, secondsUntil(quota.reset));
  headers.set("Retry-After", String(retryAfterSeconds));
  const message = `${reason} : réessayez dans ${formatSeconds(retryAfterSeconds)}.`;
  return errorResponse(new ScanError("RATE_LIMITED", message), headers, retryAfterSeconds);
}

/** Nombre entier de secondes avant l'instant `timestampMs` (0 s'il est déjà passé). */
function secondsUntil(timestampMs: number): number {
  return Math.max(0, Math.ceil((timestampMs - Date.now()) / 1000));
}

/** Durée lisible : « 1 seconde », « 42 secondes ». */
function formatSeconds(seconds: number): string {
  return seconds > 1 ? `${seconds} secondes` : `${seconds} seconde`;
}

/** Réponse d'erreur JSON (`ApiErrorBody`), au statut HTTP associé au code de l'erreur. */
function errorResponse(error: ScanError, headers: Headers, retryAfterSeconds?: number): Response {
  const body: ApiErrorBody = { error: { code: error.code, message: error.message } };
  if (retryAfterSeconds !== undefined) body.error.retryAfterSeconds = retryAfterSeconds;
  return Response.json(body, { status: error.httpStatus, headers });
}

/**
 * Les erreurs prévues (`ScanError`) sont renvoyées telles quelles : leur message est écrit pour
 * l'utilisateur. Toute autre exception est un bogue : son détail part dans le journal du serveur,
 * jamais dans la réponse, où il pourrait révéler le fonctionnement interne de l'application.
 */
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

/**
 * Journal minimal d'un scan réussi : une ligne JSON, facile à filtrer dans les journaux de Vercel.
 * Ni adresse IP (donnée personnelle) ni URL complète (sa requête peut contenir un jeton) :
 * seulement l'hôte analysé et le résultat.
 */
function logScan(report: ScanReport): void {
  const { grade, score } = report.score;
  const host = report.target.hostname;
  console.info(
    JSON.stringify({ event: "scan", host, grade, score, durationMs: report.durationMs }),
  );
}
