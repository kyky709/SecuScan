/**
 * Chaque scan envoie une dizaine de requêtes au site analysé : /api/scan limite donc par client
 * (IP) et par site analysé, quel que soit le demandeur, afin qu'on ne puisse pas s'en servir
 * pour harceler une cible.
 *
 * En mémoire, chaque instance serverless aurait ses propres compteurs : sur Vercel, on passe par
 * Upstash Redis dès que ses identifiants sont définis.
 *
 * RGPD : une IP est une donnée personnelle. Les clés sont des condensats SHA-256 (`hashKey`) qui
 * disparaissent à la fin de la fenêtre.
 */
import "server-only";
import { createHash } from "node:crypto";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { RATE_LIMIT_PER_CLIENT, RATE_LIMIT_PER_TARGET } from "@/lib/config";

export interface RateLimitResult {
  success: boolean;
  limit: number;
  remaining: number;
  /** Horodatage en ms où une nouvelle requête sera acceptée. */
  reset: number;
}

export interface RateLimiter {
  limit(key: string): Promise<RateLimitResult>;
}

export interface MemoryRateLimiter extends RateLimiter {
  /** Exposé pour vérifier la purge dans les tests. */
  trackedKeys(): number;
}

export interface RateLimiters {
  client: RateLimiter;
  target: RateLimiter;
}

// La route consulte deux limites avant un scan de 20 s max, dans une fonction limitée à 30 s :
// un Redis lent ne doit pas consommer ce budget.
const UPSTASH_TIMEOUT_MS = 1_000;

/**
 * Fenêtre glissante exacte : contrairement à une fenêtre fixe, on ne peut pas doubler le débit à
 * cheval sur deux fenêtres. Les requêtes refusées ne sont pas comptées : un client bloqué retrouve
 * l'accès dès que sa plus ancienne requête sort de la fenêtre.
 */
export function createMemoryRateLimiter(options: {
  limit: number;
  windowMs: number;
  now?: () => number;
}): MemoryRateLimiter {
  const { limit, windowMs, now = Date.now } = options;
  // Instants des requêtes acceptées, du plus ancien au plus récent.
  const requestTimes = new Map<string, number[]>();
  let lastPurge = now();

  function purgeExpiredKeys(currentTime: number): void {
    // Au plus une fois par fenêtre : parcourir toutes les clés à chaque requête coûterait cher.
    if (currentTime - lastPurge < windowMs) return;
    lastPurge = currentTime;
    for (const [key, times] of requestTimes) {
      const latest = times.at(-1);
      if (latest === undefined || latest <= currentTime - windowMs) requestTimes.delete(key);
    }
  }

  return {
    async limit(key) {
      const currentTime = now();
      purgeExpiredKeys(currentTime);

      const windowStart = currentTime - windowMs;
      const recent = (requestTimes.get(key) ?? []).filter((time) => time > windowStart);
      const success = recent.length < limit;
      if (success) recent.push(currentTime);
      requestTimes.set(key, recent);

      const oldest = recent[0] ?? currentTime;
      return {
        success,
        limit,
        remaining: Math.max(0, limit - recent.length),
        reset: oldest + windowMs,
      };
    },
    trackedKeys: () => requestTimes.size,
  };
}

// Si Redis est injoignable ou trop lent, on se replie sur la mémoire : mieux vaut une limite par
// instance que plus de limite du tout, et le service reste disponible.
export function createUpstashRateLimiter(options: {
  limit: number;
  windowMs: number;
  prefix: string;
  url: string;
  token: string;
}): RateLimiter {
  const { limit, windowMs, prefix, url, token } = options;
  const ratelimit = new Ratelimit({
    redis: new Redis({ url, token }),
    limiter: Ratelimit.slidingWindow(limit, `${windowMs} ms`),
    prefix,
    timeout: UPSTASH_TIMEOUT_MS,
  });
  const fallback = createMemoryRateLimiter({ limit, windowMs });

  return {
    async limit(key) {
      try {
        const result = await ratelimit.limit(key);
        // Sur timeout, la bibliothèque laisse passer la requête avec des compteurs à 0,
        // inexploitables pour les en-têtes RateLimit-*.
        if (result.reason === "timeout") return fallback.limit(key);
        const { success, remaining, reset } = result;
        return { success, limit: result.limit, remaining, reset };
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.error(JSON.stringify({ event: "rate-limit-error", prefix, message }));
        return fallback.limit(key);
      }
    },
  };
}

// Singleton : les compteurs en mémoire doivent survivre d'une requête à l'autre.
let rateLimiters: RateLimiters | undefined;

export function getRateLimiters(): RateLimiters {
  rateLimiters ??= createRateLimiters();
  return rateLimiters;
}

function createRateLimiters(): RateLimiters {
  const credentials = upstashCredentials();
  if (credentials === null) {
    return {
      client: createMemoryRateLimiter(RATE_LIMIT_PER_CLIENT),
      target: createMemoryRateLimiter(RATE_LIMIT_PER_TARGET),
    };
  }
  return {
    client: createUpstashRateLimiter({
      ...RATE_LIMIT_PER_CLIENT,
      ...credentials,
      prefix: "secuscan:client",
    }),
    target: createUpstashRateLimiter({
      ...RATE_LIMIT_PER_TARGET,
      ...credentials,
      prefix: "secuscan:target",
    }),
  };
}

// KV_* : noms utilisés par l'intégration Vercel.
function upstashCredentials(): { url: string; token: string } | null {
  const url = readEnv("UPSTASH_REDIS_REST_URL") ?? readEnv("KV_REST_API_URL");
  const token = readEnv("UPSTASH_REDIS_REST_TOKEN") ?? readEnv("KV_REST_API_TOKEN");
  return url && token ? { url, token } : null;
}

// `.env.example` déclare ces variables vides.
function readEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

/**
 * Sur Vercel, `x-real-ip` et `x-forwarded-for` sont écrits par la plateforme, qui écrase ceux du
 * client. Derrière un autre proxy, ils peuvent être falsifiés. Sans en-tête, tous ces clients
 * partagent la clé "unknown".
 */
export function getClientIp(headers: Headers): string {
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) return realIp;
  // « client, proxy1, proxy2 »
  const forwardedFor = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwardedFor || "unknown";
}

/**
 * Pas un anonymat absolu (une IPv4 se retrouve en essayant toutes les adresses), d'où la seconde
 * garantie : les clés expirent avec la fenêtre et ne sont jamais journalisées.
 */
export function hashKey(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
