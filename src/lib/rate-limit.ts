/**
 * Limitation de débit (rate limiting) de l'API de scan.
 *
 * Chaque scan envoie une dizaine de requêtes au site analysé : sans limite, SecuScan pourrait
 * servir à harceler un site, ou voir ses propres ressources épuisées. La route /api/scan applique
 * donc deux limites (valeurs dans config.ts) :
 * - par client (adresse IP du visiteur) : contre l'abus de l'outil par une même personne ;
 * - par site analysé, quel que soit le demandeur : contre le harcèlement d'une même cible.
 *
 * Deux implémentations du même contrat `RateLimiter` :
 * - en mémoire (fenêtre glissante exacte) : par défaut, suffisante en local ou sur une instance ;
 * - Upstash Redis : compteurs partagés entre toutes les instances serverless de Vercel (en
 *   mémoire, chaque instance aurait ses propres compteurs). Utilisée dès que les variables
 *   UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN (ou KV_REST_API_URL / KV_REST_API_TOKEN,
 *   noms de l'intégration Vercel) sont définies.
 *
 * RGPD : une adresse IP est une donnée personnelle. Les clés sont donc des condensats SHA-256
 * (`hashKey`), jamais des adresses en clair, et elles disparaissent à la fin de la fenêtre.
 */
import "server-only";
import { createHash } from "node:crypto";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { RATE_LIMIT_PER_CLIENT, RATE_LIMIT_PER_TARGET } from "@/lib/config";

/** Verdict d'une limite de débit pour une requête. */
export interface RateLimitResult {
  /** La requête est-elle autorisée ? */
  success: boolean;
  /** Nombre maximal de requêtes par fenêtre. */
  limit: number;
  /** Nombre de requêtes encore possibles dans la fenêtre en cours. */
  remaining: number;
  /** Instant (en millisecondes depuis 1970) où une nouvelle requête sera de nouveau acceptée. */
  reset: number;
}

/** Contrat commun aux deux implémentations. */
export interface RateLimiter {
  /** Comptabilise une requête pour `key` et indique si elle est autorisée. */
  limit(key: string): Promise<RateLimitResult>;
}

/** Limiteur en mémoire, qui expose en plus le nombre de clés suivies (purge vérifiable). */
export interface MemoryRateLimiter extends RateLimiter {
  /** Nombre de clés actuellement en mémoire. */
  trackedKeys(): number;
}

/** Les deux limites appliquées par la route /api/scan. */
export interface RateLimiters {
  /** Par client (condensat de son adresse IP). */
  client: RateLimiter;
  /** Par site analysé (condensat du nom d'hôte). */
  target: RateLimiter;
}

/**
 * Délai maximal accordé à Redis. La route consulte deux limites avant un scan qui peut durer
 * 20 s, dans une fonction limitée à 30 s : une base lente ne doit pas consommer ce budget.
 */
const UPSTASH_TIMEOUT_MS = 1_000;

/**
 * Limiteur en mémoire à fenêtre glissante : une requête est acceptée si la clé en a fait moins de
 * `limit` pendant les `windowMs` dernières millisecondes. Contrairement à une fenêtre fixe (« 10
 * par minute calendaire »), on ne peut pas doubler le débit à cheval sur deux fenêtres.
 *
 * Les requêtes refusées ne sont pas comptées : un client bloqué retrouve l'accès dès que sa plus
 * ancienne requête sort de la fenêtre.
 *
 * @param options.limit    nombre maximal de requêtes par fenêtre
 * @param options.windowMs durée de la fenêtre, en millisecondes
 * @param options.now      horloge (remplaçable dans les tests)
 */
export function createMemoryRateLimiter(options: {
  limit: number;
  windowMs: number;
  now?: () => number;
}): MemoryRateLimiter {
  const { limit, windowMs, now = Date.now } = options;
  // Pour chaque clé : instants des requêtes acceptées dans la fenêtre, du plus ancien au plus récent.
  const requestTimes = new Map<string, number[]>();
  let lastPurge = now();

  /** Supprime les clés dont toutes les requêtes sont sorties de la fenêtre (mémoire bornée). */
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

      // Une place se libère quand la plus ancienne requête de la fenêtre en sort.
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

/**
 * Limiteur partagé, stocké dans Upstash Redis (fenêtre glissante de la bibliothèque
 * @upstash/ratelimit). Si Redis est injoignable ou trop lent, on se replie sur un limiteur en
 * mémoire : mieux vaut une limite par instance que plus de limite du tout, et le service reste
 * disponible.
 *
 * @param options.prefix préfixe des clés Redis, propre à chaque limite (« secuscan:client »…)
 * @param options.url    adresse REST de la base Upstash
 * @param options.token  jeton d'accès à la base
 */
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
        // Délai dépassé : la bibliothèque laisse passer la requête avec des compteurs à 0,
        // inexploitables pour les en-têtes RateLimit-* : on se replie sur la mémoire.
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

/** Instances partagées par toutes les requêtes traitées par cette instance du serveur. */
let rateLimiters: RateLimiters | undefined;

/**
 * Les deux limiteurs de l'API, créés au premier appel puis réutilisés (singletons) : les
 * compteurs en mémoire doivent survivre d'une requête à l'autre.
 */
export function getRateLimiters(): RateLimiters {
  rateLimiters ??= createRateLimiters();
  return rateLimiters;
}

/** Choisit Upstash si ses identifiants sont configurés, la mémoire sinon. */
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

/** Identifiants Upstash : noms officiels d'Upstash, ou ceux de l'intégration Vercel (KV_*). */
function upstashCredentials(): { url: string; token: string } | null {
  const url = readEnv("UPSTASH_REDIS_REST_URL") ?? readEnv("KV_REST_API_URL");
  const token = readEnv("UPSTASH_REDIS_REST_TOKEN") ?? readEnv("KV_REST_API_TOKEN");
  return url && token ? { url, token } : null;
}

/** Variable d'environnement non vide (`.env.example` les déclare vides), sinon undefined. */
function readEnv(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value ? value : undefined;
}

/**
 * Adresse IP du client, pour la limite par client.
 *
 * Sur Vercel, `x-real-ip` et `x-forwarded-for` sont écrits par la plateforme, qui écrase les
 * valeurs envoyées par le client : impossible de se faire passer pour quelqu'un d'autre. Hors de
 * Vercel (`next start` derrière un autre proxy), ces en-têtes peuvent être falsifiés.
 *
 * @returns l'adresse, ou "unknown" si aucun en-tête n'est présent (clé commune à ces clients)
 */
export function getClientIp(headers: Headers): string {
  const realIp = headers.get("x-real-ip")?.trim();
  if (realIp) return realIp;
  // « client, proxy1, proxy2 » : l'adresse du client est la première de la liste.
  const forwardedFor = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwardedFor || "unknown";
}

/**
 * Condensat SHA-256 (hexadécimal) d'une clé de limitation. Les compteurs ne contiennent ainsi
 * jamais d'adresse IP en clair. Ce n'est pas un anonymat absolu (on pourrait retrouver une IPv4
 * en essayant toutes les adresses possibles), d'où la seconde garantie : les clés expirent avec la
 * fenêtre et ne sont jamais journalisées.
 */
export function hashKey(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}
