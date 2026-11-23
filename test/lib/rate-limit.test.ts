// Horloge simulée (aucune attente) et bibliothèque Upstash remplacée par une doublure (aucun accès
// réseau), pour vérifier aussi le repli sur la mémoire quand Redis est lent ou en panne.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RATE_LIMIT_PER_CLIENT, RATE_LIMIT_PER_TARGET } from "@/lib/config";
import type { RateLimiter, RateLimitResult } from "@/lib/rate-limit";
import {
  createMemoryRateLimiter,
  createUpstashRateLimiter,
  getClientIp,
  hashKey,
} from "@/lib/rate-limit";

const upstash = vi.hoisted(() => ({
  instances: [] as Array<Record<string, unknown>>,
  limit: vi.fn(),
}));

vi.mock("@upstash/ratelimit", () => ({
  Ratelimit: class {
    static slidingWindow(tokens: number, window: string) {
      return { tokens, window };
    }

    limit = upstash.limit;

    constructor(options: Record<string, unknown>) {
      upstash.instances.push(options);
    }
  },
}));

vi.mock("@upstash/redis", () => ({
  Redis: class {
    constructor(readonly config: { url: string; token: string }) {}
  },
}));

const WINDOW_MS = 60_000;

function manualClock(start = 1_000_000): { now: () => number; advance: (ms: number) => void } {
  let time = start;
  return {
    now: () => time,
    advance: (ms) => {
      time += ms;
    },
  };
}

async function hit(limiter: RateLimiter, key: string, count: number): Promise<RateLimitResult[]> {
  const results: RateLimitResult[] = [];
  for (let index = 0; index < count; index += 1) {
    results.push(await limiter.limit(key));
  }
  return results;
}

describe("createMemoryRateLimiter", () => {
  it("accepte `limit` requêtes par fenêtre, puis refuse", async () => {
    const clock = manualClock();
    const limiter = createMemoryRateLimiter({ limit: 3, windowMs: WINDOW_MS, now: clock.now });

    const results = await hit(limiter, "client", 4);

    expect(results.map(({ success, remaining }) => [success, remaining])).toEqual([
      [true, 2],
      [true, 1],
      [true, 0],
      [false, 0],
    ]);
    expect(results.every((result) => result.limit === 3)).toBe(true);
    // Une place se libère quand la première requête sort de la fenêtre.
    expect(results[3]?.reset).toBe(clock.now() + WINDOW_MS);
  });

  it("fait glisser la fenêtre : une place se libère dès que la plus ancienne requête en sort", async () => {
    const clock = manualClock();
    const limiter = createMemoryRateLimiter({ limit: 2, windowMs: WINDOW_MS, now: clock.now });
    const start = clock.now();

    await limiter.limit("client"); // t = 0
    clock.advance(10_000);
    await limiter.limit("client"); // t = 10 s
    clock.advance(49_999); // t = 59,999 s : les deux requêtes sont encore dans la fenêtre
    expect(await limiter.limit("client")).toMatchObject({
      success: false,
      reset: start + WINDOW_MS,
    });

    clock.advance(1); // t = 60 s : la requête de t = 0 sort de la fenêtre
    expect(await limiter.limit("client")).toMatchObject({
      success: true,
      remaining: 0,
      reset: start + 10_000 + WINDOW_MS,
    });
  });

  it("ne compte pas les requêtes refusées", async () => {
    const clock = manualClock();
    const limiter = createMemoryRateLimiter({ limit: 1, windowMs: WINDOW_MS, now: clock.now });

    expect((await limiter.limit("client")).success).toBe(true);
    clock.advance(30_000);
    expect((await limiter.limit("client")).success).toBe(false);
    clock.advance(30_000);
    // Si le refus avait été compté, il faudrait encore attendre 30 s.
    expect((await limiter.limit("client")).success).toBe(true);
  });

  it("compte chaque clé séparément", async () => {
    const limiter = createMemoryRateLimiter({
      limit: 1,
      windowMs: WINDOW_MS,
      now: manualClock().now,
    });
    expect((await limiter.limit("a")).success).toBe(true);
    expect((await limiter.limit("b")).success).toBe(true);
    expect((await limiter.limit("a")).success).toBe(false);
  });

  it("purge les clés dont toutes les requêtes sont sorties de la fenêtre", async () => {
    const clock = manualClock();
    const limiter = createMemoryRateLimiter({ limit: 5, windowMs: WINDOW_MS, now: clock.now });

    await limiter.limit("ancienne"); // t = 0
    clock.advance(30_000);
    await limiter.limit("recente"); // t = 30 s
    expect(limiter.trackedKeys()).toBe(2);

    clock.advance(30_000); // t = 60 s : « ancienne » a expiré, « recente » est encore active
    await limiter.limit("nouvelle");
    expect(limiter.trackedKeys()).toBe(2);

    clock.advance(WINDOW_MS); // t = 120 s : tout a expiré
    await limiter.limit("derniere");
    expect(limiter.trackedKeys()).toBe(1);
  });
});

describe("createUpstashRateLimiter", () => {
  const options = {
    limit: 10,
    windowMs: WINDOW_MS,
    prefix: "secuscan:test",
    url: "https://redis.example.com",
    token: "jeton-de-test",
  };

  beforeEach(() => {
    upstash.instances.length = 0;
    upstash.limit.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("configure une fenêtre glissante partagée, préfixée, avec un délai court", () => {
    createUpstashRateLimiter(options);
    expect(upstash.instances).toHaveLength(1);
    expect(upstash.instances[0]).toMatchObject({
      prefix: "secuscan:test",
      timeout: 1_000,
      limiter: { tokens: 10, window: "60000 ms" },
      redis: { config: { url: "https://redis.example.com", token: "jeton-de-test" } },
    });
  });

  it("renvoie le verdict calculé par Redis", async () => {
    upstash.limit.mockResolvedValue({
      success: false,
      limit: 10,
      remaining: 0,
      reset: 1_234_567,
      pending: Promise.resolve(),
    });
    const result = await createUpstashRateLimiter(options).limit("cle");
    expect(result).toEqual({ success: false, limit: 10, remaining: 0, reset: 1_234_567 });
    expect(upstash.limit).toHaveBeenCalledWith("cle");
  });

  it("se replie sur la mémoire quand Redis ne répond pas à temps", async () => {
    upstash.limit.mockResolvedValue({
      success: true,
      limit: 0,
      remaining: 0,
      reset: 0,
      pending: Promise.resolve(),
      reason: "timeout",
    });
    const result = await createUpstashRateLimiter(options).limit("cle");
    expect(result).toMatchObject({ success: true, limit: 10, remaining: 9 });
  });

  it("se replie sur une vraie limite en mémoire quand Redis est en panne", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => undefined);
    upstash.limit.mockRejectedValue(new Error("connexion impossible"));
    const limiter = createUpstashRateLimiter({ ...options, limit: 1 });

    expect((await limiter.limit("cle")).success).toBe(true);
    expect((await limiter.limit("cle")).success).toBe(false);
    expect(consoleError).toHaveBeenCalledWith(
      expect.stringContaining('"event":"rate-limit-error"'),
    );
  });
});

describe("getRateLimiters", () => {
  const UPSTASH_VARIABLES = [
    "UPSTASH_REDIS_REST_URL",
    "UPSTASH_REDIS_REST_TOKEN",
    "KV_REST_API_URL",
    "KV_REST_API_TOKEN",
  ];

  beforeEach(() => {
    upstash.instances.length = 0;
    for (const name of UPSTASH_VARIABLES) vi.stubEnv(name, "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  /** Module rechargé : `getRateLimiters` repart de zéro (pas de singleton d'un test précédent). */
  async function freshModule(): Promise<typeof import("@/lib/rate-limit")> {
    vi.resetModules();
    return import("@/lib/rate-limit");
  }

  it("utilise la mémoire sans identifiants Upstash, avec les limites de config.ts", async () => {
    const { getRateLimiters } = await freshModule();
    const limiters = getRateLimiters();

    expect(upstash.instances).toHaveLength(0);
    expect((await limiters.client.limit("x")).limit).toBe(RATE_LIMIT_PER_CLIENT.limit);
    expect((await limiters.target.limit("x")).limit).toBe(RATE_LIMIT_PER_TARGET.limit);
  });

  it("renvoie toujours les mêmes instances, pour que les compteurs survivent entre requêtes", async () => {
    const { getRateLimiters } = await freshModule();
    expect(getRateLimiters()).toBe(getRateLimiters());
  });

  it("utilise Upstash avec les variables de l'intégration Vercel (KV_*)", async () => {
    vi.stubEnv("KV_REST_API_URL", "https://kv.example.com");
    vi.stubEnv("KV_REST_API_TOKEN", "jeton-kv");
    const { getRateLimiters } = await freshModule();
    getRateLimiters();

    expect(upstash.instances.map((instance) => instance.prefix)).toEqual([
      "secuscan:client",
      "secuscan:target",
    ]);
    expect(upstash.instances[0]).toMatchObject({
      limiter: { tokens: RATE_LIMIT_PER_CLIENT.limit, window: "60000 ms" },
      redis: { config: { url: "https://kv.example.com", token: "jeton-kv" } },
    });
  });

  it("ignore des identifiants incomplets (URL sans jeton)", async () => {
    vi.stubEnv("UPSTASH_REDIS_REST_URL", "https://redis.example.com");
    const { getRateLimiters } = await freshModule();
    getRateLimiters();
    expect(upstash.instances).toHaveLength(0);
  });
});

describe("getClientIp", () => {
  it.each<[headers: Record<string, string>, expected: string]>([
    [{ "x-real-ip": "203.0.113.7", "x-forwarded-for": "198.51.100.1" }, "203.0.113.7"],
    [{ "x-forwarded-for": "198.51.100.1, 10.0.0.1, 10.0.0.2" }, "198.51.100.1"],
    [{ "x-forwarded-for": "  2001:db8::1  " }, "2001:db8::1"],
    [{ "x-real-ip": "   ", "x-forwarded-for": "198.51.100.1" }, "198.51.100.1"],
    [{ "x-forwarded-for": "" }, "unknown"],
    [{}, "unknown"],
  ])("%o → %s", (headers, expected) => {
    expect(getClientIp(new Headers(headers))).toBe(expected);
  });
});

describe("hashKey", () => {
  it("calcule un condensat SHA-256 hexadécimal (vecteur de test officiel « abc »)", () => {
    expect(hashKey("abc")).toBe("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  });

  it("ne laisse jamais apparaître l'adresse IP et distingue deux adresses voisines", () => {
    const hash = hashKey("203.0.113.7");
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
    expect(hash).not.toContain("203.0.113.7");
    expect(hashKey("203.0.113.8")).not.toBe(hash);
    expect(hashKey("203.0.113.7")).toBe(hash);
  });
});
