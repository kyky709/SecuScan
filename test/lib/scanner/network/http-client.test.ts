/**
 * Tests du client HTTP sûr (http-client.ts), sans accès à Internet.
 *
 * Un serveur HTTP local (127.0.0.1, port aléatoire) joue tous les rôles : page HTML, redirections,
 * corps compressés, réponses lentes… Le client par défaut (`safeFetch`) doit refuser de le contacter :
 * c'est la protection anti-SSRF, vérifiée grâce au compteur de requêtes reçues par le serveur. Les
 * autres tests utilisent un client « de test » qui autorise explicitement ce serveur.
 *
 * Les tests HTTPS génèrent un certificat auto-signé jetable avec la commande openssl (ignorés si elle
 * est absente) ; la clé est créée dans un dossier temporaire supprimé aussitôt.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import {
  createServer,
  type Server as HttpServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import type { Server as NetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { brotliCompressSync, deflateSync, gzipSync, zstdCompressSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { USER_AGENT } from "@/lib/config";
import { createFetcher, safeFetch, toNetworkError } from "@/lib/scanner/network/http-client";
import {
  BlockedAddressError,
  createSafeLookup,
  type HostResolver,
} from "@/lib/scanner/network/safe-lookup";
import type {
  Fetcher,
  FetchSuccess,
  NetworkError,
  NetworkErrorCode,
  Result,
} from "@/lib/scanner/types";

// ─────────────────────────────────────────────────────────────────────────────
// Outils de test
// ─────────────────────────────────────────────────────────────────────────────

/** Renvoie la valeur d'un Result réussi, ou fait échouer le test avec l'erreur reçue. */
function expectOk(result: Result<FetchSuccess>): FetchSuccess {
  if (!result.ok) {
    throw new Error(`Échec inattendu : ${result.error.code} – ${result.error.message}`);
  }
  return result.value;
}

/** Vérifie qu'un Result est un échec du code attendu et renvoie l'erreur. */
function expectFailure(result: Result<FetchSuccess>, code: NetworkErrorCode): NetworkError {
  if (result.ok) throw new Error(`Succès inattendu (statut ${result.value.response.status}).`);
  expect(result.error.code).toBe(code);
  return result.error;
}

/** Démarre un serveur sur 127.0.0.1, sur un port choisi par le système, et renvoie ce port. */
function listen(server: NetServer): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") reject(new Error("Port introuvable."));
      else resolve(address.port);
    });
  });
}

/** Arrête un serveur HTTP(S) en coupant les connexions encore ouvertes. */
async function stop(server: HttpServer | HttpsServer): Promise<void> {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/** Port sur lequel plus rien n'écoute (connexion refusée garantie). */
async function closedPort(): Promise<number> {
  const server = createServer();
  const freePort = await listen(server);
  await stop(server);
  return freePort;
}

/** DNS simulé : chaque nom renvoie les adresses de la table (aucune si le nom est inconnu). */
function fakeDns(table: Record<string, string[]>): HostResolver {
  return async (hostname) =>
    (table[hostname] ?? []).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));
}

/** Erreur Node.js simulée, avec son code. */
function nodeError(code: string, message = code): Error {
  return Object.assign(new Error(message), { code });
}

// ─────────────────────────────────────────────────────────────────────────────
// Serveur HTTP local
// ─────────────────────────────────────────────────────────────────────────────

type Route = (request: IncomingMessage, response: ServerResponse) => void;

const HTML = `<!doctype html><html lang="fr"><head><title>Été à Noël : ça marche</title></head><body>${"<p>contenu</p>".repeat(1_000)}</body></html>`;
const ENCODERS: Record<string, (input: Buffer) => Buffer> = {
  gzip: gzipSync,
  deflate: deflateSync,
  br: brotliCompressSync,
  zstd: zstdCompressSync,
};

let port = 0;
let base = "";
/** Nombre de requêtes reçues : doit rester inchangé quand le client refuse une cible. */
let hits = 0;
let lastMethod = "";
let bomb = Buffer.alloc(0);

/** Route qui redirige vers `location` (calculée à l'appel : elle peut contenir le port). */
function redirect(status: number, location: string | (() => string)): Route {
  return (_request, response) => {
    response.writeHead(status, { location: typeof location === "string" ? location : location() });
    response.end();
  };
}

/** Route qui renvoie `body` avec les en-têtes donnés (statut 200 par défaut). */
function send(headers: Record<string, string>, body: string | Buffer, status = 200): Route {
  return (_request, response) => {
    response.writeHead(status, headers);
    response.end(body);
  };
}

const ROUTES: Record<string, Route> = {
  "/": send({ "content-type": "text/html; charset=utf-8" }, HTML),
  "/latin1": (_request, response) => {
    response.writeHead(200, { "content-type": "text/plain; charset=iso-8859-1" });
    response.end(Buffer.from("Café crème", "latin1"));
  },
  "/charset-inconnu": send({ "content-type": "text/plain; charset=x-inconnu" }, "Déjà vu"),
  "/json": send({ "content-type": "application/json" }, '{"message":"bonjour"}'),
  "/sans-type": (_request, response) => response.end("texte sans type"),
  "/image": send({ "content-type": "image/png" }, Buffer.from([0x89, 0x50, 0x4e, 0x47])),
  "/doublons": (_request, response) => {
    response.setHeader("set-cookie", [
      "session=abc; Secure; HttpOnly",
      "theme=sombre; Max-Age=3600",
    ]);
    response.appendHeader("content-security-policy", "default-src 'self'");
    response.appendHeader("content-security-policy", "frame-ancestors 'none'");
    response.appendHeader("server", "nginx");
    response.appendHeader("server", "apache");
    response.end("doublons");
  },
  "/relative": redirect(302, "/"),
  "/r301": redirect(301, "/r302"),
  "/r302": redirect(302, "/"),
  "/boucle": redirect(302, "/boucle"),
  "/vers-ftp": redirect(302, "ftp://example.com/fichier"),
  "/vers-javascript": redirect(302, "javascript:alert(1)"),
  "/sans-location": (_request, response) => {
    response.writeHead(302);
    response.end();
  },
  "/location-illisible": redirect(302, "http://[::1"),
  "/vers-identifiants": redirect(302, () => `http://utilisateur:secret@127.0.0.1:${port}/`),
  "/vers-port": redirect(302, "http://127.0.0.1:8080/"),
  "/vers-boucle-ipv6": redirect(302, () => `http://[::1]:${port}/`),
  "/vers-metadonnees": redirect(301, "http://169.254.169.254/latest/meta-data/"),
  "/vers-nom-interne": redirect(307, () => `http://intranet.corp.test:${port}/`),
  "/gros": send({ "content-type": "text/plain" }, Buffer.alloc(3 * 1024 * 1024, "a")),
  "/bombe": (_request, response) => {
    response.writeHead(200, { "content-type": "text/html", "content-encoding": "gzip" });
    response.end(bomb);
  },
  "/gzip-corrompu": send(
    { "content-type": "text/html", "content-encoding": "gzip" },
    "ceci n'est pas du gzip",
  ),
  "/encodage-inconnu": send({ "content-type": "text/html", "content-encoding": "compress" }, "?"),
  "/en-tetes-lents": (_request, response) => {
    const timer = setTimeout(() => response.end("trop tard"), 2_000);
    response.on("close", () => clearTimeout(timer));
  },
  "/goutte-a-goutte": (_request, response) => {
    response.writeHead(200, { "content-type": "text/html" });
    response.write("<p>début");
    const timer = setInterval(() => response.write("."), 50);
    response.on("close", () => clearInterval(timer));
  },
  "/gros-en-tete": send({ "content-type": "text/html", "x-grand": "a".repeat(20_000) }, "ok"),
  "/en-tete-geant": send({ "content-type": "text/html", "x-geant": "a".repeat(70_000) }, "ok"),
  "/echo": (request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify(request.headers));
  },
};

/** Routes calculées : /chaine/N (redirections sans fin) et /encodage/<algorithme>. */
function dynamicRoute(pathname: string): Route | undefined {
  const step = /^\/chaine\/(\d+)$/.exec(pathname)?.[1];
  if (step !== undefined) return redirect(302, `/chaine/${Number(step) + 1}`);
  const encoding = /^\/encodage\/(\w+)$/.exec(pathname)?.[1] ?? "";
  const encode = ENCODERS[encoding];
  if (encode === undefined) return undefined;
  return send(
    { "content-type": "text/html; charset=utf-8", "content-encoding": encoding },
    encode(Buffer.from(HTML)),
  );
}

const server = createServer((request, response) => {
  hits += 1;
  lastMethod = request.method ?? "";
  const { pathname } = new URL(request.url ?? "/", "http://serveur-de-test.invalid");
  const route = ROUTES[pathname] ?? dynamicRoute(pathname);
  if (route) route(request, response);
  else send({ "content-type": "text/html" }, "<p>Introuvable</p>", 404)(request, response);
});

/** Client de test : toutes les adresses autorisées, port du serveur de test autorisé. */
let local: Fetcher = safeFetch;

beforeAll(async () => {
  bomb = gzipSync(Buffer.alloc(20 * 1024 * 1024)); // 20 Mio de zéros → environ 20 Ko compressés
  port = await listen(server);
  base = `http://127.0.0.1:${port}`;
  local = createFetcher({ allowPrivate: true, allowedPorts: new Set([port]) });
});

afterAll(() => stop(server));

// ─────────────────────────────────────────────────────────────────────────────
// Protection anti-SSRF (tests de non-régression, client par défaut)
// ─────────────────────────────────────────────────────────────────────────────

/** Vérifie que la requête est refusée (BLOCKED_ADDRESS) sans que le serveur de test soit contacté. */
async function expectBlockedWithoutContact(fetcher: Fetcher, url: string): Promise<NetworkError> {
  const before = hits;
  const error = expectFailure(await fetcher(url), "BLOCKED_ADDRESS");
  expect(hits).toBe(before);
  return error;
}

describe("safeFetch : protection anti-SSRF du client par défaut", () => {
  const blockedLiterals: Array<[label: string, url: () => string]> = [
    ["127.0.0.1 sur le port du serveur de test", () => `http://127.0.0.1:${port}/`],
    ["[::1] sur le port du serveur de test", () => `http://[::1]:${port}/`],
    ["0.0.0.0 (la machine elle-même)", () => "http://0.0.0.0/"],
    ["2130706433 (127.0.0.1 en décimal)", () => "http://2130706433/"],
    ["0x7f.1 (127.0.0.1 en hexadécimal)", () => "http://0x7f.1/"],
    ["127.1 (forme abrégée)", () => "http://127.1/"],
    ["0 (0.0.0.0 abrégée)", () => "http://0/"],
    ["[::ffff:127.0.0.1] (IPv4 mappée)", () => "http://[::ffff:127.0.0.1]/"],
    ["[::] (adresse non spécifiée)", () => "http://[::]/"],
    ["[::127.0.0.1] (IPv4 « compatible »)", () => "http://[::127.0.0.1]/"],
    ["169.254.169.254 (métadonnées cloud)", () => "http://169.254.169.254/latest/meta-data/"],
    ["[fd00:ec2::254] (métadonnées AWS en IPv6)", () => "http://[fd00:ec2::254]/"],
    ["100.100.100.200 (métadonnées Alibaba Cloud)", () => "http://100.100.100.200/"],
    ["[64:ff9b::a9fe:a9fe] (NAT64 vers les métadonnées)", () => "https://[64:ff9b::a9fe:a9fe]/"],
  ];

  it.each(blockedLiterals)("refuse l'IP littérale %s", async (_label, url) => {
    const error = await expectBlockedWithoutContact(safeFetch, url());
    expect(error.message).toContain("anti-SSRF");
  });

  it("refuse 127.0.0.1 même quand le port du serveur de test est autorisé", async () => {
    const strictPolicy = createFetcher({ allowedPorts: new Set([port]) });
    const error = await expectBlockedWithoutContact(strictPolicy, `${base}/`);
    expect(error.message).toContain("bouclage");
  });

  it("refuse un nom qui pointe vers la boucle locale (localhost, vraie résolution)", async () => {
    await expectBlockedWithoutContact(safeFetch, "http://localhost/");
    const strictPolicy = createFetcher({ allowedPorts: new Set([port]) });
    await expectBlockedWithoutContact(strictPolicy, `http://localhost:${port}/`);
  });

  it("refuse un nom qui pointe vers une adresse privée", async () => {
    const fetcher = createFetcher({
      lookup: createSafeLookup({ resolve: fakeDns({ "intranet.example": ["10.0.0.5"] }) }),
    });
    const error = await expectBlockedWithoutContact(fetcher, "http://intranet.example/");
    expect(error.message).toContain("« intranet.example » pointe vers une adresse non publique");
    expect(error.message).not.toContain("10.0.0.5");
  });

  it("refuse un nom qui a une adresse publique ET une adresse privée", async () => {
    const fetcher = createFetcher({
      allowedPorts: new Set([port]),
      lookup: createSafeLookup({
        resolve: fakeDns({ "mixte.example": ["93.184.215.14", "127.0.0.1"] }),
      }),
    });
    const error = await expectBlockedWithoutContact(fetcher, `http://mixte.example:${port}/`);
    expect(error.message).toContain("adresse de bouclage");
    expect(error.message).not.toContain("127.0.0.1");
  });

  it("refuse les identifiants dans l'URL, avant toute résolution", async () => {
    const error = expectFailure(
      await safeFetch("http://utilisateur:motdepasse@example.com/"),
      "BLOCKED_ADDRESS",
    );
    expect(error.message).toContain("identifiants");
  });

  it("refuse un port non standard, avant toute résolution", async () => {
    const error = expectFailure(await safeFetch("http://example.com:8080/"), "BLOCKED_ADDRESS");
    expect(error.message).toContain("port 8080");
  });

  it.each([
    "ftp://example.com/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
  ])("refuse le schéma de %s", async (url) => {
    const error = expectFailure(await safeFetch(url), "BLOCKED_ADDRESS");
    expect(error.message).toContain("schéma");
  });

  it("signale une adresse illisible sans lever d'exception", async () => {
    const error = expectFailure(await safeFetch("ceci n'est pas une URL"), "UNKNOWN");
    expect(error.message).toContain("Adresse invalide");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Redirections
// ─────────────────────────────────────────────────────────────────────────────

describe("redirections suivies à la main", () => {
  it("résout une destination relative et garde toute la chaîne", async () => {
    const { response, chain } = expectOk(await local(`${base}/relative`));
    expect(response.status).toBe(200);
    expect(response.url).toBe(`${base}/`);
    expect(chain.map((hop) => [hop.status, hop.url])).toEqual([
      [302, `${base}/relative`],
      [200, `${base}/`],
    ]);
    expect(chain[0]?.headers.location).toBe("/");
    expect(chain[0]?.body).toBeNull();
  });

  it("suit 301 puis 302 jusqu'à la réponse finale", async () => {
    const { chain } = expectOk(await local(`${base}/r301`));
    expect(chain.map((hop) => hop.status)).toEqual([301, 302, 200]);
    expect(chain.every((hop) => hop.remoteAddress === "127.0.0.1")).toBe(true);
  });

  it("ne suit pas la redirection quand maxRedirects vaut 0", async () => {
    const { response, chain } = expectOk(await local(`${base}/relative`, { maxRedirects: 0 }));
    expect(response.status).toBe(302);
    expect(chain).toHaveLength(1);
  });

  it("s'arrête au-delà de maxRedirects (TOO_MANY_REDIRECTS) en gardant la chaîne", async () => {
    const error = expectFailure(
      await local(`${base}/chaine/0`, { maxRedirects: 3 }),
      "TOO_MANY_REDIRECTS",
    );
    expect(error.chain?.map((hop) => hop.url)).toEqual(
      [0, 1, 2, 3].map((n) => `${base}/chaine/${n}`),
    );
  });

  it("détecte une boucle de redirection", async () => {
    const error = expectFailure(await local(`${base}/boucle`), "TOO_MANY_REDIRECTS");
    expect(error.message).toContain("Boucle");
    expect(error.chain).toHaveLength(1);
  });

  it.each([
    ["/vers-ftp", "schéma « ftp: »"],
    ["/vers-javascript", "schéma « javascript: »"],
    ["/sans-location", "Location absent"],
    ["/location-illisible", "destination illisible"],
    ["/vers-identifiants", "identifiants"],
    ["/vers-port", "port 8080"],
  ])("refuse la redirection %s (INVALID_REDIRECT : %s)", async (path, reason) => {
    const error = expectFailure(await local(`${base}${path}`), "INVALID_REDIRECT");
    expect(error.message).toContain(reason);
    expect(error.chain?.map((hop) => hop.status)).toEqual([302]);
  });

  describe("vers une adresse interdite, politique n'autorisant que le serveur de test", () => {
    const onlyTestServer = (address: string): boolean => address === "127.0.0.1";
    let fetcher: Fetcher = safeFetch;

    // Créé après le démarrage du serveur : son port n'est connu qu'à ce moment-là.
    beforeAll(() => {
      fetcher = createFetcher({
        isAllowed: onlyTestServer,
        allowedPorts: new Set([port, 80]),
        lookup: createSafeLookup({
          isAllowed: onlyTestServer,
          resolve: fakeDns({ "intranet.corp.test": ["10.0.0.5"] }),
        }),
      });
    });

    it("autorise bien le serveur de test lui-même", async () => {
      expect(expectOk(await fetcher(`${base}/relative`)).response.status).toBe(200);
    });

    it.each([
      ["/vers-boucle-ipv6", "::1"],
      ["/vers-metadonnees", "métadonnées cloud"],
      ["/vers-nom-interne", "« intranet.corp.test » pointe vers une adresse non publique"],
    ])("bloque la redirection %s (%s) et garde la réponse reçue", async (path, reason) => {
      const error = expectFailure(await fetcher(`${base}${path}`), "BLOCKED_ADDRESS");
      expect(error.message).toContain(reason);
      expect(error.chain?.map((hop) => hop.url)).toEqual([`${base}${path}`]);
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Corps de réponse
// ─────────────────────────────────────────────────────────────────────────────

describe("lecture du corps", () => {
  it("lit et décode une page HTML, avec l'adresse contactée et sans TLS", async () => {
    const { response } = expectOk(await local(`${base}/`));
    expect(response).toMatchObject({
      status: 200,
      body: HTML,
      bodyTruncated: false,
      remoteAddress: "127.0.0.1",
      tls: null,
    });
    expect(response.headers["content-type"]).toBe("text/html; charset=utf-8");
    expect(response.durationMs).toBeGreaterThanOrEqual(0);
  });

  it("décode selon le charset annoncé", async () => {
    expect(expectOk(await local(`${base}/latin1`)).response.body).toBe("Café crème");
  });

  it("se replie sur UTF-8 quand le charset est inconnu", async () => {
    expect(expectOk(await local(`${base}/charset-inconnu`)).response.body).toBe("Déjà vu");
  });

  it.each([
    ["/json", '{"message":"bonjour"}'],
    ["/sans-type", "texte sans type"],
  ])("lit le corps textuel de %s", async (path, body) => {
    expect(expectOk(await local(`${base}${path}`)).response.body).toBe(body);
  });

  it("ne lit pas un corps binaire (image)", async () => {
    const { response } = expectOk(await local(`${base}/image`));
    expect(response).toMatchObject({ status: 200, body: null, bodyTruncated: false });
  });

  it("ne lit pas le corps quand maxBodyBytes vaut 0", async () => {
    expect(expectOk(await local(`${base}/`, { maxBodyBytes: 0 })).response.body).toBeNull();
  });

  it("envoie une requête HEAD sans lire de corps", async () => {
    const { response } = expectOk(await local(`${base}/`, { method: "HEAD" }));
    expect(lastMethod).toBe("HEAD");
    expect(response.body).toBeNull();
  });

  it("tronque un corps trop long", async () => {
    const { response } = expectOk(await local(`${base}/gros`, { maxBodyBytes: 1024 * 1024 }));
    expect(response.body).toHaveLength(1024 * 1024);
    expect(response.bodyTruncated).toBe(true);
  });

  it.each(["gzip", "deflate", "br", "zstd"])("décompresse un corps %s", async (encoding) => {
    const { response } = expectOk(await local(`${base}/encodage/${encoding}`));
    expect(response.headers["content-encoding"]).toBe(encoding);
    expect(response.body).toBe(HTML);
  });

  it("résiste à une bombe de décompression (taille comptée après décompression)", async () => {
    const { response } = expectOk(await local(`${base}/bombe`, { maxBodyBytes: 64 * 1024 }));
    expect(response.body).toHaveLength(64 * 1024);
    expect(response.bodyTruncated).toBe(true);
  });

  it("signale un corps compressé illisible (PROTOCOL_ERROR)", async () => {
    const error = expectFailure(await local(`${base}/gzip-corrompu`), "PROTOCOL_ERROR");
    expect(error.message).toContain("compressé");
  });

  it("ne lit pas un corps dont l'encodage est inconnu", async () => {
    expect(expectOk(await local(`${base}/encodage-inconnu`)).response.body).toBeNull();
  });

  it("renvoie une page d'erreur 404 comme une réponse (succès réseau)", async () => {
    const { response } = expectOk(await local(`${base}/inexistant`));
    expect(response.status).toBe(404);
    expect(response.body).toBe("<p>Introuvable</p>");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// En-têtes
// ─────────────────────────────────────────────────────────────────────────────

describe("en-têtes", () => {
  it("garde les en-têtes dupliqués et chaque Set-Cookie séparément", async () => {
    const { response } = expectOk(await local(`${base}/doublons`));
    expect(response.headers["content-security-policy"]).toBe(
      "default-src 'self', frame-ancestors 'none'",
    );
    expect(response.headers.server).toBe("nginx, apache");
    expect(response.setCookies).toEqual([
      "session=abc; Secure; HttpOnly",
      "theme=sombre; Max-Age=3600",
    ]);
    expect(response.headers["set-cookie"]).toBeUndefined();
    const rawServers = response.rawHeaders.filter(([name]) => name.toLowerCase() === "server");
    expect(rawServers).toHaveLength(2);
  });

  it("accepte des en-têtes de plus de 16 Kio (grosse CSP)", async () => {
    const { response } = expectOk(await local(`${base}/gros-en-tete`));
    expect(response.headers["x-grand"]).toHaveLength(20_000);
  });

  it("refuse des en-têtes de plus de 64 Kio (PROTOCOL_ERROR)", async () => {
    const error = expectFailure(await local(`${base}/en-tete-geant`), "PROTOCOL_ERROR");
    expect(error.message).toContain("64 Kio");
  });

  it("envoie les en-têtes par défaut et ceux de l'appelant, jamais d'identifiants", async () => {
    const origin = "https://secuscan-cors-probe.invalid";
    const { response } = expectOk(await local(`${base}/echo`, { headers: { Origin: origin } }));
    const received: unknown = JSON.parse(response.body ?? "{}");
    expect(received).toMatchObject({
      "user-agent": USER_AGENT,
      accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
      "accept-language": "fr-FR,fr;q=0.9,en;q=0.8",
      "accept-encoding": "gzip, deflate, br",
      origin,
    });
    expect(received).not.toHaveProperty("cookie");
    expect(received).not.toHaveProperty("authorization");
  });

  it("utilise le User-Agent configuré", async () => {
    const custom = createFetcher({
      allowPrivate: true,
      allowedPorts: new Set([port]),
      userAgent: "SecuScan-Test/1.0",
    });
    const { response } = expectOk(await custom(`${base}/echo`));
    expect(JSON.parse(response.body ?? "{}")).toMatchObject({ "user-agent": "SecuScan-Test/1.0" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Délais, annulation et erreurs réseau
// ─────────────────────────────────────────────────────────────────────────────

describe("délais et erreurs réseau", () => {
  it("abandonne une réponse trop lente (TIMEOUT)", async () => {
    const error = expectFailure(
      await local(`${base}/en-tetes-lents`, { timeoutMs: 200 }),
      "TIMEOUT",
    );
    expect(error.message).toContain("délai imparti (0,2 s)");
  });

  it("qualifie de TIMEOUT une coupure survenue pendant le corps (et non de CONNECTION_RESET)", async () => {
    expectFailure(await local(`${base}/goutte-a-goutte`, { timeoutMs: 300 }), "TIMEOUT");
  });

  it("distingue le délai global du scan…", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(new DOMException("Délai global", "TimeoutError")), 100);
    const error = expectFailure(
      await local(`${base}/en-tetes-lents`, { signal: controller.signal, timeoutMs: 5_000 }),
      "TIMEOUT",
    );
    expect(error.message).toContain("délai global du scan");
  });

  it("… d'une simple annulation", async () => {
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 100);
    const error = expectFailure(
      await local(`${base}/en-tetes-lents`, { signal: controller.signal, timeoutMs: 5_000 }),
      "UNKNOWN",
    );
    expect(error.message).toContain("annulée");
  });

  it("signale une connexion refusée", async () => {
    const refusedPort = await closedPort();
    const fetcher = createFetcher({ allowPrivate: true, allowedPorts: new Set([refusedPort]) });
    expectFailure(await fetcher(`http://127.0.0.1:${refusedPort}/`), "CONNECTION_REFUSED");
  });

  it("se connecte via la lookup (Happy Eyeballs) quand la politique l'autorise", async () => {
    const fetcher = createFetcher({
      allowPrivate: true,
      allowedPorts: new Set([port]),
      lookup: createSafeLookup({
        allowPrivate: true,
        resolve: fakeDns({ "site.example": ["127.0.0.1"] }),
      }),
    });
    const { response } = expectOk(await fetcher(`http://site.example:${port}/echo`));
    expect(response.remoteAddress).toBe("127.0.0.1");
    expect(JSON.parse(response.body ?? "{}")).toMatchObject({ host: `site.example:${port}` });
  });
});

describe("toNetworkError : traduction des erreurs de Node.js", () => {
  it.each([
    ["ENOTFOUND", "DNS_FAILURE"],
    ["EAI_AGAIN", "DNS_FAILURE"],
    ["ECONNREFUSED", "CONNECTION_REFUSED"],
    ["EHOSTUNREACH", "CONNECTION_REFUSED"],
    ["ECONNRESET", "CONNECTION_RESET"],
    ["EPIPE", "CONNECTION_RESET"],
    ["ETIMEDOUT", "TIMEOUT"],
    ["HPE_INVALID_CONSTANT", "PROTOCOL_ERROR"],
    ["HPE_HEADER_OVERFLOW", "PROTOCOL_ERROR"],
    ["ERR_SSL_WRONG_VERSION_NUMBER", "TLS_ERROR"],
    ["ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION", "TLS_ERROR"],
    ["Z_DATA_ERROR", "PROTOCOL_ERROR"],
    ["ERR_QUELCONQUE", "UNKNOWN"],
  ] as const)("%s → %s", (nodeCode, expected) => {
    const error = toNetworkError(nodeError(nodeCode, `message ${nodeCode}`));
    expect(error.code).toBe(expected);
    expect(error.message.length).toBeGreaterThan(10);
    expect(error.detail).toBe(`message ${nodeCode}`);
  });

  it("traduit un refus anti-SSRF de la lookup en BLOCKED_ADDRESS", () => {
    const blocked = new BlockedAddressError("intranet.example", {
      allowed: false,
      address: "10.0.0.5",
      reason: "réseau privé (RFC 1918)",
      range: "private",
    });
    expect(toNetworkError(blocked)).toMatchObject({
      code: "BLOCKED_ADDRESS",
      detail: "private",
    });
  });

  it("préfère la tentative la plus parlante d'une AggregateError (Happy Eyeballs)", () => {
    const aggregate = new AggregateError([
      nodeError("ENETUNREACH", "connect ENETUNREACH 2001:db8::1:443"),
      nodeError("ECONNREFUSED", "connect ECONNREFUSED 93.184.215.14:443"),
    ]);
    expect(toNetworkError(aggregate)).toMatchObject({
      code: "CONNECTION_REFUSED",
      detail: "connect ECONNREFUSED 93.184.215.14:443",
    });
  });

  it("accepte une valeur qui n'est pas une Error", () => {
    expect(toNetworkError("panne")).toMatchObject({ code: "UNKNOWN", detail: "panne" });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// HTTPS avec un certificat auto-signé jetable
// ─────────────────────────────────────────────────────────────────────────────

const HAS_OPENSSL = spawnSync("openssl", ["version"], { stdio: "ignore" }).status === 0;

/** Configuration OpenSSL : certificat pour secuscan.test, www.secuscan.test et 127.0.0.1. */
const OPENSSL_CONFIG = [
  "[req]",
  "distinguished_name = dn",
  "x509_extensions = v3",
  "prompt = no",
  "[dn]",
  "CN = secuscan.test",
  "O = SecuScan Tests",
  "[v3]",
  "subjectAltName = DNS:secuscan.test, DNS:www.secuscan.test, IP:127.0.0.1",
].join("\n");

/** Lance une commande et échoue avec sa sortie d'erreur si elle ne réussit pas. */
function run(command: string, args: string[]): void {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) throw new Error(`${command} ${args[0]} a échoué : ${result.stderr}`);
}

/** Génère une clé RSA et un certificat auto-signé jetables (dossier temporaire supprimé aussitôt). */
function generateSelfSignedCertificate(): { key: string; cert: string } {
  const directory = mkdtempSync(join(tmpdir(), "secuscan-tls-"));
  try {
    const configPath = join(directory, "openssl.cnf");
    const keyPath = join(directory, "key.pem");
    const certPath = join(directory, "cert.pem");
    writeFileSync(configPath, OPENSSL_CONFIG);
    run("openssl", [
      "genpkey",
      "-algorithm",
      "RSA",
      "-pkeyopt",
      "rsa_keygen_bits:2048",
      "-out",
      keyPath,
    ]);
    run("openssl", [
      "req",
      "-x509",
      "-new",
      "-key",
      keyPath,
      "-days",
      "30",
      "-config",
      configPath,
      "-out",
      certPath,
    ]);
    return { key: readFileSync(keyPath, "utf8"), cert: readFileSync(certPath, "utf8") };
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

describe.skipIf(!HAS_OPENSSL)(
  "HTTPS : un certificat invalide n'empêche pas de lire la réponse",
  () => {
    let httpsServer: HttpsServer | undefined;
    let tlsPort = 0;
    let fetcher: Fetcher = safeFetch;

    beforeAll(async () => {
      httpsServer = createHttpsServer(generateSelfSignedCertificate(), (_request, response) => {
        response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
        response.end("<p>Bonjour en HTTPS</p>");
      });
      tlsPort = await listen(httpsServer);
      fetcher = createFetcher({
        allowPrivate: true,
        allowedPorts: new Set([tlsPort]),
        lookup: createSafeLookup({
          allowPrivate: true,
          resolve: fakeDns({ "secuscan.test": ["127.0.0.1"], "autre-nom.test": ["127.0.0.1"] }),
        }),
      });
    });

    afterAll(async () => {
      if (httpsServer) await stop(httpsServer);
    });

    it("lit la page et rapporte le certificat auto-signé dans response.tls", async () => {
      const { response } = expectOk(await fetcher(`https://secuscan.test:${tlsPort}/`));
      expect(response).toMatchObject({
        status: 200,
        body: "<p>Bonjour en HTTPS</p>",
        remoteAddress: "127.0.0.1",
        tls: {
          authorized: false,
          authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT",
          protocol: "TLSv1.3",
        },
      });
    });

    it("vérifie le nom d'hôte même quand la chaîne est invalide (Node.js le masquerait)", async () => {
      const { response } = expectOk(await fetcher(`https://autre-nom.test:${tlsPort}/`));
      expect(response.tls).toMatchObject({
        authorized: false,
        authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID",
      });
    });

    it("vérifie une IP littérale contre les adresses IP du certificat", async () => {
      const { response } = expectOk(await fetcher(`https://127.0.0.1:${tlsPort}/`));
      expect(response.tls?.authorizationError).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
    });
  },
);
