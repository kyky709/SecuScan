/**
 * Tests de la sonde TLS (tls-probe.ts), sans accès à Internet.
 *
 * Un serveur TLS local (127.0.0.1) présente un certificat auto-signé jetable, généré au début des
 * tests avec la commande openssl dans un dossier temporaire aussitôt supprimé (aucune clé n'est
 * versionnée). Les tests sont ignorés si openssl est absent. Des serveurs TCP minimalistes simulent
 * les pannes : serveur muet (délai), serveur qui ne parle pas TLS, port fermé.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer as createTcpServer, type Server as NetServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer as createTlsServer, type TlsOptions } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createSafeLookup } from "@/lib/scanner/network/safe-lookup";
import { createTlsProber, interpretLegacyFailure, probeTls } from "@/lib/scanner/network/tls-probe";
import type {
  NetworkError,
  NetworkErrorCode,
  Result,
  TlsInfo,
  TlsProber,
} from "@/lib/scanner/types";

// ─────────────────────────────────────────────────────────────────────────────
// Outils de test
// ─────────────────────────────────────────────────────────────────────────────

/** Renvoie la valeur d'un Result réussi, ou fait échouer le test avec l'erreur reçue. */
function expectOk(result: Result<TlsInfo>): TlsInfo {
  if (!result.ok) {
    throw new Error(`Échec inattendu : ${result.error.code} – ${result.error.message}`);
  }
  return result.value;
}

/** Vérifie qu'un Result est un échec du code attendu et renvoie l'erreur. */
function expectFailure(result: Result<TlsInfo>, code: NetworkErrorCode): NetworkError {
  if (result.ok) throw new Error("Un échec était attendu.");
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

/** Serveur dont on suit les connexions, pour les fermer à la fin et les compter. */
interface TrackedServer {
  server: NetServer;
  port: number;
  /** Nombre de connexions TCP reçues. */
  connections: () => number;
  stop: () => Promise<void>;
}

/** Démarre `server` en suivant ses connexions. */
async function track(server: NetServer): Promise<TrackedServer> {
  const sockets = new Set<Socket>();
  let count = 0;
  server.on("connection", (socket: Socket) => {
    count += 1;
    sockets.add(socket);
    socket.on("error", () => undefined); // le client coupe brutalement : normal ici
    socket.on("close", () => sockets.delete(socket));
  });
  const port = await listen(server);
  return {
    server,
    port,
    connections: () => count,
    stop: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

/** Serveur TLS de test qui garde la connexion ouverte (c'est le client qui la ferme). */
function tlsServer(options: TlsOptions): NetServer {
  const server = createTlsServer({ ALPNProtocols: ["h2", "http/1.1"], ...options }, (socket) => {
    socket.on("error", () => undefined);
  });
  server.on("tlsClientError", () => undefined); // négociations refusées (anciens protocoles)
  return server;
}

/** Port sur lequel plus rien n'écoute (connexion refusée garantie). */
async function closedPort(): Promise<number> {
  const server = createTcpServer();
  const freePort = await listen(server);
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return freePort;
}

/** Erreur Node.js simulée, avec son code. */
function nodeError(code: string): Error {
  return Object.assign(new Error(code), { code });
}

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

/** DNS simulé : tous les noms de test pointent vers le serveur local. */
const testLookup = createSafeLookup({
  allowPrivate: true,
  resolve: async () => [{ address: "127.0.0.1", family: 4 }],
});

/** Sonde de test : serveur local autorisé, noms résolus vers 127.0.0.1. */
const testProber: TlsProber = createTlsProber({ allowPrivate: true, lookup: testLookup });

// ─────────────────────────────────────────────────────────────────────────────
// Sonde contre un vrai serveur TLS local
// ─────────────────────────────────────────────────────────────────────────────

describe.skipIf(!HAS_OPENSSL)("sonde TLS contre un serveur local au certificat auto-signé", () => {
  let modern: TrackedServer | undefined;
  let legacy: TrackedServer | undefined;
  let modernPort = 0;
  let legacyPort = 0;

  beforeAll(async () => {
    const credentials = generateSelfSignedCertificate();
    // Serveur moderne : TLS 1.2 minimum (réglage par défaut de Node.js).
    modern = await track(tlsServer(credentials));
    // Serveur obsolète : accepte encore TLS 1.0 et 1.1.
    legacy = await track(
      tlsServer({ ...credentials, minVersion: "TLSv1", ciphers: "DEFAULT@SECLEVEL=0" }),
    );
    modernPort = modern.port;
    legacyPort = legacy.port;
  });

  afterAll(async () => {
    await modern?.stop();
    await legacy?.stop();
  });

  it("décrit la connexion, le certificat et la chaîne", async () => {
    const info = expectOk(await testProber("secuscan.test", { port: modernPort }));
    expect(info).toMatchObject({
      hostname: "secuscan.test",
      address: "127.0.0.1",
      port: modernPort,
      protocol: "TLSv1.3",
      alpnProtocol: "h2",
      authorized: false,
      authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT",
      chain: [{ subject: "secuscan.test", issuer: "secuscan.test" }],
      legacyProtocols: { tls10: false, tls11: false },
    });
    expect(info.cipher).toMatch(/^TLS_/);
  });

  it("remplit tous les champs du certificat", async () => {
    const { certificate } = expectOk(await testProber("secuscan.test", { port: modernPort }));
    expect(certificate).toMatchObject({
      subject: "secuscan.test",
      subjectAltNames: ["secuscan.test", "www.secuscan.test", "127.0.0.1"],
      issuer: "SecuScan Tests",
      keyType: "RSA",
      keyBits: 2048,
      selfSigned: true,
    });
    expect(certificate?.serialNumber).toMatch(/^[0-9A-F]+$/i);
    expect(certificate?.fingerprint256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    expect(new Date(certificate?.validFrom ?? "").getTime()).toBeLessThanOrEqual(Date.now());
    expect(certificate?.validTo).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    expect(certificate?.daysRemaining).toBeGreaterThanOrEqual(28);
    expect(certificate?.daysRemaining).toBeLessThanOrEqual(30);
  });

  it("vérifie le nom d'hôte même quand la chaîne est invalide (Node.js le masquerait)", async () => {
    const info = expectOk(await testProber("autre-nom.test", { port: modernPort }));
    expect(info).toMatchObject({
      authorized: false,
      authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID",
    });
  });

  it("sonde une IP littérale sans SNI, vérifiée contre les IP du certificat", async () => {
    const info = expectOk(await testProber("127.0.0.1", { port: modernPort }));
    expect(info).toMatchObject({
      hostname: "127.0.0.1",
      authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT",
    });
  });

  it("détecte un serveur qui accepte encore TLS 1.0 et TLS 1.1", async () => {
    const info = expectOk(await testProber("secuscan.test", { port: legacyPort }));
    expect(info.protocol).toBe("TLSv1.3");
    expect(info.legacyProtocols).toEqual({ tls10: true, tls11: true });
  });

  it("ne teste pas les anciens protocoles si legacyProbe vaut false (une seule connexion)", async () => {
    const before = modern?.connections() ?? 0;
    const prober = createTlsProber({ allowPrivate: true, lookup: testLookup, legacyProbe: false });
    const info = expectOk(await prober("secuscan.test", { port: modernPort }));
    expect(info.legacyProtocols).toEqual({ tls10: null, tls11: null });
    expect((modern?.connections() ?? 0) - before).toBe(1);
  });

  it.each([
    "127.0.0.1",
    "[::1]",
    "localhost",
  ])("la sonde par défaut refuse %s sans se connecter (anti-SSRF)", async (host) => {
    const before = modern?.connections() ?? 0;
    const error = expectFailure(await probeTls(host, { port: modernPort }), "BLOCKED_ADDRESS");
    expect(error.message).toContain("anti-SSRF");
    expect(modern?.connections()).toBe(before);
  });

  it("distingue une simple annulation…", async () => {
    const options = { port: modernPort, signal: AbortSignal.abort() };
    const error = expectFailure(await testProber("secuscan.test", options), "UNKNOWN");
    expect(error.message).toContain("annulée");
  });

  it("… du délai global du scan", async () => {
    const controller = new AbortController();
    controller.abort(new DOMException("Délai global", "TimeoutError"));
    const options = { port: modernPort, signal: controller.signal };
    const error = expectFailure(await testProber("secuscan.test", options), "TIMEOUT");
    expect(error.message).toContain("délai global du scan");
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Pannes simulées
// ─────────────────────────────────────────────────────────────────────────────

describe("sonde TLS : pannes du serveur", () => {
  it("signale une connexion refusée", async () => {
    const port = await closedPort();
    expectFailure(await testProber("secuscan.test", { port }), "CONNECTION_REFUSED");
  });

  it("abandonne un serveur muet (TIMEOUT)", async () => {
    const silent = await track(createTcpServer(() => undefined));
    try {
      const error = expectFailure(
        await testProber("secuscan.test", { port: silent.port, timeoutMs: 200 }),
        "TIMEOUT",
      );
      expect(error.message).toContain("délai imparti (0,2 s)");
    } finally {
      await silent.stop();
    }
  });

  it("signale un serveur qui ne parle pas TLS (TLS_ERROR)", async () => {
    const plain = await track(
      createTcpServer((socket) => socket.write("HTTP/1.1 400 Bad Request\r\n\r\n")),
    );
    try {
      expectFailure(await testProber("secuscan.test", { port: plain.port }), "TLS_ERROR");
    } finally {
      await plain.stop();
    }
  });
});

describe("interpretLegacyFailure : refus de version ou test non concluant", () => {
  it.each([
    "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION",
    "ERR_SSL_UNSUPPORTED_PROTOCOL",
    "ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE",
    "ERR_SSL_TLS_ALERT_HANDSHAKE_FAILURE",
    "ERR_SSL_WRONG_VERSION_NUMBER",
  ])("%s prouve un refus (false)", (code) => {
    expect(interpretLegacyFailure(nodeError(code))).toBe(false);
  });

  it.each([
    "ERR_SSL_NO_PROTOCOLS_AVAILABLE",
    "ECONNRESET",
    "ETIMEDOUT",
    "ECONNREFUSED",
    "EBLOCKED",
    "ABORT_ERR",
  ])("%s ne prouve rien (null)", (code) => {
    expect(interpretLegacyFailure(nodeError(code))).toBeNull();
  });

  it("une erreur sans code ne prouve rien (null)", () => {
    expect(interpretLegacyFailure(new DOMException("délai", "TimeoutError"))).toBeNull();
  });
});
