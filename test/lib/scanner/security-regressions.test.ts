/**
 * Tests de non-régression des failles trouvées par la revue de sécurité (novembre 2026).
 *
 * 1. Déni de service par expression régulière (« ReDoS ») : plusieurs analyseurs utilisaient des
 *    expressions au coût quadratique. Une page piégée (balise <meta> CSP de 80 000 espaces,
 *    srcset de 80 000 virgules…) bloquait le serveur pendant plus de dix secondes, car le calcul
 *    est synchrone : le délai global du scan ne peut pas l'interrompre. Ces tests imposent un
 *    temps d'analyse court sur les pires entrées connues, à leur taille maximale réaliste
 *    (64 Kio pour un en-tête, 2 Mio pour une page).
 * 2. Fuite d'informations internes : un site qui redirigeait ses sondes vers « db.interne » faisait
 *    afficher dans le rapport l'adresse privée que le DNS de l'hébergeur associe à ce nom.
 */

import { createServer, type Server } from "node:http";
import { failure, ok } from "@test/helpers/context";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createFetcher } from "@/lib/scanner/network/http-client";
import { createSafeLookup, type HostResolver } from "@/lib/scanner/network/safe-lookup";
import { scanSite } from "@/lib/scanner/scan";
import type { Fetcher } from "@/lib/scanner/types";

/** Serveur local qui joue le site analysé ; son comportement est fixé par chaque test. */
let handler: (
  url: string,
  headers: Record<string, string | string[] | undefined>,
) => {
  status: number;
  headers: Record<string, string>;
  body: string;
} = () => ({ status: 200, headers: {}, body: "" });

const server: Server = createServer((request, response) => {
  const answer = handler(request.url ?? "/", request.headers);
  response.writeHead(answer.status, answer.headers);
  response.end(answer.body);
});
let port = 0;

beforeAll(async () => {
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (address !== null && typeof address !== "string") port = address.port;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

/**
 * Scan complet de « site-piege.fr », servi par le serveur local : le client HTTP réel est utilisé
 * (anti-SSRF compris), seule la destination des connexions est détournée vers 127.0.0.1.
 */
async function scanTrapSite(lookup?: ReturnType<typeof createSafeLookup>) {
  const isAllowed = (address: string) => address === "127.0.0.1";
  const inner = createFetcher({
    isAllowed,
    allowedPorts: new Set([80, 443, port]),
    ...(lookup ? { lookup } : {}),
  });
  const fetch: Fetcher = (url, options) =>
    inner(url.replace(/^https?:\/\/site-piege\.fr/, `http://127.0.0.1:${port}`), options);
  const started = performance.now();
  const report = await scanSite("site-piege.fr", {
    fetch,
    resolveHost: async () => ok([{ address: "93.184.215.14", family: 4 }]),
    probeTls: async () => failure("TLS_ERROR", "Pas de TLS sur le serveur de test."),
    resolveCaa: async () => ok({ domain: null, records: [] }),
  });
  return { report, elapsedMs: performance.now() - started };
}

/** Page HTML servie avec les en-têtes donnés. */
function htmlPage(body: string, headers: Record<string, string> = {}) {
  return () => ({
    status: 200,
    headers: { "content-type": "text/html; charset=utf-8", ...headers },
    body,
  });
}

/** Limite généreuse (machines de CI lentes) : les versions quadratiques prenaient des secondes. */
const MAX_SCAN_MS = 1_500;

/**
 * Taille des motifs piégés. Assez grande pour qu'une version quadratique dépasse nettement la
 * limite (≈ 7 s pour 60 000 espaces), assez petite pour qu'elle finisse quand même : avec 2 Mio,
 * une régression bloquerait le processus de test pendant des heures au lieu d'échouer, car un
 * calcul synchrone ne peut pas être interrompu par le délai du test.
 */
const TRAP_SIZE = 60_000;

/** Page HTML contenant `unit` répété TRAP_SIZE fois entre `before` et `after`. */
function trapPage(before: string, unit: string, after: string): string {
  return `${before}${unit.repeat(TRAP_SIZE)}${after}`;
}

describe("déni de service par expression régulière (ReDoS)", () => {
  it.each([
    [
      "balise <meta> CSP remplie d'espaces",
      htmlPage(
        trapPage('<meta http-equiv="Content-Security-Policy" content="script-src', " ", `'self'">`),
      ),
    ],
    ["srcset rempli de virgules", htmlPage(trapPage('<img src="a.png" srcset="a', ",", 'b,">'))],
    [
      "en-tête CSP rempli d'espaces",
      htmlPage("<p>x</p>", {
        "content-security-policy": `script-src${" ".repeat(TRAP_SIZE)}'self'`,
      }),
    ],
    ["en-tête Server rempli de chiffres", htmlPage("<p>x</p>", { server: "1".repeat(TRAP_SIZE) })],
    [
      "Permissions-Policy remplie d'espaces",
      htmlPage("<p>x</p>", { "permissions-policy": `camera=(${" ".repeat(TRAP_SIZE)}!` }),
    ],
  ])("%s : analyse en moins de 1,5 s", async (_label, page) => {
    handler = page;
    const { report, elapsedMs } = await scanTrapSite();
    expect(report.checks).toHaveLength(18);
    expect(elapsedMs).toBeLessThan(MAX_SCAN_MS);
  });

  it("security.txt piégé (espaces puis retour chariot isolé) : analyse en moins de 1,5 s", async () => {
    handler = (url) =>
      url === "/.well-known/security.txt"
        ? {
            status: 200,
            headers: { "content-type": "text/plain; charset=utf-8" },
            body: `Contact:${" ".repeat(TRAP_SIZE)}x\ry\n`,
          }
        : htmlPage("<p>x</p>")();
    const { elapsedMs } = await scanTrapSite();
    expect(elapsedMs).toBeLessThan(MAX_SCAN_MS);
  });
});

describe("aucune fuite d'information sur le réseau interne de l'hébergeur", () => {
  it("ne cite pas les adresses privées résolues pour des noms internes", async () => {
    // Le site piégé redirige security.txt et la sonde CORS vers des noms internes.
    handler = (url, headers) => {
      if (url === "/.well-known/security.txt") {
        return { status: 302, headers: { location: "http://db.internal.corp/" }, body: "" };
      }
      if (headers.origin !== undefined) {
        return { status: 302, headers: { location: "http://redis/" }, body: "" };
      }
      return htmlPage("<p>x</p>")();
    };
    // DNS « interne » de l'hébergeur (Docker, Kubernetes, zone privée…).
    const internalDns: HostResolver = async (hostname) => {
      const table: Record<string, string> = {
        "db.internal.corp": "10.20.30.40",
        redis: "172.18.0.5",
        "127.0.0.1": "127.0.0.1",
      };
      const address = table[hostname];
      return address === undefined ? [] : [{ address, family: 4 }];
    };
    const lookup = createSafeLookup({
      isAllowed: (address) => address === "127.0.0.1",
      resolve: internalDns,
    });

    const { report } = await scanTrapSite(lookup);

    // Les connexions ont bien été refusées…
    const blocked = report.probeErrors.filter((error) => error.code === "BLOCKED_ADDRESS");
    expect(blocked.map((error) => error.probe).sort()).toEqual(["cors", "securityTxt"]);
    // … sans que le rapport révèle ce que le DNS interne a répondu.
    const json = JSON.stringify(report);
    expect(json).not.toContain("10.20.30.40");
    expect(json).not.toContain("172.18.0.5");
    expect(json).toContain("« db.internal.corp » pointe vers une adresse non publique");
  });
});
