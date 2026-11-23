/**
 * Tests de la résolution DNS sûre (safe-lookup.ts).
 *
 * Le DNS est simulé par un résolveur injecté : aucun accès à Internet. Seul « localhost » passe par
 * la vraie résolution du système (/etc/hosts), pour vérifier la politique par défaut de bout en bout.
 */
import type { LookupAddress, LookupOptions } from "node:dns";
import type { LookupFunction } from "node:net";
import { describe, expect, it } from "vitest";
import {
  BlockedAddressError,
  createSafeLookup,
  errorCode,
  type HostResolver,
  resolveHost,
  untilAborted,
} from "@/lib/scanner/network/safe-lookup";
import type { NetworkError, NetworkErrorCode, Result } from "@/lib/scanner/types";

/** Réponse capturée d'une fonction `lookup`. */
interface LookupAnswer {
  error: NodeJS.ErrnoException | null;
  address: string | LookupAddress[];
  family: number | undefined;
}

/** Appelle une fonction `lookup` comme le fait Node.js et capture sa réponse. */
function callLookup(
  lookup: LookupFunction,
  hostname: string,
  options: LookupOptions,
): Promise<LookupAnswer> {
  return new Promise((resolve) => {
    lookup(hostname, options, (error, address, family) => resolve({ error, address, family }));
  });
}

/** DNS simulé : chaque nom renvoie les adresses de la table (aucune si le nom est inconnu). */
function fakeDns(table: Record<string, string[]>): HostResolver {
  return async (hostname) =>
    (table[hostname] ?? []).map((address) => ({
      address,
      family: address.includes(":") ? 6 : 4,
    }));
}

/** Résolveur qui échoue comme getaddrinfo pour un nom inexistant. */
const notFound: HostResolver = async (hostname) => {
  throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: "ENOTFOUND" });
};

/** Résolveur qui ne doit jamais être appelé (IP littérale : pas de DNS). */
const unexpectedDns: HostResolver = async () => {
  throw new Error("Le DNS n'aurait pas dû être interrogé.");
};

/** Vérifie qu'un Result est un échec du code attendu et renvoie l'erreur. */
function expectFailure<T>(result: Result<T>, code: NetworkErrorCode): NetworkError {
  if (result.ok) throw new Error("Un échec était attendu.");
  expect(result.error.code).toBe(code);
  return result.error;
}

/** Comme Node.js 24 avec Happy Eyeballs : toutes les adresses sont demandées. */
const HAPPY_EYEBALLS: LookupOptions = { family: undefined, hints: 1024, all: true };

describe("createSafeLookup : forme des réponses attendue par Node.js", () => {
  const lookup = createSafeLookup({
    resolve: fakeDns({
      "public.example": ["93.184.215.14", "2606:2800:21f:cb07:6820:80da:af6b:8b2c"],
    }),
  });

  it("répond par un tableau d'adresses quand Node.js demande all: true", async () => {
    const answer = await callLookup(lookup, "public.example", HAPPY_EYEBALLS);
    expect(answer.error).toBeNull();
    expect(answer.address).toEqual([
      { address: "93.184.215.14", family: 4 },
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
  });

  it("répond par (adresse, famille) quand all est absent", async () => {
    const answer = await callLookup(lookup, "public.example", {});
    expect(answer).toEqual({ error: null, address: "93.184.215.14", family: 4 });
  });

  it("respecte la famille imposée par la requête", async () => {
    const answer = await callLookup(lookup, "public.example", { family: 6, all: true });
    expect(answer.address).toEqual([
      { address: "2606:2800:21f:cb07:6820:80da:af6b:8b2c", family: 6 },
    ]);
  });

  it("renvoie ENOTFOUND, jamais un tableau vide, si aucune adresse ne convient", async () => {
    const onlyIpv4 = createSafeLookup({ resolve: fakeDns({ "v4.example": ["93.184.215.14"] }) });
    const answer = await callLookup(onlyIpv4, "v4.example", { family: 6, all: true });
    expect(answer.error?.code).toBe("ENOTFOUND");
  });

  it("renvoie ENOTFOUND quand le DNS ne renvoie aucune adresse", async () => {
    const empty = createSafeLookup({ resolve: fakeDns({}) });
    const answer = await callLookup(empty, "vide.example", HAPPY_EYEBALLS);
    expect(answer.error?.code).toBe("ENOTFOUND");
  });

  it("transmet les erreurs du résolveur", async () => {
    const answer = await callLookup(createSafeLookup({ resolve: notFound }), "x.example", {});
    expect(answer.error?.code).toBe("ENOTFOUND");
  });
});

describe("createSafeLookup : refus anti-SSRF", () => {
  it("refuse un nom qui pointe vers une adresse privée (erreur EBLOCKED)", async () => {
    const lookup = createSafeLookup({ resolve: fakeDns({ "intranet.example": ["10.0.0.5"] }) });
    const answer = await callLookup(lookup, "intranet.example", HAPPY_EYEBALLS);
    expect(answer.error).toBeInstanceOf(BlockedAddressError);
    expect(answer.error?.code).toBe("EBLOCKED");
    // L'adresse interne n'est pas citée : le message finit dans le rapport du visiteur.
    expect(answer.error?.message).toContain("pointe vers une adresse non publique : réseau privé");
    expect(answer.error?.message).not.toContain("10.0.0.5");
  });

  it("refuse un nom avec une adresse publique ET une adresse privée", async () => {
    const lookup = createSafeLookup({
      resolve: fakeDns({ "mixte.example": ["93.184.215.14", "169.254.169.254"] }),
    });
    const answer = await callLookup(lookup, "mixte.example", HAPPY_EYEBALLS);
    expect(answer.error).toBeInstanceOf(BlockedAddressError);
    expect(answer.error).toMatchObject({ address: "169.254.169.254", range: "linkLocal" });
  });

  it("refuse localhost avec la vraie résolution du système (politique par défaut)", async () => {
    const answer = await callLookup(createSafeLookup(), "localhost", HAPPY_EYEBALLS);
    expect(answer.error?.code).toBe("EBLOCKED");
  });

  it("allowPrivate laisse passer une adresse locale (tests uniquement)", async () => {
    const lookup = createSafeLookup({
      allowPrivate: true,
      resolve: fakeDns({ "test.example": ["127.0.0.1"] }),
    });
    const answer = await callLookup(lookup, "test.example", HAPPY_EYEBALLS);
    expect(answer.address).toEqual([{ address: "127.0.0.1", family: 4 }]);
  });

  it("isAllowed n'autorise que les adresses choisies, et refuse le nom au moindre écart", async () => {
    const options = { isAllowed: (address: string) => address === "127.0.0.1" };
    const single = createSafeLookup({ ...options, resolve: fakeDns({ a: ["127.0.0.1"] }) });
    expect((await callLookup(single, "a", HAPPY_EYEBALLS)).error).toBeNull();
    const both = createSafeLookup({ ...options, resolve: fakeDns({ b: ["127.0.0.1", "::1"] }) });
    expect((await callLookup(both, "b", HAPPY_EYEBALLS)).error?.code).toBe("EBLOCKED");
  });
});

describe("resolveHost : pré-contrôle de l'orchestrateur", () => {
  it("accepte une IPv4 publique littérale sans interroger le DNS", async () => {
    expect(await resolveHost("8.8.8.8", { resolve: unexpectedDns })).toEqual({
      ok: true,
      value: [{ address: "8.8.8.8", family: 4 }],
    });
  });

  it("accepte une IPv6 publique entre crochets", async () => {
    expect(await resolveHost("[2606:4700:4700::1111]", { resolve: unexpectedDns })).toEqual({
      ok: true,
      value: [{ address: "2606:4700:4700::1111", family: 6 }],
    });
  });

  it.each([
    ["127.0.0.1", "bouclage"],
    ["169.254.169.254", "métadonnées cloud"],
    ["[::1]", "bouclage"],
    ["[fd00:ec2::254]", "réseau privé IPv6"],
  ])("refuse l'IP littérale %s (%s)", async (host, reason) => {
    const error = expectFailure(
      await resolveHost(host, { resolve: unexpectedDns }),
      "BLOCKED_ADDRESS",
    );
    expect(error.message).toContain(reason);
    expect(error.message).toContain("anti-SSRF");
  });

  it("renvoie toutes les adresses d'un nom public", async () => {
    const resolve = fakeDns({ "site.example": ["93.184.215.14", "2606:4700:4700::1111"] });
    expect(await resolveHost("site.example", { resolve })).toEqual({
      ok: true,
      value: [
        { address: "93.184.215.14", family: 4 },
        { address: "2606:4700:4700::1111", family: 6 },
      ],
    });
  });

  it("refuse un nom qui pointe vers une adresse privée, avec un message explicite", async () => {
    const resolve = fakeDns({ "intranet.example": ["192.168.1.10"] });
    const error = expectFailure(
      await resolveHost("intranet.example", { resolve }),
      "BLOCKED_ADDRESS",
    );
    expect(error.message).toContain("« intranet.example » pointe vers une adresse non publique");
    expect(error.message).not.toContain("192.168.1.10");
    expect(error.message).toContain("réseau privé");
  });

  it("refuse un nom avec une adresse publique et une adresse privée", async () => {
    const resolve = fakeDns({ "mixte.example": ["93.184.215.14", "10.0.0.1"] });
    expectFailure(await resolveHost("mixte.example", { resolve }), "BLOCKED_ADDRESS");
  });

  // Services DNS publics qui renvoient volontairement une adresse interne : le nom a l'air
  // inoffensif, seule la vérification après résolution les arrête.
  it.each([
    ["localtest.me", "127.0.0.1"],
    ["127.0.0.1.nip.io", "127.0.0.1"],
    ["169.254.169.254.nip.io", "169.254.169.254"],
  ])("refuse %s, qui pointe vers %s", async (hostname, address) => {
    const resolve = fakeDns({ [hostname]: [address] });
    expectFailure(await resolveHost(hostname, { resolve }), "BLOCKED_ADDRESS");
  });

  it("signale un nom introuvable (DNS_FAILURE)", async () => {
    const error = expectFailure(
      await resolveHost("inexistant.example", { resolve: notFound }),
      "DNS_FAILURE",
    );
    expect(error.detail).toBe("ENOTFOUND");
    expect(error.message).toContain("inexistant.example");
  });

  it("signale un nom sans adresse (DNS_FAILURE)", async () => {
    expectFailure(await resolveHost("vide.example", { resolve: fakeDns({}) }), "DNS_FAILURE");
  });

  it("abandonne une résolution trop lente (DNS_FAILURE, délai)", async () => {
    const never: HostResolver = () => new Promise(() => undefined);
    const error = expectFailure(
      await resolveHost("lent.example", { resolve: never, timeoutMs: 30 }),
      "DNS_FAILURE",
    );
    expect(error.detail).toBe("ETIMEOUT");
    expect(error.message).toContain("délai");
  });

  it("refuse localhost avec la vraie résolution du système", async () => {
    expectFailure(await resolveHost("localhost"), "BLOCKED_ADDRESS");
  });
});

describe("utilitaires partagés", () => {
  it("untilAborted renvoie le résultat si le signal ne se déclenche pas", async () => {
    await expect(untilAborted(Promise.resolve(42), new AbortController().signal)).resolves.toBe(42);
  });

  it("untilAborted abandonne dès l'annulation, même déjà survenue", async () => {
    const pending = new Promise<number>(() => undefined);
    await expect(untilAborted(pending, AbortSignal.abort(new Error("stop")))).rejects.toThrow(
      "stop",
    );
    const controller = new AbortController();
    const waiting = untilAborted(pending, controller.signal);
    controller.abort(new Error("annulé"));
    await expect(waiting).rejects.toThrow("annulé");
  });

  it("errorCode lit uniquement un code textuel", () => {
    expect(errorCode(Object.assign(new Error("x"), { code: "ECONNREFUSED" }))).toBe("ECONNREFUSED");
    expect(errorCode(new DOMException("délai", "TimeoutError"))).toBeUndefined();
    expect(errorCode("ECONNREFUSED")).toBeUndefined();
    expect(errorCode(null)).toBeUndefined();
  });
});
