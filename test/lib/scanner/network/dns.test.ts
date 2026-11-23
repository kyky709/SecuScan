/**
 * Tests de la recherche des enregistrements CAA (dns.ts), avec un DNS simulé : aucun accès réseau.
 *
 * Le DNS simulé note chaque nom interrogé, ce qui permet de vérifier la remontée de l'arbre
 * (RFC 8659 § 3) : nom exact, puis parents, jusqu'au domaine de premier niveau, racine exclue.
 */
import { describe, expect, it } from "vitest";
import { type CaaQuery, createCaaResolver } from "@/lib/scanner/network/dns";
import type { CaaInfo, NetworkError, NetworkErrorCode, Result } from "@/lib/scanner/types";

/** Réponse simulée d'un nom : des enregistrements, ou un code d'erreur DNS. */
type FakeAnswer = readonly object[] | string;

/** DNS simulé. Un nom absent de la table répond ENOTFOUND (le nom n'existe pas). */
function fakeCaa(table: Record<string, FakeAnswer>): { query: CaaQuery; queried: string[] } {
  const queried: string[] = [];
  const query: CaaQuery = async (name) => {
    queried.push(name);
    const answer = table[name] ?? "ENOTFOUND";
    if (typeof answer === "string") {
      throw Object.assign(new Error(`queryCaa ${answer} ${name}`), { code: answer });
    }
    return answer;
  };
  return { query, queried };
}

/** Renvoie la valeur d'un Result réussi, ou fait échouer le test avec l'erreur reçue. */
function expectOk(result: Result<CaaInfo>): CaaInfo {
  if (!result.ok)
    throw new Error(`Échec inattendu : ${result.error.code} – ${result.error.message}`);
  return result.value;
}

/** Vérifie qu'un Result est un échec du code attendu et renvoie l'erreur. */
function expectFailure(result: Result<CaaInfo>, code: NetworkErrorCode): NetworkError {
  if (result.ok) throw new Error("Un échec était attendu.");
  expect(result.error.code).toBe(code);
  return result.error;
}

const LETS_ENCRYPT = { critical: 0, type: "CAA", issue: "letsencrypt.org" };

describe("createCaaResolver : remontée de l'arbre DNS", () => {
  it("renvoie les enregistrements du nom lui-même, normalisés", async () => {
    const { query, queried } = fakeCaa({ "example.com": [LETS_ENCRYPT] });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("example.com"));
    expect(info).toEqual({
      domain: "example.com",
      records: [{ critical: 0, tag: "issue", value: "letsencrypt.org" }],
    });
    expect(queried).toEqual(["example.com"]);
  });

  it("remonte au parent quand un CNAME sans CAA renvoie une liste vide", async () => {
    const { query, queried } = fakeCaa({ "www.example.com": [], "example.com": [LETS_ENCRYPT] });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("www.example.com"));
    expect(info.domain).toBe("example.com");
    expect(queried).toEqual(["www.example.com", "example.com"]);
  });

  it.each(["ENODATA", "ENOTFOUND"])("remonte au parent après %s", async (code) => {
    const { query, queried } = fakeCaa({ "a.b.example.com": code, "example.com": [LETS_ENCRYPT] });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("a.b.example.com"));
    expect(info.domain).toBe("example.com");
    expect(queried).toEqual(["a.b.example.com", "b.example.com", "example.com"]);
  });

  it("interroge le domaine de premier niveau mais jamais la racine", async () => {
    const { query, queried } = fakeCaa({
      "www.example.com": "ENODATA",
      "example.com": "ENODATA",
      com: "ENODATA",
    });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("www.example.com"));
    expect(info).toEqual({ domain: null, records: [] });
    expect(queried).toEqual(["www.example.com", "example.com", "com"]);
  });

  it("ignore la casse et le point final du nom", async () => {
    const { query, queried } = fakeCaa({ "example.com": [LETS_ENCRYPT] });
    expectOk(await createCaaResolver({ resolveCaa: query })("WWW.Example.COM."));
    expect(queried).toEqual(["www.example.com", "example.com"]);
  });

  it("ne fait aucune requête pour une adresse IP", async () => {
    const { query, queried } = fakeCaa({});
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("93.184.215.14"));
    expect(info).toEqual({ domain: null, records: [] });
    expect(queried).toEqual([]);
  });
});

describe("createCaaResolver : normalisation des enregistrements de Node.js", () => {
  it("garde le drapeau critique et chaque étiquette, y compris inconnue", async () => {
    const { query } = fakeCaa({
      "example.com": [
        LETS_ENCRYPT,
        { critical: 0, type: "CAA", issuewild: ";" },
        { critical: 128, type: "CAA", iodef: "mailto:securite@example.com" },
        { critical: 0, type: "CAA", contactemail: "securite@example.com" },
      ],
    });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("example.com"));
    expect(info.records).toEqual([
      { critical: 0, tag: "issue", value: "letsencrypt.org" },
      { critical: 0, tag: "issuewild", value: ";" },
      { critical: 128, tag: "iodef", value: "mailto:securite@example.com" },
      { critical: 0, tag: "contactemail", value: "securite@example.com" },
    ]);
  });

  it("ignore un enregistrement sans étiquette et continue de remonter", async () => {
    const { query } = fakeCaa({
      "www.example.com": [{ critical: 0, type: "CAA" }],
      "example.com": [LETS_ENCRYPT],
    });
    const info = expectOk(await createCaaResolver({ resolveCaa: query })("www.example.com"));
    expect(info.domain).toBe("example.com");
  });
});

describe("createCaaResolver : pannes DNS (résultat non concluant)", () => {
  it.each([
    "ESERVFAIL",
    "EREFUSED",
    "ECONNREFUSED",
  ])("%s arrête la remontée (DNS_FAILURE)", async (code) => {
    const { query, queried } = fakeCaa({ "www.example.com": code, "example.com": [LETS_ENCRYPT] });
    const error = expectFailure(
      await createCaaResolver({ resolveCaa: query })("www.example.com"),
      "DNS_FAILURE",
    );
    expect(error.detail).toBe(code);
    expect(error.message).toContain("CAA non vérifiés");
    expect(queried).toEqual(["www.example.com"]);
  });

  it("ETIMEOUT donne TIMEOUT", async () => {
    const { query } = fakeCaa({ "example.com": "ETIMEOUT" });
    expectFailure(await createCaaResolver({ resolveCaa: query })("example.com"), "TIMEOUT");
  });

  it("abandonne une requête qui ne répond jamais (délai)", async () => {
    const never: CaaQuery = () => new Promise(() => undefined);
    const resolver = createCaaResolver({ resolveCaa: never });
    expectFailure(await resolver("example.com", { timeoutMs: 30 }), "TIMEOUT");
  });

  it("s'arrête aussitôt si le scan est déjà annulé", async () => {
    const { query } = fakeCaa({ "example.com": [LETS_ENCRYPT] });
    const resolver = createCaaResolver({ resolveCaa: query });
    expectFailure(await resolver("example.com", { signal: AbortSignal.abort() }), "TIMEOUT");
  });

  it("ne lève jamais d'exception, même si la requête lève de façon synchrone", async () => {
    const broken: CaaQuery = () => {
      throw new Error("panne");
    };
    const result = await createCaaResolver({ resolveCaa: broken })("example.com");
    expect(result.ok).toBe(false);
  });
});
