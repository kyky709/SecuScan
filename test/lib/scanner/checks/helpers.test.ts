import { failure, fetched, makeContext, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import {
  getHeader,
  hasEffectiveHsts,
  httpsResponse,
  isHtmlResponse,
  isServedOverHttps,
  lookup,
  MAX_QUOTED_LENGTH,
  notApplicable,
  originOf,
  probeErrorOutcome,
  shorten,
  splitList,
  truncateEvidence,
} from "@/lib/scanner/checks/helpers";

describe("lecture de la réponse", () => {
  it("lit un en-tête sans tenir compte de la casse du nom", () => {
    const response = makeResponse({ headers: { "X-Frame-Options": "DENY" } });
    expect(getHeader(response, "x-frame-options")).toBe("DENY");
    expect(getHeader(response, "X-FRAME-OPTIONS")).toBe("DENY");
    expect(getHeader(response, "absent")).toBeNull();
    expect(getHeader(null, "x-frame-options")).toBeNull();
  });

  it("renvoie la réponse HTTPS finale, ou null si la sonde HTTPS a échoué", () => {
    const response = makeResponse();
    expect(httpsResponse(makeContext({ https: fetched(response) }))).toBe(response);
    expect(httpsResponse(makeContext({ https: failure("TIMEOUT") }))).toBeNull();
  });

  it("reconnaît une réponse servie en HTTPS", () => {
    expect(isServedOverHttps(makeResponse({ url: "https://example.com/" }))).toBe(true);
    expect(isServedOverHttps(makeResponse({ url: "http://example.com/" }))).toBe(false);
    expect(isServedOverHttps(null)).toBe(false);
  });

  it.each([
    ["text/html; charset=utf-8", true],
    ["TEXT/HTML", true],
    ["application/xhtml+xml", true],
    ["application/json", false],
    ["", false],
  ])("reconnaît le HTML d'après Content-Type (%s)", (contentType, expected) => {
    expect(isHtmlResponse(makeResponse({ headers: { "content-type": contentType } }))).toBe(
      expected,
    );
  });
});

describe("listes, origines et valeurs affichées", () => {
  it("découpe une liste en retirant espaces et éléments vides", () => {
    expect(splitList(" a, ,b ,, c ")).toEqual(["a", "b", "c"]);
    expect(splitList("a  b\tc", /\s+/)).toEqual(["a", "b", "c"]);
    expect(splitList("")).toEqual([]);
  });

  it("donne l'origine d'une URL, ou null si elle est illisible", () => {
    expect(originOf("https://example.com:8443/a?b")).toBe("https://example.com:8443");
    expect(originOf("pas une url")).toBeNull();
  });

  it("raccourcit une preuve trop longue en indiquant sa taille réelle", () => {
    expect(truncateEvidence("abc", 3)).toBe("abc");
    expect(truncateEvidence("abcd", 3)).toBe("abc… (4 caractères)");
  });

  it("raccourcit une valeur citée dans une phrase", () => {
    expect(shorten("court")).toBe("court");
    const long = "x".repeat(MAX_QUOTED_LENGTH + 1);
    expect(shorten(long)).toBe(`${"x".repeat(MAX_QUOTED_LENGTH)}… (${long.length} caractères)`);
  });
});

describe("lookup", () => {
  const TABLE: Readonly<Record<string, string>> = { deny: "refus" };

  it("trouve une clé de la table", () => {
    expect(lookup(TABLE, "deny")).toBe("refus");
  });

  it.each([
    "constructor",
    "__proto__",
    "toString",
    "hasOwnProperty",
    "absent",
  ])("ignore les propriétés héritées d'Object (%s)", (key) => {
    expect(lookup(TABLE, key)).toBeUndefined();
  });
});

describe("verdicts communs", () => {
  it("produit un verdict « non vérifié », neutre, avec le détail technique éventuel", () => {
    expect(
      probeErrorOutcome(
        { code: "TIMEOUT", message: "Délai dépassé.", detail: "ETIMEDOUT" },
        "l'en-tête HSTS",
      ),
    ).toEqual({
      status: "error",
      scoreModifier: 0,
      summary: "Impossible de vérifier l'en-tête HSTS : Délai dépassé.",
      details: ["Détail technique : ETIMEDOUT"],
      recommendation: null,
    });
    expect(probeErrorOutcome({ code: "UNKNOWN", message: "Erreur." }, "x").details).toBeUndefined();
  });

  it("produit un verdict « sans objet », neutre", () => {
    expect(notApplicable("Rien à voir.", ["Détail."])).toEqual({
      status: "info",
      scoreModifier: 0,
      summary: "Rien à voir.",
      details: ["Détail."],
      recommendation: null,
    });
  });
});

describe("hasEffectiveHsts", () => {
  it.each([
    ["max-age=31536000", true],
    ['max-age="600"; includeSubDomains', true],
    ["includeSubDomains; MAX-AGE=1", true],
    ["max-age=0", false],
    ["max-age=abc", false],
    ["includeSubDomains", false],
  ])("« %s » → %s", (value, expected) => {
    const response = makeResponse({ headers: { "strict-transport-security": value } });
    expect(hasEffectiveHsts(response)).toBe(expected);
  });

  it("ignore HSTS reçu en HTTP clair, et une réponse absente", () => {
    const response = makeResponse({
      url: "http://example.com/",
      headers: { "strict-transport-security": "max-age=31536000" },
    });
    expect(hasEffectiveHsts(response)).toBe(false);
    expect(hasEffectiveHsts(null)).toBe(false);
  });
});
