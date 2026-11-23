/**
 * Tests de l'analyseur Set-Cookie (`parseSetCookie`, `maskCookie`), d'après l'algorithme de la
 * RFC 6265bis (§ 5.6) : un navigateur lit l'en-tête de façon tolérante (casse des attributs,
 * dernière occurrence retenue, valeurs inconnues ignorées), sauf face à un caractère de contrôle,
 * qui fait ignorer tout l'en-tête. Le contrôle « cookies » repose sur ces règles.
 */

import { describe, expect, it } from "vitest";
import { maskCookie, parseSetCookie } from "@/lib/scanner/checks/cookie-parser";

/** Analyse un en-tête en exigeant un résultat (échec explicite du test sinon). */
function parse(header: string) {
  const cookie = parseSetCookie(header);
  if (cookie === null) throw new Error(`En-tête ignoré : ${header}`);
  return cookie;
}

describe("parseSetCookie — nom et valeur", () => {
  it("lit un cookie complet", () => {
    expect(
      parse(
        "session=abc123; Path=/; Domain=.Example.com; Secure; HttpOnly; SameSite=Lax; Max-Age=3600",
      ),
    ).toEqual({
      name: "session",
      value: "abc123",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
      domain: "example.com",
      path: "/",
      maxAge: 3600,
      expires: null,
      attributes: [
        "Path=/",
        "Domain=.Example.com",
        "Secure",
        "HttpOnly",
        "SameSite=Lax",
        "Max-Age=3600",
      ],
    });
  });

  it("retire les espaces autour du nom, de la valeur et des attributs", () => {
    const cookie = parse("  id  =  42  ;   Secure  ");
    expect(cookie).toMatchObject({ name: "id", value: "42", secure: true });
    expect(cookie.attributes).toEqual(["Secure"]);
  });

  it("garde les guillemets et les « = » de la valeur (seul le premier « = » sépare)", () => {
    expect(parse('data="a=b=c"')).toMatchObject({ name: "data", value: '"a=b=c"' });
  });

  it("lit un en-tête sans « = » comme un cookie sans nom (RFC 6265bis § 5.6, étape 4)", () => {
    expect(parse("valeurseule; Secure")).toMatchObject({ name: "", value: "valeurseule" });
  });

  it("accepte un nom vide avec une valeur, et une valeur vide avec un nom", () => {
    expect(parse("=valeur")).toMatchObject({ name: "", value: "valeur" });
    expect(parse("vide=")).toMatchObject({ name: "vide", value: "" });
  });

  it.each([
    ["nom et valeur vides", "=; Secure"],
    ["en-tête vide", ""],
    ["caractère NUL", "id=a\u0000b"],
    ["retour à la ligne", "id=a\nb"],
    ["caractère DEL", "id=a\u007fb; Secure"],
  ])("ignore tout l'en-tête (%s), comme le navigateur", (_label, header) => {
    expect(parseSetCookie(header)).toBeNull();
  });

  it("accepte la tabulation, seul caractère de contrôle autorisé", () => {
    expect(parse("id=a\tb")).toMatchObject({ value: "a\tb" });
  });
});

describe("parseSetCookie — attributs", () => {
  it("lit les noms d'attributs sans tenir compte de la casse", () => {
    expect(parse("a=1; SECURE; httponly; sAmEsItE=StRiCt")).toMatchObject({
      secure: true,
      httpOnly: true,
      sameSite: "strict",
    });
  });

  it("active Secure et HttpOnly d'après leur seul nom, même avec « =false »", () => {
    expect(parse("a=1; Secure=false; HttpOnly=0")).toMatchObject({ secure: true, httpOnly: true });
  });

  it("retient la dernière occurrence d'un attribut répété", () => {
    const cookie = parse("a=1; SameSite=None; Path=/a; SameSite=Lax; Path=/b");
    expect(cookie).toMatchObject({ sameSite: "lax", path: "/b" });
  });

  it.each([
    ["Strict", "strict"],
    ["lax", "lax"],
    ["NONE", "none"],
    ["", "invalid"],
    ["Laxx", "invalid"],
  ] as const)("lit SameSite=%s comme « %s »", (value, expected) => {
    expect(parse(`a=1; SameSite=${value}`).sameSite).toBe(expected);
  });

  it("laisse SameSite à null quand l'attribut est absent", () => {
    expect(parse("a=1").sameSite).toBeNull();
  });

  it("ignore un Domain vide et retire le point initial", () => {
    expect(parse("a=1; Domain=").domain).toBeNull();
    expect(parse("a=1; Domain=.SUB.example.com").domain).toBe("sub.example.com");
  });

  it.each([
    ["3600", 3600],
    ["0", 0],
    ["-1", -1],
    ["+5", null],
    ["1.5", null],
    ["abc", null],
    ["", null],
  ])("n'accepte Max-Age=%s que s'il s'agit d'un entier", (value, expected) => {
    expect(parse(`a=1; Max-Age=${value}`).maxAge).toBe(expected);
  });

  it("lit une date Expires valide et ignore une date illisible", () => {
    expect(parse("a=1; Expires=Wed, 21 Oct 2037 07:28:00 GMT").expires).toBe(
      Date.UTC(2037, 9, 21, 7, 28, 0),
    );
    expect(parse("a=1; Expires=demain").expires).toBeNull();
  });

  it("conserve les attributs inconnus pour l'affichage, sans effet", () => {
    const cookie = parse("a=1; Priority=High; Partitioned");
    expect(cookie.attributes).toEqual(["Priority=High", "Partitioned"]);
    expect(cookie).toMatchObject({ secure: false, httpOnly: false });
  });
});

describe("maskCookie", () => {
  it("masque la valeur et garde les attributs, sans jamais afficher le secret", () => {
    const cookie = parse("session=SECRET-123; Path=/; Secure");
    const masked = maskCookie(cookie);
    expect(masked).toBe("session=***; Path=/; Secure");
    expect(masked).not.toContain("SECRET");
  });

  it("nomme « (sans nom) » un cookie sans nom", () => {
    expect(maskCookie(parse("jeton"))).toBe("(sans nom)=***");
  });
});
