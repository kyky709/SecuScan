// Exigence de confidentialité : la VALEUR d'un cookie (souvent un identifiant de session)
// n'apparaît jamais dans le rapport.

import { fetched, makeContext, makeRedirect, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { cookiesCheck } from "@/lib/scanner/checks/cookies";
import type { CheckOutcome } from "@/lib/scanner/types";

/** HSTS valide sur la réponse HTTPS : il atténue l'absence de Secure. */
const HSTS = { "strict-transport-security": "max-age=31536000" };

function evaluate(setCookies: string[], headers: Record<string, string> = {}) {
  return cookiesCheck.evaluate(makeContext({ setCookies, headers }));
}

function allText(outcome: CheckOutcome): string {
  return [outcome.summary, ...(outcome.details ?? []), outcome.evidence, outcome.recommendation]
    .filter(Boolean)
    .join("\n");
}

describe("cookiesCheck — grille de notation", () => {
  it("est sans objet (info, 0) quand le site ne dépose aucun cookie", () => {
    const outcome = evaluate([]);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toBe("Le site ne dépose aucun cookie.");
  });

  it("échoue (-40) sur un cookie de session sans Secure, sans HSTS", () => {
    const outcome = evaluate(["sessionid=abc; HttpOnly; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -40 });
    expect(outcome.summary).toBe(
      "Le cookie de session « sessionid » n'a pas l'attribut Secure et aucun HSTS ne compense : la session peut être interceptée sur une connexion non chiffrée.",
    );
  });

  it("échoue (-30) sur un cookie de session sans HttpOnly", () => {
    const outcome = evaluate(["PHPSESSID=abc; Secure; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
    expect(outcome.summary).toContain("n'a pas l'attribut HttpOnly");
  });

  it("échoue (-20) sur un cookie ordinaire sans Secure, sans HSTS", () => {
    const outcome = evaluate(["theme=sombre; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("Le cookie « theme » n'a pas l'attribut Secure");
  });

  it.each([
    ["SameSite invalide", "pref=1; Secure; SameSite=Laxx", "une valeur SameSite invalide"],
    ["SameSite vide", "pref=1; Secure; SameSite=", "une valeur SameSite invalide"],
    ["None sans Secure (HSTS présent)", "pref=1; SameSite=None", "SameSite=None sans Secure"],
  ])("échoue (-20) : %s", (_label, header, text) => {
    const outcome = evaluate([header], HSTS);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain(text);
  });

  it("échoue (-20) sur un cookie anti-CSRF sans SameSite", () => {
    const outcome = evaluate(["XSRF-TOKEN=abc; Secure"]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain(
      "Le cookie anti-CSRF « XSRF-TOKEN » n'a pas d'attribut SameSite",
    );
  });

  it("échoue (-10) sur un cookie de session sans Secure mais protégé par HSTS", () => {
    const outcome = evaluate(["connect.sid=abc; HttpOnly; SameSite=Lax"], HSTS);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -10 });
    expect(outcome.summary).toContain("HSTS limite le risque");
  });

  it("avertit (-5) sur un cookie ordinaire sans Secure mais protégé par HSTS", () => {
    const outcome = evaluate(["lang=fr; SameSite=Lax"], HSTS);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("HSTS compense en grande partie ce manque");
  });

  it("n'atténue pas par un HSTS inopérant (max-age=0)", () => {
    const outcome = evaluate(["lang=fr; SameSite=Lax"], {
      "strict-transport-security": "max-age=0",
    });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
  });

  it.each([
    ["__Secure- sans Secure", "__Secure-id=1; SameSite=Lax", "Secure obligatoire"],
    ["__Host- avec Domain", "__Host-id=1; Secure; Path=/; Domain=example.com", "Domain interdit"],
    ["__Host- sans Path=/", "__Host-id=1; Secure; Path=/app", "Path=/ obligatoire"],
    ["__Host- sans Path", "__Host-id=1; Secure", "Path=/ obligatoire"],
    ["préfixe en majuscules", "__SECURE-id=1; SameSite=Lax", "Secure obligatoire"],
    ["sans nom imitant un préfixe", "__Host-faux; Secure", "sans nom, imite un préfixe"],
  ])("avertit (-5) quand les règles d'un préfixe ne sont pas respectées (%s)", (_l, header, reason) => {
    const outcome = evaluate([header], HSTS);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain(reason);
    expect(outcome.summary).toContain("les navigateurs rejettent ce cookie");
  });

  it("réussit sans bonus (0) quand SameSite manque sur certains cookies", () => {
    const outcome = evaluate(["session=abc; Secure; HttpOnly", "pref=1; Secure; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("le cookie « session » n'a pas d'attribut SameSite");
    expect(outcome.recommendation).toContain("SameSite=Lax");
  });

  it("donne le bonus (+5) quand tous les cookies ont les attributs attendus", () => {
    const outcome = evaluate([
      "__Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
      "pref=1; Secure; SameSite=Strict",
    ]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5, recommendation: null });
    expect(outcome.summary).toBe(
      "Les cookies « __Host-session » et « pref » ont les attributs attendus : Secure, HttpOnly pour les sessions et une valeur SameSite valide.",
    );
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(cookiesCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-40, -30, -20, -10, -5, 0, 5]);
  });
});

describe("cookiesCheck — plusieurs problèmes à la fois", () => {
  it("retient le plus grave et détaille les autres, recommandations dédoublonnées", () => {
    const outcome = evaluate(["sid=1", "theme=2", "csrf_token=3; Secure"]);
    // sid : session sans Secure (-40) et sans HttpOnly (-30) ; theme : sans Secure (-20).
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -40 });
    expect(outcome.details).toEqual([
      expect.stringContaining("Le cookie de session « sid » n'a pas l'attribut HttpOnly"),
      expect.stringContaining("Le cookie « theme » n'a pas l'attribut Secure"),
      expect.stringContaining("Le cookie anti-CSRF « csrf_token » n'a pas d'attribut SameSite"),
    ]);
    const secureAdvice = outcome.recommendation?.match(/Ajoutez l'attribut Secure/g) ?? [];
    expect(secureAdvice).toHaveLength(1);
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "En-tête attendu (cookie de session)",
      "Nginx (≥ 1.19.3, devant l'application)",
      "Apache (mod_headers)",
      "Next.js (Route Handler)",
    ]);
  });

  it("accorde le pluriel et cite au plus 5 noms, puis « et N autres »", () => {
    const cookies = Array.from({ length: 7 }, (_, i) => `c${i}=1; SameSite=Lax`);
    const outcome = evaluate(cookies);
    expect(outcome.summary).toContain(
      "Les cookies « c0 », « c1 », « c2 », « c3 », « c4 » et 2 autres n'ont pas l'attribut Secure",
    );
    expect(outcome.summary).toContain("leur valeur peut circuler en clair");
  });

  it("n'évalue que la règle du préfixe pour un cookie rejeté par le navigateur", () => {
    // __Secure-sid sans Secure est rejeté : il n'existe pas côté client, ses autres défauts non plus.
    const outcome = evaluate(["__Secure-sid=1"], HSTS);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.details).toEqual([]);
  });
});

describe("cookiesCheck — collecte des cookies", () => {
  it("relève les cookies déposés par les redirections et par la sonde HTTP", () => {
    const redirect = makeRedirect("http://example.com/", "https://example.com/");
    redirect.setCookies = ["tracking=1; SameSite=Lax"];
    const outcome = cookiesCheck.evaluate(
      makeContext({ http: fetched(makeResponse(), [redirect]), headers: HSTS }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.details).toContain(
      "Le cookie « tracking » est déposé par une réponse en HTTP clair : sa valeur circule sans chiffrement.",
    );
  });

  it("ne compte qu'une fois le même en-tête reçu par les deux sondes", () => {
    const response = makeResponse({ setCookies: ["a=1; Secure; SameSite=Lax"] });
    const outcome = cookiesCheck.evaluate(
      makeContext({ https: fetched(response), http: fetched(response) }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.evidence).toBe("a=***; Secure; SameSite=Lax");
  });

  it("relève aussi les cookies des réponses reçues avant une erreur de sonde", () => {
    const redirect = makeRedirect("https://example.com/", "https://example.com/boucle");
    redirect.setCookies = ["sid=1; Secure"];
    const outcome = cookiesCheck.evaluate(
      makeContext({
        https: {
          ok: false,
          error: { code: "TOO_MANY_REDIRECTS", message: "Boucle.", chain: [redirect] },
        },
        http: { ok: false, error: { code: "CONNECTION_REFUSED", message: "Refus." } },
      }),
    );
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
  });

  it("n'évalue pas les cookies supprimés par le serveur et les signale", () => {
    const outcome = evaluate([
      "ancien=; Max-Age=0",
      "vieux=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
      // Max-Age l'emporte sur Expires : ce cookie n'est pas supprimé.
      "vivant=x; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=60; Secure; SameSite=Lax",
    ]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details).toContain(
      "Cookies supprimés par le serveur (expiration passée), non évalués : « ancien » et « vieux ».",
    );
  });

  it("ignore et signale les en-têtes Set-Cookie invalides", () => {
    const outcome = evaluate(["a=\u0001", "=", "b=1; Secure; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details).toContain(
      "2 en-têtes Set-Cookie invalides ont été ignorés, comme le ferait un navigateur.",
    );
  });

  it("dit que le site ne dépose aucun cookie quand tous ont été supprimés", () => {
    const outcome = evaluate(["a=; Max-Age=0"]);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.details?.[0]).toContain("Cookies supprimés par le serveur");
  });
});

describe("cookiesCheck — détection des cookies de session", () => {
  it.each([
    "PHPSESSID",
    "JSESSIONID",
    "ASP.NET_SessionId",
    "connect.sid",
    "jwt",
    "auth_token",
    "remember_me",
    "SID",
  ])("reconnaît « %s » comme un cookie de session", (name) => {
    const outcome = evaluate([`${name}=1; Secure; SameSite=Lax`]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
  });

  it("n'exige pas HttpOnly d'un cookie anti-CSRF, que JavaScript doit pouvoir lire", () => {
    // « XSRF-TOKEN » contient « token » mais n'est pas une session : schéma « double soumission ».
    const outcome = evaluate(["XSRF-TOKEN=abc; Secure; SameSite=Strict"]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
  });

  it("assume des faux positifs de l'heuristique (« consideration » contient « sid »)", () => {
    // Faux positif sans gravité : on exige alors HttpOnly, ce qui reste une bonne pratique.
    const outcome = evaluate(["consideration=1; Secure; SameSite=Lax"]);
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -30 });
  });
});

describe("cookiesCheck — confidentialité", () => {
  it("n'affiche jamais la valeur d'un cookie, même dans la preuve", () => {
    const outcome = evaluate([
      "session=SECRET-DE-SESSION-42; Path=/",
      "__Host-x=AUTRE-SECRET; Secure",
      "SECRET-SANS-NOM",
    ]);
    const text = allText(outcome);
    expect(text).not.toContain("SECRET-DE-SESSION-42");
    expect(text).not.toContain("AUTRE-SECRET");
    expect(text).not.toContain("SECRET-SANS-NOM");
    expect(outcome.evidence).toContain("session=***; Path=/");
  });
});
