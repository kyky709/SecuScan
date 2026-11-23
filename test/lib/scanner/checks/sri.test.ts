/**
 * Tests du contrôle « Intégrité des scripts tiers (SRI) » : chaque ligne de la grille, la
 * définition d'un script « tiers » (hôte différent de la page, comme MDN Observatory), la validité
 * des jetons integrity (spécification W3C Subresource Integrity) et les constats secondaires
 * (crossorigin manquant, feuilles de style, scripts en http:// laissés au contrôle « contenu mixte »).
 */

import { fetched, makeContext, makeHtmlInfo, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { sriCheck } from "@/lib/scanner/checks/sri";
import type { HtmlResource } from "@/lib/scanner/types";

/** Empreinte SHA-384 au format base64 (64 caractères), valeur d'exemple. */
const HASH = "oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC";

function script(url: string, integrity: string | null = null, crossorigin: string | null = null) {
  return { tag: "script", url, integrity, crossorigin, rel: null } satisfies HtmlResource;
}

function stylesheet(url: string, integrity: string | null = null) {
  return {
    tag: "link",
    url,
    integrity,
    crossorigin: "anonymous",
    rel: "stylesheet",
  } satisfies HtmlResource;
}

/** Évalue le contrôle sur une page https://example.com/ contenant ces ressources. */
function evaluate(scripts: HtmlResource[], stylesheets: HtmlResource[] = []) {
  return sriCheck.evaluate(makeContext({ html: makeHtmlInfo({ scripts, stylesheets }) }));
}

describe("sriCheck — grille de notation", () => {
  it("est sans objet (info, 0) quand la réponse n'est pas du HTML", () => {
    const outcome = sriCheck.evaluate(makeContext({ html: null }));
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("n'est pas une page HTML");
  });

  it("réussit sans bonus (0) quand la page ne charge aucun script tiers", () => {
    const outcome = evaluate([script("https://example.com/app.js")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toBe("La page ne charge aucun script depuis un autre domaine.");
  });

  it("donne le bonus (+5) quand tous les scripts tiers ont un integrity valide", () => {
    const outcome = evaluate([
      script("https://cdn.example.net/a.js", `sha384-${HASH}`, "anonymous"),
      script("https://cdn.example.org/b.js", `sha512-${HASH}`, "anonymous"),
    ]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5, recommendation: null });
    expect(outcome.summary).toBe(
      "Les 2 scripts tiers de la page sont protégés par un attribut integrity (SRI).",
    );
    expect(outcome.evidence).toContain(`integrity="sha384-${HASH}"`);
  });

  it("accorde le singulier pour un seul script tiers protégé", () => {
    const outcome = evaluate([script("https://cdn.example.net/a.js", `sha256-${HASH}`, "")]);
    expect(outcome.summary).toBe(
      "Le script tiers de la page est protégé par un attribut integrity (SRI).",
    );
  });

  it("avertit (-5) quand un script tiers n'a pas d'integrity, en citant les scripts concernés", () => {
    const outcome = evaluate([
      script("https://cdn.example.net/a.js", `sha384-${HASH}`, "anonymous"),
      script("https://cdn.example.net/b.js"),
    ]);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.summary).toContain("1 script tiers sur 2 est chargé sans attribut integrity");
    expect(outcome.details?.[0]).toBe(
      "Scripts tiers sans integrity : https://cdn.example.net/b.js.",
    );
    expect(outcome.evidence).toBe("https://cdn.example.net/b.js");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "HTML",
      "Calcul de l'empreinte (OpenSSL)",
      "Next.js (next/script)",
    ]);
  });

  it("accorde le pluriel quand plusieurs scripts tiers ne sont pas protégés", () => {
    const outcome = evaluate([
      script("https://cdn.example.net/a.js"),
      script("https://cdn.example.net/b.js"),
    ]);
    expect(outcome.summary).toContain("2 scripts tiers sur 2 sont chargés sans attribut integrity");
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(sriCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-5, 0, 5]);
  });
});

describe("sriCheck — qu'est-ce qu'un script tiers ?", () => {
  it("compte un sous-domaine comme tiers (règle d'Observatory : hôte différent)", () => {
    const outcome = evaluate([script("https://static.example.com/a.js")]);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
  });

  it("ne compte pas comme tiers le même hôte sur un autre port", () => {
    const outcome = evaluate([script("https://example.com:443/a.js")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it("compare l'hôte à celui de la réponse finale (après redirection)", () => {
    const response = makeResponse({ url: "https://www.example.com/" });
    const outcome = sriCheck.evaluate(
      makeContext({
        https: fetched(response),
        response,
        html: makeHtmlInfo({ scripts: [script("https://www.example.com/a.js")] }),
      }),
    );
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it("laisse les scripts tiers en http:// au contrôle « contenu mixte »", () => {
    const outcome = evaluate([script("http://cdn.example.net/a.js")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.summary).toContain("ceux en http:// relèvent du contrôle « Contenu mixte »");
    expect(outcome.details).toContain(
      "Scripts tiers chargés en http://, traités par le contrôle « Contenu mixte » : http://cdn.example.net/a.js.",
    );
  });
});

describe("sriCheck — validité de l'attribut integrity", () => {
  it.each([
    ["sha256", `sha256-${HASH}`],
    ["SHA384 en majuscules", `SHA384-${HASH}`],
    ["avec options", `sha512-${HASH}?ct=application/javascript`],
    ["plusieurs jetons dont un valide", `md5-abc sha384-${HASH}`],
    ["base64url", "sha256-abc_def-ghi"],
  ])("accepte un jeton utilisable (%s)", (_label, integrity) => {
    const outcome = evaluate([script("https://cdn.example.net/a.js", integrity, "anonymous")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
  });

  it.each([
    ["vide", ""],
    ["md5", "md5-abc"],
    ["sha1", `sha1-${HASH}`],
    ["sans empreinte", "sha384-"],
    ["sans algorithme", HASH],
    ["empreinte non base64", "sha384-***"],
  ])("refuse un jeton inutilisable (%s) et le signale en détail", (_label, integrity) => {
    const outcome = evaluate([script("https://cdn.example.net/a.js", integrity, "anonymous")]);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.details?.some((d) => d.startsWith("Attribut integrity inutilisable"))).toBe(
      true,
    );
  });

  it("signale integrity sans crossorigin : le navigateur bloque alors la ressource", () => {
    const outcome = evaluate([script("https://cdn.example.net/a.js", `sha384-${HASH}`)]);
    // La protection est là (bonus) mais le script ne se chargera pas : on le dit et on corrige.
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 5 });
    expect(outcome.details?.[0]).toContain("Attribut integrity sans crossorigin");
    expect(outcome.recommendation).toContain('crossorigin="anonymous"');
    expect(outcome.examples).toHaveLength(3);
  });
});

describe("sriCheck — feuilles de style et listes d'URL", () => {
  it("signale les feuilles de style tierces sans integrity, sans effet sur la note", () => {
    const outcome = evaluate([], [stylesheet("https://fonts.example.net/a.css")]);
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
    expect(outcome.details).toEqual([
      "Feuilles de style tierces sans attribut integrity (sans effet sur la note) : https://fonts.example.net/a.css.",
    ]);
  });

  it("cite au plus 10 URL, sans doublon, puis « et N autres »", () => {
    const scripts = Array.from({ length: 13 }, (_, i) =>
      script(`https://cdn${i}.example.net/a.js`),
    );
    scripts.push(script("https://cdn0.example.net/a.js"));
    const outcome = evaluate(scripts);
    expect(outcome.details?.[0]).toMatch(/cdn9\.example\.net\/a\.js et 3 autres\.$/);
    expect(outcome.summary).toContain("14 scripts tiers sur 14");
  });
});
