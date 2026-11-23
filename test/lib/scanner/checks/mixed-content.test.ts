import { fetched, makeContext, makeHtmlInfo, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { mixedContentCheck } from "@/lib/scanner/checks/mixed-content";
import type { HtmlInfo, HtmlResource } from "@/lib/scanner/types";

function resource(tag: string, url: string, rel: string | null = null): HtmlResource {
  return { tag, url, integrity: null, crossorigin: null, rel };
}

function evaluate(html: Partial<HtmlInfo>, headers: Record<string, string> = {}) {
  return mixedContentCheck.evaluate(makeContext({ headers, html: makeHtmlInfo(html) }));
}

describe("mixedContentCheck — grille de notation", () => {
  it("est sans objet (info, 0) quand la réponse n'est pas du HTML", () => {
    const outcome = mixedContentCheck.evaluate(makeContext({ html: null }));
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
  });

  it("est sans objet (info, 0) quand la page est servie en HTTP", () => {
    const response = makeResponse({ url: "http://example.com/" });
    const outcome = mixedContentCheck.evaluate(
      makeContext({
        http: fetched(response),
        response,
        html: makeHtmlInfo({ scripts: [resource("script", "http://cdn.example.net/a.js")] }),
      }),
    );
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("c'est toute la page qui circule en clair");
  });

  it("réussit (0) quand aucune ressource n'est chargée en http://", () => {
    const outcome = evaluate({
      scripts: [resource("script", "https://cdn.example.net/a.js")],
      otherResources: [resource("img", "https://example.com/a.png")],
      forms: [{ action: "https://example.com/login", method: "post" }],
    });
    expect(outcome).toMatchObject({
      status: "pass",
      scoreModifier: 0,
      summary: "La page HTTPS ne charge aucune ressource en http://.",
      recommendation: null,
    });
  });

  it.each([
    ["script", resource("script", "http://cdn.example.net/a.js")],
    ["feuille de style", resource("link", "http://cdn.example.net/a.css", "stylesheet")],
    ["préchargement", resource("link", "http://cdn.example.net/p.js", "preload")],
    ["modulepreload", resource("link", "http://cdn.example.net/m.js", "modulepreload")],
    ["iframe", resource("iframe", "http://cadre.example.org/")],
    ["frame", resource("frame", "http://cadre.example.org/")],
    ["object", resource("object", "http://example.org/o.swf")],
    ["embed", resource("embed", "http://example.org/e.swf")],
  ])("échoue (-20) sur une ressource bloquable en http:// (%s)", (_label, item) => {
    const outcome = evaluate({
      scripts: item.tag === "script" ? [item] : [],
      stylesheets: item.rel === "stylesheet" ? [item] : [],
      otherResources: item.tag !== "script" && item.rel !== "stylesheet" ? [item] : [],
    });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.summary).toContain("charge 1 ressource active en http://");
    expect(outcome.evidence).toBe(item.url);
  });

  it("échoue (-10) sur un formulaire qui envoie ses données en http://", () => {
    const outcome = evaluate({ forms: [{ action: "http://example.com/login", method: "post" }] });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -10 });
    expect(outcome.summary).toBe(
      "1 formulaire envoie ses données en http:// : elles circulent en clair et le navigateur affiche un avertissement.",
    );
  });

  it("ignore un formulaire method=dialog, qui n'envoie rien", () => {
    const outcome = evaluate({ forms: [{ action: "http://example.com/x", method: "dialog" }] });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });

  it.each([
    ["image", resource("img", "http://example.com/a.png")],
    ["audio", resource("audio", "http://example.com/a.mp3")],
    ["vidéo", resource("video", "http://example.com/a.mp4")],
    ["source", resource("source", "http://example.com/a.webm")],
    ["piste", resource("track", "http://example.com/a.vtt")],
    ["icône", resource("link", "http://example.com/favicon.ico", "icon")],
  ])("avertit (-5) sur une ressource passive en http:// (%s)", (_label, item) => {
    const outcome = evaluate({ otherResources: [item] });
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    const modifiers = new Set(mixedContentCheck.scoring.map((row) => row.modifier));
    expect([...modifiers].sort((a, b) => a - b)).toEqual([-20, -10, -5, 0]);
  });
});

describe("mixedContentCheck — le pire cas l'emporte, les autres deviennent des détails", () => {
  it("retient le script (-20) devant le formulaire et l'image, et les liste tous", () => {
    const outcome = evaluate({
      scripts: [resource("script", "http://cdn.example.net/a.js")],
      otherResources: [resource("img", "http://example.com/a.png")],
      forms: [{ action: "http://example.com/login", method: "post" }],
    });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -20 });
    expect(outcome.details).toEqual([
      "Ressources actives en http:// : http://cdn.example.net/a.js.",
      "Formulaires envoyés en http:// : http://example.com/login.",
      "Ressources passives en http:// : http://example.com/a.png.",
    ]);
    expect(outcome.evidence?.split("\n")).toHaveLength(3);
  });

  it("retient le formulaire (-10) devant l'image (-5)", () => {
    const outcome = evaluate({
      otherResources: [resource("img", "http://example.com/a.png")],
      forms: [{ action: "http://example.com/s", method: "get" }],
    });
    expect(outcome).toMatchObject({ status: "fail", scoreModifier: -10 });
  });

  it("compte chaque URL une seule fois et accorde le pluriel", () => {
    const outcome = evaluate({
      scripts: [
        resource("script", "http://cdn.example.net/a.js"),
        resource("script", "http://cdn.example.net/a.js"),
        resource("script", "http://cdn.example.net/b.js"),
      ],
    });
    expect(outcome.summary).toContain("charge 2 ressources actives en http://");
    expect(outcome.summary).toContain("les navigateurs les bloquent");
  });

  it("cite au plus 10 URL, puis « et N autres »", () => {
    const images = Array.from({ length: 12 }, (_, i) =>
      resource("img", `http://example.com/${i}.png`),
    );
    const outcome = evaluate({ otherResources: images });
    expect(outcome.details?.[0]).toMatch(/9\.png et 2 autres\.$/);
  });

  it("ignore les ressources en https:// et les liens qui ne chargent rien", () => {
    const outcome = evaluate({
      otherResources: [resource("link", "http://example.com/feed", "alternate")],
    });
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0 });
  });
});

describe("mixedContentCheck — upgrade-insecure-requests", () => {
  const html = { otherResources: [resource("img", "http://example.com/a.png")] };

  it("recommande la directive en filet de sécurité quand elle est absente", () => {
    const outcome = evaluate(html);
    expect(outcome.recommendation).toContain("upgrade-insecure-requests");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (next.config.ts)",
    ]);
  });

  it.each([
    ["en-tête", { "content-security-policy": "default-src https:; Upgrade-Insecure-Requests" }, []],
    ["balise <meta>", {}, ["upgrade-insecure-requests"]],
  ])("la reconnaît (%s) sans changer la note : il faut corriger à la source", (_l, headers, metaCsp) => {
    const outcome = evaluate({ ...html, metaCsp }, headers);
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: -5 });
    expect(outcome.details).toContain(
      "La CSP contient upgrade-insecure-requests : les navigateurs récents réécrivent ces adresses en HTTPS, mais corrigez-les quand même à la source.",
    );
    expect(outcome.examples).toBeUndefined();
  });
});
