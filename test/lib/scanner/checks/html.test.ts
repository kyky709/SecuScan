// Les contrôles SRI, contenu mixte, CSP et Referrer-Policy reposent sur cette extraction : une
// erreur ici fausserait plusieurs verdicts à la fois.

import { describe, expect, it } from "vitest";
import { extractHtmlInfo } from "@/lib/scanner/checks/html";

const PAGE = "https://example.com/dossier/page.html";

function extract(html: string, pageUrl = PAGE) {
  return extractHtmlInfo(html, pageUrl);
}

function urls(resources: ReadonlyArray<{ url: string }>): string[] {
  return resources.map((resource) => resource.url);
}

describe("extractHtmlInfo — scripts", () => {
  it("résout les URL relatives, absolues et sans schéma (//cdn) par rapport à la page", () => {
    const info = extract(`
      <script src="app.js"></script>
      <script src="/racine.js"></script>
      <script src="//cdn.example.net/lib.js"></script>
      <script src="https://autre.example.org/x.js"></script>`);
    expect(urls(info.scripts)).toEqual([
      "https://example.com/dossier/app.js",
      "https://example.com/racine.js",
      "https://cdn.example.net/lib.js",
      "https://autre.example.org/x.js",
    ]);
  });

  it("lit les attributs integrity et crossorigin, quelle que soit la casse des balises", () => {
    const info = extract(
      `<SCRIPT SRC='https://cdn.example.net/a.js' INTEGRITY="sha384-abc" CrossOrigin></SCRIPT>`,
    );
    expect(info.scripts).toEqual([
      {
        tag: "script",
        url: "https://cdn.example.net/a.js",
        integrity: "sha384-abc",
        crossorigin: "",
        rel: null,
      },
    ]);
  });

  it("accepte les attributs sans guillemets et ignore les espaces autour de l'URL", () => {
    const info = extract("<script src=  https://cdn.example.net/a.js ></script>");
    expect(urls(info.scripts)).toEqual(["https://cdn.example.net/a.js"]);
  });

  it("décode les entités HTML des URL (&amp;)", () => {
    const info = extract('<script src="https://cdn.example.net/a.js?v=1&amp;x=2"></script>');
    expect(urls(info.scripts)).toEqual(["https://cdn.example.net/a.js?v=1&x=2"]);
  });

  it.each([
    ["sans type", "<script src=a.js></script>"],
    ["type vide", '<script type="" src=a.js></script>'],
    ["text/javascript", '<script type="text/javascript" src=a.js></script>'],
    ["casse et espaces", '<script type=" Text/JavaScript " src=a.js></script>'],
    ["module", '<script type="module" src=a.js></script>'],
    ["ancien attribut language", '<script language="javascript" src=a.js></script>'],
  ])("compte un script exécutable (%s)", (_label, html) => {
    expect(extract(html).scripts).toHaveLength(1);
  });

  it.each([
    ["JSON-LD", '<script type="application/ld+json">{"@type":"Thing"}</script>'],
    ["importmap", '<script type="importmap">{"imports":{}}</script>'],
    ["gabarit", '<script type="text/template" src="tpl.html"></script>'],
    ["JSON", '<script type="application/json" src="data.json"></script>'],
  ])("ignore un bloc de données qui n'est pas exécuté (%s)", (_label, html) => {
    const info = extract(html);
    expect(info.scripts).toEqual([]);
    expect(info.inlineScriptCount).toBe(0);
  });

  it("compte les scripts en ligne non vides, pas les vides", () => {
    const info = extract("<script>alert(1)</script><script>   </script><script></script>");
    expect(info.inlineScriptCount).toBe(1);
    expect(info.scripts).toEqual([]);
  });

  it.each([
    ["javascript:", "javascript:alert(1)"],
    ["data:", "data:text/javascript,alert(1)"],
    ["blob:", "blob:https://example.com/uuid"],
    ["about:", "about:blank"],
    ["vide", ""],
    ["espaces", "   "],
  ])("ignore un src qui ne charge rien depuis un serveur (%s)", (_label, src) => {
    expect(extract(`<script src="${src}"></script>`).scripts).toEqual([]);
  });

  it("ignore les scripts placés dans un commentaire ou dans un <template> (contenu inerte)", () => {
    const info = extract(`
      <!-- <script src="https://cdn.example.net/commentaire.js"></script> -->
      <template><script src="https://cdn.example.net/gabarit.js"></script><img src="http://x.fr/a.png"></template>
      <script src="https://cdn.example.net/vrai.js"></script>`);
    expect(urls(info.scripts)).toEqual(["https://cdn.example.net/vrai.js"]);
    expect(info.otherResources).toEqual([]);
  });
});

describe("extractHtmlInfo — URL de base (<base href>)", () => {
  it("résout les URL par rapport au premier <base href>, et ignore les suivants", () => {
    const info = extract(`
      <base href="https://static.example.net/v2/">
      <base href="https://ignore.example.org/">
      <script src="app.js"></script>`);
    expect(info.baseHref).toBe("https://static.example.net/v2/");
    expect(urls(info.scripts)).toEqual(["https://static.example.net/v2/app.js"]);
  });

  it("résout un <base href> relatif par rapport à la page", () => {
    const info = extract('<base href="/assets/"><script src="a.js"></script>');
    expect(info.baseHref).toBe("https://example.com/assets/");
    expect(urls(info.scripts)).toEqual(["https://example.com/assets/a.js"]);
  });

  it.each([
    ["javascript:", "javascript:alert(1)"],
    ["data:", "data:text/html,x"],
    ["illisible", "https://exa mple.com:99999/"],
  ])("ignore un <base href> inutilisable (%s) et garde l'URL de la page", (_label, href) => {
    const info = extract(`<base href="${href}"><script src="a.js"></script>`);
    expect(info.baseHref).toBeNull();
    expect(urls(info.scripts)).toEqual(["https://example.com/dossier/a.js"]);
  });

  it("ignore un <base> sans attribut href", () => {
    const info = extract('<base target="_blank"><script src="a.js"></script>');
    expect(info.baseHref).toBeNull();
  });
});

describe("extractHtmlInfo — feuilles de style et autres <link>", () => {
  it("classe les feuilles de style, quelle que soit la casse et les autres mots-clés de rel", () => {
    const info = extract(`
      <link rel="stylesheet" href="a.css">
      <link rel="STYLESHEET alternate" href="b.css" media="print">
      <link rel="preload stylesheet" href="c.css">`);
    expect(urls(info.stylesheets)).toEqual([
      "https://example.com/dossier/a.css",
      "https://example.com/dossier/b.css",
      "https://example.com/dossier/c.css",
    ]);
    expect(info.stylesheets[1]?.rel).toBe("stylesheet alternate");
  });

  it("range preload, modulepreload et icon parmi les autres ressources chargées", () => {
    const info = extract(`
      <link rel="preload" as="script" href="p.js">
      <link rel="modulepreload" href="m.js">
      <link rel="icon" href="http://example.com/favicon.ico">`);
    expect(info.otherResources.map((resource) => [resource.tag, resource.rel])).toEqual([
      ["link", "preload"],
      ["link", "modulepreload"],
      ["link", "icon"],
    ]);
    expect(info.stylesheets).toEqual([]);
  });

  it("ignore les <link> qui ne chargent rien (canonical, alternate, preconnect, sans href)", () => {
    const info = extract(`
      <link rel="canonical" href="https://example.com/">
      <link rel="alternate" hreflang="en" href="/en/">
      <link rel="preconnect" href="https://cdn.example.net">
      <link rel="stylesheet">`);
    expect(info.stylesheets).toEqual([]);
    expect(info.otherResources).toEqual([]);
  });
});

describe("extractHtmlInfo — images, médias, cadres et objets", () => {
  it("relève chaque attribut d'URL des balises qui chargent une ressource", () => {
    const info = extract(`
      <img src="i.png">
      <audio src="a.mp3"></audio>
      <video src="v.mp4" poster="p.jpg"></video>
      <track src="t.vtt">
      <iframe src="https://cadre.example.org/"></iframe>
      <frame src="f.html">
      <object data="o.swf"></object>
      <embed src="e.swf">`);
    expect(info.otherResources.map((resource) => [resource.tag, resource.url])).toEqual([
      ["img", "https://example.com/dossier/i.png"],
      ["audio", "https://example.com/dossier/a.mp3"],
      ["video", "https://example.com/dossier/v.mp4"],
      ["video", "https://example.com/dossier/p.jpg"],
      ["track", "https://example.com/dossier/t.vtt"],
      ["iframe", "https://cadre.example.org/"],
      ["frame", "https://example.com/dossier/f.html"],
      ["object", "https://example.com/dossier/o.swf"],
      ["embed", "https://example.com/dossier/e.swf"],
    ]);
  });

  it("lit chaque candidat d'un srcset, descripteurs et virgules compris", () => {
    const info = extract(`
      <img src="a.png" srcset="a-1x.png 1x, http://cdn.example.net/a-2x.png 2x,a,b.png 300w">
      <picture><source srcset="s.webp" type="image/webp"></picture>`);
    expect(urls(info.otherResources)).toEqual([
      "https://example.com/dossier/a.png",
      "https://example.com/dossier/a-1x.png",
      "http://cdn.example.net/a-2x.png",
      // Une URL peut contenir des virgules : « a,b.png » est un seul candidat (algorithme HTML).
      "https://example.com/dossier/a,b.png",
      "https://example.com/dossier/s.webp",
    ]);
  });

  it("retire les virgules finales d'une URL de srcset", () => {
    const info = extract('<img srcset="x.png,,, y.png">');
    expect(urls(info.otherResources)).toEqual([
      "https://example.com/dossier/x.png",
      "https://example.com/dossier/y.png",
    ]);
  });

  it("ne confond pas une balise inconnue nommée comme une propriété d'objet", () => {
    const info = extract('<constructor src="x.js"></constructor><toString data="y"></toString>');
    expect(info.otherResources).toEqual([]);
  });

  it("garde un <iframe> jamais fermé, comme le navigateur", () => {
    const info = extract('<iframe src="https://cadre.example.org/">');
    expect(urls(info.otherResources)).toEqual(["https://cadre.example.org/"]);
  });
});

describe("extractHtmlInfo — formulaires", () => {
  it.each([
    ["sans action", "<form></form>", null, "get"],
    ["action vide", '<form action=""></form>', null, "get"],
    [
      "action relative",
      '<form action="/login" method="POST"></form>',
      "https://example.com/login",
      "post",
    ],
    [
      "action en http://",
      '<form action="http://example.com/s"></form>',
      "http://example.com/s",
      "get",
    ],
    ["méthode inconnue", '<form action="/s" method="put"></form>', "https://example.com/s", "get"],
    ["méthode dialog", '<form method="dialog"></form>', null, "dialog"],
  ])("lit l'action et la méthode (%s)", (_label, html, action, method) => {
    expect(extract(html).forms).toEqual([{ action, method }]);
  });

  it("ignore un formulaire dont l'action est illisible (le navigateur ne l'envoie pas)", () => {
    expect(extract('<form action="https://exa mple.com:99999/"></form>').forms).toEqual([]);
  });
});

describe("extractHtmlInfo — <meta> CSP et Referrer-Policy", () => {
  it("relève chaque <meta http-equiv=Content-Security-Policy>, quelle que soit la casse", () => {
    const info = extract(`
      <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'">
        <meta HTTP-EQUIV="content-security-policy" content="script-src 'none'">
        <meta http-equiv="Content-Security-Policy" content="  ">
      </head>`);
    expect(info.metaCsp).toEqual(["default-src 'self'", "script-src 'none'"]);
  });

  it("ignore une CSP en <meta> placée dans <body> (le navigateur ne l'applique pas)", () => {
    const info = extract(
      `<html><head></head><body><div><meta http-equiv="Content-Security-Policy" content="default-src 'none'"></div></body></html>`,
    );
    expect(info.metaCsp).toEqual([]);
  });

  it("garde la dernière balise <meta name=referrer> non vide", () => {
    const info = extract(`
      <meta name="referrer" content="unsafe-url">
      <meta name="Referrer" content=" no-referrer ">
      <meta name="referrer" content="">`);
    expect(info.metaReferrer).toBe("no-referrer");
  });
});

describe("extractHtmlInfo — pages mal formées ou volumineuses", () => {
  it("renvoie une page vide pour un document vide ou du texte brut", () => {
    for (const html of ["", "simple texte", "<<<>>>", "<!-- jamais fermé"]) {
      const info = extract(html);
      expect(info.scripts).toEqual([]);
      expect(info.otherResources).toEqual([]);
      expect(info.forms).toEqual([]);
    }
  });

  it("supporte une imbrication très profonde sans dépasser la pile d'appels", () => {
    const html = `${"<div>".repeat(100_000)}<script src="https://cdn.example.net/a.js"></script>`;
    expect(urls(extract(html).scripts)).toEqual(["https://cdn.example.net/a.js"]);
  });

  it("analyse une page de 2 Mio en moins d'une seconde", () => {
    const tag = '<script src="https://cdn.example.net/a.js"></script>';
    const html = tag.repeat(Math.floor((2 * 1024 * 1024) / tag.length));
    const started = performance.now();
    const info = extract(html);
    expect(performance.now() - started).toBeLessThan(1_000);
    expect(info.scripts.length).toBeGreaterThan(40_000);
  });
});
