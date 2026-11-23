import { describe, expect, it } from "vitest";
import {
  allowsAllInline,
  classifySource,
  effectiveSources,
  hasKeyword,
  hasNonceOrHash,
  honoredScriptSources,
  isBroadSource,
  isDataSource,
  isInsecureSchemeSource,
  isNoneSourceList,
  parseCspHeader,
  parseMetaCsp,
  parseSerializedPolicy,
  sourceScheme,
} from "@/lib/scanner/checks/csp-parser";

describe("parseSerializedPolicy", () => {
  it("lit les directives et leurs sources", () => {
    const policy = parseSerializedPolicy(
      "default-src 'self'; img-src https://img.example.com data:",
      "header",
    );
    expect([...policy.directives.keys()]).toEqual(["default-src", "img-src"]);
    expect(policy.directives.get("img-src")).toEqual(["https://img.example.com", "data:"]);
    expect(policy.duplicates).toEqual([]);
    expect(policy.ignored).toEqual([]);
    expect(policy.source).toBe("header");
  });

  it("met les noms de directive en minuscules et tolère blancs et « ; » superflus", () => {
    const policy = parseSerializedPolicy("  SCRIPT-Src\t'self'   'NONCE-abc' ;; ", "header");
    expect([...policy.directives.keys()]).toEqual(["script-src"]);
    // Les sources gardent leur casse : un nonce est sensible à la casse.
    expect(policy.directives.get("script-src")).toEqual(["'self'", "'NONCE-abc'"]);
    expect(policy.raw).toBe("SCRIPT-Src\t'self'   'NONCE-abc' ;;");
  });

  it("garde la première occurrence d'une directive répétée et la signale", () => {
    const policy = parseSerializedPolicy("script-src 'self'; Script-Src *", "header");
    expect(policy.directives.get("script-src")).toEqual(["'self'"]);
    expect(policy.duplicates).toEqual(["script-src"]);
  });

  it("ignore un morceau contenant un caractère non ASCII", () => {
    const policy = parseSerializedPolicy(
      "script-src 'self'; img-src https://café.example",
      "header",
    );
    expect([...policy.directives.keys()]).toEqual(["script-src"]);
  });

  it("conserve une directive sans valeur (liste de sources vide)", () => {
    const policy = parseSerializedPolicy("upgrade-insecure-requests; script-src", "header");
    expect(policy.directives.get("upgrade-insecure-requests")).toEqual([]);
    expect(policy.directives.get("script-src")).toEqual([]);
  });

  it("renvoie une politique vide pour un texte vide", () => {
    expect(parseSerializedPolicy("   ", "header").directives.size).toBe(0);
  });
});

describe("parseCspHeader", () => {
  it("découpe sur la virgule : chaque morceau est une politique distincte", () => {
    const policies = parseCspHeader("default-src 'self', script-src 'none'", "header");
    expect(policies.map((policy) => [...policy.directives.keys()])).toEqual([
      ["default-src"],
      ["script-src"],
    ]);
  });

  it("ne voit pas de répétition entre deux politiques (en-têtes joints par « , »)", () => {
    const policies = parseCspHeader("default-src 'self', default-src 'none'", "header");
    expect(policies).toHaveLength(2);
    expect(policies.flatMap((policy) => policy.duplicates)).toEqual([]);
  });

  it("écarte les politiques vides", () => {
    expect(parseCspHeader(" , ;", "header")).toEqual([]);
    expect(parseCspHeader("", "header")).toEqual([]);
    expect(parseCspHeader("default-src 'self',", "header")).toHaveLength(1);
  });

  it("note la provenance de chaque politique", () => {
    expect(parseCspHeader("default-src 'self'", "report-only")[0]?.source).toBe("report-only");
  });
});

describe("parseMetaCsp", () => {
  it("retire frame-ancestors, report-uri et sandbox, ignorés dans une balise <meta>", () => {
    const policy = parseMetaCsp(
      "default-src 'self'; frame-ancestors 'none'; report-uri /csp; sandbox allow-forms",
    );
    expect([...policy.directives.keys()]).toEqual(["default-src"]);
    expect(policy.ignored).toEqual(["frame-ancestors", "report-uri", "sandbox"]);
    expect(policy.source).toBe("meta");
  });

  it("forme une seule politique, sans découpage sur la virgule", () => {
    const policy = parseMetaCsp("default-src 'self', script-src 'none'");
    expect([...policy.directives.keys()]).toEqual(["default-src"]);
    expect(policy.directives.get("default-src")).toEqual(["'self',", "script-src", "'none'"]);
  });

  it("peut renvoyer une politique vide (seulement des directives ignorées)", () => {
    const policy = parseMetaCsp("frame-ancestors 'none'");
    expect(policy.directives.size).toBe(0);
    expect(policy.ignored).toEqual(["frame-ancestors"]);
  });
});

describe("effectiveSources", () => {
  const policy = parseSerializedPolicy(
    "default-src 'self'; child-src https://frames.example.com; base-uri 'none'",
    "header",
  );

  it("se replie sur default-src quand la directive est absente", () => {
    expect(effectiveSources(policy, "script-src")).toEqual(["'self'"]);
    expect(effectiveSources(policy, "script-src-elem")).toEqual(["'self'"]);
    expect(effectiveSources(policy, "object-src")).toEqual(["'self'"]);
    expect(effectiveSources(policy, "img-src")).toEqual(["'self'"]);
  });

  it("suit la chaîne de repli de CSP3 (frame-src et worker-src → child-src)", () => {
    expect(effectiveSources(policy, "frame-src")).toEqual(["https://frames.example.com"]);
    expect(effectiveSources(policy, "worker-src")).toEqual(["https://frames.example.com"]);
  });

  it("préfère la directive elle-même à son repli", () => {
    const strict = parseSerializedPolicy("default-src *; script-src 'self'", "header");
    expect(effectiveSources(strict, "script-src")).toEqual(["'self'"]);
  });

  it("n'applique aucun repli à base-uri, form-action et frame-ancestors", () => {
    expect(effectiveSources(policy, "base-uri")).toEqual(["'none'"]);
    expect(effectiveSources(policy, "form-action")).toBeNull();
    expect(effectiveSources(policy, "frame-ancestors")).toBeNull();
  });

  it("renvoie null quand ni la directive ni default-src ne sont présentes", () => {
    const withoutDefault = parseSerializedPolicy("img-src 'self'", "header");
    expect(effectiveSources(withoutDefault, "script-src")).toBeNull();
  });
});

describe("classifySource", () => {
  it.each([
    ["'none'", "none"],
    ["'NONE'", "none"],
    ["'self'", "keyword"],
    ["'UNSAFE-INLINE'", "keyword"],
    ["'strict-dynamic'", "keyword"],
    ["'nonce-R4nd0m'", "nonce"],
    ["'sha256-abc='", "hash"],
    ["'SHA512-abc'", "hash"],
    ["*", "wildcard"],
    ["https:", "scheme"],
    ["data:", "scheme"],
    ["example.com", "host"],
    ["*.example.com", "host"],
    ["https://*", "host"],
    ["https://cdn.example.com:443/js/", "host"],
  ])("%s est de type %s", (source, kind) => {
    expect(classifySource(source)).toBe(kind);
  });
});

describe("sourceScheme", () => {
  it("extrait le schéma d'un schéma seul ou d'un hôte complet", () => {
    expect(sourceScheme("https:")).toBe("https");
    expect(sourceScheme("HTTP://cdn.example.com")).toBe("http");
  });

  it("renvoie null sans schéma explicite", () => {
    expect(sourceScheme("cdn.example.com:8080")).toBeNull();
    expect(sourceScheme("*.example.com")).toBeNull();
    expect(sourceScheme("'self'")).toBeNull();
  });
});

describe("isBroadSource", () => {
  it.each([
    "*",
    "https:",
    "HTTP:",
    "ftp:",
    "http://*",
    "https://*",
    "*:443",
    "https://*:*/js/",
  ])("%s est trop large", (source) => {
    expect(isBroadSource(source)).toBe(true);
  });

  it.each([
    "https://*.example.com",
    "*.example.com",
    "https://cdn.example.com",
    "'self'",
    "'unsafe-inline'",
    "data:",
    "blob:",
    "wss:",
  ])("%s n'est pas trop large", (source) => {
    expect(isBroadSource(source)).toBe(false);
  });
});

describe("isInsecureSchemeSource / isDataSource", () => {
  it("repère les schémas non chiffrés", () => {
    expect(isInsecureSchemeSource("http:")).toBe(true);
    expect(isInsecureSchemeSource("http://cdn.example.com")).toBe(true);
    expect(isInsecureSchemeSource("FTP://files.example.com")).toBe(true);
    expect(isInsecureSchemeSource("https:")).toBe(false);
    expect(isInsecureSchemeSource("https://cdn.example.com")).toBe(false);
    expect(isInsecureSchemeSource("cdn.example.com")).toBe(false);
  });

  it("repère le schéma data:", () => {
    expect(isDataSource("data:")).toBe(true);
    expect(isDataSource("DATA:")).toBe(true);
    expect(isDataSource("data.example.com")).toBe(false);
    expect(isDataSource("https:")).toBe(false);
  });
});

describe("hasKeyword / hasNonceOrHash / isNoneSourceList", () => {
  it("compare les mots-clés sans tenir compte de la casse", () => {
    expect(hasKeyword(["'SELF'", "'Unsafe-Eval'"], "'unsafe-eval'")).toBe(true);
    expect(hasKeyword(["unsafe-eval"], "'unsafe-eval'")).toBe(false);
  });

  it("repère un nonce ou une empreinte", () => {
    expect(hasNonceOrHash(["'self'", "'nonce-abc'"])).toBe(true);
    expect(hasNonceOrHash(["'sha384-abc'"])).toBe(true);
    expect(hasNonceOrHash(["'self'", "https:"])).toBe(false);
  });

  it("considère 'none' seul ou une liste vide comme « rien n'est autorisé »", () => {
    expect(isNoneSourceList(["'none'"])).toBe(true);
    expect(isNoneSourceList(["'NONE'"])).toBe(true);
    expect(isNoneSourceList([])).toBe(true);
    expect(isNoneSourceList(["'none'", "'self'"])).toBe(false);
  });
});

describe("allowsAllInline", () => {
  it("'unsafe-inline' seul autorise tout le code en ligne", () => {
    expect(allowsAllInline(["'self'", "'unsafe-inline'"], "script")).toBe(true);
    expect(allowsAllInline(["'self'", "'unsafe-inline'"], "style")).toBe(true);
  });

  it("un nonce ou une empreinte neutralise 'unsafe-inline'", () => {
    expect(allowsAllInline(["'unsafe-inline'", "'nonce-abc'"], "script")).toBe(false);
    expect(allowsAllInline(["'unsafe-inline'", "'sha256-abc'"], "style")).toBe(false);
  });

  it("'strict-dynamic' neutralise 'unsafe-inline' pour les scripts seulement", () => {
    expect(allowsAllInline(["'unsafe-inline'", "'strict-dynamic'"], "script")).toBe(false);
    expect(allowsAllInline(["'unsafe-inline'", "'strict-dynamic'"], "style")).toBe(true);
  });

  it("sans 'unsafe-inline', le code en ligne n'est pas autorisé", () => {
    expect(allowsAllInline(["'self'"], "script")).toBe(false);
  });
});

describe("honoredScriptSources", () => {
  it("avec 'strict-dynamic', ignore hôtes, schémas, 'self' et 'unsafe-inline'", () => {
    const sources = [
      "'nonce-abc'",
      "'strict-dynamic'",
      "https:",
      "'unsafe-inline'",
      "'SELF'",
      "*",
      "cdn.example.com",
      "'unsafe-eval'",
    ];
    expect(honoredScriptSources(sources)).toEqual([
      "'nonce-abc'",
      "'strict-dynamic'",
      "'unsafe-eval'",
    ]);
  });

  it("sans 'strict-dynamic', garde toutes les sources", () => {
    const sources = ["'self'", "https://cdn.example.com", "'unsafe-inline'"];
    expect(honoredScriptSources(sources)).toEqual(sources);
  });
});
