import { failure, fetched, makeContext, makeHtmlInfo, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { cspCheck } from "@/lib/scanner/checks/csp";
import { REFS } from "@/lib/scanner/references";
import type { Reference } from "@/lib/scanner/types";

/** Politique complète et sans source dangereuse (+5). */
const STRICT =
  "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

function evaluate(headers: Record<string, string>, metaCsp: string[] = []) {
  return cspCheck.evaluate(makeContext({ headers, html: makeHtmlInfo({ metaCsp }) }));
}

function evaluatePolicy(policy: string) {
  return evaluate({ "content-security-policy": policy });
}

/** Rang des familles de références : fiches OWASP, Top 10, ASVS, WSTG, puis MDN, RFC et autres. */
function referenceRank(reference: Reference): number {
  const ranks: Record<string, number> = {
    "owasp-cheatsheet": 0,
    "owasp-secure-headers": 0,
    "owasp-top10": 1,
    "owasp-asvs": 2,
    "owasp-wstg": 3,
  };
  return ranks[reference.kind] ?? 4;
}

describe("cspCheck : définition", () => {
  it("expose chaque ligne de la grille de notation", () => {
    expect(cspCheck.id).toBe("csp");
    expect(cspCheck.category).toBe("headers");
    expect(cspCheck.scoring.map((row) => row.modifier)).toEqual([
      -25, -25, -20, -20, -10, -10, 0, 5, 10,
    ]);
  });

  it("cite uniquement le catalogue de références, OWASP d'abord", () => {
    const catalog = Object.values(REFS).flatMap((group) => Object.values(group));
    for (const reference of cspCheck.references) expect(catalog).toContain(reference);
    const ranks = cspCheck.references.map(referenceRank);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe("cspCheck : absence de CSP appliquée", () => {
  it("aucun en-tête ni balise <meta> : fail -25 avec conseils et exemples", () => {
    const outcome = evaluate({});
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-25);
    expect(outcome.summary).toContain("Aucune Content Security Policy");
    expect(outcome.evidence).toBeNull();
    expect(outcome.recommendation).toContain("nonce");
    expect(outcome.examples?.map((example) => example.label)).toEqual([
      "Nginx",
      "Apache",
      "Next.js (proxy.ts)",
    ]);
  });

  it("une politique Report-Only seule ne compte pas : fail -25", () => {
    const outcome = evaluate({ "content-security-policy-report-only": STRICT });
    expect(outcome.scoreModifier).toBe(-25);
    expect(outcome.summary).toContain("Report-Only");
    expect(outcome.evidence).toBe(`Content-Security-Policy-Report-Only: ${STRICT}`);
    expect(outcome.recommendation).toContain("Votre politique Report-Only");
  });

  it("une balise <meta> qui ne contient que des directives ignorées ne compte pas : fail -25", () => {
    const outcome = evaluate({}, ["frame-ancestors 'none'; report-uri /csp"]);
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-25);
    expect(outcome.summary).toContain("balise <meta>");
    expect(outcome.details).toContain(
      "Directives ignorées par le navigateur dans la balise <meta> : frame-ancestors, report-uri.",
    );
  });
});

describe("cspCheck : CSP invalide", () => {
  it.each(["", "  ;  ", " , "])("en-tête sans directive lisible (%j) : fail -25", (value) => {
    const outcome = evaluatePolicy(value);
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-25);
    expect(outcome.summary).toContain("aucune directive lisible");
  });

  it("directive répétée dans une même politique : fail -25", () => {
    const outcome = evaluatePolicy(`${STRICT}; Script-Src *`);
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-25);
    expect(outcome.summary).toContain("(script-src)");
    expect(outcome.recommendation).toContain("une seule fois");
    // Le détail décrit la politique telle que le navigateur l'applique (première occurrence).
    expect(outcome.details?.[0]).toContain("aucune source dangereuse");
  });

  it("directive répétée dans une balise <meta> : fail -25", () => {
    expect(evaluate({}, ["default-src 'self'; default-src 'none'"]).scoreModifier).toBe(-25);
  });

  it("deux en-têtes joints par « , » ne forment pas une directive répétée", () => {
    const outcome = evaluatePolicy("default-src 'self', default-src 'none'");
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(10);
  });
});

describe("cspCheck : scripts non restreints (fail -20)", () => {
  it("ni script-src ni default-src", () => {
    const outcome = evaluatePolicy("upgrade-insecure-requests");
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toBe(
      "La CSP ne restreint pas les scripts : elle ne contient ni script-src ni default-src.",
    );
  });

  it("'unsafe-inline' sans nonce ni empreinte", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'",
    );
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("'unsafe-inline'");
  });

  it("'unsafe-inline' hérité de default-src", () => {
    expect(evaluatePolicy("default-src 'self' 'unsafe-inline'").scoreModifier).toBe(-20);
  });

  it("data: dans script-src", () => {
    const outcome = evaluatePolicy("default-src 'self'; script-src 'self' data:");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("data:");
  });

  it.each([
    "*",
    "https:",
    "http:",
    "ftp:",
    "https://*",
    "http://*",
  ])("source trop large %s dans script-src", (source) => {
    const outcome = evaluatePolicy(
      `default-src 'self'; script-src 'self' ${source}; object-src 'none'`,
    );
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain(`trop larges (${source})`);
  });

  it("source trop large dans object-src", () => {
    const outcome = evaluatePolicy("default-src 'self'; object-src *");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("plugins");
  });

  it("object-src non restreinte (ni object-src ni default-src)", () => {
    const outcome = evaluatePolicy("script-src 'self'");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("ne restreint pas les plugins");
  });

  it("est insensible à la casse des directives et des mots-clés", () => {
    const outcome = evaluatePolicy(
      "DEFAULT-SRC 'SELF'; SCRIPT-SRC 'SELF' 'UNSAFE-INLINE'; OBJECT-SRC 'NONE'",
    );
    expect(outcome.scoreModifier).toBe(-20);
  });
});

describe("cspCheck : sources neutralisées par un nonce ou 'strict-dynamic'", () => {
  it("'unsafe-inline' accompagné d'un nonce n'est pas pénalisé", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'self' 'unsafe-inline' 'nonce-R4nd0m'; object-src 'none'",
    );
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toContain(
      "'unsafe-inline' est ignoré par les navigateurs récents, car script-src contient un nonce, une empreinte ou 'strict-dynamic' : il ne sert que de repli pour les anciens navigateurs.",
    );
  });

  it("avec 'strict-dynamic' et un nonce, https: et 'unsafe-inline' sont ignorés", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'nonce-R4nd0m' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'",
    );
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(
      outcome.details?.some((detail) => detail.startsWith("'strict-dynamic' est utilisé :")),
    ).toBe(true);
  });

  it("signale 'strict-dynamic' sans nonce ni empreinte", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'strict-dynamic' https:; object-src 'none'",
    );
    expect(outcome.details).toContain(
      "'strict-dynamic' est utilisé sans nonce ni empreinte : les navigateurs récents bloquent alors tous les scripts de la page.",
    );
  });
});

describe("cspCheck : schémas non sécurisés", () => {
  it("http:// pour les scripts d'une page HTTPS : fail -20", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'self' http://cdn.example.com; object-src 'none'",
    );
    expect(outcome.status).toBe("fail");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("(http://cdn.example.com)");
  });

  it("ftp:// hérité de default-src pour les objets : fail -20", () => {
    const outcome = evaluatePolicy("default-src 'self' ftp://files.example.com; script-src 'self'");
    expect(outcome.scoreModifier).toBe(-20);
    expect(outcome.summary).toContain("transmis en clair");
  });

  it("http:// n'est pas compté sur une page servie en HTTP", () => {
    const policy = "default-src 'self'; script-src 'self' http://cdn.example.com; img-src http:";
    const httpResponse = makeResponse({
      url: "http://example.com/",
      headers: { "content-type": "text/html", "content-security-policy": policy },
    });
    const context = makeContext({
      https: failure("CONNECTION_REFUSED"),
      http: fetched(httpResponse),
    });
    const outcome = cspCheck.evaluate(context);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
  });

  it("http:// seulement pour les images : warning -10", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; img-src 'self' http://img.example.com; object-src 'none'",
    );
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(-10);
    expect(outcome.summary).toContain("images ou des médias");
  });

  it("ftp: seulement pour les médias : warning -10", () => {
    expect(
      evaluatePolicy("default-src 'self'; media-src ftp:; object-src 'none'").scoreModifier,
    ).toBe(-10);
  });
});

describe("cspCheck : 'unsafe-eval' (warning -10)", () => {
  it("dans script-src", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; script-src 'self' 'unsafe-eval'; object-src 'none'",
    );
    expect(outcome.status).toBe("warning");
    expect(outcome.scoreModifier).toBe(-10);
    expect(outcome.summary).toContain("'unsafe-eval'");
  });

  it("hérité de default-src", () => {
    expect(
      evaluatePolicy("default-src 'self' 'unsafe-eval'; object-src 'none'").scoreModifier,
    ).toBe(-10);
  });

  it("dans style-src", () => {
    expect(
      evaluatePolicy("default-src 'self'; style-src 'self' 'unsafe-eval'; object-src 'none'")
        .scoreModifier,
    ).toBe(-10);
  });
});

describe("cspCheck : politiques conformes", () => {
  it("seul style-src est faible : pass 0", () => {
    const outcome = evaluatePolicy(
      "default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'",
    );
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toContain("style-src est permissive");
    expect(outcome.recommendation).toContain("style-src");
  });

  it("'unsafe-inline' neutralisé par un nonce dans style-src : pas de faiblesse", () => {
    const policy =
      "default-src 'self'; style-src 'self' 'unsafe-inline' 'nonce-R4nd0m'; object-src 'none'";
    expect(evaluatePolicy(policy).scoreModifier).toBe(5);
  });

  it("aucune source dangereuse : pass +5, sans recommandation si rien ne manque", () => {
    const outcome = evaluatePolicy(STRICT);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toEqual([]);
    expect(outcome.recommendation).toBeNull();
    expect(outcome.examples).toEqual([]);
    expect(outcome.evidence).toBe(`Content-Security-Policy: ${STRICT}`);
  });

  it("default-src 'none' sans source dangereuse : pass +10", () => {
    const outcome = evaluatePolicy(
      "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    );
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(10);
    expect(outcome.recommendation).toBeNull();
  });

  it("default-src 'none' en majuscules : pass +10", () => {
    expect(evaluatePolicy("DEFAULT-SRC 'NONE'; SCRIPT-SRC 'SELF'").scoreModifier).toBe(10);
  });

  it("+5 avec les directives de durcissement manquantes en détail et en recommandation", () => {
    const outcome = evaluatePolicy("default-src 'self'");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toHaveLength(4);
    expect(outcome.details?.[0]).toContain("object-src n'est pas 'none'");
    expect(outcome.details?.[1]).toContain("base-uri est absente");
    expect(outcome.details?.[2]).toContain("form-action est absente");
    expect(outcome.details?.[3]).toContain("frame-ancestors est absente");
    expect(outcome.recommendation).toBe(
      "Pour renforcer encore la politique, ajoutez : object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'.",
    );
    expect(outcome.examples).toHaveLength(3);
  });
});

describe("cspCheck : plusieurs politiques et balises <meta>", () => {
  it("plusieurs politiques dans l'en-tête : la plus protectrice l'emporte", () => {
    const outcome = evaluatePolicy(`script-src 'self' 'unsafe-inline' https:, ${STRICT}`);
    expect(outcome.status).toBe("pass");
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toContain(
      "2 politiques CSP sont appliquées en même temps : une ressource doit être autorisée par chacune, le verdict retient donc la plus protectrice.",
    );
  });

  it("en-tête annexe (frame-ancestors seule) et politique complète en <meta>", () => {
    const outcome = evaluate({ "content-security-policy": "frame-ancestors 'none'" }, [
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'",
    ]);
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.recommendation).toBeNull();
    expect(
      outcome.details?.some((detail) =>
        detail.startsWith("Une CSP est déclarée dans une balise <meta>"),
      ),
    ).toBe(true);
  });

  it("CSP en <meta> seule : appliquée, mais frame-ancestors y est ignorée", () => {
    const outcome = evaluate({}, [STRICT]);
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.evidence).toBe(
      `<meta http-equiv="Content-Security-Policy" content="${STRICT}">`,
    );
    expect(outcome.details).toContain(
      "Directives ignorées par le navigateur dans la balise <meta> : frame-ancestors.",
    );
    expect(
      outcome.details?.some((detail) => detail.startsWith("frame-ancestors est absente")),
    ).toBe(true);
  });

  it("en-tête vide mais balise <meta> valide : la <meta> s'applique", () => {
    const outcome = evaluate({ "content-security-policy": "" }, [STRICT]);
    expect(outcome.scoreModifier).toBe(5);
    expect(outcome.details).toContain(
      "L'en-tête Content-Security-Policy ne contient aucune directive lisible : il est sans effet.",
    );
  });

  it("signale une politique Report-Only présente à côté d'une CSP appliquée", () => {
    const outcome = evaluate({
      "content-security-policy": STRICT,
      "content-security-policy-report-only": "default-src 'none'",
    });
    expect(outcome.scoreModifier).toBe(5);
    expect(
      outcome.details?.some((detail) => detail.includes("Report-Only est aussi présente")),
    ).toBe(true);
    expect(outcome.evidence).toBe(
      `Content-Security-Policy: ${STRICT}\nContent-Security-Policy-Report-Only: default-src 'none'`,
    );
  });
});

describe("cspCheck : sonde en échec", () => {
  it("sans aucune réponse : statut error, 0 point", () => {
    const context = makeContext({
      https: failure("TIMEOUT", "Délai dépassé."),
      http: failure("CONNECTION_REFUSED"),
    });
    const outcome = cspCheck.evaluate(context);
    expect(outcome.status).toBe("error");
    expect(outcome.scoreModifier).toBe(0);
    expect(outcome.summary).toBe(
      "Impossible de vérifier la Content Security Policy : Délai dépassé.",
    );
  });
});

describe("cspCheck : cohérence avec la grille", () => {
  it.each([
    "",
    STRICT,
    "default-src 'none'",
    "script-src 'self'",
    "default-src 'self'; script-src 'self' 'unsafe-eval'",
    "default-src 'self'; img-src http:",
    "default-src 'self'; style-src *",
  ])("le modificateur de « %s » figure dans la grille", (policy) => {
    const modifiers = cspCheck.scoring.map((row) => row.modifier);
    expect(modifiers).toContain(evaluatePolicy(policy).scoreModifier);
  });
});
