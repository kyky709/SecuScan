/**
 * Tests du registre des contrôles (`CHECKS`, `getCheck`) et de ses invariants.
 *
 * Le registre est l'unique source de vérité : l'orchestrateur évalue les contrôles dans son
 * ordre, la page Méthodologie et la documentation en sont tirées. Ces tests garantissent que
 * chaque contrôle est complet (titre, description, sources, grille) et que ses références
 * proviennent toutes du catalogue vérifié `REFS`.
 */

import { describe, expect, it } from "vitest";
import { CHECKS, getCheck } from "@/lib/scanner/checks";
import { CATEGORIES } from "@/lib/scanner/labels";
import { REFS } from "@/lib/scanner/references";
import type { Reference } from "@/lib/scanner/types";

/** Ordre d'affichage attendu, famille par famille. */
const EXPECTED_ORDER = [
  "https-redirect",
  "tls-certificate",
  "tls-protocol",
  "hsts",
  "csp",
  "clickjacking",
  "content-type-options",
  "referrer-policy",
  "permissions-policy",
  "cross-origin-isolation",
  "xss-protection",
  "cookies",
  "sri",
  "mixed-content",
  "cors",
  "information-disclosure",
  "security-txt",
  "caa",
];

/** Toutes les références du catalogue, à plat (le catalogue est un objet imbriqué). */
function catalogue(node: unknown): Reference[] {
  if (typeof node !== "object" || node === null) return [];
  if ("url" in node && "label" in node && "kind" in node) return [node as Reference];
  return Object.values(node).flatMap(catalogue);
}

describe("registre des contrôles", () => {
  it("contient les 18 contrôles, dans l'ordre d'affichage", () => {
    expect(CHECKS.map((check) => check.id)).toEqual(EXPECTED_ORDER);
  });

  it("regroupe les contrôles par famille, dans l'ordre des familles", () => {
    const families = CHECKS.map((check) => check.category).filter(
      (category, index, all) => index === 0 || all[index - 1] !== category,
    );
    expect(families).toEqual(CATEGORIES.map((category) => category.id));
  });

  it("donne à chaque contrôle un titre unique, une description et au moins une source", () => {
    const titles = new Set(CHECKS.map((check) => check.title));
    expect(titles.size).toBe(CHECKS.length);
    for (const check of CHECKS) {
      expect(check.title.trim(), check.id).not.toBe("");
      expect(check.description.length, check.id).toBeGreaterThan(80);
      expect(check.references.length, check.id).toBeGreaterThan(0);
    }
  });

  it("ne cite que des références du catalogue vérifié, toutes en HTTPS", () => {
    const known = catalogue(REFS);
    for (const check of CHECKS) {
      for (const reference of check.references) {
        expect(known, `${check.id} : ${reference.label}`).toContainEqual(reference);
        expect(reference.url.startsWith("https://"), reference.url).toBe(true);
      }
    }
  });

  it("décrit une grille de notation lisible, aux modificateurs entiers", () => {
    for (const check of CHECKS) {
      expect(check.scoring.length, check.id).toBeGreaterThan(0);
      for (const row of check.scoring) {
        expect(row.outcome.trim(), check.id).not.toBe("");
        expect(Number.isInteger(row.modifier), `${check.id} : ${row.outcome}`).toBe(true);
      }
    }
  });
});

describe("getCheck", () => {
  it("retrouve chaque contrôle par son identifiant", () => {
    for (const check of CHECKS) expect(getCheck(check.id)).toBe(check);
  });

  it.each([
    "",
    "HSTS",
    "inconnu",
    "__proto__",
    "constructor",
    "toString",
  ])("renvoie undefined pour « %s »", (id) => {
    expect(getCheck(id)).toBeUndefined();
  });
});
