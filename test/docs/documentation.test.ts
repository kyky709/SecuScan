/**
 * Tests de la documentation : elle doit rester fidèle au code et à elle-même.
 *
 * - Chaque lien relatif du README et de docs/ mène à un fichier existant (pas de lien cassé après un
 *   renommage).
 * - Chaque contrôle du registre est décrit dans 21-controles.md et noté dans 22-notation.md : ajouter
 *   un contrôle sans le documenter fait échouer la CI.
 * - Les seuils des notes annoncés dans 22-notation.md sont ceux de scoring.ts.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CHECKS } from "@/lib/scanner/checks";
import { GRADE_THRESHOLDS } from "@/lib/scanner/scoring";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const DOCS = join(ROOT, "docs");

/** Fichiers Markdown documentés : le README et tout docs/. */
const MARKDOWN_FILES = [
  join(ROOT, "README.md"),
  ...readdirSync(DOCS)
    .filter((name) => name.endsWith(".md"))
    .map((name) => join(DOCS, name)),
];

function read(path: string): string {
  return readFileSync(path, "utf8");
}

/** Liens Markdown relatifs « [texte](chemin) », sans ancre, hors liens web et adresses e-mail. */
function relativeLinks(markdown: string): string[] {
  const links = [...markdown.matchAll(/\]\(([^)\s]+)\)/g)].map((match) => match[1] ?? "");
  return links
    .filter((link) => !/^(?:https?:|mailto:|#)/.test(link))
    .map((link) => link.split("#")[0] ?? "")
    .filter((link) => link !== "");
}

describe("documentation — liens", () => {
  it.each(
    MARKDOWN_FILES.map((path) => [path.slice(ROOT.length + 1), path]),
  )("%s : chaque lien relatif mène à un fichier existant", (_name, path) => {
    const broken = relativeLinks(read(path)).filter(
      (link) => !existsSync(resolve(dirname(path), link)),
    );
    expect(broken).toEqual([]);
  });
});

describe("documentation — fidèle au code", () => {
  const controls = read(join(DOCS, "21-controles.md"));
  const notation = read(join(DOCS, "22-notation.md"));

  it.each(
    CHECKS.map((check) => [check.id]),
  )("le contrôle « %s » est décrit dans 21-controles.md et noté dans 22-notation.md", (id) => {
    expect(controls).toContain(`\`${id}\``);
    expect(notation).toContain(`\`${id}\``);
  });

  it("22-notation.md annonce les seuils de notes de scoring.ts", () => {
    for (const { grade, minScore } of GRADE_THRESHOLDS) {
      expect(notation).toContain(`| **${grade}** | ${minScore} |`);
    }
  });
});
