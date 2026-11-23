// RFC 9116 § 2 et § 4. La signature OpenPGP « en clair » (RFC 4880 § 7) est retirée mais pas
// vérifiée : il faudrait la clé publique de l'organisation.

export interface SecurityTxtField {
  /** En minuscules : les noms de champs sont insensibles à la casse. */
  name: string;
  value: string;
}

export interface ParsedSecurityTxt {
  signed: boolean;
  fields: SecurityTxtField[];
  invalidLines: number;
}

/** RFC 9116 et registre IANA (qui ajoute CSAF), avec leur casse usuelle. */
export const KNOWN_FIELDS: ReadonlyMap<string, string> = new Map([
  ["acknowledgments", "Acknowledgments"],
  ["canonical", "Canonical"],
  ["contact", "Contact"],
  ["csaf", "CSAF"],
  ["encryption", "Encryption"],
  ["expires", "Expires"],
  ["hiring", "Hiring"],
  ["policy", "Policy"],
  ["preferred-languages", "Preferred-Languages"],
]);

const PGP_SIGNED_MESSAGE = "-----BEGIN PGP SIGNED MESSAGE-----";
const PGP_SIGNATURE = "-----BEGIN PGP SIGNATURE-----";

/** RFC 9116 § 4, « field-name ». */
const FIELD_NAME = /^[A-Za-z0-9-]+$/;

/** Ne lève jamais d'exception : une ligne illisible est seulement comptée dans `invalidLines`. */
export function parseSecurityTxt(text: string): ParsedSecurityTxt {
  // Fins de ligne CRLF ou LF (RFC 9116 § 4) ; une éventuelle marque d'ordre des octets est retirée.
  const lines = text.replace(/^﻿/, "").split(/\r?\n/);
  const { content, signed } = unwrapSignature(lines);
  const fields: SecurityTxtField[] = [];
  let invalidLines = 0;
  for (const line of content) {
    const trimmed = line.trim();
    if (trimmed === "" || trimmed.startsWith("#")) continue;
    const field = parseFieldLine(trimmed);
    if (field === null) {
      invalidLines += 1;
      continue;
    }
    fields.push(field);
  }
  return { signed, fields, invalidLines };
}

/**
 * Le nom doit être collé aux deux-points ; un CR isolé rend la ligne illisible. Pas de
 * `/^([\w-]+):\s*(.*)$/`, quadratique sur une longue suite d'espaces suivie d'un CR isolé : plus
 * d'une seconde pour 60 000 espaces, exploitable par un site piégé (ReDoS).
 */
function parseFieldLine(line: string): SecurityTxtField | null {
  const colon = line.indexOf(":");
  if (colon === -1) return null;
  const name = line.slice(0, colon);
  const value = line.slice(colon + 1);
  if (!FIELD_NAME.test(name) || value.includes("\r")) return null;
  return { name: name.toLowerCase(), value: value.trim() };
}

/** `name` en minuscules. */
export function fieldValues(parsed: ParsedSecurityTxt, name: string): string[] {
  return parsed.fields.filter((field) => field.name === name).map((field) => field.value);
}

/**
 * Retire l'enveloppe d'un message signé :
 *   -----BEGIN PGP SIGNED MESSAGE-----
 *   Hash: SHA512            ← en-têtes d'armure, jusqu'à la première ligne vide
 *
 *   Contact: …              ← contenu signé
 *   -----BEGIN PGP SIGNATURE-----
 *   …                       ← signature, ignorée
 */
function unwrapSignature(lines: string[]): { content: string[]; signed: boolean } {
  const start = lines.findIndex((line) => line.trim() !== "");
  if (lines[start]?.trim() !== PGP_SIGNED_MESSAGE) return { content: lines, signed: false };

  const blank = lines.findIndex((line, index) => index > start && line.trim() === "");
  if (blank === -1) return { content: [], signed: true };
  const end = lines.findIndex((line, index) => index > blank && line.trim() === PGP_SIGNATURE);
  const content = lines.slice(blank + 1, end === -1 ? undefined : end);
  // Dans le texte signé, une ligne qui commence par un tiret est « échappée » en « - - ».
  return {
    content: content.map((line) => (line.startsWith("- ") ? line.slice(2) : line)),
    signed: true,
  };
}
