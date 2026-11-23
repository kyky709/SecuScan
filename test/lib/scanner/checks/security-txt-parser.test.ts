import { describe, expect, it } from "vitest";
import { fieldValues, parseSecurityTxt } from "@/lib/scanner/checks/security-txt-parser";

describe("parseSecurityTxt", () => {
  it("lit les champs, en minuscules, avec leur valeur sans espaces autour", () => {
    const parsed = parseSecurityTxt(
      "Contact: mailto:security@example.com\nEXPIRES:   2030-01-01T00:00:00Z  \nPolicy:https://example.com/p",
    );
    expect(parsed).toEqual({
      signed: false,
      invalidLines: 0,
      fields: [
        { name: "contact", value: "mailto:security@example.com" },
        { name: "expires", value: "2030-01-01T00:00:00Z" },
        { name: "policy", value: "https://example.com/p" },
      ],
    });
  });

  it("garde les deux-points de la valeur (seul le premier sépare le nom)", () => {
    const parsed = parseSecurityTxt("Contact: https://example.com:443/contact");
    expect(fieldValues(parsed, "contact")).toEqual(["https://example.com:443/contact"]);
  });

  it("accepte les fins de ligne CRLF, la marque d'ordre des octets et les commentaires", () => {
    const parsed = parseSecurityTxt(
      "﻿# Commentaire\r\nContact: tel:+33100000000\r\n\r\n   # autre\r\nHiring: https://example.com/jobs\r\n",
    );
    expect(parsed.fields.map((field) => field.name)).toEqual(["contact", "hiring"]);
    expect(parsed.invalidLines).toBe(0);
  });

  it("compte les lignes illisibles sans s'arrêter", () => {
    const parsed = parseSecurityTxt(
      "Contact: mailto:a@b.fr\nceci n'est pas un champ\nNom avec espace: x\n: sans nom\nExpires: 2030-01-01T00:00:00Z",
    );
    expect(parsed.fields.map((field) => field.name)).toEqual(["contact", "expires"]);
    expect(parsed.invalidLines).toBe(3);
  });

  it("refuse une valeur qui contient un retour chariot isolé", () => {
    const parsed = parseSecurityTxt("Contact: mailto:a@b.fr\rautre");
    expect(parsed.fields).toEqual([]);
    expect(parsed.invalidLines).toBe(1);
  });

  it("renvoie l'ordre du fichier pour un champ répété", () => {
    const parsed = parseSecurityTxt("Contact: mailto:a@b.fr\nContact: https://b.fr/c");
    expect(fieldValues(parsed, "contact")).toEqual(["mailto:a@b.fr", "https://b.fr/c"]);
    expect(fieldValues(parsed, "expires")).toEqual([]);
  });

  it("lit le contenu d'un fichier signé et ignore l'enveloppe et la signature", () => {
    const parsed = parseSecurityTxt(
      [
        "-----BEGIN PGP SIGNED MESSAGE-----",
        "Hash: SHA512",
        "",
        "Contact: mailto:security@example.com",
        "- -----Ligne échappée: commençant par un tiret",
        "Expires: 2030-01-01T00:00:00Z",
        "-----BEGIN PGP SIGNATURE-----",
        "",
        "iQIzBAEBCgAdFiEE",
        "-----END PGP SIGNATURE-----",
      ].join("\n"),
    );
    expect(parsed.signed).toBe(true);
    expect(parsed.fields.map((field) => field.name)).toEqual(["contact", "expires"]);
    // « - -----Ligne… » devient « -----Ligne échappée: … », qui n'est pas un nom de champ valide.
    expect(parsed.invalidLines).toBe(1);
  });

  it("ne lit rien d'un fichier signé sans ligne vide après l'en-tête d'armure", () => {
    const parsed = parseSecurityTxt("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512");
    expect(parsed).toEqual({ signed: true, fields: [], invalidLines: 0 });
  });

  it("ne lève pas d'exception sur un fichier vide", () => {
    expect(parseSecurityTxt("")).toEqual({ signed: false, fields: [], invalidLines: 0 });
  });
});
