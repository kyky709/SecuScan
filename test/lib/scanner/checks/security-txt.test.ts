/**
 * Tests du contrôle « Fichier security.txt » (RFC 9116) : chaque ligne de la grille (neutre pour
 * la note), la détection des « faux 200 » (une page HTML renvoyée pour toute adresse inconnue
 * n'est pas un security.txt), les exigences de la RFC (Contact, Expires unique et futur au format
 * RFC 3339, text/plain, HTTPS) et les constats secondaires (expiration lointaine, Canonical,
 * charset, signature, redirection).
 */

import { failure, fetched, makeContext, makeRedirect, makeResponse } from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { securityTxtCheck } from "@/lib/scanner/checks/security-txt";
import type { HttpResponse } from "@/lib/scanner/types";

const URL_TXT = "https://example.com/.well-known/security.txt";
const DAY_MS = 24 * 60 * 60 * 1000;

/** Date RFC 3339 dans `days` jours (négatif = passée) : les tests ne vieillissent pas. */
function isoIn(days: number): string {
  return new Date(Date.now() + days * DAY_MS).toISOString().replace(/\.\d{3}Z$/, "Z");
}

const VALID_BODY = `Contact: mailto:security@example.com\nExpires: ${isoIn(90)}\n`;

/** Réponse de la sonde security.txt. */
function txt(body: string | null, overrides: Partial<HttpResponse> = {}): HttpResponse {
  return makeResponse({
    url: URL_TXT,
    headers: { "content-type": "text/plain; charset=utf-8" },
    body,
    ...overrides,
  });
}

function evaluate(response: HttpResponse, redirects: HttpResponse[] = []) {
  return securityTxtCheck.evaluate(makeContext({ securityTxt: fetched(response, redirects) }));
}

describe("securityTxtCheck — grille de notation (tout est neutre pour la note)", () => {
  it("renvoie une erreur neutre (0) quand la sonde a échoué", () => {
    const outcome = securityTxtCheck.evaluate(
      makeContext({ securityTxt: failure("CONNECTION_RESET", "Connexion interrompue.") }),
    );
    expect(outcome).toMatchObject({ status: "error", scoreModifier: 0 });
  });

  it("informe (0) de l'absence de fichier (404), avec un exemple personnalisé", () => {
    const outcome = evaluate(txt(null, { status: 404 }));
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toBe(
      "Aucun fichier security.txt : l'adresse répond avec le statut HTTP 404.",
    );
    expect(outcome.examples?.[0]?.code).toContain("Contact: mailto:security@example.com");
    expect(outcome.recommendation).toContain("https://example.com/.well-known/security.txt");
  });

  it.each([
    [
      "servie en text/html",
      txt("<!doctype html><title>Accueil</title>", { headers: { "content-type": "text/html" } }),
    ],
    ["servie en text/plain mais commençant par <", txt("  <html><body>404</body></html>")],
  ])("reconnaît un « faux 200 » : page HTML %s", (_label, response) => {
    const outcome = evaluate(response);
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("la réponse est une page HTML");
  });

  it("informe (0) quand la réponse ne contient aucun champ de la RFC 9116", () => {
    const outcome = evaluate(txt("Bonjour, rien à voir ici."));
    expect(outcome).toMatchObject({ status: "info", scoreModifier: 0 });
    expect(outcome.summary).toContain("aucun champ défini par la RFC 9116");
  });

  it("réussit (0) avec un fichier valide : Contact et Expires futur", () => {
    const outcome = evaluate(txt(VALID_BODY));
    expect(outcome).toMatchObject({ status: "pass", scoreModifier: 0, recommendation: null });
    expect(outcome.summary).toMatch(
      /^Le fichier security\.txt est présent et valide \(contact : mailto:security@example\.com ; expire le \d{1,2} \S+ \d{4}\)\.$/,
    );
    expect(outcome.details?.[0]).toBe("Champs trouvés : Contact, Expires.");
    expect(outcome.evidence).toBe(VALID_BODY);
  });

  it.each([
    ["Contact absent", `Expires: ${isoIn(90)}`, "champ Contact absent"],
    [
      "Contact invalide",
      `Contact: security@example.com\nExpires: ${isoIn(90)}`,
      "aucun Contact valide",
    ],
    ["Expires absent", "Contact: mailto:a@example.com", "champ Expires absent"],
    [
      "Expires dépassé",
      `Contact: mailto:a@example.com\nExpires: ${isoIn(-1)}`,
      "date Expires dépassée",
    ],
    [
      "Expires illisible",
      "Contact: mailto:a@example.com\nExpires: 31/12/2030",
      "date Expires illisible",
    ],
    [
      "Expires répété",
      `Contact: mailto:a@example.com\nExpires: ${isoIn(30)}\nExpires: ${isoIn(60)}`,
      "champ Expires présent plusieurs fois",
    ],
  ])("avertit sans pénalité (0) quand le fichier est incomplet : %s", (_label, body, problem) => {
    const outcome = evaluate(txt(body));
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("présent mais incomplet ou non conforme");
    expect(outcome.summary).toContain(problem);
  });

  it("avertit quand le fichier n'est pas servi en text/plain", () => {
    const outcome = evaluate(
      txt(VALID_BODY, { headers: { "content-type": "application/octet-stream" } }),
    );
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("type application/octet-stream au lieu de text/plain");
  });

  it("avertit quand le corps n'a pas pu être lu (type non textuel)", () => {
    const outcome = evaluate(txt(null, { headers: { "content-type": "image/png" } }));
    expect(outcome).toMatchObject({ status: "warning", scoreModifier: 0 });
    expect(outcome.summary).toContain("son contenu n'a pas pu être lu");
  });

  it("avertit quand le fichier est servi en HTTP clair", () => {
    const outcome = evaluate(
      txt(VALID_BODY, { url: "http://example.com/.well-known/security.txt" }),
    );
    expect(outcome.summary).toContain("fichier servi en HTTP et non en HTTPS");
  });

  it("déclare chaque modificateur possible dans la grille", () => {
    expect(new Set(securityTxtCheck.scoring.map((row) => row.modifier))).toEqual(new Set([0]));
  });
});

describe("securityTxtCheck — constats secondaires", () => {
  it("accepte le format RFC 3339 en minuscules, avec fraction et décalage horaire", () => {
    const date = isoIn(30).replace("T", "t").replace("Z", "+02:00");
    const outcome = evaluate(txt(`Contact: tel:+33100000000\nExpires: ${date}`));
    expect(outcome).toMatchObject({ status: "pass" });
  });

  it("signale une date Expires à plus d'un an", () => {
    const outcome = evaluate(txt(`Contact: https://example.com/c\nExpires: ${isoIn(500)}`));
    expect(outcome).toMatchObject({ status: "pass" });
    expect(outcome.details?.some((d) => d.includes("est à plus d'un an"))).toBe(true);
  });

  it("liste les champs trouvés et compte les répétitions", () => {
    const outcome = evaluate(
      txt(
        `Contact: mailto:a@example.com\nContact: https://example.com/c\nExpires: ${isoIn(30)}\nPreferred-Languages: fr, en`,
      ),
    );
    expect(outcome.details?.[0]).toBe(
      "Champs trouvés : Contact (2), Expires, Preferred-Languages.",
    );
  });

  it("signale les Contact ignorés à côté d'un Contact valide", () => {
    const outcome = evaluate(
      txt(`Contact: security@example.com\nContact: mailto:a@example.com\nExpires: ${isoIn(30)}`),
    );
    expect(outcome).toMatchObject({ status: "pass" });
    expect(outcome.details).toContain(
      "Contact ignoré (mailto:, tel: ou https:// attendu) : security@example.com.",
    );
  });

  it("signale un charset manquant ou différent de utf-8", () => {
    const sansCharset = evaluate(txt(VALID_BODY, { headers: { "content-type": "text/plain" } }));
    expect(sansCharset.details).toContain(
      "Content-Type sans charset : la RFC 9116 demande text/plain; charset=utf-8.",
    );
    const latin1 = evaluate(
      txt(VALID_BODY, { headers: { "content-type": "text/plain; charset=ISO-8859-1" } }),
    );
    expect(latin1.details).toContain("Jeu de caractères iso-8859-1 au lieu de utf-8.");
  });

  it("signale un Canonical qui ne mentionne pas l'adresse du fichier", () => {
    const outcome = evaluate(
      txt(`${VALID_BODY}Canonical: https://autre.example.org/.well-known/security.txt\n`),
    );
    expect(outcome.details?.some((d) => d.startsWith("Le champ Canonical ne mentionne pas"))).toBe(
      true,
    );
  });

  it("indique si le fichier est signé ou non", () => {
    expect(evaluate(txt(VALID_BODY)).details).toContain(
      "Fichier non signé : la RFC 9116 recommande une signature OpenPGP accompagnée d'un champ Canonical.",
    );
    const signed = `-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\n${VALID_BODY}-----BEGIN PGP SIGNATURE-----\nabc\n-----END PGP SIGNATURE-----\n`;
    expect(evaluate(txt(signed)).details).toContain(
      "Fichier signé (OpenPGP) ; SecuScan ne vérifie pas la signature.",
    );
  });

  it("signale une redirection et un fichier tronqué", () => {
    const final = txt(VALID_BODY, {
      url: "https://www.example.com/.well-known/security.txt",
      bodyTruncated: true,
    });
    const outcome = evaluate(final, [makeRedirect(URL_TXT, final.url)]);
    expect(outcome.details).toContain(
      "Fichier obtenu après redirection vers https://www.example.com/.well-known/security.txt.",
    );
    expect(outcome.details).toContain(
      "Fichier tronqué à la lecture : il dépasse la taille maximale analysée.",
    );
  });

  it("compte les lignes illisibles", () => {
    const outcome = evaluate(txt(`${VALID_BODY}ligne sans deux-points\nautre ligne\n`));
    expect(outcome.details).toContain(
      "2 lignes ne respectent pas le format « Champ: valeur » et ont été ignorées.",
    );
  });
});
