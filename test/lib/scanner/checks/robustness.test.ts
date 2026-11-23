/**
 * Tests de robustesse de TOUS les contrôles, sur des contextes dégradés ou piégés.
 *
 * Les tests de chaque contrôle vérifient sa grille cas par cas ; ceux-ci vérifient des
 * invariants communs aux 18 contrôles, face à ce qu'un site malveillant ou cassé peut renvoyer :
 * - un contrôle est une fonction pure qui ne lève JAMAIS d'exception ;
 * - son statut fait partie des cinq statuts prévus ;
 * - son effet sur la note figure dans sa propre grille (`scoring`), que la page Méthodologie
 *   et la documentation affichent : la note annoncée est toujours explicable. Seule exception
 *   admise : 0 point pour un contrôle « non vérifié » (error) ou « sans objet » (info) ;
 * - ses textes ne contiennent ni « undefined », ni « NaN », ni code JavaScript (« [native code] »
 *   apparaissait quand une valeur d'en-tête comme « constructor » servait de clé d'objet) ;
 * - ses phrases restent lisibles (un en-tête de 60 000 caractères n'y est pas recopié en entier).
 */

import {
  failure,
  fetched,
  makeContext,
  makeHtmlInfo,
  makeRedirect,
  makeResponse,
  makeTarget,
} from "@test/helpers/context";
import { describe, expect, it } from "vitest";
import { CHECKS } from "@/lib/scanner/checks";
import { MAX_EVIDENCE_LENGTH } from "@/lib/scanner/checks/helpers";
import type {
  CheckDefinition,
  CheckOutcome,
  HtmlResource,
  NetworkErrorCode,
  ScanContext,
} from "@/lib/scanner/types";

const NETWORK_ERROR_CODES: NetworkErrorCode[] = [
  "BLOCKED_ADDRESS",
  "DNS_FAILURE",
  "CONNECTION_REFUSED",
  "CONNECTION_RESET",
  "TIMEOUT",
  "TLS_ERROR",
  "TOO_MANY_REDIRECTS",
  "INVALID_REDIRECT",
  "PROTOCOL_ERROR",
  "UNKNOWN",
];

/** En-têtes lus par les contrôles (voir les appels à getHeader). */
const SECURITY_HEADERS = [
  "strict-transport-security",
  "content-security-policy",
  "content-security-policy-report-only",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
  "feature-policy",
  "cross-origin-opener-policy",
  "cross-origin-embedder-policy",
  "cross-origin-resource-policy",
  "x-xss-protection",
  "server",
  "x-powered-by",
  "x-aspnet-version",
  "x-generator",
  "x-runtime",
  "access-control-allow-origin",
  "access-control-allow-credentials",
  "vary",
  "content-type",
];

/** Valeurs piégées : vides, mal formées, géantes (limite de 64 Kio des en-têtes), « magiques ». */
const HOSTILE_VALUES: Array<[label: string, value: string]> = [
  ["vide", ""],
  ["espaces", "   "],
  ["virgules", ",,,"],
  ["points-virgules", ";;;"],
  ["guillemets", `"'"'`],
  ["unicode", "é😀‮ "],
  ["caractère de contrôle", "a\u0000b\u0007"],
  ["__proto__", "__proto__"],
  ["constructor", "constructor"],
  ["toString", "toString"],
  ["dupliqué", "nosniff, DENY, max-age=1, *"],
  ["max-age géant", `max-age=${"9".repeat(400)}`],
  ["très long", "a".repeat(60_000)],
  ["espaces internes", `x${" ".repeat(60_000)}y`],
  ["chiffres", "1".repeat(60_000)],
];

/** Liens HTML inhabituels (schémas exotiques, URL vides ou relatives). */
function oddResources(tag: string): HtmlResource[] {
  return [
    "javascript:alert(1)",
    "data:text/javascript,1",
    "",
    "/relatif.js",
    "HTTP://EX.COM/a",
  ].map((url) => ({ tag, url, integrity: "md5-xyz", crossorigin: "", rel: "stylesheet" }));
}

/** Contextes à éprouver, chacun avec un nom lisible dans le rapport de test. */
function hostileContexts(): Array<[name: string, context: ScanContext]> {
  const contexts: Array<[string, ScanContext]> = [];

  for (const code of NETWORK_ERROR_CODES) {
    const partialChain = [makeRedirect("http://example.com/", "https://example.com/")];
    // Toutes les sondes en échec, avec ou sans réponses reçues avant l'erreur.
    for (const chain of [undefined, partialChain]) {
      const error = failure(code, "Échec simulé.", chain ? { chain } : {});
      contexts.push([
        `toutes les sondes en échec (${code}${chain ? ", chaîne partielle" : ""})`,
        makeContext({
          https: error,
          http: error,
          tls: failure(code),
          securityTxt: failure(code),
          cors: failure(code),
          caa: failure(code),
          response: null,
          html: null,
        }),
      ]);
    }
    // Site accessible seulement en HTTP clair.
    const httpOnly = makeResponse({ url: "http://example.com/" });
    contexts.push([
      `HTTPS en échec (${code}), HTTP seul`,
      makeContext({
        https: failure(code),
        http: fetched(httpOnly),
        tls: failure(code),
        response: httpOnly,
        html: makeHtmlInfo({ scripts: oddResources("script") }),
      }),
    ]);
  }

  for (const header of SECURITY_HEADERS) {
    for (const [label, value] of HOSTILE_VALUES) {
      const response = makeResponse({ headers: { "content-type": "text/html", [header]: value } });
      contexts.push([
        `${header} : ${label}`,
        makeContext({ https: fetched(response), cors: fetched(response), response }),
      ]);
    }
  }

  for (const [label, value] of HOSTILE_VALUES) {
    contexts.push([
      `Set-Cookie : ${label}`,
      makeContext({ setCookies: [value, `${value}=1; SameSite=${value}`] }),
    ]);
    contexts.push([
      `<meta> CSP et referrer : ${label}`,
      makeContext({ html: makeHtmlInfo({ metaCsp: [value], metaReferrer: value }) }),
    ]);
    const securityTxt = makeResponse({
      url: "https://example.com/.well-known/security.txt",
      headers: { "content-type": "text/plain" },
      body: `Contact: ${value}\nExpires: ${value}\n${value}`,
    });
    contexts.push([`security.txt : ${label}`, makeContext({ securityTxt: fetched(securityTxt) })]);
  }

  for (const status of [204, 304, 404, 500]) {
    const response = makeResponse({ status, body: null, bodyTruncated: true });
    contexts.push([`réponse HTTPS ${status}`, makeContext({ https: fetched(response), response })]);
  }
  contexts.push(["réponse analysée absente", makeContext({ response: null })]);
  contexts.push(["page non HTML", makeContext({ html: null })]);
  contexts.push([
    "HTML aux liens inhabituels",
    makeContext({
      html: makeHtmlInfo({
        scripts: oddResources("script"),
        stylesheets: oddResources("link"),
        otherResources: oddResources("img"),
        forms: [{ action: "javascript:void(0)", method: "post" }],
      }),
    }),
  ]);
  contexts.push([
    "boucle de redirections",
    makeContext({
      http: fetched(
        makeResponse(),
        Array.from({ length: 30 }, () =>
          makeRedirect("http://example.com/", "http://example.com/"),
        ),
      ),
    }),
  ]);
  contexts.push([
    "redirection vers javascript:",
    makeContext({
      http: failure("INVALID_REDIRECT", "Redirection invalide.", {
        chain: [makeRedirect("http://example.com/", "javascript:alert(1)", 302)],
      }),
    }),
  ]);
  contexts.push([
    "cible adresse IPv6",
    makeContext({
      target: makeTarget({
        input: "[2001:db8::1]",
        url: "https://[2001:db8::1]/",
        hostname: "2001:db8::1",
        isIpAddress: true,
      }),
    }),
  ]);
  return contexts;
}

/** Mots qui trahissent une valeur JavaScript affichée par erreur dans un texte. */
const FORBIDDEN_WORDS = ["undefined", "NaN", "Infinity", "[object Object]", "[native code]"];

/** Longueur maximale raisonnable d'un constat ou d'un détail. */
const MAX_SENTENCE_LENGTH = 1_500;

/** Vérifie les invariants d'un verdict ; renvoie la liste des manquements. */
function violations(check: CheckDefinition, outcome: CheckOutcome): string[] {
  const problems: string[] = [];
  if (!["pass", "warning", "fail", "info", "error"].includes(outcome.status)) {
    problems.push(`statut inconnu « ${outcome.status} »`);
  }
  const declared = check.scoring.map((row) => row.modifier);
  const neutral =
    outcome.scoreModifier === 0 && (outcome.status === "error" || outcome.status === "info");
  if (!declared.includes(outcome.scoreModifier) && !neutral) {
    problems.push(`modificateur ${outcome.scoreModifier} absent de la grille [${declared}]`);
  }
  const sentences = [outcome.summary, ...(outcome.details ?? []), outcome.recommendation ?? ""];
  if (outcome.summary.trim() === "") problems.push("résumé vide");
  for (const sentence of sentences) {
    const word = FORBIDDEN_WORDS.find((forbidden) => sentence.includes(forbidden));
    if (word) problems.push(`« ${word} » dans « ${sentence.slice(0, 120)} »`);
    if (sentence.length > MAX_SENTENCE_LENGTH) {
      problems.push(`phrase de ${sentence.length} caractères : « ${sentence.slice(0, 80)}… »`);
    }
  }
  if (typeof outcome.evidence === "string") {
    // truncateEvidence ajoute au plus « … (NNNNNN caractères) ».
    if (outcome.evidence.length > MAX_EVIDENCE_LENGTH + 30) {
      problems.push(`preuve de ${outcome.evidence.length} caractères`);
    }
  }
  for (const example of outcome.examples ?? []) {
    if (!example.label || !example.language || !example.code) problems.push("exemple incomplet");
  }
  return problems;
}

describe("robustesse des 18 contrôles face à des contextes dégradés ou piégés", () => {
  it.each(hostileContexts())("%s", (_name, context) => {
    const problems: string[] = [];
    for (const check of CHECKS) {
      let outcome: CheckOutcome;
      try {
        outcome = check.evaluate(context);
      } catch (error) {
        problems.push(`${check.id} : exception ${String(error)}`);
        continue;
      }
      problems.push(...violations(check, outcome).map((problem) => `${check.id} : ${problem}`));
    }
    expect(problems).toEqual([]);
  });
});
