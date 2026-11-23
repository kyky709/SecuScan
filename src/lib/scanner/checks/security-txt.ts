// Seul contrôle qui dépend de l'horloge (date Expires). Piège des « faux 200 » : beaucoup de sites
// renvoient leur page d'accueil ou une page d'erreur HTML avec le statut 200 pour toute adresse.
import { REFS } from "../references";
import type { CheckDefinition, CheckOutcome, FixExample, HttpResponse } from "../types";
import {
  getHeader,
  isHtmlResponse,
  isServedOverHttps,
  notApplicable,
  probeErrorOutcome,
  shorten,
  truncateEvidence,
} from "./helpers";
import {
  fieldValues,
  KNOWN_FIELDS,
  type ParsedSecurityTxt,
  parseSecurityTxt,
} from "./security-txt-parser";

/** « 2026-12-31T18:37:07Z » ; T et Z aussi en minuscules. */
const RFC3339_DATE_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/i;

const VALID_CONTACT = /^(?:mailto:|tel:|https:\/\/)/i;

const DAY_MS = 24 * 60 * 60 * 1000;
const YEAR_MS = 365 * DAY_MS;

const DATE_FORMAT = new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeZone: "UTC" });

function parseExpires(value: string): number | null {
  if (!RFC3339_DATE_TIME.test(value)) return null;
  // Date.parse ne reconnaît pas toujours « t » et « z » minuscules, que la RFC 3339 autorise.
  const time = Date.parse(value.toUpperCase());
  return Number.isNaN(time) ? null : time;
}

function contentTypeOf(response: HttpResponse): { mediaType: string; charset: string | null } {
  const [mediaType = "", ...parameters] = (getHeader(response, "content-type") ?? "").split(";");
  const charset = parameters
    .map((parameter) => parameter.trim().toLowerCase())
    .find((parameter) => parameter.startsWith("charset="));
  return {
    mediaType: mediaType.trim().toLowerCase(),
    charset: charset?.slice("charset=".length).replace(/"/g, "") ?? null,
  };
}

function absenceReason(response: HttpResponse): string | null {
  if (response.status !== 200) return `l'adresse répond avec le statut HTTP ${response.status}`;
  // Un security.txt commence par un champ, un commentaire ou une signature, jamais par « < ».
  if (isHtmlResponse(response) || (response.body ?? "").trimStart().startsWith("<")) {
    return "la réponse est une page HTML (page d'accueil ou d'erreur renvoyée pour toute adresse inconnue)";
  }
  return null;
}

/** Exigences de la RFC 9116 : chaque manquement rend le fichier non conforme. */
function findProblems(parsed: ParsedSecurityTxt, response: HttpResponse, now: number): string[] {
  const problems: string[] = [];
  const contacts = fieldValues(parsed, "contact");
  if (!contacts.some((contact) => VALID_CONTACT.test(contact))) {
    problems.push(
      contacts.length === 0
        ? "champ Contact absent"
        : "aucun Contact valide (mailto:, tel: ou https:// attendu)",
    );
  }
  const expires = fieldValues(parsed, "expires");
  const [onlyExpires] = expires;
  if (onlyExpires === undefined) {
    problems.push("champ Expires absent");
  } else if (expires.length > 1) {
    problems.push("champ Expires présent plusieurs fois (une seule occurrence autorisée)");
  } else {
    const time = parseExpires(onlyExpires);
    if (time === null) problems.push("date Expires illisible (format RFC 3339 attendu)");
    else if (time <= now) problems.push(`date Expires dépassée (${DATE_FORMAT.format(time)})`);
  }
  const { mediaType } = contentTypeOf(response);
  if (mediaType !== "text/plain") {
    problems.push(`type ${shorten(mediaType) || "non précisé"} au lieu de text/plain`);
  }
  if (!isServedOverHttps(response)) problems.push("fichier servi en HTTP et non en HTTPS");
  return problems;
}

/** Constats sans effet sur le verdict. */
function describeFile(
  parsed: ParsedSecurityTxt,
  response: HttpResponse,
  requestedUrl: string,
  now: number,
): string[] {
  const details: string[] = [];
  const counts = new Map<string, number>();
  for (const { name } of parsed.fields) {
    const label = KNOWN_FIELDS.get(name);
    if (label !== undefined) counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const found = [...counts].map(([label, count]) => (count > 1 ? `${label} (${count})` : label));
  details.push(`Champs trouvés : ${found.join(", ")}.`);

  const expires = fieldValues(parsed, "expires");
  const time = expires.length === 1 ? parseExpires(expires[0] ?? "") : null;
  if (time !== null && time - now > YEAR_MS) {
    details.push(
      `La date Expires (${DATE_FORMAT.format(time)}) est à plus d'un an : la RFC 9116 recommande moins d'un an pour éviter des informations périmées.`,
    );
  }
  const invalidContacts = fieldValues(parsed, "contact").filter((c) => !VALID_CONTACT.test(c));
  if (invalidContacts.length > 0) {
    details.push(
      `Contact ignoré (mailto:, tel: ou https:// attendu) : ${invalidContacts.map(shorten).join(", ")}.`,
    );
  }
  details.push(
    parsed.signed
      ? "Fichier signé (OpenPGP) ; SecuScan ne vérifie pas la signature."
      : "Fichier non signé : la RFC 9116 recommande une signature OpenPGP accompagnée d'un champ Canonical.",
  );
  const canonicals = fieldValues(parsed, "canonical");
  if (canonicals.length > 0 && !canonicals.some((c) => c === response.url || c === requestedUrl)) {
    details.push(
      `Le champ Canonical ne mentionne pas l'adresse du fichier (${response.url}) : la RFC 9116 conseille alors de ne pas se fier à son contenu.`,
    );
  }
  const { mediaType, charset } = contentTypeOf(response);
  if (mediaType === "text/plain" && charset !== "utf-8") {
    details.push(
      charset === null
        ? "Content-Type sans charset : la RFC 9116 demande text/plain; charset=utf-8."
        : `Jeu de caractères ${charset} au lieu de utf-8.`,
    );
  }
  if (parsed.invalidLines > 0) {
    details.push(
      parsed.invalidLines > 1
        ? `${parsed.invalidLines} lignes ne respectent pas le format « Champ: valeur » et ont été ignorées.`
        : "Une ligne ne respecte pas le format « Champ: valeur » et a été ignorée.",
    );
  }
  if (response.url !== requestedUrl) {
    details.push(`Fichier obtenu après redirection vers ${response.url}.`);
  }
  if (response.bodyTruncated) {
    details.push("Fichier tronqué à la lecture : il dépasse la taille maximale analysée.");
  }
  return details;
}

function securityTxtExamples(hostname: string, now: number): FixExample[] {
  const expires = `${new Date(now + 180 * DAY_MS).toISOString().slice(0, 10)}T00:00:00Z`;
  const lines = [
    `Contact: mailto:security@${hostname}`,
    `Expires: ${expires}`,
    "Preferred-Languages: fr, en",
    `Canonical: https://${hostname}/.well-known/security.txt`,
  ];
  return [
    { label: "Contenu du fichier", language: "text", code: lines.join("\n") },
    {
      label: "Nginx",
      language: "nginx",
      code: `location = /.well-known/security.txt {
    alias /var/www/security.txt;
    charset utf-8;  # Content-Type: text/plain; charset=utf-8
}`,
    },
    {
      label: "Apache",
      language: "apache",
      code: `# Fichier déposé dans <DocumentRoot>/.well-known/security.txt
<Files "security.txt">
    ForceType text/plain
    AddDefaultCharset utf-8
</Files>`,
    },
    {
      label: "Next.js (Route Handler)",
      language: "ts",
      code: `// app/.well-known/security.txt/route.ts
const SECURITY_TXT = [
${lines.map((line) => `  ${JSON.stringify(line)},`).join("\n")}
  "",
].join("\\n");

export function GET() {
  return new Response(SECURITY_TXT, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}`,
    },
  ];
}

export const securityTxtCheck: CheckDefinition = {
  id: "security-txt",
  category: "exposure",
  title: "Fichier security.txt",
  description:
    "Le fichier /.well-known/security.txt (RFC 9116) indique aux chercheurs en sécurité comment signaler une vulnérabilité : contact, date d'expiration, politique de divulgation. Sans lui, un problème découvert risque de ne jamais vous parvenir ou d'être rendu public sans que vous soyez prévenu.",
  references: [
    REFS.cheatSheets.vulnerabilityDisclosure,
    REFS.asvs.appendixD,
    REFS.wstg.INFO03,
    REFS.rfc.securityTxt,
    REFS.other.securityTxt,
  ],
  scoring: [
    { outcome: "Sonde en échec", modifier: 0 },
    { outcome: "Absent (statut ≠ 200, contenu HTML ou aucun champ security.txt)", modifier: 0 },
    {
      outcome:
        "Présent mais incomplet ou non conforme : Contact ou Expires manquant, Expires dépassé, type ≠ text/plain, servi hors HTTPS",
      modifier: 0,
    },
    { outcome: "Présent et valide (Contact + Expires futur)", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    if (!context.securityTxt.ok) {
      return probeErrorOutcome(context.securityTxt.error, "le fichier security.txt");
    }
    const { response, chain } = context.securityTxt.value;
    const requestedUrl = chain[0]?.url ?? response.url;
    const now = Date.now();
    const examples = securityTxtExamples(context.target.hostname, now);
    const recommendation = `Publiez https://${context.target.hostname}/.well-known/security.txt, servi en text/plain; charset=utf-8, avec au moins un champ Contact (mailto:, tel: ou https://) et un champ Expires (date RFC 3339 à moins d'un an), à renouveler avant son expiration.`;

    const reason = absenceReason(response);
    if (reason !== null) {
      return {
        ...notApplicable(`Aucun fichier security.txt : ${reason}.`),
        recommendation,
        examples,
      };
    }
    if (response.body === null) {
      // Le corps n'est lu que pour les types texte : ici, le type est forcément autre.
      const { mediaType } = contentTypeOf(response);
      return {
        status: "warning",
        scoreModifier: 0,
        summary: `Un fichier security.txt est servi avec le type ${shorten(mediaType) || "non précisé"} au lieu de text/plain : son contenu n'a pas pu être lu.`,
        recommendation,
        examples,
      };
    }

    const parsed = parseSecurityTxt(response.body);
    if (!parsed.fields.some(({ name }) => KNOWN_FIELDS.has(name))) {
      return {
        ...notApplicable(
          "Aucun fichier security.txt : la réponse ne contient aucun champ défini par la RFC 9116.",
        ),
        evidence: truncateEvidence(response.body),
        recommendation,
        examples,
      };
    }

    const problems = findProblems(parsed, response, now);
    const details = describeFile(parsed, response, requestedUrl, now);
    const evidence = truncateEvidence(response.body);
    if (problems.length > 0) {
      return {
        status: "warning",
        scoreModifier: 0,
        summary: `Le fichier security.txt est présent mais incomplet ou non conforme : ${problems.join(", ")}.`,
        details,
        evidence,
        recommendation,
        examples,
      };
    }

    const contact = fieldValues(parsed, "contact").find((c) => VALID_CONTACT.test(c)) ?? "";
    const expires = parseExpires(fieldValues(parsed, "expires")[0] ?? "") ?? now;
    return {
      status: "pass",
      scoreModifier: 0,
      summary: `Le fichier security.txt est présent et valide (contact : ${shorten(contact)} ; expire le ${DATE_FORMAT.format(expires)}).`,
      details,
      evidence,
      recommendation: null,
    };
  },
};
