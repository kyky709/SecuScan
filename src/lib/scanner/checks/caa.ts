/**
 * Contrôle « caa » : enregistrements DNS CAA (Certification Authority Authorization, RFC 8659).
 *
 * Rôle : indiquer si le domaine limite, par DNS, les autorités de certification autorisées à lui
 * délivrer des certificats, et lesquelles.
 * Pourquoi : sans CAA, n'importe quelle autorité reconnue peut émettre un certificat pour le
 * domaine ; une autorité trompée ou compromise pourrait alors délivrer un certificat frauduleux.
 * Les navigateurs ne lisent pas CAA : ce sont les autorités qui doivent le respecter avant d'émettre.
 * Place dans l'architecture : contrôle pur, lit `context.caa` (sonde DNS qui remonte l'arbre des
 * domaines parents, RFC 8659 § 3) ; sans effet sur la note (bonne pratique).
 */
import { REFS } from "../references";
import type { CaaRecord, CheckDefinition, CheckOutcome, FixExample } from "../types";
import { notApplicable, probeErrorOutcome, shorten, truncateEvidence } from "./helpers";

/** Étiquettes connues (RFC 8659 et registre IANA) : une étiquette critique inconnue bloque tout. */
const KNOWN_TAGS: ReadonlySet<string> = new Set([
  "issue",
  "issuewild",
  "iodef",
  "contactemail",
  "contactphone",
  "issuevmc",
  "issuemail",
]);

/** Drapeau « Issuer Critical » : bit de poids fort de l'octet de drapeaux (valeur 128). */
const CRITICAL_FLAG = 128;

/** Autorité d'une valeur issue/issuewild (« letsencrypt.org; validationmethods=… ») ; "" = aucune. */
function issuerOf(record: CaaRecord): string {
  return (record.value.split(";")[0] ?? "").trim().toLowerCase();
}

function uniqueIssuers(records: CaaRecord[]): string[] {
  return [...new Set(records.map(issuerOf).filter((issuer) => issuer !== ""))];
}

/** Constats détaillés : domaine d'origine, certificats génériques, iodef, valeurs bloquantes. */
function describeRecords(records: CaaRecord[], domain: string | null, hostname: string): string[] {
  const details: string[] = [];
  if (domain !== null && domain !== hostname) {
    details.push(
      `Enregistrements trouvés sur le domaine parent ${domain} : ils s'appliquent aussi à ${hostname}.`,
    );
  }
  const issue = records.filter((record) => record.tag === "issue");
  if (issue.length > 0 && uniqueIssuers(issue).length === 0) {
    details.push("Valeur issue « ; » : aucune autorité ne peut émettre de certificat classique.");
  }
  const issuewild = records.filter((record) => record.tag === "issuewild");
  if (issuewild.length > 0) {
    const issuers = uniqueIssuers(issuewild);
    details.push(
      issuers.length > 0
        ? `Certificats génériques (*.${domain ?? hostname}) autorisés pour : ${issuers.join(", ")}.`
        : "Certificats génériques (wildcard) interdits (issuewild « ; »).",
    );
  }
  const iodef = records.filter((record) => record.tag === "iodef").map((record) => record.value);
  details.push(
    iodef.length > 0
      ? `Signalement des demandes refusées (iodef) : ${iodef.join(", ")}.`
      : "Aucun enregistrement iodef : les autorités ne peuvent pas vous signaler une demande refusée.",
  );
  for (const record of records) {
    if ((record.critical & CRITICAL_FLAG) !== 0 && !KNOWN_TAGS.has(record.tag)) {
      details.push(
        `Étiquette critique inconnue « ${record.tag} » : les autorités doivent refuser toute émission.`,
      );
    }
  }
  return details;
}

function caaExamples(hostname: string): FixExample[] {
  return [
    {
      label: "Zone DNS (format BIND)",
      language: "dns",
      code: `; Seule Let's Encrypt peut émettre ; certificats génériques interdits ; signalement par e-mail
${hostname}.  3600  IN  CAA  0 issue "letsencrypt.org"
${hostname}.  3600  IN  CAA  0 issuewild ";"
${hostname}.  3600  IN  CAA  0 iodef "mailto:security@${hostname}"`,
    },
  ];
}

/** Contrôle des enregistrements DNS CAA. */
export const caaCheck: CheckDefinition = {
  id: "caa",
  category: "exposure",
  title: "Enregistrements DNS CAA",
  description:
    "Les enregistrements DNS CAA (RFC 8659) listent les autorités de certification autorisées à émettre des certificats pour le domaine. Ils réduisent le risque qu'une autre autorité, trompée ou compromise, délivre un certificat frauduleux. Les navigateurs ne les lisent pas : ce sont les autorités qui doivent les respecter.",
  references: [REFS.cheatSheets.tlsCaa, REFS.rfc.caa],
  scoring: [
    { outcome: "Hôte = adresse IP", modifier: 0 },
    { outcome: "Sonde en échec", modifier: 0 },
    {
      outcome: "Aucun enregistrement CAA (ou aucun issue/issuewild : émission non restreinte)",
      modifier: 0,
    },
    { outcome: "Enregistrements issue/issuewild présents", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    const { hostname } = context.target;
    if (context.target.isIpAddress) {
      return notApplicable(
        "L'hôte analysé est une adresse IP : les enregistrements CAA ne concernent que les noms de domaine.",
      );
    }
    if (!context.caa.ok) return probeErrorOutcome(context.caa.error, "les enregistrements CAA");

    const { domain } = context.caa.value;
    // Les étiquettes se comparent sans tenir compte de la casse.
    const records = context.caa.value.records.map((record) => ({
      ...record,
      tag: record.tag.toLowerCase(),
    }));
    const evidence =
      records.length > 0
        ? truncateEvidence(
            records
              .map((r) => `${domain ?? hostname}. CAA ${r.critical} ${r.tag} "${r.value}"`)
              .join("\n"),
          )
        : null;

    const restricting = records.filter((r) => r.tag === "issue" || r.tag === "issuewild");
    if (restricting.length === 0) {
      return {
        status: "info",
        scoreModifier: 0,
        summary:
          records.length === 0
            ? "Aucun enregistrement CAA : toute autorité de certification peut émettre un certificat pour ce domaine."
            : "Les enregistrements CAA ne contiennent ni issue ni issuewild : ils ne restreignent pas l'émission de certificats.",
        details: records.length > 0 ? describeRecords(records, domain, hostname) : undefined,
        evidence,
        recommendation:
          'Publiez des enregistrements CAA qui listent les autorités que vous utilisez (par exemple issue "letsencrypt.org"), interdisez les certificats génériques si vous n\'en avez pas besoin (issuewild ";") et ajoutez un iodef pour être prévenu des demandes refusées.',
        examples: caaExamples(hostname),
      };
    }

    const issueRecords = records.filter((record) => record.tag === "issue");
    const issuers = uniqueIssuers(issueRecords);
    // Sans enregistrement issue, issuewild n'encadre que les certificats génériques : toute
    // autorité peut encore émettre un certificat classique (RFC 8659 § 4.3).
    const wildcardOnly = issueRecords.length === 0;
    let summary: string;
    if (wildcardOnly) {
      summary =
        "Les enregistrements CAA n'encadrent que les certificats génériques (issuewild) : sans enregistrement issue, toute autorité peut émettre un certificat classique pour ce domaine.";
    } else if (issuers.length > 0) {
      summary = `Les enregistrements CAA n'autorisent que ${issuers.map(shorten).join(", ")} à émettre des certificats pour ce domaine.`;
    } else {
      summary =
        "Les enregistrements CAA interdisent à toute autorité d'émettre un certificat classique pour ce domaine (issue « ; »).";
    }
    return {
      status: "pass",
      scoreModifier: 0,
      summary,
      details: describeRecords(records, domain, hostname),
      evidence,
      recommendation: wildcardOnly
        ? 'Ajoutez un enregistrement issue qui liste vos autorités (par exemple issue "letsencrypt.org").'
        : null,
      examples: wildcardOnly ? caaExamples(hostname) : undefined,
    };
  },
};
