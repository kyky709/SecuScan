import { httpsResponse, probeErrorOutcome, truncateEvidence } from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type {
  CertificateInfo,
  CheckDefinition,
  CheckOutcome,
  FixExample,
  HttpResponse,
  NetworkError,
  NetworkErrorCode,
  ResponseTlsInfo,
  TlsInfo,
} from "@/lib/scanner/types";

const NO_HTTPS_CODES: ReadonlySet<NetworkErrorCode> = new Set([
  "CONNECTION_REFUSED",
  "TIMEOUT",
  "TLS_ERROR",
  "CONNECTION_RESET",
]);

const INCOMPLETE_CHAIN_CODES: ReadonlySet<string> = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
]);

/** Codes de validation Node.js/OpenSSL, formulés pour suivre « … est invalide : ». */
const ERROR_REASONS: Readonly<Record<string, string>> = {
  CERT_HAS_EXPIRED: "il a expiré",
  CERT_NOT_YET_VALID: "il n'est pas encore valide (sa date de début de validité est dans le futur)",
  DEPTH_ZERO_SELF_SIGNED_CERT:
    "il est auto-signé, aucune autorité de certification reconnue ne l'a émis",
  SELF_SIGNED_CERT_IN_CHAIN: "sa chaîne remonte à une autorité racine inconnue des navigateurs",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE:
    "sa chaîne est incomplète, le serveur n'envoie pas le certificat intermédiaire",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    "son émetteur est introuvable, certificat intermédiaire manquant ou autorité inconnue",
  ERR_TLS_CERT_ALTNAME_INVALID: "il ne couvre pas ce nom d'hôte",
  CERT_REVOKED: "il a été révoqué par son autorité",
  CERT_SIGNATURE_FAILURE: "sa signature est invalide",
  CERT_UNTRUSTED: "il n'est pas reconnu comme digne de confiance",
  CERT_REJECTED: "il a été rejeté",
  UNABLE_TO_GET_ISSUER_CERT: "le certificat de son émetteur est introuvable",
  CERT_CHAIN_TOO_LONG: "sa chaîne de certificats est trop longue",
  INVALID_CA: "un certificat de sa chaîne n'est pas une autorité de certification valide",
  EE_KEY_TOO_SMALL: "sa clé est trop courte pour être acceptée",
  CA_MD_TOO_WEAK:
    "un certificat de sa chaîne est signé avec un algorithme trop faible (SHA-1, MD5)",
};

const EXPIRY_WARNING_DAYS = 14;
const DAY_MS = 86_400_000;

const ADVICE = {
  noHttps:
    "Activez HTTPS sur le port 443 avec un certificat d'une autorité reconnue : Let's Encrypt est gratuit et s'automatise avec Certbot ; Vercel, Netlify ou Cloudflare fournissent les certificats automatiquement.",
  expired:
    "Renouvelez le certificat dès maintenant et automatisez son renouvellement (Certbot ou client ACME de l'hébergeur) ; vérifiez aussi l'horloge du serveur.",
  hostname:
    "Faites émettre un certificat qui couvre exactement ce nom d'hôte (ajoutez-le à ses noms alternatifs, SAN), par exemple avec Certbot : -d example.com -d www.example.com.",
  untrusted:
    "Remplacez le certificat auto-signé (ou émis par une autorité privée) par un certificat d'une autorité publique reconnue, par exemple Let's Encrypt (gratuit).",
  generic:
    "Installez un certificat valide, émis par une autorité reconnue, couvrant tous les noms du site, avec sa chaîne complète.",
  chain:
    "Configurez le serveur pour envoyer la chaîne complète : le certificat du site suivi du ou des certificats intermédiaires (fichier fullchain.pem avec Certbot).",
  weakKey:
    "Générez une nouvelle clé (RSA 2048 bits minimum, 3072 conseillés, ou ECDSA P-256) et faites réémettre le certificat.",
  renew:
    "Renouvelez le certificat sans attendre et vérifiez que le renouvellement automatique fonctionne (par exemple : certbot renew --dry-run).",
} as const;

interface ErrorClassification {
  severity: "invalid" | "incomplete";
  reason: string;
  recommendation: string;
}

function describeError(code: string | null): string {
  if (code === null) return "il n'a pas pu être validé";
  return ERROR_REASONS[code] ?? `il n'a pas pu être validé (code ${code})`;
}

function invalidRecommendation(code: string | null): string {
  switch (code) {
    case "CERT_HAS_EXPIRED":
    case "CERT_NOT_YET_VALID":
      return ADVICE.expired;
    case "ERR_TLS_CERT_ALTNAME_INVALID":
      return ADVICE.hostname;
    case "DEPTH_ZERO_SELF_SIGNED_CERT":
    case "SELF_SIGNED_CERT_IN_CHAIN":
      return ADVICE.untrusted;
    default:
      return ADVICE.generic;
  }
}

function normalizeName(name: string): string {
  return name
    .replace(/^(?:DNS|IP Address):/i, "")
    .trim()
    .toLowerCase()
    .replace(/\.$/, "");
}

/** « *.example.com » couvre exactement un niveau : ni « example.com » ni « a.b.example.com ». */
function coversHostname(names: readonly string[], hostname: string): boolean {
  const host = normalizeName(hostname);
  return names.some((name) => {
    const pattern = normalizeName(name);
    if (pattern === host) return true;
    if (!pattern.startsWith("*.")) return false;
    const suffix = pattern.slice(1);
    const label = host.slice(0, host.length - suffix.length);
    return host.endsWith(suffix) && label.length > 0 && !label.includes(".");
  });
}

/**
 * Quand la chaîne est en erreur, Node.js ne contrôle plus le nom d'hôte (comportement vérifié) :
 * on le fait nous-mêmes, pour ne pas réduire à une « chaîne incomplète » un certificat émis pour un
 * autre site.
 */
function classifyError(
  code: string | null,
  hostname: string,
  certificate: CertificateInfo | null,
): ErrorClassification {
  const reason = describeError(code);
  if (code === null || !INCOMPLETE_CHAIN_CODES.has(code)) {
    return { severity: "invalid", reason, recommendation: invalidRecommendation(code) };
  }
  const names = certificate?.subjectAltNames ?? [];
  if (names.length > 0 && !coversHostname(names, hostname)) {
    return {
      severity: "invalid",
      reason: `${describeError("ERR_TLS_CERT_ALTNAME_INVALID")} ; de plus, ${reason}`,
      recommendation: ADVICE.hostname,
    };
  }
  return { severity: "incomplete", reason, recommendation: ADVICE.chain };
}

function weakKeyReason(certificate: CertificateInfo): string | null {
  const type = certificate.keyType?.toUpperCase() ?? "";
  const bits = certificate.keyBits;
  if (bits === null) return null;
  if (type.startsWith("RSA") && bits < 2048) return `clé RSA de ${bits} bits (minimum 2048)`;
  if ((type === "EC" || type.startsWith("ECDSA")) && bits < 256) {
    return `clé EC de ${bits} bits (minimum 256)`;
  }
  return null;
}

/**
 * Moins de 14 jours restants ET moins d'un tiers de la durée de vie : les certificats courts
 * (quelques jours) ont toujours moins de 14 jours devant eux et sont renouvelés aux deux tiers.
 */
function renewalIsLate(certificate: CertificateInfo): boolean {
  const { daysRemaining } = certificate;
  if (daysRemaining < 0 || daysRemaining >= EXPIRY_WARNING_DAYS) return false;
  const lifetimeDays =
    (Date.parse(certificate.validTo) - Date.parse(certificate.validFrom)) / DAY_MS;
  // Durée de vie illisible : on s'en tient au seuil de 14 jours.
  if (!Number.isFinite(lifetimeDays) || lifetimeDays <= 0) return true;
  return daysRemaining < lifetimeDays / 3;
}

function days(count: number): string {
  return `${count} jour${Math.abs(count) > 1 ? "s" : ""}`;
}

/** JJ/MM/AAAA en UTC, indépendamment de la langue du serveur. */
function formatDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  const day = String(date.getUTCDate()).padStart(2, "0");
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  return `${day}/${month}/${date.getUTCFullYear()}`;
}

function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function certificateDetails(tls: TlsInfo): string[] {
  const details: string[] = [];
  const certificate = tls.certificate;
  if (certificate) {
    details.push(`Émetteur : ${certificate.issuer}.`);
    const remaining =
      certificate.daysRemaining >= 0
        ? `${days(certificate.daysRemaining)} restants`
        : `expiré depuis ${days(-certificate.daysRemaining)}`;
    details.push(
      `Validité : du ${formatDate(certificate.validFrom)} au ${formatDate(certificate.validTo)} (${remaining}).`,
    );
    const names = certificate.subjectAltNames;
    if (names.length > 0) {
      const shown = names.slice(0, 10).join(", ");
      const more = names.length > 10 ? ` et ${names.length - 10} autres` : "";
      details.push(`Noms couverts (SAN) : ${shown}${more}.`);
    }
    if (certificate.keyType !== null || certificate.keyBits !== null) {
      const bits = certificate.keyBits === null ? "" : ` de ${certificate.keyBits} bits`;
      details.push(`Clé publique : ${certificate.keyType ?? "type inconnu"}${bits}.`);
    }
  }
  const lastIssuer = tls.chain.at(-1)?.issuer;
  const path = tls.chain.map((link) => link.subject);
  if (lastIssuer !== undefined && lastIssuer !== path.at(-1)) path.push(lastIssuer);
  if (path.length > 0) details.push(`Chaîne présentée : ${path.join(" → ")}.`);
  // Limite connue : Node.js ne consulte ni OCSP ni les listes de révocation (CRL).
  details.push(
    "La révocation (OCSP, CRL) n'est pas vérifiée : un certificat révoqué apparaîtrait ici comme valide.",
  );
  return details;
}

function certificateEvidence(tls: TlsInfo): string | null {
  const parts: string[] = [];
  if (tls.certificate) {
    parts.push(`sujet=${tls.certificate.subject}`, `émetteur=${tls.certificate.issuer}`);
    parts.push(`expiration=${tls.certificate.validTo}`);
  }
  if (tls.authorizationError) parts.push(`erreur=${tls.authorizationError}`);
  return parts.length > 0 ? truncateEvidence(parts.join(" ; ")) : null;
}

function certificateExamples(hostname: string): FixExample[] {
  return [
    {
      label: "Certbot (Let's Encrypt)",
      language: "sh",
      code: `# Obtenir un certificat gratuit (remplacez --nginx par --apache si besoin)
sudo certbot --nginx -d ${hostname}
# Vérifier que le renouvellement automatique fonctionne
sudo certbot renew --dry-run`,
    },
    {
      label: "Nginx",
      language: "nginx",
      code: `server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name ${hostname};
    # fullchain.pem = certificat du site + certificats intermédiaires
    ssl_certificate     /etc/letsencrypt/live/${hostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${hostname}/privkey.pem;
}`,
    },
    {
      label: "Apache",
      language: "apache",
      code: `<VirtualHost *:443>
    ServerName ${hostname}
    SSLEngine on
    # Apache 2.4.8 et plus : le fichier peut contenir la chaîne complète
    SSLCertificateFile    /etc/letsencrypt/live/${hostname}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${hostname}/privkey.pem
</VirtualHost>`,
    },
  ];
}

/**
 * `firstHttps` porte la validation du certificat faite pendant la connexion HTTPS : quand seule la
 * sonde TLS dédiée a échoué (serveur qui coupe les connexions simultanées…), on s'en sert.
 */
function evaluateProbeFailure(
  error: NetworkError,
  firstHttps: HttpResponse | null,
  hostname: string,
): CheckOutcome {
  if (firstHttps?.tls) return evaluateFromHttpsConnection(error, firstHttps.tls, hostname);
  // « Pas de HTTPS » seulement si la sonde HTTPS a, elle aussi, échoué : sinon HTTPS fonctionne
  // et l'échec de la sonde TLS est accidentel (on ne pénalise pas ce qu'on n'a pas pu observer).
  if (firstHttps === null && NO_HTTPS_CODES.has(error.code)) {
    return {
      status: "fail",
      scoreModifier: -30,
      summary: "HTTPS n'est pas disponible : la connexion TLS sur le port 443 a échoué.",
      details: [`Sonde TLS : ${error.message}`],
      evidence: error.detail ?? error.code,
      recommendation: ADVICE.noHttps,
      examples: certificateExamples(hostname),
    };
  }
  return probeErrorOutcome(error, "le certificat TLS");
}

/**
 * Moins détaillé (ni émetteur, ni dates, ni clé), mais suffisant pour reconnaître un certificat
 * expiré, auto-signé ou émis pour un autre nom, plutôt que de répondre « non vérifié ».
 */
function evaluateFromHttpsConnection(
  error: NetworkError,
  tls: ResponseTlsInfo,
  hostname: string,
): CheckOutcome {
  const details = [
    `La sonde TLS dédiée a échoué (${error.message}) : ce verdict s'appuie sur la connexion HTTPS de l'analyse, sans le détail du certificat (émetteur, dates, clé).`,
  ];
  const evidence = tls.authorizationError ?? "certificat accepté";
  if (tls.authorized) {
    return {
      status: "pass",
      scoreModifier: 0,
      summary: `Le certificat présenté par ${hostname} lors de la connexion HTTPS est valide.`,
      details,
      evidence,
      recommendation: null,
    };
  }
  const classification = classifyError(tls.authorizationError, hostname, null);
  const invalid = classification.severity === "invalid";
  return {
    status: invalid ? "fail" : "warning",
    scoreModifier: invalid ? -50 : -10,
    summary: invalid
      ? `Le certificat de ${hostname} est invalide : ${classification.reason}.`
      : `La chaîne de certificats de ${hostname} est incomplète : les navigateurs savent souvent la compléter, mais d'autres clients (applications, API, curl) échoueront.`,
    details,
    evidence,
    recommendation: classification.recommendation,
    examples: certificateExamples(hostname),
  };
}

export const tlsCertificateCheck: CheckDefinition = {
  id: "tls-certificate",
  category: "transport",
  title: "Certificat TLS",
  description:
    "Le certificat prouve au navigateur qu'il parle bien au site demandé. Il doit être émis par une autorité reconnue, être en cours de validité, couvrir le nom d'hôte et être envoyé avec sa chaîne complète. Sinon, le navigateur affiche une alerte que les visiteurs apprennent à ignorer, ce qui facilite les attaques de l'homme du milieu.",
  references: [
    REFS.cheatSheets.tlsCertificates,
    REFS.top10.A04,
    REFS.asvs["12.2.2"],
    REFS.wstg.CRYP01Certificates,
    REFS.mdn.tls,
  ],
  scoring: [
    { outcome: "Connexion TLS impossible : pas de HTTPS", modifier: -30 },
    { outcome: "Sonde TLS en échec pour une autre raison (non vérifié)", modifier: 0 },
    {
      outcome:
        "Certificat invalide (expiré, pas encore valide, auto-signé, autorité inconnue, nom non couvert…)",
      modifier: -50,
    },
    { outcome: "Certificat invalide sur l'hôte final atteint après redirection", modifier: -50 },
    { outcome: "Chaîne de certificats incomplète", modifier: -10 },
    { outcome: "Clé trop faible (RSA < 2048 bits, EC < 256 bits)", modifier: -10 },
    { outcome: "Expiration proche, renouvellement en retard", modifier: 0 },
    { outcome: "Certificat valide", modifier: 0 },
  ],
  evaluate(context) {
    const final = httpsResponse(context);
    if (!context.tls.ok) {
      const firstHttps = context.https.ok ? (context.https.value.chain[0] ?? null) : null;
      return evaluateProbeFailure(context.tls.error, firstHttps, context.target.hostname);
    }

    const tls = context.tls.value;
    const host = tls.hostname;
    const details = certificateDetails(tls);
    const evidence = certificateEvidence(tls);
    const examples = certificateExamples(host);

    const own = tls.authorized
      ? null
      : classifyError(tls.authorizationError, host, tls.certificate);
    if (own?.severity === "invalid") {
      return {
        status: "fail",
        scoreModifier: -50,
        summary: `Le certificat de ${host} est invalide : ${own.reason}.`,
        details,
        evidence,
        recommendation: own.recommendation,
        examples,
      };
    }

    // La réponse HTTPS finale vient souvent d'un autre hôte, après redirection.
    const finalTls = final?.tls;
    const finalHost = final ? hostOf(final.url) : host;
    const remote =
      finalTls && !finalTls.authorized
        ? classifyError(finalTls.authorizationError, finalHost, null)
        : null;
    if (remote?.severity === "invalid") {
      const where = finalHost === host ? host : `${finalHost}, atteint après redirection,`;
      return {
        status: "fail",
        scoreModifier: -50,
        summary: `Le certificat de ${where} est invalide : ${remote.reason}.`,
        details: [
          `Erreur observée sur ${final?.url} : ${finalTls?.authorizationError}.`,
          ...details,
        ],
        evidence,
        recommendation: remote.recommendation,
        examples,
      };
    }

    // Problèmes à -10, sans cumul : le premier sert de résumé.
    const issues: Array<{ summary: string; recommendation: string }> = [];
    for (const [name, classification] of [
      [host, own],
      [finalHost, remote],
    ] as const) {
      if (classification?.severity === "incomplete") {
        issues.push({
          summary: `La chaîne de certificats de ${name} est incomplète : les navigateurs savent souvent la compléter, mais d'autres clients (applications, API, curl) échoueront.`,
          recommendation: classification.recommendation,
        });
      }
    }
    const weakKey = tls.certificate ? weakKeyReason(tls.certificate) : null;
    if (weakKey) {
      issues.push({
        summary: `Le certificat utilise une clé trop faible : ${weakKey}.`,
        recommendation: ADVICE.weakKey,
      });
    }
    const [main, ...others] = issues;
    if (main) {
      return {
        status: "warning",
        scoreModifier: -10,
        summary: main.summary,
        details: [...others.map((issue) => issue.summary), ...details],
        evidence,
        recommendation: [...new Set(issues.map((issue) => issue.recommendation))].join(" "),
        examples,
      };
    }

    if (tls.certificate && renewalIsLate(tls.certificate)) {
      return {
        status: "warning",
        scoreModifier: 0,
        summary: `Le certificat est valide mais expire dans ${days(tls.certificate.daysRemaining)} : son renouvellement semble en retard.`,
        details,
        evidence,
        recommendation: ADVICE.renew,
        examples,
      };
    }

    const facts = tls.certificate
      ? ` (émis par ${tls.certificate.issuer}, expire dans ${days(tls.certificate.daysRemaining)})`
      : "";
    return {
      status: "pass",
      scoreModifier: 0,
      summary: `Le certificat de ${host} est valide${facts}.`,
      details,
      evidence,
      recommendation: null,
    };
  },
};
