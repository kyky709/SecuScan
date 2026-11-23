/**
 * Contrôle « Version de TLS ».
 *
 * Rôle : vérifier que le serveur négocie une version moderne de TLS (1.2 ou 1.3) et qu'il refuse
 * les versions obsolètes TLS 1.0 et TLS 1.1.
 *
 * Pourquoi : les anciennes versions ont des faiblesses connues (BEAST, POODLE, chiffrements et
 * fonctions de hachage dépassés) et ont été officiellement abandonnées par la RFC 8996 (2021).
 * Tant qu'un serveur les accepte, un attaquant peut tenter de forcer leur utilisation.
 *
 * Place dans l'architecture : contrôle pur de la famille « transport ». Il lit la sonde TLS
 * (`context.tls`) : version négociée par une connexion normale, puis résultat des connexions
 * d'essai limitées à TLS 1.0 et à TLS 1.1 (`legacyProtocols`, null = test non concluant).
 */
import { probeErrorOutcome } from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, FixExample, TlsInfo } from "@/lib/scanner/types";

/** Libellés lisibles des versions renvoyées par Node.js (`socket.getProtocol()`). */
const PROTOCOL_LABELS: Readonly<Record<string, string>> = {
  SSLv2: "SSL 2.0",
  SSLv3: "SSL 3.0",
  TLSv1: "TLS 1.0",
  "TLSv1.1": "TLS 1.1",
  "TLSv1.2": "TLS 1.2",
  "TLSv1.3": "TLS 1.3",
};

/** Versions antérieures à TLS 1.2 : abandonnées (RFC 8996) et refusées par les navigateurs. */
const OBSOLETE_PROTOCOLS: ReadonlySet<string> = new Set(["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]);

/** Exemples : n'autoriser que TLS 1.2 et TLS 1.3. */
const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Dans le bloc http ou server (port 443)
ssl_protocols TLSv1.2 TLSv1.3;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Dans la configuration de mod_ssl ou le VirtualHost *:443
SSLProtocol -all +TLSv1.2 +TLSv1.3`,
  },
];

/** Description lisible d'un résultat de test d'ancien protocole. */
function legacyResult(accepted: boolean | null): string {
  if (accepted === null) return "test non concluant, sans pénalité";
  return accepted ? "accepté par le serveur" : "refusé";
}

/** Constats secondaires : suite de chiffrement, ALPN, anciens protocoles. */
function protocolDetails(tls: TlsInfo): string[] {
  const details: string[] = [];
  if (tls.cipher) details.push(`Suite de chiffrement négociée : ${tls.cipher}.`);
  if (tls.alpnProtocol === "h2") {
    details.push("Protocole applicatif négocié (ALPN) : h2, c'est-à-dire HTTP/2.");
  } else if (tls.alpnProtocol) {
    details.push(
      `Protocole applicatif négocié (ALPN) : ${tls.alpnProtocol} (HTTP/2 n'est pas proposé).`,
    );
  } else {
    details.push(
      "Aucun protocole applicatif annoncé par ALPN : le serveur ne propose probablement pas HTTP/2.",
    );
  }
  details.push(`TLS 1.0 : ${legacyResult(tls.legacyProtocols.tls10)}.`);
  details.push(`TLS 1.1 : ${legacyResult(tls.legacyProtocols.tls11)}.`);
  return details;
}

/** Contrôle de la version de TLS. */
export const tlsProtocolCheck: CheckDefinition = {
  id: "tls-protocol",
  category: "transport",
  title: "Version de TLS",
  description:
    "TLS chiffre les échanges entre le navigateur et le serveur. Les versions SSL 3.0, TLS 1.0 et TLS 1.1 ont des faiblesses connues et ont été abandonnées par la RFC 8996 ; un serveur qui les accepte encore s'expose à des attaques par repli de version. Seuls TLS 1.2 et TLS 1.3, plus rapide et plus sûr, devraient être proposés.",
  references: [
    REFS.cheatSheets.tlsProtocols,
    REFS.top10.A04,
    REFS.asvs["12.1.1"],
    REFS.wstg.CRYP01Server,
    REFS.mdn.tls,
    REFS.rfc.deprecateTls,
  ],
  scoring: [
    { outcome: "Sonde TLS en échec (déjà pénalisé par le contrôle du certificat)", modifier: 0 },
    { outcome: "Protocole négocié antérieur à TLS 1.2", modifier: -30 },
    { outcome: "TLS 1.0 ou TLS 1.1 encore acceptés", modifier: -20 },
    { outcome: "TLS 1.2 négocié, TLS 1.3 non proposé", modifier: 0 },
    { outcome: "TLS 1.3 négocié", modifier: 0 },
  ],
  evaluate(context) {
    // Pas de nouvelle pénalité : l'absence de HTTPS est déjà comptée par tls-certificate.
    if (!context.tls.ok) return probeErrorOutcome(context.tls.error, "la version de TLS");

    const tls = context.tls.value;
    const label = tls.protocol === null ? undefined : PROTOCOL_LABELS[tls.protocol];
    if (tls.protocol === null || label === undefined) {
      return {
        status: "error",
        scoreModifier: 0,
        summary: "La version de TLS négociée n'a pas pu être déterminée.",
        evidence: tls.protocol,
        recommendation: null,
      };
    }

    const details = protocolDetails(tls);
    const evidence = tls.cipher ? `${tls.protocol} (${tls.cipher})` : tls.protocol;

    if (OBSOLETE_PROTOCOLS.has(tls.protocol)) {
      return {
        status: "fail",
        scoreModifier: -30,
        summary: `Le serveur négocie ${label}, une version obsolète et vulnérable de TLS.`,
        details,
        evidence,
        recommendation:
          "Mettez à jour la configuration TLS du serveur pour n'autoriser que TLS 1.2 et TLS 1.3 : SSL 3.0, TLS 1.0 et TLS 1.1 sont abandonnés (RFC 8996).",
        examples: EXAMPLES,
      };
    }

    const { tls10, tls11 } = tls.legacyProtocols;
    if (tls10 === true || tls11 === true) {
      const accepted = [tls10 === true ? "TLS 1.0" : null, tls11 === true ? "TLS 1.1" : null]
        .filter((version) => version !== null)
        .join(" et ");
      return {
        status: "fail",
        scoreModifier: -20,
        summary: `Le serveur négocie ${label} mais accepte encore ${accepted}, versions obsolètes.`,
        details,
        evidence,
        recommendation:
          "Désactivez TLS 1.0 et TLS 1.1 (abandonnés par la RFC 8996 et refusés par les navigateurs actuels) : n'autorisez que TLS 1.2 et TLS 1.3.",
        examples: EXAMPLES,
      };
    }

    // Un test non concluant (null) n'est pas pénalisé, mais on n'affirme pas pour autant le refus.
    const refusal = tls10 === false && tls11 === false ? " et refuse les anciennes versions" : "";
    if (tls.protocol === "TLSv1.2") {
      return {
        status: "pass",
        scoreModifier: 0,
        summary: `Le serveur négocie TLS 1.2${refusal}, mais ne propose pas TLS 1.3.`,
        details,
        evidence,
        recommendation:
          "Activez aussi TLS 1.3 : la négociation est plus rapide (un seul aller-retour) et seules des suites de chiffrement modernes sont possibles.",
        examples: EXAMPLES,
      };
    }

    return {
      status: "pass",
      scoreModifier: 0,
      summary: `Le serveur négocie TLS 1.3, la version la plus récente${refusal}.`,
      details,
      evidence,
      recommendation: null,
    };
  },
};
