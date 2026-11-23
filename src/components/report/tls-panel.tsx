/**
 * Panneau « Connexion TLS » : résultat de la négociation TLS directe avec le serveur (port 443).
 *
 * Il donne les faits bruts sur lesquels s'appuient les contrôles « Certificat TLS » et « Version
 * de TLS » : version et suite de chiffrement négociées, validité et émetteur du certificat, noms
 * couverts, taille de clé, chaîne présentée et acceptation des protocoles obsolètes TLS 1.0 / 1.1.
 */
import { Lock } from "lucide-react";
import type { CertificateInfo, TlsInfo } from "@/lib/scanner/types";
import { MUTED_TEXT } from "../ui/styles";
import { formatDate, formatDaysRemaining, formatLegacyProtocol, formatTlsVersion } from "./format";
import { InfoItem, InfoList, Panel } from "./panel";

/** Clé publique lisible : « EC 256 bits », « RSA 2048 bits ». */
function formatKey(certificate: CertificateInfo): string {
  const type = certificate.keyType ?? "type inconnu";
  return certificate.keyBits ? `${type} ${certificate.keyBits} bits` : type;
}

/** Période de validité : « du 1 octobre 2026 au 30 décembre 2026 (encore 60 jours) ». */
function formatValidity(certificate: CertificateInfo): string {
  const { daysRemaining } = certificate;
  const remaining =
    daysRemaining > 0
      ? `encore ${formatDaysRemaining(daysRemaining)}`
      : formatDaysRemaining(daysRemaining);
  return `du ${formatDate(certificate.validFrom)} au ${formatDate(certificate.validTo)} (${remaining})`;
}

/** Détail du certificat du serveur. */
function CertificateItems({ certificate }: { certificate: CertificateInfo }) {
  return (
    <>
      <InfoItem label="Sujet du certificat">{certificate.subject}</InfoItem>
      <InfoItem label="Émetteur">{certificate.issuer}</InfoItem>
      <InfoItem label="Validité">{formatValidity(certificate)}</InfoItem>
      <InfoItem label="Clé publique">{formatKey(certificate)}</InfoItem>
      <InfoItem label="Noms couverts (SAN)">
        {certificate.subjectAltNames.length > 0 ? certificate.subjectAltNames.join(", ") : "aucun"}
      </InfoItem>
      <InfoItem label="Auto-signé">{certificate.selfSigned ? "oui" : "non"}</InfoItem>
      <InfoItem label="Empreinte SHA-256" mono>
        {certificate.fingerprint256}
      </InfoItem>
      <InfoItem label="Numéro de série" mono>
        {certificate.serialNumber}
      </InfoItem>
    </>
  );
}

/** Contenu du panneau quand la négociation TLS a réussi. */
function TlsDetails({ tls }: { tls: TlsInfo }) {
  return (
    <div className="space-y-4">
      <InfoList>
        <InfoItem label="Version négociée">{formatTlsVersion(tls.protocol)}</InfoItem>
        <InfoItem label="Suite de chiffrement" mono>
          {tls.cipher ?? "inconnue"}
        </InfoItem>
        <InfoItem label="Protocole applicatif (ALPN)">{tls.alpnProtocol ?? "non annoncé"}</InfoItem>
        <InfoItem label="Certificat">
          {tls.authorized
            ? "valide"
            : `invalide (${tls.authorizationError ?? "raison non précisée"})`}
        </InfoItem>
        <InfoItem label="TLS 1.0 (obsolète)">
          {formatLegacyProtocol(tls.legacyProtocols.tls10)}
        </InfoItem>
        <InfoItem label="TLS 1.1 (obsolète)">
          {formatLegacyProtocol(tls.legacyProtocols.tls11)}
        </InfoItem>
        {tls.certificate ? <CertificateItems certificate={tls.certificate} /> : null}
      </InfoList>
      {tls.chain.length > 0 ? (
        <div className="space-y-1.5 text-sm">
          <p className="font-medium text-zinc-900 dark:text-zinc-100">
            Chaîne de certificats présentée par le serveur
          </p>
          <ol className="list-decimal space-y-1 pl-5 text-zinc-700 dark:text-zinc-300">
            {tls.chain.map((link) => (
              <li key={`${link.subject} ${link.issuer}`}>
                {link.subject} <span className={MUTED_TEXT}>(émis par {link.issuer})</span>
              </li>
            ))}
          </ol>
        </div>
      ) : null}
    </div>
  );
}

/** Panneau des informations TLS (ou explication si la négociation a échoué). */
export function TlsPanel({ tls }: { tls: TlsInfo | null }) {
  return (
    <Panel
      id="panneau-tls"
      title="Connexion TLS"
      icon={<Lock aria-hidden="true" className="size-4 text-zinc-500 dark:text-zinc-400" />}
      description="Négociation directe avec le serveur sur le port 443."
    >
      {tls ? (
        <TlsDetails tls={tls} />
      ) : (
        <p className={`text-sm ${MUTED_TEXT}`}>
          La négociation TLS a échoué : aucune information n'est disponible (voir « Sondes en échec
          »).
        </p>
      )}
    </Panel>
  );
}
