/**
 * Registre des contrôles : la liste complète, dans l'ordre d'affichage du rapport.
 *
 * Chaque contrôle vit dans son propre fichier (`checks/<id>.ts`) et exporte une `CheckDefinition`
 * (métadonnées + fonction d'évaluation pure). Ce registre est le seul endroit qui les rassemble :
 * - l'orchestrateur (scan.ts) évalue `CHECKS` dans cet ordre ;
 * - l'interface s'en sert pour présenter la méthodologie (titres, grilles de notation, sources).
 *
 * Ajouter un contrôle = créer son fichier, puis l'insérer ici à sa place dans sa famille.
 * L'ordre suit les familles de `CATEGORIES` (labels.ts) : transport, en-têtes, cookies, contenu,
 * exposition.
 */
import type { CheckDefinition } from "@/lib/scanner/types";
import { caaCheck } from "./caa";
import { clickjackingCheck } from "./clickjacking";
import { contentTypeOptionsCheck } from "./content-type-options";
import { cookiesCheck } from "./cookies";
import { corsCheck } from "./cors";
import { crossOriginIsolationCheck } from "./cross-origin-isolation";
import { cspCheck } from "./csp";
import { hstsCheck } from "./hsts";
import { httpsRedirectCheck } from "./https-redirect";
import { informationDisclosureCheck } from "./information-disclosure";
import { mixedContentCheck } from "./mixed-content";
import { permissionsPolicyCheck } from "./permissions-policy";
import { referrerPolicyCheck } from "./referrer-policy";
import { securityTxtCheck } from "./security-txt";
import { sriCheck } from "./sri";
import { tlsCertificateCheck } from "./tls-certificate";
import { tlsProtocolCheck } from "./tls-protocol";
import { xssProtectionCheck } from "./xss-protection";

/** Tous les contrôles, dans l'ordre d'affichage (famille par famille). */
export const CHECKS: readonly CheckDefinition[] = [
  // Chiffrement et transport
  httpsRedirectCheck,
  tlsCertificateCheck,
  tlsProtocolCheck,
  hstsCheck,
  // En-têtes de sécurité
  cspCheck,
  clickjackingCheck,
  contentTypeOptionsCheck,
  referrerPolicyCheck,
  permissionsPolicyCheck,
  crossOriginIsolationCheck,
  xssProtectionCheck,
  // Cookies
  cookiesCheck,
  // Contenu et ressources
  sriCheck,
  mixedContentCheck,
  corsCheck,
  // Exposition et bonnes pratiques
  informationDisclosureCheck,
  securityTxtCheck,
  caaCheck,
];

/**
 * Retrouve un contrôle par son identifiant (ex. "hsts"), ou undefined s'il n'existe pas.
 * Accepte une chaîne quelconque (paramètre d'URL…) : la recherche fait office de validation.
 */
export function getCheck(id: string): CheckDefinition | undefined {
  return CHECKS.find((check) => check.id === id);
}
