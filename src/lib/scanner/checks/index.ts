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

/** Ordre d'affichage du rapport, famille par famille (cf. `CATEGORIES` dans labels.ts). */
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

/** `id` peut venir d'un paramètre d'URL : la recherche fait office de validation. */
export function getCheck(id: string): CheckDefinition | undefined {
  return CHECKS.find((check) => check.id === id);
}
