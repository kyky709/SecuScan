/**
 * Libellés français partagés par le moteur, l'API et l'interface.
 * Ce module ne dépend d'aucun code serveur : il peut être importé par les composants clients.
 */
import type { CheckCategory, CheckStatus } from "./types";

/** Familles de contrôles, dans l'ordre d'affichage du rapport. */
export const CATEGORIES: ReadonlyArray<{ id: CheckCategory; label: string; description: string }> =
  [
    {
      id: "transport",
      label: "Chiffrement et transport",
      description: "Disponibilité de HTTPS, redirection, certificat, version de TLS et HSTS.",
    },
    {
      id: "headers",
      label: "En-têtes de sécurité",
      description:
        "En-têtes HTTP qui demandent au navigateur d'activer ses protections (CSP, clickjacking…).",
    },
    {
      id: "cookies",
      label: "Cookies",
      description:
        "Attributs de sécurité des cookies déposés par le site (Secure, HttpOnly, SameSite).",
    },
    {
      id: "content",
      label: "Contenu et ressources",
      description: "Intégrité des scripts tiers, contenu mixte et partage entre origines (CORS).",
    },
    {
      id: "exposure",
      label: "Exposition et bonnes pratiques",
      description: "Informations divulguées, contact de sécurité (security.txt) et DNS CAA.",
    },
  ];

/** Libellé court de chaque statut. */
export const STATUS_LABELS: Record<CheckStatus, string> = {
  pass: "Conforme",
  warning: "À améliorer",
  fail: "À corriger",
  info: "Information",
  error: "Non vérifié",
};

/** Ordre de gravité des statuts, du plus grave au moins grave (pour trier ou filtrer). */
export const STATUS_SEVERITY: readonly CheckStatus[] = ["fail", "warning", "error", "info", "pass"];
