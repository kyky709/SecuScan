// Sans dépendance serveur : importable par les composants clients.
import type { CheckCategory, CheckStatus } from "./types";

/** Dans l'ordre d'affichage du rapport. */
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

export const STATUS_LABELS: Record<CheckStatus, string> = {
  pass: "Conforme",
  warning: "À améliorer",
  fail: "À corriger",
  info: "Information",
  error: "Non vérifié",
};

/** Du plus grave au moins grave. */
export const STATUS_SEVERITY: readonly CheckStatus[] = ["fail", "warning", "error", "info", "pass"];
