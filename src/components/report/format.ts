/**
 * Mise en forme des données du rapport pour l'affichage : durées, dates, scores, modificateurs…
 *
 * Ce sont des fonctions pures, sans React ni DOM : faciles à tester et partagées par tous les
 * composants du rapport. Les nombres et les dates suivent les usages français (virgule décimale,
 * espace insécable avant l'unité, mois en toutes lettres) grâce à l'API `Intl` du navigateur.
 */
import type { CheckStatus, ScanReport, ScoreBreakdown } from "@/lib/scanner/types";

/** Espace insécable : empêche un retour à la ligne entre un nombre et son unité (« 3,2 s »). */
const NBSP = " ";

/** Signe moins typographique (U+2212), plus lisible que le trait d'union dans « −20 ». */
const MINUS = "−";

/**
 * Seuil des bonus : ils ne s'ajoutent que si le score après pénalités atteint cette valeur.
 *
 * Valeur recopiée de `BONUS_THRESHOLD` (src/lib/scanner/scoring.ts) : les composants clients ne
 * dépendent que des types et des libellés du moteur, pour ne jamais embarquer de code serveur dans
 * le navigateur. Un test vérifie que les deux valeurs restent identiques. Le rapport indique déjà
 * si les bonus ont été appliqués (`bonusesApplied`) : cette constante ne sert qu'à l'expliquer.
 */
export const BONUS_THRESHOLD = 90;

/** « s » final des noms au pluriel (en français, 0 et 1 restent au singulier). */
function plural(count: number): string {
  return Math.abs(count) >= 2 ? "s" : "";
}

/** Durée en secondes avec une décimale, ex. 3200 → « 3,2 s ». */
export function formatDuration(durationMs: number): string {
  const seconds = new Intl.NumberFormat("fr-FR", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(durationMs / 1000);
  return `${seconds}${NBSP}s`;
}

/** Convertit une date ISO 8601, ou renvoie null si elle est illisible. */
function parseDate(isoDate: string): Date | null {
  const date = new Date(isoDate);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** Date et heure locales, ex. « 15 novembre 2026 à 21:03 ». */
export function formatDateTime(isoDate: string): string {
  const date = parseDate(isoDate);
  if (!date) return isoDate;
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short" }).format(date);
}

/** Date seule, ex. « 30 décembre 2026 ». */
export function formatDate(isoDate: string): string {
  const date = parseDate(isoDate);
  if (!date) return isoDate;
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(date);
}

/** Modificateur de score signé : « +5 », « −20 » ou « 0 ». */
export function formatModifier(modifier: number): string {
  if (modifier > 0) return `+${modifier}`;
  if (modifier < 0) return `${MINUS}${Math.abs(modifier)}`;
  return "0";
}

/** Modificateur en toutes lettres, pour les lecteurs d'écran : « pénalité de 20 points ». */
export function describeModifier(modifier: number): string {
  if (modifier > 0) return `bonus de ${modifier} point${plural(modifier)}`;
  if (modifier < 0) return `pénalité de ${Math.abs(modifier)} point${plural(modifier)}`;
  return "sans effet sur la note";
}

/** Score sur 100, ex. « 85/100 ». Un score supérieur à 100 est affiché tel quel (« 115/100 »). */
export function formatScore(score: number): string {
  return `${score}/100`;
}

/** Version de TLS lisible : « TLSv1.3 » → « TLS 1.3 ». */
export function formatTlsVersion(protocol: string | null): string {
  if (!protocol) return "inconnue";
  return protocol.replace(/^TLSv/, "TLS ").replace(/^SSLv/, "SSL ");
}

/** Jours restants avant l'expiration d'un certificat : « 60 jours », « expiré depuis 3 jours ». */
export function formatDaysRemaining(days: number): string {
  if (days < 0) return `expiré depuis ${Math.abs(days)} jour${plural(days)}`;
  if (days === 0) return "expire aujourd'hui";
  return `${days} jour${plural(days)}`;
}

/** Délai avant de pouvoir réessayer (limitation de débit) : « 42 secondes », « 3 minutes ». */
export function formatRetryDelay(seconds: number): string {
  const wholeSeconds = Math.max(1, Math.ceil(seconds));
  if (wholeSeconds < 120) return `${wholeSeconds} seconde${plural(wholeSeconds)}`;
  return `${Math.ceil(wholeSeconds / 60)} minutes`;
}

/**
 * Nom du fichier d'export JSON : « secuscan-<hôte>-<date>.json », ex.
 * « secuscan-example.com-2026-11-15.json ». Les caractères impropres à un nom de fichier (les « : »
 * d'une adresse IPv6, par exemple) sont remplacés par des tirets.
 */
export function exportFileName(report: ScanReport): string {
  const host = report.target.hostname.toLowerCase().replace(/[^a-z0-9.-]+/g, "-");
  const date = report.scannedAt.slice(0, 10);
  return `secuscan-${host}-${date}.json`;
}

/**
 * Lien de partage d'une analyse : la page d'accueil avec `?url=<hôte>`. Les rapports ne sont pas
 * conservés : ouvrir ce lien relance une analyse (le résultat peut donc avoir changé entre-temps).
 */
export function shareUrlFor(hostname: string, origin: string): string {
  return `${origin}/?url=${encodeURIComponent(hostname)}`;
}

/** Un statut demande-t-il une action (à corriger ou à améliorer) ? Sert au filtre du rapport. */
export function isProblem(status: CheckStatus): boolean {
  return status === "fail" || status === "warning";
}

/**
 * Nature d'une redirection d'après son code HTTP (« Redirection permanente »), ou null si ce
 * n'est pas une redirection connue.
 */
export function describeRedirectStatus(status: number): string | null {
  // 301 et 308 sont mémorisés par les navigateurs ; 302, 303 et 307 sont à refaire à chaque visite.
  if (status === 301 || status === 308) return "Redirection permanente";
  if (status === 302 || status === 303 || status === 307) return "Redirection temporaire";
  return null;
}

/** Résultat du test d'un ancien protocole TLS (true = accepté, false = refusé, null = inconnu). */
export function formatLegacyProtocol(accepted: boolean | null): string {
  if (accepted === null) return "test non concluant";
  return accepted ? "accepté (à désactiver)" : "refusé";
}

/** Noms lisibles des sondes, indexés par le nom technique utilisé dans `probeErrors`. */
const PROBE_LABELS: Record<string, string> = {
  https: "Requête HTTPS",
  http: "Requête HTTP",
  tls: "Négociation TLS",
  securityTxt: "Fichier security.txt",
  cors: "Test CORS",
  caa: "Enregistrements DNS CAA",
};

/** Nom lisible d'une sonde (« caa » → « Enregistrements DNS CAA ») ; nom technique sinon. */
export function probeLabel(probe: string): string {
  return PROBE_LABELS[probe] ?? probe;
}

/**
 * Masque la valeur d'un cookie dans un en-tête Set-Cookie, en gardant son nom et ses attributs :
 * « session=abc123; Secure; HttpOnly » devient « session=***; Secure; HttpOnly ».
 *
 * Même pour une visite anonyme, une valeur de cookie peut servir d'identifiant de session : on ne
 * l'affiche jamais (règle également suivie par le contrôle des cookies), car un rapport peut être
 * partagé en capture d'écran. Les attributs, eux, sont précisément ce qu'on veut examiner.
 */
export function maskSetCookie(value: string): string {
  const separatorIndex = value.indexOf(";");
  const pair = separatorIndex === -1 ? value : value.slice(0, separatorIndex);
  const attributes = separatorIndex === -1 ? "" : value.slice(separatorIndex);
  const equalsIndex = pair.indexOf("=");
  // Sans « = », la chaîne entière est la valeur et le nom est vide (RFC 6265bis § 5.6).
  const name = equalsIndex === -1 ? "" : pair.slice(0, equalsIndex).trim();
  return `${name}=***${attributes}`;
}

/** Valeur d'un en-tête prête à afficher : valeurs de cookies masquées, le reste inchangé. */
export function displayHeaderValue(name: string, value: string): string {
  return name.toLowerCase() === "set-cookie" ? maskSetCookie(value) : value;
}

/** Explication du score en français, affichée sous la note. */
export interface ScoreExplanation {
  /** Calcul détaillé, ex. « 100 − 45 (pénalités) = 55 ». */
  formula: string;
  /** Pourquoi les bonus ont été comptés ou non. */
  bonusNote: string;
}

/**
 * Explique le calcul du score en langage clair.
 *
 * Règle (reprise de MDN HTTP Observatory) : score = 100 + pénalités ; les bonus ne s'ajoutent que
 * si ce score atteint le seuil, et alors tous ensemble (tout ou rien) ; le score ne descend pas
 * sous 0. On s'appuie sur `bonusesApplied` calculé par le serveur, seule source de vérité.
 */
export function explainScore(score: ScoreBreakdown): ScoreExplanation {
  const afterPenalties = score.base + score.penalties;
  const terms: string[] = [String(score.base)];
  if (score.penalties < 0) terms.push(`${MINUS} ${Math.abs(score.penalties)} (pénalités)`);
  if (score.bonusesApplied && score.bonuses > 0) terms.push(`+ ${score.bonuses} (bonus)`);
  if (terms.length === 1) terms.push("(aucune pénalité ni bonus)");

  // Le plancher à 0 n'intervient que pour un score très bas (bonus forcément non appliqués).
  const floorNote =
    !score.bonusesApplied && afterPenalties < 0 ? " (le score ne descend pas sous 0)" : "";
  const formula = `${terms.join(" ")} = ${score.score}${floorNote}`;

  let bonusNote: string;
  if (score.bonuses === 0) {
    bonusNote = "Aucun bonus obtenu.";
  } else if (score.bonusesApplied) {
    bonusNote = `Les bonus (+${score.bonuses}) sont comptés : le score après pénalités (${afterPenalties}) atteint le seuil de ${BONUS_THRESHOLD}.`;
  } else {
    bonusNote = `Les bonus (+${score.bonuses}) ne sont pas comptés : ils ne s'ajoutent que si le score après pénalités atteint ${BONUS_THRESHOLD}, or il est de ${Math.max(0, afterPenalties)}. Ainsi, un bonus ne masque jamais un vrai problème.`;
  }

  return { formula, bonusNote };
}
