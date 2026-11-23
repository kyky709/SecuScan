import type { CheckStatus, ScanReport, ScoreBreakdown } from "@/lib/scanner/types";

// Espace insécable : pas de retour à la ligne entre un nombre et son unité (« 3,2 s »).
const NBSP = " ";

// Signe moins typographique (U+2212), plus lisible que le trait d'union.
const MINUS = "−";

// Copie de `BONUS_THRESHOLD` (src/lib/scanner/scoring.ts) : les composants clients ne dépendent
// que des types du moteur, pour ne jamais embarquer de code serveur. Un test vérifie que les deux
// valeurs restent identiques.
export const BONUS_THRESHOLD = 90;

// En français, 0 et 1 restent au singulier.
function plural(count: number): string {
  return Math.abs(count) >= 2 ? "s" : "";
}

export function formatDuration(durationMs: number): string {
  const seconds = new Intl.NumberFormat("fr-FR", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  }).format(durationMs / 1000);
  return `${seconds}${NBSP}s`;
}

function parseDate(isoDate: string): Date | null {
  const date = new Date(isoDate);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(isoDate: string): string {
  const date = parseDate(isoDate);
  if (!date) return isoDate;
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "long", timeStyle: "short" }).format(date);
}

export function formatDate(isoDate: string): string {
  const date = parseDate(isoDate);
  if (!date) return isoDate;
  return new Intl.DateTimeFormat("fr-FR", { dateStyle: "long" }).format(date);
}

export function formatModifier(modifier: number): string {
  if (modifier > 0) return `+${modifier}`;
  if (modifier < 0) return `${MINUS}${Math.abs(modifier)}`;
  return "0";
}

/** Pour les lecteurs d'écran : « pénalité de 20 points ». */
export function describeModifier(modifier: number): string {
  if (modifier > 0) return `bonus de ${modifier} point${plural(modifier)}`;
  if (modifier < 0) return `pénalité de ${Math.abs(modifier)} point${plural(modifier)}`;
  return "sans effet sur la note";
}

// Pas de plafond : un score supérieur à 100 est affiché tel quel (« 115/100 »).
export function formatScore(score: number): string {
  return `${score}/100`;
}

export function formatTlsVersion(protocol: string | null): string {
  if (!protocol) return "inconnue";
  return protocol.replace(/^TLSv/, "TLS ").replace(/^SSLv/, "SSL ");
}

export function formatDaysRemaining(days: number): string {
  if (days < 0) return `expiré depuis ${Math.abs(days)} jour${plural(days)}`;
  if (days === 0) return "expire aujourd'hui";
  return `${days} jour${plural(days)}`;
}

export function formatRetryDelay(seconds: number): string {
  const wholeSeconds = Math.max(1, Math.ceil(seconds));
  if (wholeSeconds < 120) return `${wholeSeconds} seconde${plural(wholeSeconds)}`;
  return `${Math.ceil(wholeSeconds / 60)} minutes`;
}

// Les caractères impropres à un nom de fichier (« : » d'une IPv6…) deviennent des tirets.
export function exportFileName(report: ScanReport): string {
  const host = report.target.hostname.toLowerCase().replace(/[^a-z0-9.-]+/g, "-");
  const date = report.scannedAt.slice(0, 10);
  return `secuscan-${host}-${date}.json`;
}

// Les rapports ne sont pas conservés : ouvrir ce lien relance une analyse.
export function shareUrlFor(hostname: string, origin: string): string {
  return `${origin}/?url=${encodeURIComponent(hostname)}`;
}

export function isProblem(status: CheckStatus): boolean {
  return status === "fail" || status === "warning";
}

export function describeRedirectStatus(status: number): string | null {
  // 301 et 308 sont mémorisés par les navigateurs ; 302, 303 et 307 sont à refaire à chaque visite.
  if (status === 301 || status === 308) return "Redirection permanente";
  if (status === 302 || status === 303 || status === 307) return "Redirection temporaire";
  return null;
}

export function formatLegacyProtocol(accepted: boolean | null): string {
  if (accepted === null) return "test non concluant";
  return accepted ? "accepté (à désactiver)" : "refusé";
}

const PROBE_LABELS: Record<string, string> = {
  https: "Requête HTTPS",
  http: "Requête HTTP",
  tls: "Négociation TLS",
  securityTxt: "Fichier security.txt",
  cors: "Test CORS",
  caa: "Enregistrements DNS CAA",
};

export function probeLabel(probe: string): string {
  return PROBE_LABELS[probe] ?? probe;
}

/**
 * Une valeur de cookie peut servir d'identifiant de session, et un rapport peut être partagé en
 * capture d'écran : on ne l'affiche jamais. Les attributs, eux, sont ce qu'on veut examiner.
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

export function displayHeaderValue(name: string, value: string): string {
  return name.toLowerCase() === "set-cookie" ? maskSetCookie(value) : value;
}

export interface ScoreExplanation {
  formula: string;
  bonusNote: string;
}

// S'appuie sur `bonusesApplied`, calculé par le serveur : seule source de vérité sur les bonus.
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
