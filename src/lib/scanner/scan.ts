/**
 * Orchestrateur du scan : la « coquille impérative » autour du « cœur fonctionnel ».
 *
 *   saisie ─► normalizeTarget ─► pré-contrôle DNS ─► 6 sondes réseau en parallèle ─► ScanContext
 *          ─► contrôles purs (CHECKS) ─► computeScore ─► ScanReport
 *
 * Tout ce qui touche au réseau (lent, faillible) se passe ici et dans `network/` ; les contrôles ne
 * reçoivent que des faits déjà collectés et restent de simples fonctions pures. Les dépendances
 * (client HTTP, sonde TLS, DNS, horloge, liste des contrôles) sont injectables : les tests
 * remplacent le réseau par des réponses fabriquées.
 *
 * Robustesse : une sonde qui échoue ne fait pas échouer le scan (le contrôle concerné passe au
 * statut « error », sans pénalité) et un contrôle qui lève une exception non plus. Seuls une
 * saisie refusée, un nom introuvable ou interdit, ou un site totalement injoignable (ni HTTPS ni
 * HTTP) empêchent de produire un rapport : ils lèvent une `ScanError`.
 */
import { setTimeout } from "node:timers/promises";
import {
  CORS_PROBE_ORIGIN,
  MAX_BODY_BYTES,
  MAX_SECURITY_TXT_BYTES,
  SCAN_TIMEOUT_MS,
  SCANNER_NAME,
  SCANNER_VERSION,
} from "@/lib/config";
import { CHECKS } from "@/lib/scanner/checks";
import { getHeader, isHtmlResponse } from "@/lib/scanner/checks/helpers";
import { extractHtmlInfo } from "@/lib/scanner/checks/html";
import { ScanError } from "@/lib/scanner/errors";
import { probeTls, resolveCaa, resolveHost, safeFetch } from "@/lib/scanner/network";
import { computeScore } from "@/lib/scanner/scoring";
import { normalizeTarget } from "@/lib/scanner/target";
import type {
  CaaInfo,
  CaaResolver,
  CheckDefinition,
  CheckOutcome,
  CheckResult,
  CheckStatus,
  Fetcher,
  FetchSuccess,
  HtmlInfo,
  HttpResponse,
  NetworkErrorCode,
  RedirectHop,
  Result,
  ScanContext,
  ScanReport,
  ScanTarget,
  ScoreBreakdown,
  TlsProber,
} from "@/lib/scanner/types";

/**
 * Pré-contrôle DNS (`resolveHost` de la couche réseau) : le nom existe-t-il, et toutes ses
 * adresses sont-elles publiques ? Renvoie les adresses résolues, ou une erreur DNS_FAILURE /
 * BLOCKED_ADDRESS. Seul le verdict compte ici : les adresses sont revérifiées à chaque connexion.
 */
export type HostResolver = (
  hostname: string,
) => Promise<Result<Array<{ address: string; family: number }>>>;

/** Dépendances du scan, remplaçables dans les tests (aucun accès réseau réel). */
export interface ScanDependencies {
  /** Client HTTP(S) sûr : anti-SSRF, redirections revalidées, délais, taille de corps bornée. */
  fetch: Fetcher;
  /** Sonde TLS : certificat, protocole négocié, anciens protocoles acceptés. */
  probeTls: TlsProber;
  /** Recherche des enregistrements DNS CAA (en remontant vers les domaines parents). */
  resolveCaa: CaaResolver;
  /** Pré-contrôle DNS du nom d'hôte. */
  resolveHost: HostResolver;
  /** Contrôles à évaluer, dans l'ordre d'affichage. */
  checks: readonly CheckDefinition[];
  /** Horloge : millisecondes écoulées depuis le 1er janvier 1970 (comme `Date.now`). */
  now: () => number;
}

/** Dépendances réelles, utilisées en production. */
const DEFAULT_DEPENDENCIES: ScanDependencies = {
  fetch: safeFetch,
  probeTls,
  resolveCaa,
  resolveHost,
  checks: CHECKS,
  now: Date.now,
};

/** Résultats bruts des six sondes réseau, tels qu'ils seront rangés dans le `ScanContext`. */
type ProbeResults = Pick<ScanContext, "https" | "http" | "tls" | "securityTxt" | "cors" | "caa">;

/** Noms des sondes, tels qu'ils apparaissent dans `ScanReport.probeErrors`. */
const PROBE_NAMES = [
  "https",
  "http",
  "tls",
  "securityTxt",
  "cors",
  "caa",
] as const satisfies ReadonlyArray<keyof ProbeResults>;

/** Résumé d'un contrôle qui a levé une exception (bogue de SecuScan, pas du site analysé). */
const CHECK_FAILURE_SUMMARY =
  "Ce contrôle n'a pas pu être évalué à cause d'une erreur interne de SecuScan ; il n'a aucun effet sur la note.";

/**
 * Analyse un site et produit son rapport complet.
 *
 * @param input        adresse saisie par l'utilisateur (normalisée par `normalizeTarget`)
 * @param dependencies dépendances à remplacer (tests) ; les autres gardent leur valeur réelle
 * @throws {ScanError} saisie refusée (INVALID_URL, TARGET_NOT_ALLOWED…), nom introuvable
 *   (DNS_FAILURE), site injoignable (TARGET_UNREACHABLE) ou trop lent (TIMEOUT)
 */
export async function scanSite(
  input: string,
  dependencies: Partial<ScanDependencies> = {},
): Promise<ScanReport> {
  const deps: ScanDependencies = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  const startedAt = deps.now();

  // 1. Saisie → cible normalisée (première barrière anti-SSRF).
  const target = normalizeTarget(input);
  // 2. Pré-contrôle DNS : un nom inexistant ou pointant vers une adresse privée est refusé
  //    clairement, avant toute connexion.
  await assertResolvable(target, deps.resolveHost);
  // 3. Sondes réseau en parallèle, sous un délai global.
  const probes = await runProbes(target, deps);
  assertReachable(probes);
  // 4. Contexte : réponse analysée et éléments extraits de son HTML.
  const context = buildContext(target, probes);
  // 5. Contrôles purs, chacun isolé des erreurs des autres.
  const checks = deps.checks.map((check) => evaluateCheck(check, context));
  // 6. Notation.
  const score = computeScore(checks);

  return buildReport({ context, checks, score, startedAt, finishedAt: deps.now() });
}

/**
 * Refuse un nom qui ne se résout pas, ou qui pointe vers une adresse non publique.
 * Si `resolveHost` levait une exception (bogue), elle remonterait et le scan échouerait :
 * on ne se connecte jamais à une cible dont la vérification n'a pas abouti.
 */
async function assertResolvable(target: ScanTarget, resolveHost: HostResolver): Promise<void> {
  const resolution = await resolveHost(target.hostname);
  if (resolution.ok) return;
  if (resolution.error.code === "BLOCKED_ADDRESS") {
    throw new ScanError(
      "TARGET_NOT_ALLOWED",
      `« ${target.hostname} » pointe vers une adresse privée, locale ou réservée : par sécurité, SecuScan n'analyse que des sites accessibles depuis Internet.`,
    );
  }
  throw new ScanError(
    "DNS_FAILURE",
    `Le nom de domaine « ${target.hostname} » est introuvable ou son serveur DNS ne répond pas : vérifiez l'adresse saisie.`,
  );
}

/**
 * Lance les six sondes en même temps : le scan dure le temps de la plus lente, pas la somme.
 * Elles partagent un seul signal d'annulation : au-delà de `SCAN_TIMEOUT_MS`, tout ce qui est
 * encore en cours est interrompu (chaque requête a en plus son propre délai, plus court).
 */
async function runProbes(target: ScanTarget, deps: ScanDependencies): Promise<ProbeResults> {
  const signal = AbortSignal.timeout(SCAN_TIMEOUT_MS);

  const [https, http, tls, securityTxt, cors, caa] = await Promise.all([
    // Page analysée, en HTTPS, avec son corps (HTML).
    settle("https", () => deps.fetch(target.url, { signal, maxBodyBytes: MAX_BODY_BYTES }), signal),
    // Même adresse en HTTP clair, sans le corps : seule la redirection vers HTTPS nous intéresse.
    settle("http", () => deps.fetch(httpUrlOf(target.url), { signal, maxBodyBytes: 0 }), signal),
    settle("tls", () => deps.probeTls(target.hostname, { port: 443, signal }), signal),
    settle(
      "securityTxt",
      () =>
        deps.fetch(securityTxtUrlOf(target.url), {
          signal,
          maxRedirects: 3,
          maxBodyBytes: MAX_SECURITY_TXT_BYTES,
        }),
      signal,
    ),
    // Requête « venant » d'une origine étrangère : le site autorise-t-il n'importe quelle origine ?
    settle(
      "cors",
      () =>
        deps.fetch(target.url, { signal, headers: { Origin: CORS_PROBE_ORIGIN }, maxBodyBytes: 0 }),
      signal,
    ),
    target.isIpAddress
      ? Promise.resolve(noCaaForIpAddress())
      : settle("caa", () => deps.resolveCaa(target.hostname, { signal })),
  ]);

  return { https, http, tls, securityTxt, cors, caa };
}

/**
 * Codes d'échec jugés passagers. Une connexion coupée par le serveur (ECONNRESET) vient souvent
 * d'une surcharge ou d'une limite de connexions simultanées par client (constaté sur badssl.com) :
 * la refaire une fois suffit le plus souvent. Les autres échecs (refus, délai, erreur TLS…) sont
 * stables : réessayer ne ferait qu'allonger le scan et solliciter davantage le site.
 */
const TRANSIENT_ERROR_CODES: ReadonlySet<NetworkErrorCode> = new Set(["CONNECTION_RESET"]);

/** Pause avant la nouvelle tentative : laisse au serveur le temps de libérer des connexions. */
const RETRY_DELAY_MS = 500;

/**
 * Attend `ms` millisecondes, sauf si le scan est annulé entre-temps (délai global).
 * @returns true si la pause est allée à son terme, false si le scan a été annulé
 */
async function pause(ms: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return false;
  try {
    await setTimeout(ms, undefined, { signal });
    return true;
  } catch {
    return false;
  }
}

/**
 * Exécute une sonde en garantissant un `Result`. Les sondes ne lèvent jamais d'exception par
 * contrat, mais par sécurité une exception devient un échec de sonde (code UNKNOWN) : une sonde
 * défaillante ne doit pas faire échouer tout le scan. Un échec passager (connexion coupée) est
 * retenté une fois.
 */
async function settle<T>(
  probe: string,
  run: () => Promise<Result<T>>,
  signal?: AbortSignal,
): Promise<Result<T>> {
  try {
    const first = await run();
    if (first.ok || !TRANSIENT_ERROR_CODES.has(first.error.code)) return first;
    // Échec passager : une seule nouvelle tentative, après une courte pause.
    if (!(await pause(RETRY_DELAY_MS, signal))) return first;
    return await run();
  } catch (error) {
    logUnexpectedError("probe-error", error, { probe });
    return {
      ok: false,
      error: { code: "UNKNOWN", message: "Erreur inattendue pendant la vérification." },
    };
  }
}

/** Même adresse en HTTP clair (pour vérifier la redirection HTTP → HTTPS). */
function httpUrlOf(url: string): string {
  const httpUrl = new URL(url);
  httpUrl.protocol = "http:";
  return httpUrl.href;
}

/** Emplacement normalisé du fichier security.txt, à la racine du site (RFC 9116 § 3). */
function securityTxtUrlOf(url: string): string {
  return new URL("/.well-known/security.txt", url).href;
}

/**
 * CAA ne concerne que les noms de domaine : pour une adresse IP, on enregistre un résultat vide
 * (le contrôle `caa` l'affiche comme « sans objet »). Ce n'est pas un échec de sonde.
 */
function noCaaForIpAddress(): Result<CaaInfo> {
  return { ok: true, value: { domain: null, records: [] } };
}

/**
 * Sans aucune réponse, ni en HTTPS ni en HTTP, il n'y a rien à analyser : on lève une ScanError
 * qui explique pourquoi (délai dépassé, adresse interdite ou site injoignable).
 */
function assertReachable({ https, http }: ProbeResults): void {
  if (https.ok || http.ok) return;

  if (https.error.code === "TIMEOUT" && http.error.code === "TIMEOUT") {
    throw new ScanError(
      "TIMEOUT",
      `Le site n'a répondu ni en HTTPS ni en HTTP dans le délai imparti (${SCAN_TIMEOUT_MS / 1000} secondes).`,
    );
  }
  // Le pré-contrôle DNS avait accepté le nom, mais la protection anti-SSRF a bloqué la connexion :
  // la réponse DNS a changé entre-temps (attaque par « DNS rebinding ») ou une redirection mène
  // vers une adresse interne.
  if (https.error.code === "BLOCKED_ADDRESS" || http.error.code === "BLOCKED_ADDRESS") {
    throw new ScanError(
      "TARGET_NOT_ALLOWED",
      "La connexion au site a été bloquée : il mène (directement ou par une redirection) vers une adresse privée, locale ou réservée.",
    );
  }
  throw new ScanError(
    "TARGET_UNREACHABLE",
    `Le site ne répond ni en HTTPS ni en HTTP. HTTPS : ${https.error.message} HTTP : ${http.error.message}`,
  );
}

/** Rassemble les faits collectés : c'est l'unique entrée des contrôles. */
function buildContext(target: ScanTarget, probes: ProbeResults): ScanContext {
  const response = analysedResponse(probes);
  return { target, ...probes, response, html: extractHtml(response, target.hostname) };
}

/** Réponse analysée : celle de HTTPS si possible, sinon celle de HTTP (site sans HTTPS). */
function analysedResponse({ https, http }: ProbeResults): HttpResponse | null {
  if (https.ok) return https.value.response;
  if (http.ok) return http.value.response;
  return null;
}

/**
 * Extrait les scripts, feuilles de style, formulaires… de la page, si c'est du HTML dont le corps
 * a été lu. Un HTML pathologique ne doit pas faire échouer le scan : en cas d'exception, les
 * contrôles concernés (SRI, contenu mixte…) traitent la page comme non HTML.
 *
 * @param hostname hôte analysé, pour le journal : pas l'URL complète, dont la requête peut
 *   contenir un jeton ou un identifiant collé par l'utilisateur
 */
function extractHtml(response: HttpResponse | null, hostname: string): HtmlInfo | null {
  if (response === null || response.body === null || !isHtmlResponse(response)) return null;
  try {
    return extractHtmlInfo(response.body, response.url);
  } catch (error) {
    logUnexpectedError("html-error", error, { host: hostname });
    return null;
  }
}

/**
 * Évalue un contrôle et complète son verdict avec ses métadonnées. Les champs facultatifs du
 * verdict reçoivent une valeur explicite (liste vide, null) : le JSON de l'API est toujours complet.
 */
function evaluateCheck(check: CheckDefinition, context: ScanContext): CheckResult {
  const outcome = evaluateSafely(check, context);
  return {
    id: check.id,
    category: check.category,
    title: check.title,
    description: check.description,
    references: check.references,
    status: outcome.status,
    scoreModifier: outcome.scoreModifier,
    summary: outcome.summary,
    details: outcome.details ?? [],
    evidence: outcome.evidence ?? null,
    recommendation: outcome.recommendation ?? null,
    examples: outcome.examples ?? [],
  };
}

/**
 * Les contrôles sont des fonctions pures qui ne doivent jamais lever d'exception. Si l'un d'eux
 * le fait quand même (bogue face à une réponse inattendue), il passe au statut « error », sans
 * effet sur la note, et les autres contrôles sont évalués normalement.
 */
function evaluateSafely(check: CheckDefinition, context: ScanContext): CheckOutcome {
  try {
    return check.evaluate(context);
  } catch (error) {
    logUnexpectedError("check-error", error, { check: check.id });
    return {
      status: "error",
      scoreModifier: 0,
      summary: CHECK_FAILURE_SUMMARY,
      recommendation: null,
    };
  }
}

/** Assemble le rapport renvoyé par l'API. */
function buildReport(parts: {
  context: ScanContext;
  checks: CheckResult[];
  score: ScoreBreakdown;
  startedAt: number;
  finishedAt: number;
}): ScanReport {
  const { context, checks, score, startedAt, finishedAt } = parts;
  const { target, response } = context;
  return {
    schemaVersion: 1,
    scanner: { name: SCANNER_NAME, version: SCANNER_VERSION },
    target: {
      input: target.input,
      url: target.url,
      hostname: target.hostname,
      finalUrl: response?.url ?? null,
      ip: response?.remoteAddress ?? null,
    },
    scannedAt: new Date(startedAt).toISOString(),
    // L'horloge système peut reculer (synchronisation NTP) : jamais de durée négative.
    durationMs: Math.max(0, finishedAt - startedAt),
    score,
    summary: countByStatus(checks),
    checks,
    redirects: { fromHttp: redirectHops(context.http), fromHttps: redirectHops(context.https) },
    // On note même si le statut final est une erreur (404, 500…) : l'interface le signale.
    response: response ? { status: response.status, headers: response.rawHeaders } : null,
    tls: context.tls.ok ? context.tls.value : null,
    probeErrors: probeErrorsOf(context),
  };
}

/** Nombre de contrôles par statut (tous les statuts sont présents, éventuellement à 0). */
function countByStatus(checks: readonly CheckResult[]): Record<CheckStatus, number> {
  const summary: Record<CheckStatus, number> = { pass: 0, warning: 0, fail: 0, info: 0, error: 0 };
  for (const check of checks) {
    summary[check.status] += 1;
  }
  return summary;
}

/**
 * Chaîne de redirections d'une sonde, pour l'affichage. Sonde réussie : redirections puis réponse
 * finale (sans destination). Sonde en échec : les réponses reçues avant l'erreur (boucle,
 * redirection interdite…), qui sont toutes des redirections.
 */
function redirectHops(result: Result<FetchSuccess>): RedirectHop[] {
  if (!result.ok)
    return (result.error.chain ?? []).map((response) => toRedirectHop(response, false));
  const { chain } = result.value;
  return chain.map((response, index) => toRedirectHop(response, index === chain.length - 1));
}

/** Étape d'une chaîne de redirections. */
function toRedirectHop(response: HttpResponse, isFinalResponse: boolean): RedirectHop {
  return {
    url: response.url,
    status: response.status,
    location: isFinalResponse ? null : resolveLocation(response),
  };
}

/**
 * Destination d'une redirection en URL absolue : l'en-tête Location peut être relatif (« /fr/ »).
 * S'il est illisible, on le garde tel quel pour montrer ce que le serveur a réellement envoyé.
 */
function resolveLocation(response: HttpResponse): string | null {
  const location = getHeader(response, "location");
  if (location === null) return null;
  return URL.parse(location, response.url)?.href ?? location;
}

/** Sondes en échec, pour expliquer à l'utilisateur les contrôles au statut « error ». */
function probeErrorsOf(context: ScanContext): ScanReport["probeErrors"] {
  return PROBE_NAMES.flatMap((probe) => {
    const result = context[probe];
    return result.ok ? [] : [{ probe, code: result.error.code, message: result.error.message }];
  });
}

/**
 * Journalise côté serveur une erreur inattendue (une ligne JSON, sans donnée personnelle).
 * Le détail technique reste dans le journal : il n'est jamais renvoyé au client.
 */
function logUnexpectedError(event: string, error: unknown, context: Record<string, string>): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(JSON.stringify({ event, ...context, message }));
}
