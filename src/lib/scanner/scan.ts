/**
 * Une sonde ou un contrôle qui échoue donne un statut « error », sans pénalité. Seuls une saisie
 * refusée, un nom introuvable ou interdit, ou un site injoignable en HTTPS comme en HTTP empêchent
 * de produire un rapport (`ScanError`).
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

// Seul le verdict compte ici (DNS_FAILURE ou BLOCKED_ADDRESS) : les adresses sont revérifiées à
// chaque connexion.
export type HostResolver = (
  hostname: string,
) => Promise<Result<Array<{ address: string; family: number }>>>;

/** Injectables pour que les tests remplacent le réseau. */
export interface ScanDependencies {
  fetch: Fetcher;
  probeTls: TlsProber;
  resolveCaa: CaaResolver;
  resolveHost: HostResolver;
  /** Dans l'ordre d'affichage. */
  checks: readonly CheckDefinition[];
  now: () => number;
}

const DEFAULT_DEPENDENCIES: ScanDependencies = {
  fetch: safeFetch,
  probeTls,
  resolveCaa,
  resolveHost,
  checks: CHECKS,
  now: Date.now,
};

type ProbeResults = Pick<ScanContext, "https" | "http" | "tls" | "securityTxt" | "cors" | "caa">;

const PROBE_NAMES = [
  "https",
  "http",
  "tls",
  "securityTxt",
  "cors",
  "caa",
] as const satisfies ReadonlyArray<keyof ProbeResults>;

const CHECK_FAILURE_SUMMARY =
  "Ce contrôle n'a pas pu être évalué à cause d'une erreur interne de SecuScan ; il n'a aucun effet sur la note.";

export async function scanSite(
  input: string,
  dependencies: Partial<ScanDependencies> = {},
): Promise<ScanReport> {
  const deps: ScanDependencies = { ...DEFAULT_DEPENDENCIES, ...dependencies };
  const startedAt = deps.now();

  const target = normalizeTarget(input);
  // Un nom inexistant ou privé est refusé clairement, avant toute connexion.
  await assertResolvable(target, deps.resolveHost);
  const probes = await runProbes(target, deps);
  assertReachable(probes);
  const context = buildContext(target, probes);
  const checks = deps.checks.map((check) => evaluateCheck(check, context));
  const score = computeScore(checks);

  return buildReport({ context, checks, score, startedAt, finishedAt: deps.now() });
}

// Une exception de `resolveHost` remonte volontairement : on ne se connecte jamais à une cible dont
// la vérification n'a pas abouti.
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

// Un seul signal pour toutes les sondes : au-delà de `SCAN_TIMEOUT_MS`, tout ce qui est encore en
// cours est interrompu (chaque requête a en plus son propre délai, plus court).
async function runProbes(target: ScanTarget, deps: ScanDependencies): Promise<ProbeResults> {
  const signal = AbortSignal.timeout(SCAN_TIMEOUT_MS);

  const [https, http, tls, securityTxt, cors, caa] = await Promise.all([
    settle("https", () => deps.fetch(target.url, { signal, maxBodyBytes: MAX_BODY_BYTES }), signal),
    // Seule la redirection vers HTTPS nous intéresse : pas besoin du corps.
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
 * Un ECONNRESET vient souvent d'une limite de connexions simultanées par client (constaté sur
 * badssl.com) : une nouvelle tentative suffit le plus souvent. Les autres échecs sont stables :
 * réessayer ne ferait qu'allonger le scan et solliciter davantage le site.
 */
const TRANSIENT_ERROR_CODES: ReadonlySet<NetworkErrorCode> = new Set(["CONNECTION_RESET"]);

const RETRY_DELAY_MS = 500;

/** false si le scan a été annulé pendant la pause. */
async function pause(ms: number, signal?: AbortSignal): Promise<boolean> {
  if (signal?.aborted) return false;
  try {
    await setTimeout(ms, undefined, { signal });
    return true;
  } catch {
    return false;
  }
}

// Les sondes ne lèvent pas d'exception par contrat ; si l'une le fait quand même, elle ne doit
// pas faire échouer tout le scan.
async function settle<T>(
  probe: string,
  run: () => Promise<Result<T>>,
  signal?: AbortSignal,
): Promise<Result<T>> {
  try {
    const first = await run();
    if (first.ok || !TRANSIENT_ERROR_CODES.has(first.error.code)) return first;
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

function httpUrlOf(url: string): string {
  const httpUrl = new URL(url);
  httpUrl.protocol = "http:";
  return httpUrl.href;
}

/** RFC 9116 § 3. */
function securityTxtUrlOf(url: string): string {
  return new URL("/.well-known/security.txt", url).href;
}

// CAA ne concerne que les noms de domaine : pour une IP, résultat vide (« sans objet »), pas un
// échec de sonde.
function noCaaForIpAddress(): Result<CaaInfo> {
  return { ok: true, value: { domain: null, records: [] } };
}

function assertReachable({ https, http }: ProbeResults): void {
  if (https.ok || http.ok) return;

  if (https.error.code === "TIMEOUT" && http.error.code === "TIMEOUT") {
    throw new ScanError(
      "TIMEOUT",
      `Le site n'a répondu ni en HTTPS ni en HTTP dans le délai imparti (${SCAN_TIMEOUT_MS / 1000} secondes).`,
    );
  }
  // Le pré-contrôle DNS avait accepté le nom : la réponse DNS a changé entre-temps (DNS rebinding)
  // ou une redirection mène vers une adresse interne.
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

function buildContext(target: ScanTarget, probes: ProbeResults): ScanContext {
  const response = analysedResponse(probes);
  return { target, ...probes, response, html: extractHtml(response, target.hostname) };
}

function analysedResponse({ https, http }: ProbeResults): HttpResponse | null {
  if (https.ok) return https.value.response;
  if (http.ok) return http.value.response;
  return null;
}

/**
 * Un HTML pathologique ne doit pas faire échouer le scan : la page est alors traitée comme non
 * HTML. On journalise l'hôte et non l'URL, dont la requête peut contenir un jeton.
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

// Les champs facultatifs reçoivent une valeur explicite : le JSON de l'API est toujours complet.
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

// Un contrôle qui lève (bogue face à une réponse inattendue) passe au statut « error », sans effet
// sur la note ni sur les autres contrôles.
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
    // Renseigné même pour un statut d'erreur (404, 500…) : l'interface le signale.
    response: response ? { status: response.status, headers: response.rawHeaders } : null,
    tls: context.tls.ok ? context.tls.value : null,
    probeErrors: probeErrorsOf(context),
  };
}

function countByStatus(checks: readonly CheckResult[]): Record<CheckStatus, number> {
  const summary: Record<CheckStatus, number> = { pass: 0, warning: 0, fail: 0, info: 0, error: 0 };
  for (const check of checks) {
    summary[check.status] += 1;
  }
  return summary;
}

// Sonde en échec : les réponses reçues avant l'erreur (boucle, redirection interdite…) sont
// toutes des redirections.
function redirectHops(result: Result<FetchSuccess>): RedirectHop[] {
  if (!result.ok)
    return (result.error.chain ?? []).map((response) => toRedirectHop(response, false));
  const { chain } = result.value;
  return chain.map((response, index) => toRedirectHop(response, index === chain.length - 1));
}

function toRedirectHop(response: HttpResponse, isFinalResponse: boolean): RedirectHop {
  return {
    url: response.url,
    status: response.status,
    location: isFinalResponse ? null : resolveLocation(response),
  };
}

// Un Location illisible est gardé tel quel pour montrer ce que le serveur a réellement envoyé.
function resolveLocation(response: HttpResponse): string | null {
  const location = getHeader(response, "location");
  if (location === null) return null;
  return URL.parse(location, response.url)?.href ?? location;
}

function probeErrorsOf(context: ScanContext): ScanReport["probeErrors"] {
  return PROBE_NAMES.flatMap((probe) => {
    const result = context[probe];
    return result.ok ? [] : [{ probe, code: result.error.code, message: result.error.message }];
  });
}

// Le détail technique reste dans le journal serveur, jamais renvoyé au client.
function logUnexpectedError(event: string, error: unknown, context: Record<string, string>): void {
  const message = error instanceof Error ? error.message : String(error);
  console.error(JSON.stringify({ event, ...context, message }));
}
