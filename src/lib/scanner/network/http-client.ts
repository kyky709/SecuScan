/**
 * `fetch()` ne permet ni de contrôler l'adresse réellement contactée (anti-SSRF), ni de lire la
 * réponse d'un site au certificat invalide, ni de récupérer les en-têtes dupliqués. D'où
 * `node:http` / `node:https`, avec :
 * - `lookup` sûre (safe-lookup.ts) : chaque adresse DNS est vérifiée au moment de la connexion ;
 * - IP littérales vérifiées ici, car Node.js n'appelle pas `lookup` pour une IP ;
 * - `agent: false` : un agent keep-alive réutiliserait une connexion déjà ouverte SANS rappeler
 *   `lookup` (contournement démontré par l'expérience) ;
 * - redirections suivies à la main, chaque étape revalidée (schéma, port, identifiants, adresse) ;
 * - délai total par AbortSignal (l'option `timeout` de Node.js ne détecte qu'une inactivité et
 *   n'annule rien), taille de corps bornée APRÈS décompression ;
 * - `rejectUnauthorized: false` pour lire les en-têtes même si le certificat est invalide ; sa
 *   validité est rapportée dans `response.tls` ;
 * - aucun cookie ni identifiant transmis.
 */
import { request as httpRequest, type IncomingMessage } from "node:http";
import { request as httpsRequest, type RequestOptions } from "node:https";
import type { LookupFunction } from "node:net";
import type { Readable, Transform } from "node:stream";
import { checkServerIdentity, type PeerCertificate, TLSSocket } from "node:tls";
import {
  constants,
  createBrotliDecompress,
  createGunzip,
  createInflate,
  createZstdDecompress,
} from "node:zlib";
import {
  ALLOWED_PORTS,
  MAX_BODY_BYTES,
  MAX_REDIRECTS,
  REQUEST_TIMEOUT_MS,
  USER_AGENT,
} from "@/lib/config";
import type {
  Fetcher,
  FetchOptions,
  FetchSuccess,
  HttpResponse,
  NetworkError,
  NetworkErrorCode,
  ResponseTlsInfo,
  Result,
} from "@/lib/scanner/types";
import { type AddressPolicyOptions, applyAddressPolicy, isIpLiteral, stripBrackets } from "./ip";
import {
  BlockedAddressError,
  createSafeLookup,
  describeBlockedAddress,
  errorCode,
} from "./safe-lookup";

const ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8";
const ACCEPT_LANGUAGE = "fr-FR,fr;q=0.9,en;q=0.8";
const ACCEPT_ENCODING = "gzip, deflate, br";
/** Une grosse CSP dépasse les 16 Kio par défaut. */
const MAX_HEADER_BYTES = 64 * 1024;
/** Spécification Fetch : 300 et 304 ne redirigent pas. */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
const TEXTUAL_TYPES: ReadonlySet<string> = new Set([
  "application/xhtml+xml",
  "application/json",
  "application/xml",
]);
const MAX_QUOTED_LENGTH = 200;
const UNREACHABLE_CODES: ReadonlySet<string> = new Set(["ENETUNREACH", "EHOSTUNREACH"]);

/** Tolère un flux compressé tronqué au lieu d'échouer sur ses derniers octets. */
const ZLIB_TOLERANT = { finishFlush: constants.Z_SYNC_FLUSH };

const DECODERS: Readonly<Record<string, () => Transform>> = {
  gzip: () => createGunzip(ZLIB_TOLERANT),
  "x-gzip": () => createGunzip(ZLIB_TOLERANT),
  // « deflate » désigne le format zlib (RFC 9110), que createInflate attend.
  deflate: () => createInflate(ZLIB_TOLERANT),
  br: () => createBrotliDecompress({ finishFlush: constants.BROTLI_OPERATION_FLUSH }),
  // Expérimental dans Node.js 24 : non annoncé, mais décodé si un serveur l'envoie.
  zstd: () => createZstdDecompress(),
};

export interface FetcherOptions extends AddressPolicyOptions {
  /** Défaut : `createSafeLookup()` avec la même politique. */
  lookup?: LookupFunction;
  userAgent?: string;
  /** Défaut : `ALLOWED_PORTS` ; les tests y ajoutent le port de leur serveur. */
  allowedPorts?: ReadonlySet<number>;
}

interface FetcherConfig {
  policy: AddressPolicyOptions;
  lookup: LookupFunction;
  userAgent: string;
  allowedPorts: ReadonlySet<number>;
}

type ResponseHead = Omit<HttpResponse, "body" | "bodyTruncated" | "durationMs">;

// Délais et traduction des erreurs, partagés avec tls-probe.ts.

export interface Deadline {
  /** `timer` ou `external`, le premier qui se déclenche. */
  signal: AbortSignal;
  timer: AbortSignal;
  /** Délai global du scan. */
  external: AbortSignal | undefined;
  timeoutMs: number;
}

export function createDeadline(timeoutMs: number, external?: AbortSignal): Deadline {
  const timer = AbortSignal.timeout(timeoutMs);
  const signal = external ? AbortSignal.any([timer, external]) : timer;
  return { signal, timer, external, timeoutMs };
}

function isTimeoutReason(reason: unknown): boolean {
  return typeof reason === "object" && reason !== null && "name" in reason
    ? reason.name === "TimeoutError"
    : false;
}

function formatSeconds(milliseconds: number): string {
  const seconds = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 }).format(
    milliseconds / 1000,
  );
  return `${seconds} s`;
}

/**
 * À tester AVANT le code d'erreur : une interruption après la réception des en-têtes se manifeste
 * par un ECONNRESET (« aborted ») qui passerait sinon pour une coupure du serveur.
 *
 * @param action début de phrase, ex. « Le serveur n'a pas répondu »
 */
export function interruptionError(deadline: Deadline, action: string): NetworkError | null {
  if (deadline.timer.aborted) {
    return {
      code: "TIMEOUT",
      message: `${action} dans le délai imparti (${formatSeconds(deadline.timeoutMs)}).`,
      detail: `délai de ${deadline.timeoutMs} ms dépassé`,
    };
  }
  if (!deadline.external?.aborted) return null;
  if (isTimeoutReason(deadline.external.reason)) {
    return {
      code: "TIMEOUT",
      message: `${action} avant la fin du délai global du scan.`,
      detail: "délai global du scan dépassé",
    };
  }
  return {
    code: "UNKNOWN",
    message: "L'opération a été annulée avant d'aboutir.",
    detail: "ABORT_ERR",
  };
}

/**
 * Quand toutes les tentatives Happy Eyeballs échouent, Node.js renvoie une AggregateError qui porte
 * le code de la PREMIÈRE tentative, souvent ENETUNREACH (pas d'IPv6 sur le serveur de SecuScan) :
 * on préfère l'erreur d'une autre tentative.
 */
function primaryError(error: unknown): unknown {
  if (!(error instanceof AggregateError)) return error;
  const attempts: unknown[] = error.errors;
  const informative = attempts.find((attempt) => !UNREACHABLE_CODES.has(errorCode(attempt) ?? ""));
  return informative ?? attempts[0] ?? error;
}

/** Codes de zlib, brotli et zstd. */
function isDecompressionError(code: string): boolean {
  return code.startsWith("Z_") || code.startsWith("ERR__") || /BROTLI|ZSTD/i.test(code);
}

function translateCode(code: string): { code: NetworkErrorCode; message: string } {
  switch (code) {
    case "ENOTFOUND":
    case "ENODATA":
    case "EAI_AGAIN":
    case "EAI_FAIL":
    case "EAI_NONAME":
      return {
        code: "DNS_FAILURE",
        message: "Le nom de domaine ne se résout pas : aucune adresse IP n'a été trouvée.",
      };
    case "ECONNREFUSED":
      return {
        code: "CONNECTION_REFUSED",
        message: "Connexion refusée par le serveur (port fermé ou service arrêté).",
      };
    case "ENETUNREACH":
    case "EHOSTUNREACH":
      return {
        code: "CONNECTION_REFUSED",
        message: "Serveur injoignable : aucune route réseau ne mène à son adresse.",
      };
    case "ECONNRESET":
    case "ECONNABORTED":
    case "EPIPE":
      return {
        code: "CONNECTION_RESET",
        message: "La connexion a été interrompue par le serveur.",
      };
    case "ETIMEDOUT":
    case "ERR_TLS_HANDSHAKE_TIMEOUT":
      return { code: "TIMEOUT", message: "Le serveur n'a pas répondu à temps." };
    case "HPE_HEADER_OVERFLOW":
      return {
        code: "PROTOCOL_ERROR",
        message: `En-têtes de réponse trop volumineux (plus de ${MAX_HEADER_BYTES / 1024} Kio).`,
      };
  }
  if (code.startsWith("HPE_")) {
    return { code: "PROTOCOL_ERROR", message: "Réponse HTTP mal formée." };
  }
  if (code.startsWith("ERR_SSL_") || code.startsWith("ERR_TLS_") || code === "EPROTO") {
    return {
      code: "TLS_ERROR",
      message:
        "La négociation TLS a échoué (versions de protocole ou suites de chiffrement incompatibles).",
    };
  }
  if (isDecompressionError(code)) {
    return { code: "PROTOCOL_ERROR", message: "Le corps compressé de la réponse est illisible." };
  }
  return { code: "UNKNOWN", message: "Erreur réseau inattendue." };
}

export function toNetworkError(error: unknown): NetworkError {
  if (error instanceof BlockedAddressError) {
    return {
      code: "BLOCKED_ADDRESS",
      message: error.message,
      // Catégorie seulement : l'adresse interne ne doit pas apparaître dans le rapport.
      detail: error.range,
    };
  }
  const primary = primaryError(error);
  const code = errorCode(primary) ?? "";
  const technical = primary instanceof Error ? primary.message : String(primary);
  return { ...translateCode(code), detail: technical || code || undefined };
}

/**
 * Piège démontré par l'expérience : quand la chaîne est invalide (expirée, auto-signée…), Node.js
 * ne vérifie PAS le nom d'hôte. On le vérifie donc toujours avec `tls.checkServerIdentity`. Une
 * erreur de nom l'emporte : aucun navigateur ne la contourne, alors qu'il peut encore compléter
 * une chaîne seulement incomplète.
 */
export function readAuthorization(
  socket: TLSSocket,
  hostname: string,
): Pick<ResponseTlsInfo, "authorized" | "authorizationError"> {
  if (socket.authorized) return { authorized: true, authorizationError: null };
  // À l'exécution, `authorizationError` est une chaîne (ex. "CERT_HAS_EXPIRED").
  const chainError = socket.authorizationError
    ? String(socket.authorizationError)
    : "UNKNOWN_CERTIFICATE_ERROR";
  const nameError = hostnameError(hostname, socket.getPeerCertificate());
  return { authorized: false, authorizationError: nameError ?? chainError };
}

function hostnameError(hostname: string, certificate: PeerCertificate): string | null {
  try {
    const error = checkServerIdentity(hostname, certificate);
    return error === undefined ? null : (errorCode(error) ?? "ERR_TLS_CERT_ALTNAME_INVALID");
  } catch {
    return null; // certificat inexploitable : l'erreur de chaîne suffit à le signaler
  }
}

function shorten(text: string): string {
  return text.length <= MAX_QUOTED_LENGTH ? text : `${text.slice(0, MAX_QUOTED_LENGTH)}…`;
}

interface UrlProblem {
  /** L'adresse elle-même est interdite (anti-SSRF), plutôt que la forme de l'URL. */
  blockedAddress: boolean;
  message: string;
}

// Avant toute connexion, pour la requête initiale comme pour chaque redirection. Les noms d'hôte,
// eux, sont vérifiés par la `lookup` sûre au moment de la connexion.
function findUrlProblem(url: URL, config: FetcherConfig): UrlProblem | null {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return {
      blockedAddress: false,
      message: `Le schéma « ${url.protocol} » n'est pas pris en charge : seules les adresses http:// et https:// sont autorisées.`,
    };
  }
  // Node.js transformerait « utilisateur:motdepasse@ » en en-tête Authorization.
  if (url.username !== "" || url.password !== "") {
    return {
      blockedAddress: false,
      message: "Les identifiants dans l'adresse (utilisateur:mot de passe@) sont interdits.",
    };
  }
  // Node.js n'appelle pas `lookup` pour une IP littérale : c'est donc ici qu'on la vérifie. Le
  // parseur d'URL a déjà normalisé les formes piégées (« 2130706433 » → « 127.0.0.1 »).
  if (isIpLiteral(url.hostname)) {
    const verdict = applyAddressPolicy(url.hostname, config.policy);
    if (!verdict.allowed) {
      return {
        blockedAddress: true,
        message: describeBlockedAddress(url.hostname, verdict.address, verdict.reason),
      };
    }
  }
  const port = url.port === "" ? (url.protocol === "https:" ? 443 : 80) : Number(url.port);
  if (!config.allowedPorts.has(port)) {
    return {
      blockedAddress: false,
      message: `Le port ${port} est interdit (ports autorisés : ${[...config.allowedPorts].join(", ")}).`,
    };
  }
  return null;
}

function refusalError(url: URL, problem: UrlProblem, isRedirect: boolean): NetworkError {
  if (!isRedirect) return { code: "BLOCKED_ADDRESS", message: problem.message };
  return {
    code: problem.blockedAddress ? "BLOCKED_ADDRESS" : "INVALID_REDIRECT",
    message: `Redirection vers ${shorten(url.href)} refusée. ${problem.message}`,
  };
}

function redirectTarget(
  current: URL,
  message: IncomingMessage,
  status: number,
): URL | NetworkError {
  const location = message.headers.location?.trim() ?? "";
  if (location === "") {
    return {
      code: "INVALID_REDIRECT",
      message: `Redirection invalide : la réponse ${status} n'indique pas de destination (en-tête Location absent).`,
    };
  }
  try {
    const next = new URL(location, current);
    next.hash = "";
    return next;
  } catch {
    return {
      code: "INVALID_REDIRECT",
      message: `Redirection invalide : destination illisible (« ${shorten(location)} »).`,
    };
  }
}

function buildHeaders(options: FetchOptions, config: FetcherConfig): Record<string, string> {
  const headers: Record<string, string> = {
    "user-agent": config.userAgent,
    accept: ACCEPT,
    "accept-language": ACCEPT_LANGUAGE,
    "accept-encoding": ACCEPT_ENCODING,
  };
  for (const [name, value] of Object.entries(options.headers ?? {})) {
    headers[name.toLowerCase()] = value;
  }
  return headers;
}

function sendRequest(
  url: URL,
  options: FetchOptions,
  config: FetcherConfig,
  signal: AbortSignal,
): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const hostname = stripBrackets(url.hostname);
    const requestOptions: RequestOptions = {
      method: options.method ?? "GET",
      headers: buildHeaders(options, config),
      agent: false, // connexion neuve à chaque requête : `lookup` est toujours rappelée
      lookup: config.lookup,
      signal,
      maxHeaderSize: MAX_HEADER_BYTES,
      rejectUnauthorized: false,
      servername: isIpLiteral(hostname) ? undefined : hostname, // SNI : jamais une IP (RFC 6066)
    };
    const request =
      url.protocol === "https:"
        ? httpsRequest(url, requestOptions, resolve)
        : httpRequest(url, requestOptions, resolve);
    // `on` et non `once` : une erreur peut survenir après la réponse (coupure, délai) et, sans
    // écouteur, arrêterait le processus.
    request.on("error", reject);
    request.end();
  });
}

/** [nom, valeur, nom, valeur…] → paires. */
function toPairs(raw: string[]): Array<[name: string, value: string]> {
  const pairs: Array<[string, string]> = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    pairs.push([raw[index] ?? "", raw[index + 1] ?? ""]);
  }
  return pairs;
}

function readTlsInfo(message: IncomingMessage, hostname: string): ResponseTlsInfo | null {
  const socket = message.socket;
  if (!(socket instanceof TLSSocket)) return null;
  return { ...readAuthorization(socket, hostname), protocol: socket.getProtocol() };
}

// À appeler avant de détruire la réponse : le socket n'a plus d'adresse ensuite.
function readResponseHead(url: URL, message: IncomingMessage): ResponseHead {
  const headers: Record<string, string> = {};
  let setCookies: string[] = [];
  // `message.headers` supprimerait les doublons de server, content-type, location… et cacherait
  // des configurations ambiguës (deux CSP, deux HSTS).
  for (const [name, values] of Object.entries(message.headersDistinct)) {
    if (values === undefined) continue;
    // Set-Cookie ne se joint pas par une virgule : les dates en contiennent.
    if (name === "set-cookie") setCookies = values;
    else headers[name] = values.join(", ");
  }
  return {
    url: url.href,
    status: message.statusCode ?? 0,
    headers,
    rawHeaders: toPairs(message.rawHeaders),
    setCookies,
    remoteAddress: message.socket.remoteAddress ?? null,
    tls: readTlsInfo(message, stripBrackets(url.hostname)),
  };
}

function isTextual(contentType: string | undefined): boolean {
  const mime = (contentType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
  return (
    mime === "" || // type absent : souvent du HTML mal étiqueté
    mime.startsWith("text/") ||
    TEXTUAL_TYPES.has(mime) ||
    mime.endsWith("+json") ||
    mime.endsWith("+xml")
  );
}

function toBuffer(chunk: unknown): Buffer {
  return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
}

// On compte les octets DÉCOMPRESSÉS : quelques Ko compressés peuvent produire des Go de données.
async function collectBytes(
  message: IncomingMessage,
  decoder: Transform | null,
  maxBytes: number,
): Promise<{ bytes: Buffer; truncated: boolean }> {
  if (decoder !== null) {
    // pipe() ne transmet pas les erreurs : sans ce relais, une coupure laisserait le décompresseur
    // attendre indéfiniment.
    message.on("error", (error) => decoder.destroy(error));
  }
  const source: Readable = decoder === null ? message : message.pipe(decoder);
  const chunks: Buffer[] = [];
  let size = 0;
  let truncated = false;
  try {
    for await (const chunk of source) {
      const bytes = toBuffer(chunk);
      const room = maxBytes - size;
      if (bytes.length > room) {
        chunks.push(bytes.subarray(0, room));
        size += room;
        truncated = true;
        break; // quitter la boucle détruit `source`
      }
      chunks.push(bytes);
      size += bytes.length;
    }
  } finally {
    message.destroy(); // arrête le téléchargement
    decoder?.destroy();
  }
  return { bytes: Buffer.concat(chunks, size), truncated };
}

function decodeText(bytes: Buffer, contentType: string | undefined): string {
  const charset = /charset\s*=\s*"?([^";\s]+)/i.exec(contentType ?? "")?.[1];
  try {
    return new TextDecoder(charset ?? "utf-8").decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes); // étiquette inconnue : TextDecoder lève une RangeError
  }
}

// Le corps n'est lu que s'il sert à l'analyse : inutile de télécharger une image.
async function readBody(
  message: IncomingMessage,
  head: ResponseHead,
  options: FetchOptions,
): Promise<Pick<HttpResponse, "body" | "bodyTruncated">> {
  const maxBytes = options.maxBodyBytes ?? MAX_BODY_BYTES;
  const contentType = head.headers["content-type"];
  const encoding = (head.headers["content-encoding"] ?? "").trim().toLowerCase() || "identity";
  const createDecoder = DECODERS[encoding];
  const decodable = encoding === "identity" || createDecoder !== undefined;

  if (options.method === "HEAD" || maxBytes <= 0 || !isTextual(contentType) || !decodable) {
    message.destroy();
    return { body: null, bodyTruncated: false };
  }
  const { bytes, truncated } = await collectBytes(message, createDecoder?.() ?? null, maxBytes);
  return { body: decodeText(bytes, contentType), bodyTruncated: truncated };
}

function elapsedMs(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

function failure(error: NetworkError, chain: HttpResponse[]): Result<FetchSuccess> {
  return { ok: false, error: { ...error, chain } };
}

async function fetchWithRedirects(
  input: string,
  options: FetchOptions,
  config: FetcherConfig,
): Promise<Result<FetchSuccess>> {
  const chain: HttpResponse[] = [];
  let current: URL;
  try {
    current = new URL(input);
  } catch {
    return failure(
      { code: "UNKNOWN", message: `Adresse invalide : « ${shorten(input)} ».` },
      chain,
    );
  }
  current.hash = ""; // le fragment n'est jamais envoyé au serveur

  const maxRedirects = options.maxRedirects ?? MAX_REDIRECTS;
  const deadline = createDeadline(options.timeoutMs ?? REQUEST_TIMEOUT_MS, options.signal);
  const visited = new Set<string>();

  try {
    for (;;) {
      const problem = findUrlProblem(current, config);
      if (problem) return failure(refusalError(current, problem, chain.length > 0), chain);
      visited.add(current.href);

      const startedAt = performance.now();
      const message = await sendRequest(current, options, config, deadline.signal);
      const head = readResponseHead(current, message);

      if (REDIRECT_STATUSES.has(head.status) && maxRedirects > 0) {
        message.destroy();
        chain.push({ ...head, body: null, bodyTruncated: false, durationMs: elapsedMs(startedAt) });
        if (chain.length > maxRedirects) {
          return failure(
            {
              code: "TOO_MANY_REDIRECTS",
              message: `Trop de redirections : plus de ${maxRedirects} étapes.`,
            },
            chain,
          );
        }
        const next = redirectTarget(current, message, head.status);
        if (!(next instanceof URL)) return failure(next, chain);
        // Sans cookies ni état, revenir sur une URL déjà visitée bouclerait sans fin.
        if (visited.has(next.href)) {
          return failure(
            {
              code: "TOO_MANY_REDIRECTS",
              message: `Boucle de redirection : ${shorten(next.href)} a déjà été visitée.`,
            },
            chain,
          );
        }
        current = next; // revalidée en haut de la boucle, puis par la lookup sûre
        continue;
      }

      const response: HttpResponse = {
        ...head,
        ...(await readBody(message, head, options)),
        durationMs: elapsedMs(startedAt),
      };
      chain.push(response);
      return { ok: true, value: { response, chain } };
    }
  } catch (error) {
    const interrupted = interruptionError(deadline, "Le serveur n'a pas répondu");
    return failure(interrupted ?? toNetworkError(error), chain);
  }
}

export function createFetcher(options: FetcherOptions = {}): Fetcher {
  const policy: AddressPolicyOptions = {
    allowPrivate: options.allowPrivate,
    isAllowed: options.isAllowed,
  };
  const config: FetcherConfig = {
    policy,
    lookup: options.lookup ?? createSafeLookup(policy),
    userAgent: options.userAgent ?? USER_AGENT,
    allowedPorts: options.allowedPorts ?? ALLOWED_PORTS,
  };
  return async (url, fetchOptions = {}) => {
    try {
      return await fetchWithRedirects(url, fetchOptions, config);
    } catch (error) {
      // Le contrat d'un Fetcher est de ne jamais lever d'exception.
      return failure(toNetworkError(error), []);
    }
  };
}

export const safeFetch: Fetcher = createFetcher();
