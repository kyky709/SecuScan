/**
 * Client HTTP(S) sûr de SecuScan : `safeFetch(url, options)` renvoie la réponse finale et la chaîne
 * des redirections, ou une erreur normalisée en français. Il ne lève jamais d'exception.
 *
 * Pourquoi ne pas utiliser `fetch()` ? Il ne permet ni de contrôler l'adresse réellement contactée
 * (anti-SSRF), ni de lire la réponse d'un site au certificat invalide, ni de récupérer les en-têtes
 * dupliqués. On utilise donc `node:http` / `node:https`, avec des réglages choisis :
 * - `lookup` sûre (safe-lookup.ts) : chaque adresse DNS est vérifiée au moment de la connexion ;
 * - IP littérales vérifiées ici, car Node.js n'appelle pas `lookup` pour une IP ;
 * - `agent: false` : un agent « keep-alive » réutiliserait une connexion déjà ouverte SANS rappeler
 *   `lookup` (contournement démontré par l'expérience) ;
 * - redirections suivies à la main, chaque étape revalidée (schéma, port, identifiants, adresse) ;
 * - délai total par AbortSignal (l'option `timeout` de Node.js ne détecte qu'une inactivité et
 *   n'annule rien), taille de corps bornée APRÈS décompression (bombe de décompression) ;
 * - `rejectUnauthorized: false` : on veut lire les en-têtes même si le certificat est invalide ; la
 *   validité est rapportée dans `response.tls` et notée par le contrôle tls-certificate ;
 * - aucun cookie ni identifiant transmis, User-Agent explicite.
 *
 * Place dans l'architecture : utilisé par l'orchestrateur (scan.ts) pour les sondes https, http,
 * security.txt et CORS. Ce module fournit aussi la gestion des délais, la traduction des erreurs de
 * Node.js en `NetworkError` et la lecture de la validité d'un certificat, réutilisées par la sonde TLS
 * (tls-probe.ts) pour que les deux sondes parlent le même langage.
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

// ─────────────────────────────────────────────────────────────────────────────
// Réglages
// ─────────────────────────────────────────────────────────────────────────────

/** En-tête Accept d'un navigateur qui demande une page HTML. */
const ACCEPT = "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8";
/** Langues préférées : SecuScan est un outil francophone. */
const ACCEPT_LANGUAGE = "fr-FR,fr;q=0.9,en;q=0.8";
/** Encodages annoncés. zstd n'est pas annoncé, mais il est décodé si un serveur l'envoie quand même. */
const ACCEPT_ENCODING = "gzip, deflate, br";
/** Taille maximale des en-têtes d'une réponse : une grosse CSP dépasse les 16 Kio par défaut. */
const MAX_HEADER_BYTES = 64 * 1024;
/** Statuts de redirection selon la spécification Fetch (300 et 304 ne redirigent pas). */
const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);
/** Types de contenu dont le corps est lu, en plus de text/*, *+json et *+xml. */
const TEXTUAL_TYPES: ReadonlySet<string> = new Set([
  "application/xhtml+xml",
  "application/json",
  "application/xml",
]);
/** Longueur maximale d'une URL citée dans un message (une destination peut être très longue). */
const MAX_QUOTED_LENGTH = 200;
/** Codes d'une tentative de connexion vers une famille d'adresses que le serveur ne peut pas joindre. */
const UNREACHABLE_CODES: ReadonlySet<string> = new Set(["ENETUNREACH", "EHOSTUNREACH"]);

/** Tolère un flux compressé tronqué (Z_SYNC_FLUSH) au lieu d'échouer sur ses derniers octets. */
const ZLIB_TOLERANT = { finishFlush: constants.Z_SYNC_FLUSH };

/** Décompresseurs pris en charge, par valeur de Content-Encoding. */
const DECODERS: Readonly<Record<string, () => Transform>> = {
  gzip: () => createGunzip(ZLIB_TOLERANT),
  "x-gzip": () => createGunzip(ZLIB_TOLERANT),
  // « deflate » désigne le format zlib (RFC 9110), que createInflate attend.
  deflate: () => createInflate(ZLIB_TOLERANT),
  br: () => createBrotliDecompress({ finishFlush: constants.BROTLI_OPERATION_FLUSH }),
  // Expérimental dans Node.js 24 : non annoncé, mais décodé si un serveur l'envoie.
  zstd: () => createZstdDecompress(),
};

/** Réglages d'un client HTTP. Par défaut tout est strict ; les autres valeurs servent aux tests. */
export interface FetcherOptions extends AddressPolicyOptions {
  /** Fonction `lookup` des sockets. Défaut : `createSafeLookup()` avec la même politique. */
  lookup?: LookupFunction;
  /** User-Agent envoyé. Défaut : `USER_AGENT`. */
  userAgent?: string;
  /** Ports autorisés. Défaut : `ALLOWED_PORTS` (80 et 443) ; un test y ajoute le port de son serveur. */
  allowedPorts?: ReadonlySet<number>;
}

/** Réglages résolus d'un client (valeurs par défaut appliquées). */
interface FetcherConfig {
  policy: AddressPolicyOptions;
  lookup: LookupFunction;
  userAgent: string;
  allowedPorts: ReadonlySet<number>;
}

/** Réponse dont les en-têtes sont lus, mais pas encore le corps. */
type ResponseHead = Omit<HttpResponse, "body" | "bodyTruncated" | "durationMs">;

// ─────────────────────────────────────────────────────────────────────────────
// Délais et traduction des erreurs (partagés avec tls-probe.ts)
// ─────────────────────────────────────────────────────────────────────────────

/** Délai d'une opération réseau : son propre minuteur, combiné au signal éventuel de l'appelant. */
export interface Deadline {
  /** Signal à transmettre aux sockets : il se déclenche au premier des deux événements. */
  signal: AbortSignal;
  /** Minuteur propre à l'opération. */
  timer: AbortSignal;
  /** Signal de l'appelant (délai global du scan), s'il existe. */
  external: AbortSignal | undefined;
  /** Durée du minuteur, en millisecondes (pour le message d'erreur). */
  timeoutMs: number;
}

/** Démarre le délai total d'une opération (`AbortSignal.timeout`), combiné au signal de l'appelant. */
export function createDeadline(timeoutMs: number, external?: AbortSignal): Deadline {
  const timer = AbortSignal.timeout(timeoutMs);
  const signal = external ? AbortSignal.any([timer, external]) : timer;
  return { signal, timer, external, timeoutMs };
}

/** La raison d'une annulation est-elle un délai dépassé (`AbortSignal.timeout`) ? */
function isTimeoutReason(reason: unknown): boolean {
  return typeof reason === "object" && reason !== null && "name" in reason
    ? reason.name === "TimeoutError"
    : false;
}

/** Durée lisible en français, ex. « 8 s » ou « 0,5 s ». */
function formatSeconds(milliseconds: number): string {
  const seconds = new Intl.NumberFormat("fr-FR", { maximumFractionDigits: 1 }).format(
    milliseconds / 1000,
  );
  return `${seconds} s`;
}

/**
 * Erreur à rapporter si l'opération a été interrompue (délai ou annulation), sinon null.
 * Ce test passe AVANT la lecture du code d'erreur : une coupure survenue après la réception des
 * en-têtes se manifeste par une erreur ECONNRESET (« aborted ») qui, sinon, passerait pour une
 * connexion interrompue par le serveur.
 *
 * @param action début de phrase décrivant l'échec, ex. « Le serveur n'a pas répondu »
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
 * Erreur la plus parlante. Quand toutes les tentatives « Happy Eyeballs » échouent, Node.js renvoie
 * une AggregateError qui porte le code de la PREMIÈRE tentative, souvent ENETUNREACH (pas d'IPv6 sur
 * le serveur de SecuScan) : on préfère alors l'erreur d'une autre tentative.
 */
function primaryError(error: unknown): unknown {
  if (!(error instanceof AggregateError)) return error;
  const attempts: unknown[] = error.errors;
  const informative = attempts.find((attempt) => !UNREACHABLE_CODES.has(errorCode(attempt) ?? ""));
  return informative ?? attempts[0] ?? error;
}

/** Le code vient-il d'un décompresseur (zlib, brotli, zstd) qui ne comprend pas le corps reçu ? */
function isDecompressionError(code: string): boolean {
  return code.startsWith("Z_") || code.startsWith("ERR__") || /BROTLI|ZSTD/i.test(code);
}

/** Code normalisé et message français pour un code d'erreur Node.js. */
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

/**
 * Traduit une erreur de Node.js (socket, DNS, TLS, HTTP, décompression) en `NetworkError` :
 * code normalisé, message français pour l'utilisateur, détail technique pour le débogage.
 */
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
 * Validité du certificat présenté sur une connexion TLS (`authorized`, `authorizationError`).
 *
 * Piège démontré par l'expérience : quand la chaîne de certificats est invalide (expirée,
 * auto-signée…), Node.js ne vérifie PAS le nom d'hôte. On le vérifie donc toujours soi-même avec
 * `tls.checkServerIdentity`. Une erreur de nom l'emporte : aucun navigateur ne la contourne, alors
 * qu'une chaîne seulement incomplète peut encore être complétée par le navigateur.
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

/** Code d'erreur si le certificat ne couvre pas `hostname` (nom ou IP), sinon null. */
function hostnameError(hostname: string, certificate: PeerCertificate): string | null {
  try {
    const error = checkServerIdentity(hostname, certificate);
    return error === undefined ? null : (errorCode(error) ?? "ERR_TLS_CERT_ALTNAME_INVALID");
  } catch {
    return null; // certificat inexploitable : l'erreur de chaîne suffit à le signaler
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Validation des URL et des redirections
// ─────────────────────────────────────────────────────────────────────────────

/** Raccourcit un texte venu du serveur avant de le citer dans un message. */
function shorten(text: string): string {
  return text.length <= MAX_QUOTED_LENGTH ? text : `${text.slice(0, MAX_QUOTED_LENGTH)}…`;
}

/** Problème qui interdit de contacter une URL. */
interface UrlProblem {
  /** L'adresse elle-même est interdite (anti-SSRF), plutôt que la forme de l'URL. */
  blockedAddress: boolean;
  /** Explication en français (une phrase complète). */
  message: string;
}

/**
 * Vérifie une URL AVANT toute connexion : requête initiale et chaque redirection.
 * Les noms d'hôte, eux, sont vérifiés par la `lookup` sûre au moment de la connexion.
 */
function findUrlProblem(url: URL, config: FetcherConfig): UrlProblem | null {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return {
      blockedAddress: false,
      message: `Le schéma « ${url.protocol} » n'est pas pris en charge : seules les adresses http:// et https:// sont autorisées.`,
    };
  }
  // Node.js transformerait « utilisateur:motdepasse@ » en en-tête Authorization : on ne transmet
  // jamais d'identifiants à un site analysé.
  if (url.username !== "" || url.password !== "") {
    return {
      blockedAddress: false,
      message: "Les identifiants dans l'adresse (utilisateur:mot de passe@) sont interdits.",
    };
  }
  // Node.js n'appelle pas `lookup` pour une IP littérale : c'est donc ici qu'on la vérifie.
  // L'analyseur d'URL a déjà normalisé les formes piégées (« 2130706433 » → « 127.0.0.1 »).
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

/**
 * Erreur correspondant à une URL refusée. Requête initiale : BLOCKED_ADDRESS (requête refusée par la
 * politique anti-SSRF). Redirection : INVALID_REDIRECT, sauf adresse interdite (BLOCKED_ADDRESS).
 */
function refusalError(url: URL, problem: UrlProblem, isRedirect: boolean): NetworkError {
  if (!isRedirect) return { code: "BLOCKED_ADDRESS", message: problem.message };
  return {
    code: problem.blockedAddress ? "BLOCKED_ADDRESS" : "INVALID_REDIRECT",
    message: `Redirection vers ${shorten(url.href)} refusée. ${problem.message}`,
  };
}

/** Destination d'une redirection (en-tête Location), ou l'erreur qui empêche de la suivre. */
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
    // Une destination relative (« /fr/ ») se résout par rapport à l'URL courante.
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

// ─────────────────────────────────────────────────────────────────────────────
// Échange HTTP : requête, en-têtes, corps
// ─────────────────────────────────────────────────────────────────────────────

/** En-têtes de la requête : valeurs par défaut, puis en-têtes de l'appelant (noms en minuscules). */
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

/** Envoie une requête et attend les en-têtes de la réponse (le corps reste à lire). */
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
      agent: false, // une connexion neuve par requête : `lookup` est toujours rappelée
      lookup: config.lookup,
      signal,
      maxHeaderSize: MAX_HEADER_BYTES,
      rejectUnauthorized: false, // certificat invalide : on lit quand même, et on le signale
      servername: isIpLiteral(hostname) ? undefined : hostname, // SNI : jamais une IP (RFC 6066)
    };
    const request =
      url.protocol === "https:"
        ? httpsRequest(url, requestOptions, resolve)
        : httpRequest(url, requestOptions, resolve);
    // `on` et non `once` : une erreur peut encore survenir après la réponse (coupure, délai) ;
    // sans écouteur, Node.js la lèverait comme exception non interceptée et arrêterait le processus.
    request.on("error", reject);
    request.end();
  });
}

/** Transforme la liste plate de Node.js [nom, valeur, nom, valeur…] en paires. */
function toPairs(raw: string[]): Array<[name: string, value: string]> {
  const pairs: Array<[string, string]> = [];
  for (let index = 0; index + 1 < raw.length; index += 2) {
    pairs.push([raw[index] ?? "", raw[index + 1] ?? ""]);
  }
  return pairs;
}

/** Informations TLS de la connexion qui a porté la réponse (null en HTTP clair). */
function readTlsInfo(message: IncomingMessage, hostname: string): ResponseTlsInfo | null {
  const socket = message.socket;
  if (!(socket instanceof TLSSocket)) return null;
  return { ...readAuthorization(socket, hostname), protocol: socket.getProtocol() };
}

/**
 * Lit statut, en-têtes, adresse et TLS d'une réponse. À appeler avant de détruire la réponse :
 * le socket n'a plus d'adresse ensuite.
 */
function readResponseHead(url: URL, message: IncomingMessage): ResponseHead {
  const headers: Record<string, string> = {};
  let setCookies: string[] = [];
  // `headersDistinct` garde chaque valeur : `message.headers` supprimerait les doublons de server,
  // content-type, location… et cacherait des configurations ambiguës (deux CSP, deux HSTS).
  for (const [name, values] of Object.entries(message.headersDistinct)) {
    if (values === undefined) continue;
    // Set-Cookie ne se joint pas par une virgule (les dates en contiennent) : liste à part.
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

/** Le corps est-il du texte utile à l'analyse (HTML, XHTML, JSON, security.txt…) ? */
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

/** Convertit un morceau de flux en Buffer (les flux binaires de Node.js en produisent déjà). */
function toBuffer(chunk: unknown): Buffer {
  return Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
}

/**
 * Lit au plus `maxBytes` octets DÉCOMPRESSÉS. Compter après décompression protège des « bombes » :
 * quelques Ko compressés peuvent produire des Go de données.
 */
async function collectBytes(
  message: IncomingMessage,
  decoder: Transform | null,
  maxBytes: number,
): Promise<{ bytes: Buffer; truncated: boolean }> {
  if (decoder !== null) {
    // pipe() ne transmet pas les erreurs : sans ce relais, une coupure de la réponse laisserait
    // le décompresseur attendre indéfiniment.
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
    message.destroy(); // arrête le téléchargement (sans effet si la réponse est déjà complète)
    decoder?.destroy();
  }
  return { bytes: Buffer.concat(chunks, size), truncated };
}

/** Décode le corps selon le charset annoncé ; UTF-8 par défaut ou si le charset est inconnu. */
function decodeText(bytes: Buffer, contentType: string | undefined): string {
  const charset = /charset\s*=\s*"?([^";\s]+)/i.exec(contentType ?? "")?.[1];
  try {
    return new TextDecoder(charset ?? "utf-8").decode(bytes);
  } catch {
    return new TextDecoder("utf-8").decode(bytes); // étiquette inconnue : TextDecoder lève une RangeError
  }
}

/**
 * Lit le corps s'il est utile : méthode GET, `maxBodyBytes` > 0, type textuel et encodage connu.
 * Sinon la réponse est détruite (inutile de télécharger une image) et le corps vaut null.
 */
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

/** Durée écoulée depuis `startedAt` (performance.now()), arrondie à la milliseconde. */
function elapsedMs(startedAt: number): number {
  return Math.round(performance.now() - startedAt);
}

// ─────────────────────────────────────────────────────────────────────────────
// Boucle principale : requête, redirections, réponse finale
// ─────────────────────────────────────────────────────────────────────────────

/** Échec accompagné des réponses déjà reçues (ex. redirections suivies avant une redirection interdite). */
function failure(error: NetworkError, chain: HttpResponse[]): Result<FetchSuccess> {
  return { ok: false, error: { ...error, chain } };
}

/** Suit la requête et ses redirections, en revalidant chaque étape. */
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
        message.destroy(); // le corps d'une redirection n'est jamais lu
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

/**
 * Crée un client HTTP(S) sûr. Sans option, il applique la politique stricte (adresses publiques
 * seulement, ports 80 et 443) ; les options servent aux tests (serveur local, DNS simulé).
 */
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
      // Filet de sécurité : le contrat d'un Fetcher est de ne jamais lever d'exception.
      return failure(toNetworkError(error), []);
    }
  };
}

/** Client HTTP(S) par défaut, strict : c'est lui que le scanner utilise. */
export const safeFetch: Fetcher = createFetcher();
