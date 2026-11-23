// Les sondes réseau (lentes, faillibles) collectent des faits bruts dans un `ScanContext` ; les
// contrôles sont des fonctions pures `ScanContext → CheckOutcome`, sans accès réseau.

export type Result<T, E = NetworkError> = { ok: true; value: T } | { ok: false; error: E };

/** Indépendants des codes internes de Node.js. */
export type NetworkErrorCode =
  /** Adresse privée, locale ou réservée (anti-SSRF). */
  | "BLOCKED_ADDRESS"
  | "DNS_FAILURE"
  | "CONNECTION_REFUSED"
  /** ECONNRESET, « socket hang up »… */
  | "CONNECTION_RESET"
  /** Connexion, réponse ou délai global du scan. */
  | "TIMEOUT"
  | "TLS_ERROR"
  | "TOO_MANY_REDIRECTS"
  /** Location absent ou illisible ; schéma, port ou identifiants interdits. */
  | "INVALID_REDIRECT"
  | "PROTOCOL_ERROR"
  | "UNKNOWN";

export interface NetworkError {
  code: NetworkErrorCode;
  /** Affiché à l'utilisateur. */
  message: string;
  /** Code Node.js d'origine, pour le débogage. */
  detail?: string;
  /** Réponses reçues avant l'erreur (redirections suivies avant une redirection interdite). */
  chain?: HttpResponse[];
}

export interface ResponseTlsInfo {
  /** Chaîne de confiance, dates et nom d'hôte valides. */
  authorized: boolean;
  /** Ex. CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID. */
  authorizationError: string | null;
  /** Ex. "TLSv1.3". */
  protocol: string | null;
}

export interface HttpResponse {
  url: string;
  status: number;
  /** Noms en minuscules, valeurs multiples jointes par ", " (sauf Set-Cookie : `setCookies`). */
  headers: Record<string, string>;
  /** Ordre, casse et doublons d'origine, pour l'affichage. */
  rawHeaders: Array<[name: string, value: string]>;
  /** Séparés : des Set-Cookie ne peuvent pas être joints par une virgule. */
  setCookies: string[];
  /** Tronqué à la taille maximale ; null s'il n'a pas été lu. */
  body: string | null;
  bodyTruncated: boolean;
  remoteAddress: string | null;
  /** null en HTTP clair. */
  tls: ResponseTlsInfo | null;
  durationMs: number;
}

export interface FetchOptions {
  /** Défaut : GET. */
  method?: "GET" | "HEAD";
  /** User-Agent et Accept sont fournis par défaut. */
  headers?: Record<string, string>;
  /** 0 = ne pas suivre. Défaut : `MAX_REDIRECTS`. */
  maxRedirects?: number;
  /** Par requête. Défaut : `REQUEST_TIMEOUT_MS`. */
  timeoutMs?: number;
  /** 0 = ne pas lire le corps. Défaut : `MAX_BODY_BYTES`. */
  maxBodyBytes?: number;
  signal?: AbortSignal;
}

/** Succès au sens réseau : une réponse a été obtenue, quel que soit son statut. */
export interface FetchSuccess {
  /** Réponse finale, après redirections. */
  response: HttpResponse;
  /** Redirections puis réponse finale (au moins un élément). */
  chain: HttpResponse[];
}

/** Requête anti-SSRF. Ne lève jamais d'exception. */
export type Fetcher = (url: string, options?: FetchOptions) => Promise<Result<FetchSuccess>>;

export interface CertificateInfo {
  /** CN du sujet uniquement. */
  subject: string;
  subjectAltNames: string[];
  /** Organisation ou CN de l'autorité de certification. */
  issuer: string;
  /** ISO 8601. */
  validFrom: string;
  /** ISO 8601. */
  validTo: string;
  /** Négatif si expiré, calculé au moment du scan. */
  daysRemaining: number;
  serialNumber: string;
  fingerprint256: string;
  keyType: string | null;
  keyBits: number | null;
  /** Émetteur = sujet. */
  selfSigned: boolean;
}

/** Négociation TLS directe sur le port 443. */
export interface TlsInfo {
  hostname: string;
  address: string;
  port: number;
  protocol: string | null;
  /** Nom standard, ex. "TLS_AES_128_GCM_SHA256". */
  cipher: string | null;
  alpnProtocol: string | null;
  authorized: boolean;
  authorizationError: string | null;
  /** Certificat feuille. */
  certificate: CertificateInfo | null;
  /** Du certificat du serveur vers la racine. */
  chain: Array<{ subject: string; issuer: string }>;
  /** true = accepté par le serveur, false = refusé, null = test non concluant. */
  legacyProtocols: { tls10: boolean | null; tls11: boolean | null };
}

export type TlsProber = (
  hostname: string,
  options?: { port?: number; timeoutMs?: number; signal?: AbortSignal },
) => Promise<Result<TlsInfo>>;

/** RFC 8659 : autorités autorisées à émettre un certificat pour le domaine. */
export interface CaaRecord {
  /** 0 ou 128. */
  critical: number;
  /** "issue", "issuewild", "iodef"… */
  tag: string;
  value: string;
}

export interface CaaInfo {
  /** Domaine où les enregistrements ont été trouvés en remontant l'arbre DNS (null si aucun). */
  domain: string | null;
  records: CaaRecord[];
}

export type CaaResolver = (
  hostname: string,
  options?: { timeoutMs?: number; signal?: AbortSignal },
) => Promise<Result<CaaInfo>>;

export interface ScanTarget {
  input: string;
  /** Toujours https://hôte[/chemin][?requête], sans fragment ni port. */
  url: string;
  /** Minuscules, sans point final, IDN en punycode, IPv6 sans crochets. */
  hostname: string;
  isIpAddress: boolean;
}

export interface HtmlResource {
  tag: string;
  /** Absolue, résolue par rapport à la page et à un éventuel <base href>. */
  url: string;
  integrity: string | null;
  crossorigin: string | null;
  rel: string | null;
}

export interface HtmlInfo {
  scripts: HtmlResource[];
  /** <script> sans src, hors JSON/données. */
  inlineScriptCount: number;
  stylesheets: HtmlResource[];
  otherResources: HtmlResource[];
  /** `action` résolue en URL absolue ; null si absente (même page). */
  forms: Array<{ action: string | null; method: string }>;
  metaCsp: string[];
  metaReferrer: string | null;
  baseHref: string | null;
}

/** Unique entrée des contrôles. Chaque sonde peut échouer indépendamment des autres. */
export interface ScanContext {
  target: ScanTarget;
  /** Redirections suivies, corps HTML lu. */
  https: Result<FetchSuccess>;
  /** Même URL en HTTP clair, corps non lu : sert au contrôle de redirection. */
  http: Result<FetchSuccess>;
  tls: Result<TlsInfo>;
  /** /.well-known/security.txt (RFC 9116). */
  securityTxt: Result<FetchSuccess>;
  /** Même URL en HTTPS avec un en-tête `Origin` étranger. */
  cors: Result<FetchSuccess>;
  caa: Result<CaaInfo>;
  /** Réponse de la sonde HTTPS si elle a réussi, sinon celle de la sonde HTTP. */
  response: HttpResponse | null;
  /** null si `response` n'est pas du HTML. */
  html: HtmlInfo | null;
}

/** Stables : utilisés par l'API, l'interface et la documentation. */
export type CheckId =
  | "https-redirect"
  | "hsts"
  | "tls-certificate"
  | "tls-protocol"
  | "csp"
  | "clickjacking"
  | "content-type-options"
  | "referrer-policy"
  | "permissions-policy"
  | "cross-origin-isolation"
  | "xss-protection"
  | "cookies"
  | "sri"
  | "mixed-content"
  | "cors"
  | "information-disclosure"
  | "security-txt"
  | "caa";

export type CheckCategory = "transport" | "headers" | "cookies" | "content" | "exposure";

/**
 * warning : risque limité ou défense en profondeur absente ; fail : faiblesse à corriger ;
 * info : sans impact sur la sécurité ; error : la sonde nécessaire a échoué.
 */
export type CheckStatus = "pass" | "warning" | "fail" | "info" | "error";

export type ReferenceKind =
  | "owasp-top10"
  | "owasp-asvs"
  | "owasp-cheatsheet"
  | "owasp-wstg"
  | "owasp-secure-headers"
  | "mdn"
  | "rfc"
  | "spec"
  | "other";

export interface Reference {
  kind: ReferenceKind;
  label: string;
  url: string;
}

export interface FixExample {
  /** Environnement : "Nginx", "Next.js (next.config.ts)", "Vercel (vercel.json)"… */
  label: string;
  language: string;
  code: string;
}

export interface CheckOutcome {
  status: CheckStatus;
  /** Négatif = pénalité, positif = bonus ; valeurs fixées par la grille `scoring` du contrôle. */
  scoreModifier: number;
  summary: string;
  details?: string[];
  /** Valeur brute observée (en-tête, cookie…). */
  evidence?: string | null;
  /** null si rien à faire. */
  recommendation?: string | null;
  examples?: FixExample[];
}

export interface CheckDefinition {
  id: CheckId;
  category: CheckCategory;
  title: string;
  /** Mécanisme et risque couvert, en 2 à 4 phrases (page méthodologie). */
  description: string;
  references: Reference[];
  /** Un résultat possible par ligne, affiché dans la méthodologie. */
  scoring: Array<{ outcome: string; modifier: number }>;
  /** Fonction pure : aucun accès réseau, aucune exception attendue. */
  evaluate(context: ScanContext): CheckOutcome;
}

export interface CheckResult extends CheckOutcome {
  id: CheckId;
  category: CheckCategory;
  title: string;
  description: string;
  references: Reference[];
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "E" | "F";

/** Voir scoring.ts. */
export interface ScoreBreakdown {
  base: number;
  /** ≤ 0. */
  penalties: number;
  /** Bonus obtenus, qu'ils soient appliqués ou non. */
  bonuses: number;
  /** Le score après pénalités a atteint le seuil des bonus. */
  bonusesApplied: boolean;
  /** Plancher à 0, sans plafond. */
  score: number;
  grade: Grade;
}

export interface RedirectHop {
  url: string;
  status: number;
  /** Location résolu ; null pour la réponse finale. */
  location: string | null;
}

export interface ScanReport {
  /** Incrémentée en cas de changement incompatible. */
  schemaVersion: 1;
  scanner: { name: string; version: string };
  target: {
    input: string;
    url: string;
    hostname: string;
    /** Après redirections (HTTPS si disponible) ; null si injoignable. */
    finalUrl: string | null;
    ip: string | null;
  };
  /** ISO 8601. */
  scannedAt: string;
  durationMs: number;
  score: ScoreBreakdown;
  summary: Record<CheckStatus, number>;
  /** Dans l'ordre d'affichage (par famille). */
  checks: CheckResult[];
  redirects: { fromHttp: RedirectHop[]; fromHttps: RedirectHop[] };
  response: { status: number; headers: Array<[name: string, value: string]> } | null;
  /** null si la sonde TLS a échoué. */
  tls: TlsInfo | null;
  /** Expliquent les contrôles en erreur. */
  probeErrors: Array<{ probe: string; code: NetworkErrorCode; message: string }>;
}
