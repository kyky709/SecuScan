/**
 * Modèle de données du moteur de scan.
 *
 * Ce fichier est le « contrat » partagé par toutes les couches du scanner :
 *
 *   saisie ─► cible normalisée ─► sondes réseau ─► ScanContext ─► contrôles ─► notation ─► ScanReport
 *                (target.ts)        (network/)                    (checks/)   (scoring.ts)
 *
 * Les sondes réseau (entrées/sorties, lentes, faillibles) collectent des faits bruts dans un
 * `ScanContext`. Les contrôles sont ensuite de simples fonctions pures `ScanContext → CheckOutcome` :
 * ils ne font aucun accès réseau, ce qui les rend faciles à comprendre et à tester.
 */

// ─────────────────────────────────────────────────────────────────────────────
// Résultats génériques
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Résultat d'une opération qui peut échouer, sans exception.
 * Oblige l'appelant à traiter explicitement le cas d'erreur (`if (!r.ok) …`).
 */
export type Result<T, E = NetworkError> = { ok: true; value: T } | { ok: false; error: E };

// ─────────────────────────────────────────────────────────────────────────────
// Couche réseau (src/lib/scanner/network/)
// ─────────────────────────────────────────────────────────────────────────────

/** Codes d'erreur réseau normalisés, indépendants des codes internes de Node.js. */
export type NetworkErrorCode =
  /** L'hôte pointe vers une adresse privée, locale ou réservée : requête refusée (anti-SSRF). */
  | "BLOCKED_ADDRESS"
  /** Le nom de domaine ne se résout pas (ENOTFOUND, ENODATA…). */
  | "DNS_FAILURE"
  /** Connexion refusée par le serveur (ECONNREFUSED). */
  | "CONNECTION_REFUSED"
  /** Connexion interrompue (ECONNRESET, « socket hang up »…). */
  | "CONNECTION_RESET"
  /** Délai dépassé (connexion, réponse ou délai global du scan). */
  | "TIMEOUT"
  /** Échec de la négociation TLS (protocole ou suite de chiffrement incompatibles…). */
  | "TLS_ERROR"
  /** Trop de redirections successives. */
  | "TOO_MANY_REDIRECTS"
  /** Redirection invalide : en-tête Location absent ou illisible, schéma, port ou identifiants interdits. */
  | "INVALID_REDIRECT"
  /** Réponse HTTP mal formée. */
  | "PROTOCOL_ERROR"
  /** Toute autre erreur. */
  | "UNKNOWN";

export interface NetworkError {
  code: NetworkErrorCode;
  /** Message lisible, en français, destiné à l'utilisateur. */
  message: string;
  /** Détail technique (code Node.js d'origine…), utile au débogage. */
  detail?: string;
  /** Réponses déjà reçues avant l'erreur (ex. redirections suivies avant une redirection interdite). */
  chain?: HttpResponse[];
}

/** Informations TLS associées à une réponse HTTPS (null pour une réponse en HTTP clair). */
export interface ResponseTlsInfo {
  /** Le certificat est-il valide (chaîne de confiance, dates, nom d'hôte) ? */
  authorized: boolean;
  /** Code d'erreur de validation (ex. CERT_HAS_EXPIRED, ERR_TLS_CERT_ALTNAME_INVALID), sinon null. */
  authorizationError: string | null;
  /** Version négociée, ex. "TLSv1.3". */
  protocol: string | null;
}

/** Une réponse HTTP telle que reçue par la sonde. */
export interface HttpResponse {
  /** URL demandée pour obtenir cette réponse. */
  url: string;
  /** Code de statut HTTP (200, 301…). */
  status: number;
  /**
   * En-têtes, noms en minuscules. Les valeurs multiples d'un même en-tête sont jointes par ", "
   * (sémantique HTTP standard), sauf Set-Cookie, fourni séparément dans `setCookies`.
   */
  headers: Record<string, string>;
  /** En-têtes tels que reçus (ordre et casse d'origine, doublons conservés), pour l'affichage. */
  rawHeaders: Array<[name: string, value: string]>;
  /** Chaque en-tête Set-Cookie, séparément (ils ne peuvent pas être joints par une virgule). */
  setCookies: string[];
  /** Corps décodé en texte (HTML, security.txt…), tronqué à la taille maximale ; null s'il n'a pas été lu. */
  body: string | null;
  /** Le corps a-t-il été tronqué ? */
  bodyTruncated: boolean;
  /** Adresse IP effectivement contactée. */
  remoteAddress: string | null;
  /** Informations TLS de la connexion (null en HTTP clair). */
  tls: ResponseTlsInfo | null;
  /** Durée de l'échange, en millisecondes. */
  durationMs: number;
}

/** Options d'une requête HTTP(S) sortante. */
export interface FetchOptions {
  /** Méthode HTTP (GET par défaut). */
  method?: "GET" | "HEAD";
  /** En-têtes supplémentaires (User-Agent et Accept sont fournis par défaut). */
  headers?: Record<string, string>;
  /** Nombre maximal de redirections à suivre (0 = ne pas suivre). Défaut : `MAX_REDIRECTS`. */
  maxRedirects?: number;
  /** Délai maximal de chaque requête, en millisecondes. Défaut : `REQUEST_TIMEOUT_MS`. */
  timeoutMs?: number;
  /** Nombre maximal d'octets de corps à lire (0 = ne pas lire le corps). Défaut : `MAX_BODY_BYTES`. */
  maxBodyBytes?: number;
  /** Signal d'annulation (délai global du scan). */
  signal?: AbortSignal;
}

/** Résultat d'une requête réussie (au sens réseau : une réponse a été obtenue, quel que soit son statut). */
export interface FetchSuccess {
  /** Réponse finale, après les éventuelles redirections. */
  response: HttpResponse;
  /** Toutes les réponses reçues dans l'ordre : redirections puis réponse finale (au moins un élément). */
  chain: HttpResponse[];
}

/** Effectue une requête HTTP(S) sûre (anti-SSRF). Ne lève jamais d'exception : renvoie un Result. */
export type Fetcher = (url: string, options?: FetchOptions) => Promise<Result<FetchSuccess>>;

/** Certificat X.509 présenté par le serveur. */
export interface CertificateInfo {
  /** Nom commun (CN) du sujet. */
  subject: string;
  /** Noms couverts par le certificat (extension Subject Alternative Name), ex. ["example.com", "*.example.com"]. */
  subjectAltNames: string[];
  /** Émetteur (organisation ou nom commun de l'autorité de certification). */
  issuer: string;
  /** Début de validité (ISO 8601). */
  validFrom: string;
  /** Fin de validité (ISO 8601). */
  validTo: string;
  /** Jours restants avant expiration (négatif si expiré), calculés au moment du scan. */
  daysRemaining: number;
  /** Numéro de série (hexadécimal). */
  serialNumber: string;
  /** Empreinte SHA-256. */
  fingerprint256: string;
  /** Type de clé publique ("RSA", "EC"…), si connu. */
  keyType: string | null;
  /** Taille de la clé en bits, si connue. */
  keyBits: number | null;
  /** Certificat auto-signé (émetteur = sujet) ? */
  selfSigned: boolean;
}

/** Résultat de la sonde TLS (négociation directe sur le port 443). */
export interface TlsInfo {
  hostname: string;
  /** Adresse IP contactée. */
  address: string;
  port: number;
  /** Version de TLS négociée, ex. "TLSv1.3". */
  protocol: string | null;
  /** Suite de chiffrement négociée (nom standard), ex. "TLS_AES_128_GCM_SHA256". */
  cipher: string | null;
  /** Protocole applicatif négocié par ALPN ("h2", "http/1.1"), si annoncé. */
  alpnProtocol: string | null;
  /** Le certificat est-il valide (confiance, dates, nom d'hôte) ? */
  authorized: boolean;
  /** Code d'erreur de validation (CERT_HAS_EXPIRED, DEPTH_ZERO_SELF_SIGNED_CERT, ERR_TLS_CERT_ALTNAME_INVALID…). */
  authorizationError: string | null;
  /** Certificat du serveur (feuille). */
  certificate: CertificateInfo | null;
  /** Chaîne présentée, du certificat du serveur vers la racine. */
  chain: Array<{ subject: string; issuer: string }>;
  /**
   * Prise en charge des protocoles obsolètes TLS 1.0 et 1.1 :
   * true = accepté par le serveur, false = refusé, null = test non concluant.
   */
  legacyProtocols: { tls10: boolean | null; tls11: boolean | null };
}

/** Négocie une connexion TLS avec l'hôte et décrit le certificat et le protocole. */
export type TlsProber = (
  hostname: string,
  options?: { port?: number; timeoutMs?: number; signal?: AbortSignal },
) => Promise<Result<TlsInfo>>;

/** Enregistrement DNS CAA (RFC 8659) : quelles autorités peuvent émettre un certificat pour le domaine. */
export interface CaaRecord {
  /** Drapeau « critique » (0 ou 128). */
  critical: number;
  /** Étiquette : "issue", "issuewild", "iodef"… */
  tag: string;
  /** Valeur, ex. "letsencrypt.org". */
  value: string;
}

export interface CaaInfo {
  /** Domaine où les enregistrements ont été trouvés en remontant l'arbre DNS (null si aucun). */
  domain: string | null;
  records: CaaRecord[];
}

/** Cherche les enregistrements CAA applicables à un nom d'hôte (remontée vers les domaines parents). */
export type CaaResolver = (
  hostname: string,
  options?: { timeoutMs?: number; signal?: AbortSignal },
) => Promise<Result<CaaInfo>>;

// ─────────────────────────────────────────────────────────────────────────────
// Cible et contexte de scan
// ─────────────────────────────────────────────────────────────────────────────

/** Cible normalisée à partir de la saisie de l'utilisateur (voir target.ts). */
export interface ScanTarget {
  /** Saisie brute. */
  input: string;
  /** URL analysée, toujours en HTTPS : https://hôte[/chemin][?requête] (sans fragment ni port). */
  url: string;
  /** Nom d'hôte normalisé : minuscules, sans point final, IDN en punycode, IPv6 sans crochets. */
  hostname: string;
  /** L'hôte est-il une adresse IP littérale ? */
  isIpAddress: boolean;
}

/** Ressource référencée par la page HTML (script, feuille de style, image…). */
export interface HtmlResource {
  /** Balise : "script", "link", "img", "iframe", "audio", "video", "source", "object", "embed"… */
  tag: string;
  /** URL absolue (résolue par rapport à l'URL de la page et à un éventuel <base href>). */
  url: string;
  /** Attribut integrity (Subresource Integrity), sinon null. */
  integrity: string | null;
  /** Attribut crossorigin, sinon null. */
  crossorigin: string | null;
  /** Attribut rel (pour <link>), sinon null. */
  rel: string | null;
}

/** Éléments extraits du HTML de la page analysée (voir checks/html.ts). */
export interface HtmlInfo {
  /** Scripts externes (<script src>). */
  scripts: HtmlResource[];
  /** Nombre de scripts en ligne (<script> sans src, hors JSON/données). */
  inlineScriptCount: number;
  /** Feuilles de style externes (<link rel="stylesheet">). */
  stylesheets: HtmlResource[];
  /** Autres ressources chargées : img, audio, video, source, track, iframe, frame, object, embed, link preload… */
  otherResources: HtmlResource[];
  /** Formulaires : action résolue en URL absolue (null si absente = même page) et méthode. */
  forms: Array<{ action: string | null; method: string }>;
  /** Contenu des balises <meta http-equiv="Content-Security-Policy">. */
  metaCsp: string[];
  /** Contenu de <meta name="referrer">, sinon null. */
  metaReferrer: string | null;
  /** URL de <base href>, sinon null. */
  baseHref: string | null;
}

/**
 * Faits collectés par les sondes réseau. C'est l'unique entrée des contrôles.
 * Chaque sonde peut échouer indépendamment : son résultat est un `Result`.
 */
export interface ScanContext {
  target: ScanTarget;
  /** GET sur l'URL en HTTPS, redirections suivies, corps lu (HTML). */
  https: Result<FetchSuccess>;
  /** GET sur la même URL en HTTP clair, redirections suivies, corps non lu (contrôle de redirection). */
  http: Result<FetchSuccess>;
  /** Négociation TLS directe avec l'hôte (port 443). */
  tls: Result<TlsInfo>;
  /** GET https://hôte/.well-known/security.txt (RFC 9116). */
  securityTxt: Result<FetchSuccess>;
  /** GET de l'URL en HTTPS avec un en-tête `Origin` étranger, pour tester la politique CORS. */
  cors: Result<FetchSuccess>;
  /** Enregistrements DNS CAA. */
  caa: Result<CaaInfo>;
  /** Réponse finale analysée : celle de la sonde HTTPS si elle a réussi, sinon celle de la sonde HTTP. */
  response: HttpResponse | null;
  /** Éléments extraits du HTML de `response` (null si la réponse n'est pas du HTML). */
  html: HtmlInfo | null;
}

// ─────────────────────────────────────────────────────────────────────────────
// Contrôles (src/lib/scanner/checks/)
// ─────────────────────────────────────────────────────────────────────────────

/** Identifiants stables des contrôles (utilisés par l'API, l'interface et la documentation). */
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

/** Familles de contrôles, dans l'ordre d'affichage. */
export type CheckCategory = "transport" | "headers" | "cookies" | "content" | "exposure";

/**
 * Statut d'un contrôle :
 * - pass    : conforme aux bonnes pratiques ;
 * - warning : amélioration recommandée (risque limité, défense en profondeur absente) ;
 * - fail    : faiblesse de sécurité à corriger ;
 * - info    : information sans impact sur la sécurité ;
 * - error   : contrôle impossible (la sonde nécessaire a échoué).
 */
export type CheckStatus = "pass" | "warning" | "fail" | "info" | "error";

/** Famille d'une référence documentaire (pour l'affichage d'un badge). */
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

/** Lien vers une source qui justifie un contrôle ou une recommandation. */
export interface Reference {
  kind: ReferenceKind;
  /** Libellé affiché, ex. "OWASP Top 10 – A02:2025 Security Misconfiguration". */
  label: string;
  url: string;
}

/** Exemple de configuration à copier pour corriger un problème. */
export interface FixExample {
  /** Environnement : "Nginx", "Apache", "Next.js (next.config.ts)", "Vercel (vercel.json)"… */
  label: string;
  /** Langage pour la coloration (nginx, apache, ts, json, http…). */
  language: string;
  code: string;
}

/** Verdict produit par un contrôle. */
export interface CheckOutcome {
  status: CheckStatus;
  /**
   * Effet sur le score (base 100) : négatif = pénalité, positif = bonus, 0 = neutre.
   * Les valeurs possibles de chaque contrôle sont fixées par la grille de notation (docs/22-notation.md).
   */
  scoreModifier: number;
  /** Une phrase en français qui résume le constat. */
  summary: string;
  /** Constats complémentaires (une phrase par élément). */
  details?: string[];
  /** Valeur brute observée (en-tête, cookie…), affichée telle quelle. */
  evidence?: string | null;
  /** Comment corriger ou améliorer (français), null si rien à faire. */
  recommendation?: string | null;
  /** Exemples de configuration pour appliquer la recommandation. */
  examples?: FixExample[];
}

/** Définition d'un contrôle : métadonnées statiques et fonction d'évaluation pure. */
export interface CheckDefinition {
  id: CheckId;
  category: CheckCategory;
  /** Titre court, ex. "HTTP Strict Transport Security (HSTS)". */
  title: string;
  /** Rôle du mécanisme et risque couvert (2 à 4 phrases, français), affiché dans la méthodologie. */
  description: string;
  /** Sources : OWASP (Top 10, ASVS, Cheat Sheets, WSTG), MDN, RFC… */
  references: Reference[];
  /** Grille de notation lisible (affichée dans la méthodologie) : un résultat possible par ligne. */
  scoring: Array<{ outcome: string; modifier: number }>;
  /** Évalue le contrôle. Fonction pure : aucun accès réseau, aucune exception attendue. */
  evaluate(context: ScanContext): CheckOutcome;
}

/** Résultat complet d'un contrôle, tel que renvoyé par l'API. */
export interface CheckResult extends CheckOutcome {
  id: CheckId;
  category: CheckCategory;
  title: string;
  description: string;
  references: Reference[];
}

// ─────────────────────────────────────────────────────────────────────────────
// Notation et rapport
// ─────────────────────────────────────────────────────────────────────────────

/** Note finale, de la meilleure à la moins bonne. */
export type Grade = "A+" | "A" | "B" | "C" | "D" | "E" | "F";

/** Détail du calcul du score (voir scoring.ts). */
export interface ScoreBreakdown {
  /** Score de départ (100). */
  base: number;
  /** Somme des pénalités (valeur négative ou nulle). */
  penalties: number;
  /** Somme des bonus obtenus (valeur positive ou nulle), qu'ils soient appliqués ou non. */
  bonuses: number;
  /** Les bonus ne comptent que si le score après pénalités atteint le seuil (voir scoring.ts). */
  bonusesApplied: boolean;
  /** Score final (borné entre 0 et le maximum). */
  score: number;
  grade: Grade;
}

/** Étape d'une chaîne de redirections, pour l'affichage. */
export interface RedirectHop {
  url: string;
  status: number;
  /** Destination annoncée (en-tête Location résolu), null pour la réponse finale. */
  location: string | null;
}

/** Rapport de scan renvoyé par `POST /api/scan`. */
export interface ScanReport {
  /** Version du format du rapport (incrémentée en cas de changement incompatible). */
  schemaVersion: 1;
  scanner: { name: string; version: string };
  target: {
    input: string;
    url: string;
    hostname: string;
    /** URL finale après redirections (HTTPS si disponible), null si injoignable. */
    finalUrl: string | null;
    /** Adresse IP contactée pour la réponse finale. */
    ip: string | null;
  };
  /** Date du scan (ISO 8601). */
  scannedAt: string;
  /** Durée totale du scan, en millisecondes. */
  durationMs: number;
  score: ScoreBreakdown;
  /** Nombre de contrôles par statut. */
  summary: Record<CheckStatus, number>;
  /** Résultats, dans l'ordre d'affichage (par famille). */
  checks: CheckResult[];
  /** Redirections observées depuis http:// et depuis https://. */
  redirects: { fromHttp: RedirectHop[]; fromHttps: RedirectHop[] };
  /** Statut HTTP et en-têtes bruts de la réponse finale analysée. */
  response: { status: number; headers: Array<[name: string, value: string]> } | null;
  /** Détails TLS (null si la sonde TLS a échoué). */
  tls: TlsInfo | null;
  /** Sondes qui ont échoué (pour expliquer les contrôles en erreur). */
  probeErrors: Array<{ probe: string; code: NetworkErrorCode; message: string }>;
}
