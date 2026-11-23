// Note C : 100 − 10 (HSTS) − 25 (CSP) − 5 (cookies) − 5 (contenu mixte) = 55, et le bonus de +5
// (clickjacking) n'est pas compté car 55 < 90. Le rapport couvre les cinq statuts et tous les
// panneaux, dont un Set-Cookie dont la valeur doit être masquée et une sonde en échec (CAA).
import { REFS } from "@/lib/scanner/references";
import type { CheckId, CheckResult, ScanReport } from "@/lib/scanner/types";

const CSP_EXAMPLES: CheckResult["examples"] = [
  {
    label: "Nginx",
    language: "nginx",
    code: "add_header Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\" always;",
  },
  {
    label: "Apache",
    language: "apache",
    code: "Header always set Content-Security-Policy \"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\"",
  },
  {
    label: "Next.js (next.config.ts)",
    language: "ts",
    code: 'headers: async () => [{ source: "/:path*", headers: [{ key: "Content-Security-Policy", value: "default-src \'self\'" }] }]',
  },
];

const CHECKS: CheckResult[] = [
  {
    id: "https-redirect",
    category: "transport",
    title: "Redirection HTTP vers HTTPS",
    description:
      "Vérifie que la version http:// du site redirige vers https://, pour que les visiteurs ne restent pas sur une connexion non chiffrée.",
    references: [REFS.cheatSheets.tlsAllPages, REFS.wstg.CRYP01Redirect],
    status: "pass",
    scoreModifier: 0,
    summary: "http://example.com/ redirige directement vers https://example.com/ (même hôte).",
    details: ["Redirection permanente (301) : elle est mémorisée par les navigateurs."],
    recommendation: null,
  },
  {
    id: "tls-certificate",
    category: "transport",
    title: "Certificat TLS",
    description:
      "Vérifie que le certificat présenté est valide, reconnu et couvre le nom du site, sans quoi le navigateur affiche une alerte de sécurité.",
    references: [REFS.cheatSheets.tlsCertificates, REFS.asvs["12.2.2"]],
    status: "pass",
    scoreModifier: 0,
    summary: "Le certificat est valide pour example.com et expire dans 60 jours.",
    details: ["Émetteur : Let's Encrypt.", "Clé EC de 256 bits."],
    recommendation: null,
  },
  {
    id: "tls-protocol",
    category: "transport",
    title: "Version de TLS",
    description:
      "Vérifie que le serveur utilise une version récente de TLS et refuse TLS 1.0 et 1.1, abandonnés par la RFC 8996.",
    references: [REFS.cheatSheets.tlsProtocols, REFS.rfc.deprecateTls],
    status: "pass",
    scoreModifier: 0,
    summary: "TLS 1.3 est négocié ; TLS 1.0 et TLS 1.1 sont refusés.",
    recommendation: null,
  },
  {
    id: "hsts",
    category: "transport",
    title: "HTTP Strict Transport Security (HSTS)",
    description:
      "L'en-tête HSTS impose au navigateur d'utiliser HTTPS pour toutes les visites suivantes, ce qui empêche une attaque de type « homme du milieu » de rétrograder la connexion en HTTP.",
    references: [REFS.cheatSheets.hsts, REFS.asvs["3.4.1"], REFS.mdn.hsts],
    status: "warning",
    scoreModifier: -10,
    summary:
      "L'en-tête HSTS est présent avec max-age=86400 (1 jour), en dessous des 180 jours recommandés.",
    evidence: "max-age=86400",
    recommendation: "Portez max-age à au moins 31536000 (un an).",
    examples: [
      {
        label: "Nginx",
        language: "nginx",
        code: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
      },
    ],
  },
  {
    id: "csp",
    category: "headers",
    title: "Content Security Policy (CSP)",
    description:
      "La CSP indique au navigateur quelles sources de scripts, de styles et d'images sont autorisées : c'est la principale défense en profondeur contre les failles XSS.",
    references: [REFS.cheatSheets.csp, REFS.top10.A05, REFS.asvs["3.4.3"], REFS.mdn.csp],
    status: "fail",
    scoreModifier: -25,
    summary: "Aucune Content-Security-Policy n'est appliquée.",
    details: [
      "Aucun en-tête Content-Security-Policy ni balise meta équivalente.",
      "Une politique Report-Only seule n'offre aucune protection.",
    ],
    evidence: null,
    recommendation:
      "Déclarez une politique stricte, au minimum default-src 'self'; object-src 'none'; base-uri 'none'.",
    examples: CSP_EXAMPLES,
  },
  {
    id: "clickjacking",
    category: "headers",
    title: "Protection contre le clickjacking",
    description:
      "Empêche d'autres sites d'afficher vos pages dans un cadre invisible pour piéger les clics de vos visiteurs.",
    references: [REFS.cheatSheets.clickjacking, REFS.mdn.xFrameOptions],
    status: "pass",
    scoreModifier: 5,
    summary: "X-Frame-Options vaut SAMEORIGIN : seules vos propres pages peuvent intégrer le site.",
    evidence: "SAMEORIGIN",
    recommendation: null,
  },
  {
    id: "content-type-options",
    category: "headers",
    title: "X-Content-Type-Options",
    description:
      "La valeur nosniff interdit au navigateur de deviner le type d'un fichier, ce qui évite qu'un fichier déposé soit exécuté comme un script.",
    references: [REFS.cheatSheets.httpHeadersXcto, REFS.mdn.xContentTypeOptions],
    status: "pass",
    scoreModifier: 0,
    summary: "X-Content-Type-Options vaut nosniff.",
    evidence: "nosniff",
    recommendation: null,
  },
  {
    id: "referrer-policy",
    category: "headers",
    title: "Referrer-Policy",
    description:
      "Contrôle l'adresse de provenance transmise aux autres sites, qui peut contenir des informations sensibles.",
    references: [REFS.cheatSheets.httpHeadersReferrer, REFS.mdn.referrerPolicy],
    status: "info",
    scoreModifier: 0,
    summary:
      "Aucune Referrer-Policy : le navigateur applique strict-origin-when-cross-origin par défaut.",
    recommendation: "Déclarez explicitement Referrer-Policy: strict-origin-when-cross-origin.",
  },
  {
    id: "permissions-policy",
    category: "headers",
    title: "Permissions-Policy",
    description:
      "Désactive les fonctionnalités sensibles du navigateur (caméra, micro, géolocalisation) dont le site n'a pas besoin.",
    references: [REFS.cheatSheets.httpHeadersPermissions, REFS.mdn.permissionsPolicy],
    status: "warning",
    scoreModifier: 0,
    summary: "Aucun en-tête Permissions-Policy.",
    recommendation: "Ajoutez Permissions-Policy: camera=(), microphone=(), geolocation=().",
  },
  {
    id: "cross-origin-isolation",
    category: "headers",
    title: "Isolation entre origines (COOP, CORP, COEP)",
    description:
      "Isole la fenêtre du site des autres origines, ce qui limite les fuites d'informations entre sites (XS-Leaks).",
    references: [REFS.cheatSheets.httpHeadersCoop, REFS.mdn.coop],
    status: "info",
    scoreModifier: 0,
    summary: "Cross-Origin-Opener-Policy est absent.",
    recommendation:
      "Ajoutez Cross-Origin-Opener-Policy: same-origin si le site n'ouvre pas de fenêtres tierces.",
  },
  {
    id: "xss-protection",
    category: "headers",
    title: "X-XSS-Protection (obsolète)",
    description:
      "Ancien filtre anti-XSS des navigateurs, supprimé car il pouvait lui-même créer des failles.",
    references: [REFS.secureHeaders.xssProtection, REFS.mdn.xXssProtection],
    status: "pass",
    scoreModifier: 0,
    summary: "L'en-tête obsolète X-XSS-Protection est absent, comme recommandé.",
    recommendation: null,
  },
  {
    id: "cookies",
    category: "cookies",
    title: "Attributs des cookies",
    description:
      "Vérifie que les cookies sont protégés (Secure, HttpOnly, SameSite) contre l'interception et le vol de session.",
    references: [REFS.cheatSheets.sessionCookies, REFS.asvs["3.3.1"], REFS.mdn.setCookie],
    status: "warning",
    scoreModifier: -5,
    summary: "Le cookie « prefs » n'a pas l'attribut Secure ; HSTS limite le risque.",
    evidence: "prefs=***; Path=/; SameSite=Lax",
    recommendation: "Ajoutez l'attribut Secure à tous les cookies.",
  },
  {
    id: "sri",
    category: "content",
    title: "Subresource Integrity (SRI)",
    description:
      "Vérifie que les scripts chargés depuis d'autres sites portent une empreinte d'intégrité, pour bloquer un fichier modifié.",
    references: [REFS.cheatSheets.thirdPartyJsSri, REFS.mdn.sri],
    status: "pass",
    scoreModifier: 0,
    summary: "La page ne charge aucun script tiers.",
    recommendation: null,
  },
  {
    id: "mixed-content",
    category: "content",
    title: "Contenu mixte",
    description:
      "Vérifie qu'une page servie en HTTPS ne charge pas de ressources en HTTP, qu'un attaquant pourrait modifier.",
    references: [REFS.cheatSheets.tlsMixedContent, REFS.mdn.mixedContent],
    status: "warning",
    scoreModifier: -5,
    summary: "1 ressource passive est chargée en http://.",
    details: ["http://example.com/logo.png (img)"],
    recommendation: "Chargez toutes les ressources en https://.",
  },
  {
    id: "cors",
    category: "content",
    title: "Partage entre origines (CORS)",
    description:
      "Vérifie que le site n'autorise pas n'importe quel autre site à lire ses réponses avec les cookies du visiteur.",
    references: [REFS.cheatSheets.html5Cors, REFS.mdn.cors],
    status: "pass",
    scoreModifier: 0,
    summary: "Aucun en-tête Access-Control-Allow-Origin n'est renvoyé.",
    recommendation: null,
  },
  {
    id: "information-disclosure",
    category: "exposure",
    title: "Divulgation d'informations",
    description:
      "Repère les en-têtes qui révèlent la technologie et la version du serveur, utiles à un attaquant.",
    references: [REFS.secureHeaders.disclosure, REFS.mdn.server],
    status: "info",
    scoreModifier: 0,
    summary: "L'en-tête Server indique la technologie, sans version : nginx.",
    evidence: "Server: nginx",
    recommendation: null,
  },
  {
    id: "security-txt",
    category: "exposure",
    title: "Fichier security.txt",
    description:
      "Le fichier security.txt indique comment signaler une faille de sécurité au propriétaire du site.",
    references: [REFS.cheatSheets.vulnerabilityDisclosure, REFS.rfc.securityTxt],
    status: "info",
    scoreModifier: 0,
    summary: "Aucun fichier security.txt n'a été trouvé.",
    recommendation: "Publiez un fichier /.well-known/security.txt avec Contact et Expires.",
  },
  {
    id: "caa",
    category: "exposure",
    title: "Enregistrements DNS CAA",
    description:
      "Les enregistrements CAA désignent les autorités autorisées à émettre des certificats pour le domaine.",
    references: [REFS.cheatSheets.tlsCaa, REFS.rfc.caa],
    status: "error",
    scoreModifier: 0,
    summary:
      "Impossible de vérifier les enregistrements CAA : la requête DNS a dépassé le délai imparti.",
    recommendation: null,
  },
];

export const sampleReport: ScanReport = {
  schemaVersion: 1,
  scanner: { name: "SecuScan", version: "1.0.0" },
  target: {
    input: "example.com",
    url: "https://example.com/",
    hostname: "example.com",
    finalUrl: "https://example.com/",
    ip: "93.184.215.14",
  },
  scannedAt: "2026-11-15T20:03:00.000Z",
  durationMs: 3200,
  score: { base: 100, penalties: -45, bonuses: 5, bonusesApplied: false, score: 55, grade: "C" },
  summary: { pass: 8, warning: 4, fail: 1, info: 4, error: 1 },
  checks: CHECKS,
  redirects: {
    fromHttp: [
      { url: "http://example.com/", status: 301, location: "https://example.com/" },
      { url: "https://example.com/", status: 200, location: null },
    ],
    fromHttps: [{ url: "https://example.com/", status: 200, location: null }],
  },
  response: {
    status: 200,
    headers: [
      ["Content-Type", "text/html; charset=utf-8"],
      ["Server", "nginx"],
      ["Strict-Transport-Security", "max-age=86400"],
      ["X-Frame-Options", "SAMEORIGIN"],
      ["X-Content-Type-Options", "nosniff"],
      ["Set-Cookie", "prefs=theme-dark-42; Path=/; SameSite=Lax"],
      ["Cache-Control", "max-age=600"],
    ],
  },
  tls: {
    hostname: "example.com",
    address: "93.184.215.14",
    port: 443,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_256_GCM_SHA384",
    alpnProtocol: "h2",
    authorized: true,
    authorizationError: null,
    certificate: {
      subject: "example.com",
      subjectAltNames: ["example.com", "www.example.com"],
      issuer: "Let's Encrypt",
      validFrom: "2026-10-01T00:00:00.000Z",
      validTo: "2026-12-30T00:00:00.000Z",
      daysRemaining: 60,
      serialNumber: "04A1B2C3D4E5F6",
      fingerprint256: "AA:BB:CC:DD",
      keyType: "EC",
      keyBits: 256,
      selfSigned: false,
    },
    chain: [
      { subject: "example.com", issuer: "E7" },
      { subject: "E7", issuer: "ISRG Root X1" },
    ],
    legacyProtocols: { tls10: false, tls11: false },
  },
  probeErrors: [
    { probe: "caa", code: "TIMEOUT", message: "La requête DNS a dépassé le délai imparti." },
  ],
};

export function makeReport(overrides: Partial<ScanReport> = {}): ScanReport {
  return { ...sampleReport, ...overrides };
}

export function sampleCheck(id: CheckId): CheckResult {
  const check = sampleReport.checks.find((candidate) => candidate.id === id);
  if (!check) throw new Error(`Contrôle absent du rapport d'exemple : ${id}`);
  return check;
}
