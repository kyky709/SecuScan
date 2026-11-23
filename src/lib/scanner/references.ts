/**
 * Catalogue des références documentaires citées par les contrôles.
 *
 * Chaque recommandation de SecuScan s'appuie sur une source reconnue, OWASP en priorité :
 * - OWASP Top 10:2025 : les dix grandes familles de risques des applications web ;
 * - OWASP ASVS 5.0.0 : exigences de vérification précises (format de citation officiel « v5.0.0-3.4.1 ») ;
 * - OWASP Cheat Sheet Series : guides pratiques de mise en œuvre ;
 * - OWASP WSTG : guide de test (v4.2 stable ; version « latest » pour les tests absents de la v4.2) ;
 * - OWASP Secure Headers Project : valeurs d'en-têtes recommandées ;
 * - MDN, RFC et sites de référence pour le détail technique.
 *
 * Toutes les URL ont été vérifiées le 2026-11-15 (pages et ancres). Centraliser les liens ici
 * évite les doublons et facilite leur mise à jour lors d'une nouvelle édition d'un référentiel.
 */
import type { Reference, ReferenceKind } from "./types";

/** Construit une référence. */
function ref(kind: ReferenceKind, label: string, url: string): Reference {
  return { kind, label, url };
}

const TOP10 = "https://owasp.org/Top10/2025";
const ASVS = "https://github.com/OWASP/ASVS/blob/v5.0.0_release/5.0/en";
const CS = "https://cheatsheetseries.owasp.org/cheatsheets";
const WSTG = "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing";
const WSTG_LATEST = "https://wstg.owasp.org/latest/4-Web_Application_Security_Testing";
const MDN = "https://developer.mozilla.org/en-US/docs/Web";
const MDN_HEADERS = `${MDN}/HTTP/Reference/Headers`;

/** Chapitres de l'ASVS 5.0.0 (fichiers sources officiels sur GitHub). */
const ASVS_V3_COOKIES = `${ASVS}/0x12-V3-Web-Frontend-Security.md#v33-cookie-setup`;
const ASVS_V3_HEADERS = `${ASVS}/0x12-V3-Web-Frontend-Security.md#v34-browser-security-mechanism-headers`;
const ASVS_V3_INTEGRITY = `${ASVS}/0x12-V3-Web-Frontend-Security.md#v36-external-resource-integrity`;
const ASVS_V3_OTHER = `${ASVS}/0x12-V3-Web-Frontend-Security.md#v37-other-browser-security-considerations`;
const ASVS_V12_TLS = `${ASVS}/0x21-V12-Secure-Communication.md#v121-general-tls-security-guidance`;
const ASVS_V12_HTTPS = `${ASVS}/0x21-V12-Secure-Communication.md#v122-https-communication-with-external-facing-services`;
const ASVS_V13_LEAKAGE = `${ASVS}/0x22-V13-Configuration.md#v134-unintended-information-leakage`;
const ASVS_APPENDIX_D = `${ASVS}/0x93-Appendix-D_Recommendations.md#recommended-in-scope-mechanisms`;

export const REFS = {
  /** OWASP Top 10:2025 (édition finale). */
  top10: {
    A01: ref(
      "owasp-top10",
      "OWASP Top 10:2025 – A01 Broken Access Control",
      `${TOP10}/A01_2025-Broken_Access_Control/`,
    ),
    A02: ref(
      "owasp-top10",
      "OWASP Top 10:2025 – A02 Security Misconfiguration",
      `${TOP10}/A02_2025-Security_Misconfiguration/`,
    ),
    A03: ref(
      "owasp-top10",
      "OWASP Top 10:2025 – A03 Software Supply Chain Failures",
      `${TOP10}/A03_2025-Software_Supply_Chain_Failures/`,
    ),
    A04: ref(
      "owasp-top10",
      "OWASP Top 10:2025 – A04 Cryptographic Failures",
      `${TOP10}/A04_2025-Cryptographic_Failures/`,
    ),
    A05: ref("owasp-top10", "OWASP Top 10:2025 – A05 Injection", `${TOP10}/A05_2025-Injection/`),
    A08: ref(
      "owasp-top10",
      "OWASP Top 10:2025 – A08 Software or Data Integrity Failures",
      `${TOP10}/A08_2025-Software_or_Data_Integrity_Failures/`,
    ),
  },

  /** OWASP ASVS 5.0.0 : exigences citées au format officiel « v5.0.0-<id> ». */
  asvs: {
    "3.3.1": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.3.1 – Attribut Secure et préfixe __Secure-/__Host- des cookies",
      ASVS_V3_COOKIES,
    ),
    "3.3.2": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.3.2 – Attribut SameSite adapté à l'usage du cookie",
      ASVS_V3_COOKIES,
    ),
    "3.3.3": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.3.3 – Préfixe __Host- par défaut",
      ASVS_V3_COOKIES,
    ),
    "3.3.4": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.3.4 – Attribut HttpOnly pour les jetons de session",
      ASVS_V3_COOKIES,
    ),
    "3.4.1": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.1 – Strict-Transport-Security d'au moins un an",
      ASVS_V3_HEADERS,
    ),
    "3.4.2": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.2 – Access-Control-Allow-Origin fixe ou liste d'origines autorisées",
      ASVS_V3_HEADERS,
    ),
    "3.4.3": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.3 – Content-Security-Policy (au minimum object-src 'none' et base-uri 'none')",
      ASVS_V3_HEADERS,
    ),
    "3.4.4": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.4 – X-Content-Type-Options: nosniff",
      ASVS_V3_HEADERS,
    ),
    "3.4.5": ref("owasp-asvs", "OWASP ASVS v5.0.0-3.4.5 – Referrer-Policy", ASVS_V3_HEADERS),
    "3.4.6": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.6 – Directive CSP frame-ancestors",
      ASVS_V3_HEADERS,
    ),
    "3.4.8": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.4.8 – Cross-Origin-Opener-Policy",
      ASVS_V3_HEADERS,
    ),
    "3.6.1": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.6.1 – Intégrité des ressources externes (SRI)",
      ASVS_V3_INTEGRITY,
    ),
    "3.7.4": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-3.7.4 – Domaine inscrit sur la liste de préchargement HSTS",
      ASVS_V3_OTHER,
    ),
    "12.1.1": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-12.1.1 – Seules les versions récentes de TLS (1.2, 1.3)",
      ASVS_V12_TLS,
    ),
    "12.2.1": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-12.2.1 – TLS pour toutes les connexions, sans repli en clair",
      ASVS_V12_HTTPS,
    ),
    "12.2.2": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-12.2.2 – Certificats TLS publiquement reconnus",
      ASVS_V12_HTTPS,
    ),
    "13.4.6": ref(
      "owasp-asvs",
      "OWASP ASVS v5.0.0-13.4.6 – Pas de version détaillée des composants exposée",
      ASVS_V13_LEAKAGE,
    ),
    appendixD: ref(
      "owasp-asvs",
      "OWASP ASVS 5.0.0 – Annexe D : publier un fichier security.txt (recommandation)",
      ASVS_APPENDIX_D,
    ),
  },

  /** OWASP Cheat Sheet Series. */
  cheatSheets: {
    httpHeaders: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Security Response Headers Cheat Sheet",
      `${CS}/HTTP_Headers_Cheat_Sheet.html`,
    ),
    httpHeadersHsts: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Strict-Transport-Security",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#strict-transport-security-hsts`,
    ),
    httpHeadersCsp: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Content-Security-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#content-security-policy-csp`,
    ),
    httpHeadersXfo: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : X-Frame-Options",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#x-frame-options`,
    ),
    httpHeadersXcto: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : X-Content-Type-Options",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#x-content-type-options`,
    ),
    httpHeadersReferrer: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Referrer-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#referrer-policy`,
    ),
    httpHeadersPermissions: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Permissions-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#permissions-policy-formerly-feature-policy`,
    ),
    httpHeadersCoop: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Cross-Origin-Opener-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#cross-origin-opener-policy-coop`,
    ),
    httpHeadersCoep: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Cross-Origin-Embedder-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#cross-origin-embedder-policy-coep`,
    ),
    httpHeadersCorp: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Cross-Origin-Resource-Policy",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#cross-origin-resource-policy-corp`,
    ),
    httpHeadersXxp: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : X-XSS-Protection",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#x-xss-protection`,
    ),
    httpHeadersAcao: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Access-Control-Allow-Origin",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#access-control-allow-origin`,
    ),
    httpHeadersServer: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : Server",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#server`,
    ),
    httpHeadersPoweredBy: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Headers Cheat Sheet : X-Powered-By",
      `${CS}/HTTP_Headers_Cheat_Sheet.html#x-powered-by`,
    ),
    hsts: ref(
      "owasp-cheatsheet",
      "OWASP – HTTP Strict Transport Security Cheat Sheet",
      `${CS}/HTTP_Strict_Transport_Security_Cheat_Sheet.html`,
    ),
    csp: ref(
      "owasp-cheatsheet",
      "OWASP – Content Security Policy Cheat Sheet",
      `${CS}/Content_Security_Policy_Cheat_Sheet.html`,
    ),
    cspFraming: ref(
      "owasp-cheatsheet",
      "OWASP – CSP Cheat Sheet : se protéger du clickjacking",
      `${CS}/Content_Security_Policy_Cheat_Sheet.html#preventing-framing-attacks-clickjacking-cross-site-leaks`,
    ),
    cspUpgrade: ref(
      "owasp-cheatsheet",
      "OWASP – CSP Cheat Sheet : upgrade-insecure-requests",
      `${CS}/Content_Security_Policy_Cheat_Sheet.html#upgrading-insecure-requests`,
    ),
    clickjacking: ref(
      "owasp-cheatsheet",
      "OWASP – Clickjacking Defense Cheat Sheet",
      `${CS}/Clickjacking_Defense_Cheat_Sheet.html`,
    ),
    tlsAllPages: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : TLS sur toutes les pages",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#use-tls-for-all-pages`,
    ),
    tlsCertificates: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : certificats",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#certificates`,
    ),
    tlsProtocols: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : protocoles robustes uniquement",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#only-support-strong-protocols`,
    ),
    tlsMixedContent: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : ne pas mélanger contenu TLS et non TLS",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#do-not-mix-tls-and-non-tls-content`,
    ),
    tlsSecureCookies: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : cookies sécurisés",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#use-secure-cookies`,
    ),
    tlsCaa: ref(
      "owasp-cheatsheet",
      "OWASP – Transport Layer Security Cheat Sheet : enregistrements CAA",
      `${CS}/Transport_Layer_Security_Cheat_Sheet.html#use-caa-records-to-restrict-which-cas-can-issue-certificates`,
    ),
    sessionCookies: ref(
      "owasp-cheatsheet",
      "OWASP – Session Management Cheat Sheet : cookies",
      `${CS}/Session_Management_Cheat_Sheet.html#cookies`,
    ),
    csrfSameSite: ref(
      "owasp-cheatsheet",
      "OWASP – CSRF Prevention Cheat Sheet : attribut SameSite",
      `${CS}/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#samesite-cookie-attribute`,
    ),
    html5Cors: ref(
      "owasp-cheatsheet",
      "OWASP – HTML5 Security Cheat Sheet : Cross-Origin Resource Sharing",
      `${CS}/HTML5_Security_Cheat_Sheet.html#cross-origin-resource-sharing`,
    ),
    thirdPartyJsSri: ref(
      "owasp-cheatsheet",
      "OWASP – Third Party JavaScript Management Cheat Sheet : Subresource Integrity",
      `${CS}/Third_Party_Javascript_Management_Cheat_Sheet.html#subresource-integrity`,
    ),
    xsLeaksCoop: ref(
      "owasp-cheatsheet",
      "OWASP – Cross-site leaks Cheat Sheet : COOP",
      `${CS}/XS_Leaks_Cheat_Sheet.html#cross-origin-opener-policy-coop`,
    ),
    vulnerabilityDisclosure: ref(
      "owasp-cheatsheet",
      "OWASP – Vulnerability Disclosure Cheat Sheet : publier ses coordonnées",
      `${CS}/Vulnerability_Disclosure_Cheat_Sheet.html#publishing-contact-details`,
    ),
    ssrf: ref(
      "owasp-cheatsheet",
      "OWASP – Server-Side Request Forgery Prevention Cheat Sheet",
      `${CS}/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html`,
    ),
  },

  /** OWASP Web Security Testing Guide. */
  wstg: {
    CRYP01Redirect: ref(
      "owasp-wstg",
      "OWASP WSTG-CRYP-01 – Redirection de HTTP vers HTTPS",
      `${WSTG}/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/#redirecting-from-http-to-https`,
    ),
    CRYP01Certificates: ref(
      "owasp-wstg",
      "OWASP WSTG-CRYP-01 – Certificats numériques",
      `${WSTG}/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/#digital-certificates`,
    ),
    CRYP01Server: ref(
      "owasp-wstg",
      "OWASP WSTG-CRYP-01 – Configuration TLS du serveur",
      `${WSTG}/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/#server-configuration`,
    ),
    CRYP01MixedContent: ref(
      "owasp-wstg",
      "OWASP WSTG-CRYP-01 – Contenu actif mixte",
      `${WSTG}/09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security/#mixed-active-content`,
    ),
    CONF07: ref(
      "owasp-wstg",
      "OWASP WSTG-CONF-07 – Test HTTP Strict Transport Security",
      `${WSTG}/02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security/`,
    ),
    CONF12: ref(
      "owasp-wstg",
      "OWASP WSTG-CONF-12 – Content Security Policy",
      `${WSTG_LATEST}/02-Configuration_and_Deployment_Management/12-Content_Security_Policy/`,
    ),
    CONF14: ref(
      "owasp-wstg",
      "OWASP WSTG-CONF-14 – Autres erreurs de configuration des en-têtes de sécurité",
      `${WSTG_LATEST}/02-Configuration_and_Deployment_Management/14-Other_HTTP_Security_Header_Misconfigurations/`,
    ),
    CLNT07: ref(
      "owasp-wstg",
      "OWASP WSTG-CLNT-07 – Testing Cross Origin Resource Sharing",
      `${WSTG}/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing/`,
    ),
    CLNT09: ref(
      "owasp-wstg",
      "OWASP WSTG-CLNT-09 – Testing for Clickjacking",
      `${WSTG}/11-Client-side_Testing/09-Testing_for_Clickjacking/`,
    ),
    SESS02: ref(
      "owasp-wstg",
      "OWASP WSTG-SESS-02 – Testing for Cookies Attributes",
      `${WSTG}/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes/`,
    ),
    INFO02: ref(
      "owasp-wstg",
      "OWASP WSTG-INFO-02 – Fingerprint Web Server",
      `${WSTG}/01-Information_Gathering/02-Fingerprint_Web_Server/`,
    ),
    INFO03: ref(
      "owasp-wstg",
      "OWASP WSTG-INFO-03 – Fichiers de métadonnées du serveur (security.txt)",
      `${WSTG}/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage/#security-txt`,
    ),
    INFO08: ref(
      "owasp-wstg",
      "OWASP WSTG-INFO-08 – Fingerprint Web Application Framework",
      `${WSTG}/01-Information_Gathering/08-Fingerprint_Web_Application_Framework/`,
    ),
  },

  /** OWASP Secure Headers Project. */
  secureHeaders: {
    configuration: ref(
      "owasp-secure-headers",
      "OWASP Secure Headers Project – Configuration recommandée",
      "https://secure-headers-project.owasp.org/best-practices/#configuration-proposal",
    ),
    disclosure: ref(
      "owasp-secure-headers",
      "OWASP Secure Headers Project – En-têtes à supprimer (divulgation d'informations)",
      "https://secure-headers-project.owasp.org/best-practices/#prevent-information-disclosure-via-http-headers",
    ),
    xssProtection: ref(
      "owasp-secure-headers",
      "OWASP Secure Headers Project – X-XSS-Protection (obsolète)",
      "https://secure-headers-project.owasp.org/response-headers/#x-xss-protection",
    ),
  },

  /** Documentation MDN. */
  mdn: {
    hsts: ref("mdn", "MDN – Strict-Transport-Security", `${MDN_HEADERS}/Strict-Transport-Security`),
    csp: ref("mdn", "MDN – Content-Security-Policy", `${MDN_HEADERS}/Content-Security-Policy`),
    frameAncestors: ref(
      "mdn",
      "MDN – CSP : frame-ancestors",
      `${MDN_HEADERS}/Content-Security-Policy/frame-ancestors`,
    ),
    xFrameOptions: ref("mdn", "MDN – X-Frame-Options", `${MDN_HEADERS}/X-Frame-Options`),
    clickjacking: ref("mdn", "MDN – Clickjacking", `${MDN}/Security/Attacks/Clickjacking`),
    xContentTypeOptions: ref(
      "mdn",
      "MDN – X-Content-Type-Options",
      `${MDN_HEADERS}/X-Content-Type-Options`,
    ),
    referrerPolicy: ref("mdn", "MDN – Referrer-Policy", `${MDN_HEADERS}/Referrer-Policy`),
    permissionsPolicy: ref("mdn", "MDN – Permissions-Policy", `${MDN_HEADERS}/Permissions-Policy`),
    coop: ref(
      "mdn",
      "MDN – Cross-Origin-Opener-Policy",
      `${MDN_HEADERS}/Cross-Origin-Opener-Policy`,
    ),
    coep: ref(
      "mdn",
      "MDN – Cross-Origin-Embedder-Policy",
      `${MDN_HEADERS}/Cross-Origin-Embedder-Policy`,
    ),
    corp: ref(
      "mdn",
      "MDN – Cross-Origin-Resource-Policy",
      `${MDN_HEADERS}/Cross-Origin-Resource-Policy`,
    ),
    xXssProtection: ref("mdn", "MDN – X-XSS-Protection", `${MDN_HEADERS}/X-XSS-Protection`),
    setCookie: ref("mdn", "MDN – Set-Cookie", `${MDN_HEADERS}/Set-Cookie`),
    cookies: ref("mdn", "MDN – Utiliser les cookies HTTP", `${MDN}/HTTP/Guides/Cookies`),
    cors: ref("mdn", "MDN – Cross-Origin Resource Sharing (CORS)", `${MDN}/HTTP/Guides/CORS`),
    sri: ref(
      "mdn",
      "MDN – Subresource Integrity",
      `${MDN}/Security/Defenses/Subresource_Integrity`,
    ),
    mixedContent: ref("mdn", "MDN – Contenu mixte", `${MDN}/Security/Mixed_content`),
    tls: ref(
      "mdn",
      "MDN – Guide pratique : configuration TLS",
      `${MDN}/Security/Practical_implementation_guides/TLS`,
    ),
    server: ref("mdn", "MDN – Server", `${MDN_HEADERS}/Server`),
    xPoweredBy: ref("mdn", "MDN – X-Powered-By", `${MDN_HEADERS}/X-Powered-By`),
    observatoryScoring: ref(
      "mdn",
      "MDN HTTP Observatory – Tests et notation",
      "https://developer.mozilla.org/en-US/observatory/docs/tests_and_scoring",
    ),
  },

  /** Normes de l'IETF. */
  rfc: {
    hsts: ref(
      "rfc",
      "RFC 6797 – HTTP Strict Transport Security",
      "https://www.rfc-editor.org/rfc/rfc6797",
    ),
    deprecateTls: ref(
      "rfc",
      "RFC 8996 – Abandon de TLS 1.0 et TLS 1.1",
      "https://www.rfc-editor.org/rfc/rfc8996",
    ),
    caa: ref(
      "rfc",
      "RFC 8659 – DNS Certification Authority Authorization (CAA)",
      "https://www.rfc-editor.org/rfc/rfc8659",
    ),
    securityTxt: ref("rfc", "RFC 9116 – security.txt", "https://www.rfc-editor.org/rfc/rfc9116"),
    xFrameOptions: ref(
      "rfc",
      "RFC 7034 – X-Frame-Options",
      "https://www.rfc-editor.org/rfc/rfc7034",
    ),
  },

  /** Autres ressources de référence. */
  other: {
    hstsPreload: ref(
      "other",
      "hstspreload.org – Liste de préchargement HSTS des navigateurs",
      "https://hstspreload.org/",
    ),
    securityTxt: ref(
      "other",
      "securitytxt.org – Générateur de fichier security.txt",
      "https://securitytxt.org/",
    ),
    strictCsp: ref(
      "other",
      "web.dev – Mitigate XSS with a strict CSP",
      "https://web.dev/articles/strict-csp",
    ),
  },
} as const;
