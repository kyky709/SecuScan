/**
 * Contrôle « Divulgation d'informations techniques ».
 *
 * Rôle : repérer les en-têtes de réponse qui révèlent le logiciel du serveur, le framework ou
 * leur numéro de version (Server, X-Powered-By, X-AspNet-Version…).
 *
 * Pourquoi : une version précise (« Apache/2.4.41 ») permet à un attaquant de chercher
 * directement les vulnérabilités connues de cette version. Masquer ces informations ne remplace
 * pas les mises à jour (un logiciel s'identifie aussi autrement), mais ne coûte rien.
 *
 * Place dans l'architecture : contrôle pur de la famille « exposure », qui lit la réponse
 * analysée (`context.response`). Le nom d'un hébergeur ou d'un CDN (« Server: cloudflare ») est
 * seulement informatif : il désigne une infrastructure déjà visible par le DNS.
 */
import {
  getHeader,
  notApplicable,
  probeErrorOutcome,
  truncateEvidence,
} from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type { CheckDefinition, CheckOutcome, FixExample } from "@/lib/scanner/types";

/** En-têtes examinés et ce que chacun révèle. */
const DISCLOSURE_HEADERS: ReadonlyArray<{ name: string; reveals: string }> = [
  { name: "Server", reveals: "logiciel du serveur web" },
  { name: "X-Powered-By", reveals: "langage ou framework de l'application" },
  { name: "X-AspNet-Version", reveals: "version d'ASP.NET" },
  { name: "X-AspNetMvc-Version", reveals: "version d'ASP.NET MVC" },
  { name: "X-Generator", reveals: "CMS ou générateur du site" },
  { name: "X-Runtime", reveals: "framework Ruby (Rack, Rails) et durée de traitement" },
  { name: "X-Version", reveals: "version de l'application" },
];

/**
 * Version précise : au moins « majeure.mineure » (2.4.41, 8.1). Une version majeure seule
 * (« Drupal 10 ») renseigne peu : elle ne permet pas de cibler une faille précise.
 *
 * « un chiffre, un point, un chiffre » suffit pour détecter « 2.4.41 ». L'écriture plus intuitive
 * `/\d+\.\d+/` détecte exactement les mêmes valeurs, mais son coût devient quadratique sur une
 * longue suite de chiffres sans point (le moteur réessaie à chaque position) : un en-tête Server
 * piégé de 60 000 chiffres coûtait plus d'une seconde de calcul (ReDoS).
 */
const VERSION_PATTERN = /\d\.\d/;

/** Hébergeurs et CDN courants, reconnus au début de l'en-tête Server. */
const CDN_PATTERN =
  /^(?:cloudflare|vercel|netlify|cloudfront|amazons3|akamaighost|github\.com|google frontend|gws|bunnycdn)/i;

/** Nature de l'information exposée, de la plus à la moins sensible. */
type Exposure = "version" | "technology" | "cdn";

interface Finding {
  name: string;
  value: string;
  reveals: string;
  exposure: Exposure;
}

/** Classe la valeur d'un en-tête. */
function classify(name: string, value: string): Exposure {
  if (name === "Server" && CDN_PATTERN.test(value.trim())) return "cdn";
  // X-Runtime contient une durée en secondes (ex. 0.012345), pas une version : seule sa
  // présence renseigne sur la technologie.
  if (name === "X-Runtime") return "technology";
  return VERSION_PATTERN.test(value) ? "version" : "technology";
}

/** Phrase de détail pour un en-tête observé. */
function describeFinding(finding: Finding): string {
  const shown = `${finding.name} : « ${truncateEvidence(finding.value, 100)} »`;
  switch (finding.exposure) {
    case "version":
      return `${shown}, version précise exposée (${finding.reveals}).`;
    case "technology":
      return `${shown}, technologie exposée sans version précise (${finding.reveals}).`;
    case "cdn":
      return `${shown} désigne l'hébergeur ou le CDN, une information publique : aucune action nécessaire.`;
  }
}

/** Liste lisible de noms d'en-têtes : « Server », « Server et X-Powered-By »… */
function listNames(findings: readonly Finding[]): string {
  const names = findings.map((finding) => finding.name);
  const last = names.pop();
  return names.length === 0 ? (last ?? "") : `${names.join(", ")} et ${last}`;
}

/** Exemples pour masquer les versions et supprimer les en-têtes superflus. */
const EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Masque la version de Nginx (en-tête Server et pages d'erreur)
server_tokens off;
# Retire X-Powered-By ajouté par l'application (proxy ou PHP-FPM)
proxy_hide_header X-Powered-By;
fastcgi_hide_header X-Powered-By;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# Configuration principale (httpd.conf), pas dans un .htaccess
ServerTokens Prod
ServerSignature Off
# Module mod_headers : les deux tables (réponses réussies et autres)
Header unset X-Powered-By
Header always unset X-Powered-By`,
  },
  {
    label: "Next.js (next.config.ts)",
    language: "ts",
    code: `import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Supprime l'en-tête « X-Powered-By: Next.js »
  poweredByHeader: false,
};

export default nextConfig;`,
  },
  {
    label: "Express (Node.js)",
    language: "js",
    code: `// Supprime l'en-tête « X-Powered-By: Express »
app.disable("x-powered-by");`,
  },
  {
    label: "PHP (php.ini)",
    language: "ini",
    code: `; Supprime l'en-tête « X-Powered-By: PHP/… »
expose_php = Off`,
  },
  {
    label: "IIS / ASP.NET (web.config)",
    language: "xml",
    code: `<configuration>
  <system.web>
    <!-- Supprime X-AspNet-Version -->
    <httpRuntime enableVersionHeader="false" />
  </system.web>
  <system.webServer>
    <!-- IIS 10 et plus : supprime l'en-tête Server -->
    <security>
      <requestFiltering removeServerHeader="true" />
    </security>
    <httpProtocol>
      <customHeaders>
        <remove name="X-Powered-By" />
      </customHeaders>
    </httpProtocol>
  </system.webServer>
</configuration>`,
  },
];

/** Rappel ajouté dès qu'une technologie est exposée. */
const PATCH_REMINDER =
  "Masquer ces informations ne remplace pas les mises à jour : un attaquant peut identifier un logiciel autrement (OWASP WSTG-INFO-02).";

/** Contrôle des en-têtes qui divulguent la technologie du serveur. */
export const informationDisclosureCheck: CheckDefinition = {
  id: "information-disclosure",
  category: "exposure",
  title: "Divulgation d'informations techniques",
  description:
    "Certains en-têtes (Server, X-Powered-By, X-AspNet-Version…) annoncent le logiciel du serveur, le framework et parfois leur version exacte. Une version précise permet à un attaquant de chercher directement les failles connues de ce logiciel. Les retirer ne remplace pas les mises à jour, mais rend la reconnaissance plus difficile.",
  references: [
    REFS.cheatSheets.httpHeadersServer,
    REFS.cheatSheets.httpHeadersPoweredBy,
    REFS.secureHeaders.disclosure,
    REFS.top10.A02,
    REFS.asvs["13.4.6"],
    REFS.wstg.INFO02,
    REFS.wstg.INFO08,
    REFS.mdn.server,
    REFS.mdn.xPoweredBy,
  ],
  scoring: [
    { outcome: "Version logicielle exposée (ex. Apache/2.4.41, PHP/8.1)", modifier: -5 },
    {
      outcome: "Technologie exposée sans version (ex. Server: nginx, X-Powered-By: Express)",
      modifier: 0,
    },
    { outcome: "Seul l'hébergeur ou le CDN est nommé (ex. Server: cloudflare)", modifier: 0 },
    { outcome: "Rien d'exposé", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    const response = context.response;
    if (!response) {
      return context.https.ok
        ? notApplicable("Aucune réponse à analyser.")
        : probeErrorOutcome(context.https.error, "les en-têtes de la réponse");
    }

    const findings: Finding[] = DISCLOSURE_HEADERS.flatMap(({ name, reveals }) => {
      const value = getHeader(response, name);
      // Un en-tête vide ne révèle rien.
      if (value === null || value.trim() === "") return [];
      return [{ name, value, reveals, exposure: classify(name, value) }];
    });
    if (findings.length === 0) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary: "Aucun en-tête ne révèle la technologie ou la version du serveur.",
        recommendation: null,
      };
    }

    const details = findings.map(describeFinding);
    const evidence = truncateEvidence(findings.map((f) => `${f.name}: ${f.value}`).join("\n"));
    const versions = findings.filter((f) => f.exposure === "version");
    const technologies = findings.filter((f) => f.exposure === "technology");

    if (versions.length > 0) {
      return {
        status: "warning",
        scoreModifier: -5,
        summary:
          versions.length > 1
            ? `Les en-têtes ${listNames(versions)} révèlent des versions logicielles précises.`
            : `L'en-tête ${listNames(versions)} révèle une version logicielle précise.`,
        details: [...details, PATCH_REMINDER],
        evidence,
        recommendation:
          "Supprimez les en-têtes qui détaillent la technologie (X-Powered-By, X-AspNet-Version…) et réduisez Server au nom du logiciel, sans version (server_tokens off avec Nginx, ServerTokens Prod avec Apache) ; surtout, maintenez vos logiciels à jour.",
        examples: EXAMPLES,
      };
    }

    if (technologies.length > 0) {
      return {
        status: "info",
        scoreModifier: 0,
        summary:
          technologies.length > 1
            ? `Les en-têtes ${listNames(technologies)} révèlent la technologie utilisée, sans version précise.`
            : `L'en-tête ${listNames(technologies)} révèle la technologie utilisée, sans version précise.`,
        details: [...details, PATCH_REMINDER],
        evidence,
        recommendation:
          "Facultatif : supprimez ces en-têtes (le gain est limité, ils facilitent seulement l'identification de la technologie) ; l'essentiel est de maintenir vos logiciels à jour.",
        examples: EXAMPLES,
      };
    }

    return {
      status: "info",
      scoreModifier: 0,
      summary:
        "Seul le nom de l'hébergeur ou du CDN est visible : c'est une information publique, sans risque.",
      details,
      evidence,
      recommendation: null,
    };
  },
};
