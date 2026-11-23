// Fetch, « CORS check » : Access-Control-Allow-Origin doit être exactement l'origine de la requête
// (ou `*` sans identifiants), Access-Control-Allow-Credentials exactement « true » (sensible à la
// casse) ; deux valeurs jointes ne correspondent jamais.
import { CORS_PROBE_ORIGIN } from "@/lib/config";
import { REFS } from "../references";
import type { CheckDefinition, CheckOutcome, FixExample, HttpResponse } from "../types";
import { getHeader, probeErrorOutcome, shorten, splitList, truncateEvidence } from "./helpers";

function variesByOrigin(response: HttpResponse): boolean {
  const vary = getHeader(response, "vary");
  return (
    vary !== null &&
    splitList(vary).some((value) => value === "*" || value.toLowerCase() === "origin")
  );
}

function corsEvidence(response: HttpResponse): string | null {
  const names = ["Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Vary"];
  const lines = names.flatMap((name) => {
    const value = getHeader(response, name);
    return value === null ? [] : [`${name}: ${value}`];
  });
  // Vary seul n'a rien de spécifique à CORS : pas de preuve à afficher.
  const hasCorsHeader = lines.some((line) => line.startsWith("Access-Control"));
  return hasCorsHeader ? truncateEvidence(lines.join("\n")) : null;
}

const CORS_EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Dans le bloc http : liste des origines de confiance (comparaison exacte)
map $http_origin $cors_origin {
    default "";
    "https://app.example.com" $http_origin;
}

# Dans le bloc server ou location : un en-tête vide n'est pas envoyé
add_header Access-Control-Allow-Origin $cors_origin always;
add_header Access-Control-Allow-Credentials "true" always;
add_header Vary "Origin" always;`,
  },
  {
    label: "Apache (mod_setenvif et mod_headers)",
    language: "apache",
    code: `# N'autorise que des origines listées (expression ancrée : ni préfixe ni suffixe)
SetEnvIf Origin "^https://(app|admin)\\.example\\.com$" CORS_ORIGIN=$0
Header always set Access-Control-Allow-Origin "%{CORS_ORIGIN}e" env=CORS_ORIGIN
Header always set Access-Control-Allow-Credentials "true" env=CORS_ORIGIN
Header always merge Vary "Origin"`,
  },
  {
    label: "Next.js (next.config.ts)",
    language: "ts",
    code: `import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/api/:path*",
        headers: [
          // Une origine de confiance fixe, jamais l'origine reçue recopiée
          { key: "Access-Control-Allow-Origin", value: "https://app.example.com" },
          { key: "Access-Control-Allow-Credentials", value: "true" },
        ],
      },
    ];
  },
};

export default nextConfig;`,
  },
];

const ALLOWLIST_FIX =
  "Ne recopiez jamais l'origine reçue : comparez-la exactement à une liste d'origines de confiance (ni préfixe, ni suffixe, jamais « null ») avant de la renvoyer, et ajoutez Vary: Origin.";

export const corsCheck: CheckDefinition = {
  id: "cors",
  category: "content",
  title: "Partage entre origines (CORS)",
  description:
    "CORS permet à un serveur d'autoriser d'autres sites à lire ses réponses depuis le navigateur du visiteur. Mal configuré, par exemple en acceptant n'importe quelle origine avec les cookies, il laisse un site malveillant lire des données privées au nom de la victime. SecuScan envoie une requête avec une origine fictive et observe la réponse.",
  references: [
    REFS.cheatSheets.html5Cors,
    REFS.cheatSheets.httpHeadersAcao,
    REFS.top10.A01,
    REFS.asvs["3.4.2"],
    REFS.wstg.CLNT07,
    REFS.mdn.cors,
  ],
  scoring: [
    { outcome: "Sonde en échec", modifier: 0 },
    { outcome: "Pas d'Access-Control-Allow-Origin (ou valeur invalide)", modifier: 0 },
    {
      outcome: "ACAO reflète l'origine sondée et Access-Control-Allow-Credentials: true",
      modifier: -50,
    },
    { outcome: "ACAO null avec credentials", modifier: -50 },
    {
      outcome: "ACAO reflète l'origine sondée (ou vaut null) sans credentials : équivaut à *",
      modifier: 0,
    },
    { outcome: "ACAO * (contenu public ; les credentials sont interdits avec *)", modifier: 0 },
    { outcome: "ACAO limité à une origine précise", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    if (!context.cors.ok) return probeErrorOutcome(context.cors.error, "la politique CORS");
    const response = context.cors.value.response;
    const allowOrigin = getHeader(response, "access-control-allow-origin")?.trim() ?? null;
    const rawCredentials = getHeader(response, "access-control-allow-credentials");
    const credentials = rawCredentials?.trim() === "true";
    const evidence = corsEvidence(response);
    const details = [`Origine de test envoyée : ${CORS_PROBE_ORIGIN}.`];
    if (rawCredentials !== null && !credentials) {
      details.push(
        `Access-Control-Allow-Credentials vaut « ${shorten(rawCredentials)} » : seule la valeur exacte « true » est reconnue, l'en-tête est donc sans effet.`,
      );
    }

    if (allowOrigin === null) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary:
          "Aucun en-tête Access-Control-Allow-Origin : les autres sites ne peuvent pas lire les réponses depuis le navigateur d'un visiteur.",
        details,
        evidence,
        recommendation: null,
      };
    }
    if (allowOrigin.includes(",")) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary:
          "L'en-tête Access-Control-Allow-Origin contient plusieurs valeurs : invalide, il fait refuser tout accès par les navigateurs.",
        details,
        evidence,
        recommendation:
          "N'envoyez qu'un seul en-tête Access-Control-Allow-Origin, avec une seule origine (ou *).",
      };
    }
    if (allowOrigin === "*") {
      if (credentials) {
        details.push(
          "Access-Control-Allow-Credentials: true est ignoré avec * : les navigateurs refusent cette combinaison pour les requêtes avec cookies.",
        );
      }
      details.push(
        "Vérifiez que la ressource ne contient aucune donnée propre à un utilisateur : * la rend lisible par tous les sites.",
      );
      return {
        status: "info",
        scoreModifier: 0,
        summary:
          "Access-Control-Allow-Origin vaut * : le contenu est public, lisible par tous les sites mais sans les cookies du visiteur.",
        details,
        evidence,
        recommendation: null,
      };
    }

    const reflected = allowOrigin === CORS_PROBE_ORIGIN;
    if (reflected && !variesByOrigin(response)) {
      details.push(
        "L'origine est recopiée sans Vary: Origin : un cache partagé pourrait resservir cette réponse à d'autres origines (spécification Fetch, « CORS protocol and HTTP caches »).",
      );
    }
    if ((reflected || allowOrigin === "null") && credentials) {
      return {
        status: "fail",
        scoreModifier: -50,
        summary: reflected
          ? "Le serveur recopie n'importe quelle origine dans Access-Control-Allow-Origin et autorise les cookies : tout site peut lire les réponses destinées au visiteur connecté."
          : "Access-Control-Allow-Origin vaut « null » avec Access-Control-Allow-Credentials: true : n'importe quel site peut obtenir l'origine « null » (iframe sandbox) et lire les réponses du visiteur connecté.",
        details,
        evidence,
        recommendation: ALLOWLIST_FIX,
        examples: CORS_EXAMPLES,
      };
    }
    if (reflected || allowOrigin === "null") {
      return {
        status: "warning",
        scoreModifier: 0,
        summary: reflected
          ? "Le serveur recopie n'importe quelle origine dans Access-Control-Allow-Origin, sans autoriser les cookies : cela équivaut à *."
          : "Access-Control-Allow-Origin vaut « null » : n'importe quel site peut obtenir cette origine (iframe sandbox), cela équivaut à *.",
        details,
        evidence,
        recommendation: `Si le contenu est public, renvoyez simplement * ; sinon, n'autorisez que des origines de confiance. ${ALLOWLIST_FIX}`,
        examples: CORS_EXAMPLES,
      };
    }
    return {
      status: "pass",
      scoreModifier: 0,
      summary: `L'accès entre origines est limité à une origine précise (${shorten(allowOrigin)}), différente de l'origine de test.`,
      details,
      evidence,
      recommendation: null,
    };
  },
};
