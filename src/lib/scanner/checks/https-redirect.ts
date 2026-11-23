// Grille reprise du test « redirection » de MDN HTTP Observatory. La première redirection doit
// rester sur le même hôte pour que le navigateur puisse y enregistrer HSTS.
import { getHeader, probeErrorOutcome, truncateEvidence } from "@/lib/scanner/checks/helpers";
import { REFS } from "@/lib/scanner/references";
import type {
  CheckDefinition,
  CheckOutcome,
  FixExample,
  HttpResponse,
  NetworkError,
  NetworkErrorCode,
} from "@/lib/scanner/types";

const REDIRECT_STATUSES: ReadonlySet<number> = new Set([301, 302, 303, 307, 308]);

const PERMANENT_STATUSES: ReadonlySet<number> = new Set([301, 308]);

const REDIRECT_ERROR_CODES: ReadonlySet<NetworkErrorCode> = new Set([
  "INVALID_REDIRECT",
  "TOO_MANY_REDIRECTS",
]);

/** Élément suivant de la chaîne, sinon Location (chaîne interrompue par une erreur). */
function nextHopUrl(chain: readonly HttpResponse[], index: number): string | null {
  const next = chain[index + 1];
  if (next) return next.url;
  const response = chain[index];
  const location = getHeader(response, "location");
  if (!response || location === null) return null;
  try {
    return new URL(location, response.url).href;
  } catch {
    return null;
  }
}

function isRedirect(chain: readonly HttpResponse[], index: number): boolean {
  const response = chain[index];
  return (
    response !== undefined &&
    REDIRECT_STATUSES.has(response.status) &&
    nextHopUrl(chain, index) !== null
  );
}

function hostnameOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** « http://a/ (301) → https://a/ (200) ». */
function describeChain(chain: readonly HttpResponse[]): string {
  const steps = chain.map((response) => `${response.url} (${response.status})`);
  // Chaîne interrompue : on montre aussi la destination annoncée mais jamais atteinte.
  const lastIndex = chain.length - 1;
  const pending = isRedirect(chain, lastIndex) ? nextHopUrl(chain, lastIndex) : null;
  if (pending !== null && chain[lastIndex + 1] === undefined) steps.push(pending);
  return truncateEvidence(steps.join(" → "));
}

function redirectDetails(chain: readonly HttpResponse[]): string[] {
  const redirects = chain.filter((_, index) => isRedirect(chain, index));
  const count = redirects.length;
  const details = [`La chaîne compte ${count} redirection${count > 1 ? "s" : ""}.`];
  const temporary = [
    ...new Set(redirects.filter((r) => !PERMANENT_STATUSES.has(r.status)).map((r) => r.status)),
  ];
  if (temporary.length > 0) {
    details.push(
      `Redirection temporaire (code ${temporary.join(", ")}) : préférez 301 ou 308 (permanentes), que le navigateur peut mémoriser.`,
    );
  } else if (count > 0) {
    details.push("Les redirections sont permanentes (301 ou 308) : c'est le bon choix.");
  }
  return details;
}

function redirectExamples(hostname: string): FixExample[] {
  return [
    {
      label: "Nginx",
      language: "nginx",
      code: `server {
    listen 80;
    listen [::]:80;
    server_name ${hostname};
    # Redirection permanente vers HTTPS, même hôte, même chemin
    return 301 https://$host$request_uri;
}`,
    },
    {
      label: "Apache",
      language: "apache",
      code: `<VirtualHost *:80>
    ServerName ${hostname}
    # Redirection permanente vers HTTPS, même hôte, même chemin (mod_rewrite)
    RewriteEngine On
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</VirtualHost>`,
    },
    {
      label: "Next.js (next.config.ts)",
      language: "ts",
      code: `import type { NextConfig } from "next";

// Inutile sur Vercel, qui redirige déjà HTTP vers HTTPS.
// Derrière un proxy qui termine TLS, x-forwarded-proto indique le schéma d'origine.
const nextConfig: NextConfig = {
  async redirects() {
    return [
      {
        source: "/:path*",
        has: [{ type: "header", key: "x-forwarded-proto", value: "http" }],
        destination: "https://${hostname}/:path*",
        permanent: true, // code 308
      },
    ];
  },
};

export default nextConfig;`,
    },
  ];
}

function evaluateHttpUnreachable(error: NetworkError, httpsOk: boolean): CheckOutcome {
  // Sans HTTPS ni HTTP, on ne peut rien conclure (le scan est normalement interrompu avant).
  if (!httpsOk) return probeErrorOutcome(error, "la redirection de HTTP vers HTTPS");
  return {
    status: "pass",
    scoreModifier: 0,
    summary:
      "Le site ne répond pas en HTTP clair (port 80 fermé ou filtré) : aucune redirection n'est nécessaire.",
    details: [`Sonde HTTP : ${error.message}`],
    recommendation: null,
  };
}

/** Chaîne éventuellement partielle. Seule la première redirection compte pour HSTS. */
function evaluateChain(
  chain: readonly HttpResponse[],
  interruption: NetworkError | null,
  hostname: string,
): CheckOutcome {
  const examples = redirectExamples(hostname);
  const evidence = describeChain(chain);
  const first = chain[0];
  const firstHop = nextHopUrl(chain, 0);

  if (!first || firstHop === null || !isRedirect(chain, 0)) {
    return {
      status: "fail",
      scoreModifier: -20,
      summary: `Le site sert son contenu en HTTP clair (statut ${first?.status ?? "inconnu"}) au lieu de rediriger vers HTTPS.`,
      evidence,
      recommendation:
        "Redirigez toutes les requêtes HTTP vers la même adresse en HTTPS avec une redirection permanente (301 ou 308).",
      examples,
    };
  }

  const details = redirectDetails(chain);
  if (interruption) {
    details.push(
      `La suite de la chaîne n'a pas pu être suivie (${interruption.message}) : l'analyse porte sur la première redirection.`,
    );
  }

  const last = chain[chain.length - 1];
  // Une chaîne interrompue n'a pas de destination finale connue : on ne juge que la 1re étape.
  if (interruption === null && last?.url.startsWith("http:")) {
    return {
      status: "fail",
      scoreModifier: -20,
      summary: "Les redirections depuis HTTP n'aboutissent jamais à une adresse HTTPS.",
      details,
      evidence,
      recommendation:
        "Faites aboutir la chaîne sur une adresse https:// : la première redirection doit mener à la même adresse en HTTPS.",
      examples,
    };
  }

  const fromHost = hostnameOf(first.url);
  const toHost = hostnameOf(firstHop);
  if (firstHop.startsWith("http:")) {
    return {
      status: "warning",
      scoreModifier: -10,
      summary: `La première redirection mène à une autre adresse en HTTP clair (${toHost ?? firstHop}) avant d'atteindre HTTPS.`,
      details,
      evidence,
      recommendation: `Redirigez d'abord vers https://${fromHost ?? hostname}/ (même hôte), puis seulement ensuite vers l'hôte canonique : aucune étape ne doit passer en HTTP clair.`,
      examples,
    };
  }

  if (fromHost !== toHost) {
    return {
      status: "warning",
      scoreModifier: -5,
      summary: `HTTP redirige vers HTTPS, mais sur un autre hôte (${toHost ?? firstHop}) : HSTS ne peut pas être activé pour ${fromHost ?? hostname}.`,
      details,
      evidence,
      recommendation: `Redirigez d'abord vers https://${fromHost ?? hostname}/ (même hôte) qui enverra l'en-tête HSTS, puis vers ${toHost ?? "l'hôte canonique"} : sinon ${fromHost ?? hostname} reste exposé en HTTP à chaque visite.`,
      examples,
    };
  }

  const temporary = !PERMANENT_STATUSES.has(first.status);
  return {
    status: "pass",
    scoreModifier: 0,
    summary: `HTTP redirige directement vers HTTPS sur le même hôte (code ${first.status}).`,
    details,
    evidence,
    recommendation: temporary
      ? "Remplacez la redirection temporaire par une redirection permanente (301 ou 308)."
      : null,
    examples: temporary ? examples : undefined,
  };
}

export const httpsRedirectCheck: CheckDefinition = {
  id: "https-redirect",
  category: "transport",
  title: "Redirection HTTP → HTTPS",
  description:
    "Un visiteur qui saisit l'adresse sans « https:// » arrive d'abord en HTTP clair, que n'importe quel intermédiaire du réseau peut lire ou modifier. Le site doit le rediriger aussitôt vers HTTPS, sur le même hôte, avec une redirection permanente. C'est aussi la condition pour que le navigateur enregistre HSTS pour cet hôte.",
  references: [
    REFS.cheatSheets.tlsAllPages,
    REFS.top10.A04,
    REFS.asvs["12.2.1"],
    REFS.wstg.CRYP01Redirect,
    REFS.mdn.tls,
    REFS.mdn.observatoryScoring,
  ],
  scoring: [
    { outcome: "HTTP injoignable (port 80 fermé) alors que HTTPS répond", modifier: 0 },
    { outcome: "HTTPS indisponible alors que HTTP répond", modifier: -20 },
    { outcome: "Contenu servi en HTTP clair, sans redirection", modifier: -20 },
    { outcome: "Redirection invalide ou trop de redirections", modifier: -20 },
    { outcome: "La chaîne de redirections se termine en HTTP", modifier: -20 },
    { outcome: "Première redirection vers une autre adresse en HTTP", modifier: -10 },
    { outcome: "Première redirection vers HTTPS sur un autre hôte", modifier: -5 },
    { outcome: "Première redirection vers HTTPS sur le même hôte", modifier: 0 },
  ],
  evaluate(context) {
    const { http, https } = context;
    const hostname = context.target.hostname;
    const partialChain = http.ok ? http.value.chain : (http.error.chain ?? []);

    if (!http.ok && REDIRECT_ERROR_CODES.has(http.error.code)) {
      return {
        status: "fail",
        scoreModifier: -20,
        summary:
          "La redirection depuis HTTP est invalide : le visiteur n'atteint pas la version HTTPS du site.",
        details: [`Erreur : ${http.error.message}`],
        evidence: partialChain.length > 0 ? describeChain(partialChain) : null,
        recommendation:
          "Corrigez la chaîne de redirections : elle doit mener, sans boucle et en peu d'étapes, à une adresse https:// valide.",
        examples: redirectExamples(hostname),
      };
    }

    // Aucune réponse reçue sur le port 80 : rien n'est servi en clair.
    if (!http.ok && partialChain.length === 0) return evaluateHttpUnreachable(http.error, https.ok);

    if (!https.ok) {
      return {
        status: "fail",
        scoreModifier: -20,
        summary:
          "Le site répond en HTTP clair mais pas en HTTPS : les échanges ne sont pas chiffrés.",
        details: [`Sonde HTTPS : ${https.error.message}`],
        evidence: describeChain(partialChain),
        recommendation:
          "Activez HTTPS (certificat gratuit Let's Encrypt, par exemple), puis redirigez tout le trafic HTTP vers HTTPS avec une redirection permanente (301 ou 308).",
        examples: redirectExamples(hostname),
      };
    }

    return evaluateChain(partialChain, http.ok ? null : http.error, hostname);
  },
};
