/**
 * Contrôle « mixed-content » : ressources chargées en http:// par une page servie en HTTPS.
 *
 * Rôle : repérer dans `context.html` les ressources et formulaires qui utilisent http:// alors que
 * la page est en HTTPS, et les classer comme le font les navigateurs (spécification W3C Mixed Content).
 * Pourquoi : ces requêtes circulent en clair ; un attaquant sur le réseau peut les lire ou les
 * modifier. Un script modifié prendrait le contrôle de la page : c'est pourquoi les navigateurs
 * bloquent les ressources « actives ».
 * Place dans l'architecture : contrôle pur, lit `context.html` (html.ts) et `context.response`.
 *
 * Catégories (le pire cas l'emporte) :
 * - bloquables (bloquées par les navigateurs) : scripts, feuilles de style, cadres, object, embed,
 *   préchargements (<link rel="preload|modulepreload">, dont la destination peut être un script) ;
 * - formulaires dont l'action envoie les données en http:// (avertissement du navigateur) ;
 * - passives (images, audio, vidéo, icônes) : Chrome et Firefox tentent automatiquement HTTPS.
 */
import { REFS } from "../references";
import type { CheckDefinition, CheckOutcome, FixExample, HtmlInfo, HtmlResource } from "../types";
import { getHeader, isServedOverHttps, notApplicable, truncateEvidence } from "./helpers";

/** Nombre maximal d'URL citées dans un détail. */
const MAX_LISTED_URLS = 10;

const BLOCKABLE_TAGS: ReadonlySet<string> = new Set([
  "script",
  "iframe",
  "frame",
  "object",
  "embed",
]);
const PASSIVE_TAGS: ReadonlySet<string> = new Set(["img", "audio", "video", "source", "track"]);
const BLOCKABLE_LINK_RELS: ReadonlySet<string> = new Set([
  "stylesheet",
  "preload",
  "modulepreload",
]);

type MixedCategory = "blockable" | "passive";

/** Catégorie d'une ressource selon sa balise (et son attribut rel pour <link>). */
function categoryOf(resource: HtmlResource): MixedCategory | null {
  if (resource.tag === "link") {
    const rel = resource.rel?.split(" ") ?? [];
    if (rel.some((token) => BLOCKABLE_LINK_RELS.has(token))) return "blockable";
    return rel.includes("icon") ? "passive" : null;
  }
  if (BLOCKABLE_TAGS.has(resource.tag)) return "blockable";
  return PASSIVE_TAGS.has(resource.tag) ? "passive" : null;
}

/** URL sans doublon, limitées à 10, puis « et N autres ». */
function listUrls(urls: string[]): string {
  const unique = [...new Set(urls)];
  const hidden = unique.length - MAX_LISTED_URLS;
  const shown = unique.slice(0, MAX_LISTED_URLS).join(", ");
  return hidden > 0 ? `${shown} et ${hidden} ${hidden > 1 ? "autres" : "autre"}` : shown;
}

function countOf(count: number, singular: string, plural: string): string {
  return `${count} ${count > 1 ? plural : singular}`;
}

interface MixedContent {
  blockable: string[];
  forms: string[];
  passive: string[];
}

/** URL en http:// de la page, par catégorie. */
function findMixedContent(html: HtmlInfo): MixedContent {
  const found: MixedContent = { blockable: [], forms: [], passive: [] };
  for (const resource of [...html.scripts, ...html.stylesheets, ...html.otherResources]) {
    const category = categoryOf(resource);
    if (category !== null && resource.url.startsWith("http:")) found[category].push(resource.url);
  }
  for (const form of html.forms) {
    // method="dialog" ferme une boîte de dialogue sans rien envoyer.
    if (form.action?.startsWith("http:") && form.method !== "dialog") {
      found.forms.push(form.action);
    }
  }
  return found;
}

/**
 * La page déclare-t-elle la directive CSP upgrade-insecure-requests (en-tête ou <meta>) ? Les
 * navigateurs récents réécrivent alors ses URL http:// en https:// avant de les charger.
 */
function upgradesInsecureRequests(policies: string[]): boolean {
  return policies.some((policy) =>
    policy
      .split(/[;,]/)
      .some(
        (directive) =>
          directive.trim().split(/\s+/)[0]?.toLowerCase() === "upgrade-insecure-requests",
      ),
  );
}

const UPGRADE_EXAMPLES: FixExample[] = [
  {
    label: "Nginx",
    language: "nginx",
    code: `# Filet de sécurité : le navigateur réécrit les URL http:// de la page en https://.
# Un en-tête CSP séparé ne contenant que cette directive ne restreint rien d'autre.
add_header Content-Security-Policy "upgrade-insecure-requests" always;`,
  },
  {
    label: "Apache",
    language: "apache",
    code: `# « add » ajoute une politique sans remplacer une CSP existante
Header always add Content-Security-Policy "upgrade-insecure-requests"`,
  },
  {
    label: "Next.js (next.config.ts)",
    language: "ts",
    code: `import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [{ key: "Content-Security-Policy", value: "upgrade-insecure-requests" }],
      },
    ];
  },
};

export default nextConfig;`,
  },
];

/** Verdict principal : le cas le plus grave présent fixe le statut et les points. */
function worstVerdict(
  found: MixedContent,
): Pick<CheckOutcome, "status" | "scoreModifier" | "summary"> {
  if (found.blockable.length > 0) {
    const count = new Set(found.blockable).size;
    return {
      status: "fail",
      scoreModifier: -20,
      summary: `La page HTTPS charge ${countOf(count, "ressource active", "ressources actives")} en http:// (script, feuille de style, cadre ou objet) : les navigateurs ${
        count > 1 ? "les" : "la"
      } bloquent, ce qui peut casser la page, et un attaquant sur le réseau pourrait ${count > 1 ? "les" : "la"} modifier.`,
    };
  }
  if (found.forms.length > 0) {
    const count = new Set(found.forms).size;
    return {
      status: "fail",
      scoreModifier: -10,
      summary: `${countOf(count, "formulaire envoie ses", "formulaires envoient leurs")} données en http:// : elles circulent en clair et le navigateur affiche un avertissement.`,
    };
  }
  const count = new Set(found.passive).size;
  return {
    status: "warning",
    scoreModifier: -5,
    summary: `La page HTTPS charge ${countOf(count, "ressource passive", "ressources passives")} (image, audio ou vidéo) en http:// : Chrome et Firefox tentent automatiquement HTTPS, Safari peut ${
      count > 1 ? "les" : "la"
    } bloquer.`,
  };
}

/** Contrôle du contenu mixte. */
export const mixedContentCheck: CheckDefinition = {
  id: "mixed-content",
  category: "content",
  title: "Contenu mixte",
  description:
    "Une page servie en HTTPS qui charge des ressources en http:// perd une partie de la protection de TLS : un attaquant placé sur le réseau peut lire ou modifier ces ressources. Les navigateurs bloquent les ressources actives (scripts, styles, cadres) et tentent HTTPS pour les images et médias ; un formulaire envoyé en http:// déclenche un avertissement.",
  references: [
    REFS.cheatSheets.tlsMixedContent,
    REFS.cheatSheets.cspUpgrade,
    REFS.top10.A04,
    REFS.asvs["12.2.1"],
    REFS.wstg.CRYP01MixedContent,
    REFS.mdn.mixedContent,
  ],
  scoring: [
    { outcome: "Page non HTML ou servie en HTTP (sans objet)", modifier: 0 },
    {
      outcome:
        "Ressource « bloquable » en http:// : script, feuille de style, iframe/frame, object, embed",
      modifier: -20,
    },
    { outcome: "Formulaire dont l'action envoie en http://", modifier: -10 },
    {
      outcome:
        "Ressource passive en http:// (img, audio, video, source, track) : mise à niveau automatique par les navigateurs",
      modifier: -5,
    },
    { outcome: "Aucune ressource en http://", modifier: 0 },
  ],
  evaluate(context): CheckOutcome {
    const { html, response } = context;
    if (html === null) {
      return notApplicable(
        "La réponse analysée n'est pas une page HTML : le contrôle du contenu mixte est sans objet.",
      );
    }
    if (!isServedOverHttps(response)) {
      return notApplicable(
        "La page est servie en HTTP : il n'y a pas de contenu mixte à proprement parler, c'est toute la page qui circule en clair.",
      );
    }

    const found = findMixedContent(html);
    const allUrls = [...found.blockable, ...found.forms, ...found.passive];
    if (allUrls.length === 0) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary: "La page HTTPS ne charge aucune ressource en http://.",
        recommendation: null,
      };
    }

    const details: string[] = [];
    if (found.blockable.length > 0) {
      details.push(`Ressources actives en http:// : ${listUrls(found.blockable)}.`);
    }
    if (found.forms.length > 0) {
      details.push(`Formulaires envoyés en http:// : ${listUrls(found.forms)}.`);
    }
    if (found.passive.length > 0) {
      details.push(`Ressources passives en http:// : ${listUrls(found.passive)}.`);
    }
    const cspHeader = getHeader(response, "content-security-policy");
    const upgrades = upgradesInsecureRequests([...(cspHeader ? [cspHeader] : []), ...html.metaCsp]);
    if (upgrades) {
      details.push(
        "La CSP contient upgrade-insecure-requests : les navigateurs récents réécrivent ces adresses en HTTPS, mais corrigez-les quand même à la source.",
      );
    }

    return {
      ...worstVerdict(found),
      details,
      evidence: truncateEvidence([...new Set(allUrls)].join("\n")),
      recommendation: upgrades
        ? "Remplacez les URL http:// par des URL https:// (ou des chemins relatifs)."
        : "Remplacez les URL http:// par des URL https:// (ou des chemins relatifs) ; en filet de sécurité, ajoutez la directive CSP upgrade-insecure-requests.",
      examples: upgrades ? undefined : UPGRADE_EXAMPLES,
    };
  },
};
