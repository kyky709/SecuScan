/**
 * Contrôle « sri » : intégrité des scripts tiers (Subresource Integrity).
 *
 * Rôle : vérifier que chaque script chargé en HTTPS depuis un autre hôte que la page porte un
 * attribut integrity utilisable (empreinte SHA-256, SHA-384 ou SHA-512).
 * Pourquoi : un script tiers s'exécute avec tous les droits de la page. Si le CDN ou le fournisseur
 * est compromis, le fichier modifié s'exécute chez tous les visiteurs ; avec integrity, le navigateur
 * compare l'empreinte et refuse le fichier altéré (attaque de la chaîne d'approvisionnement).
 * Place dans l'architecture : contrôle pur, lit `context.html` (extrait par html.ts).
 *
 * Règle simple, celle de MDN Observatory : un script est « tiers » si son hôte diffère de celui de
 * la page (un sous-domaine compte donc comme tiers). Les scripts en http:// relèvent du contrôle
 * « mixed-content » et ne sont pas notés ici.
 */
import { REFS } from "../references";
import type { CheckDefinition, CheckOutcome, FixExample, HtmlResource } from "../types";
import { notApplicable, splitList, truncateEvidence } from "./helpers";

/**
 * Jeton d'intégrité utilisable : algorithme reconnu, tiret, empreinte en base64, options éventuelles
 * (« ?… »). Un navigateur ignore les jetons d'un algorithme inconnu (md5, sha1…) : un attribut qui ne
 * contient que ceux-là ne protège rien.
 */
const SRI_TOKEN = /^(?:sha256|sha384|sha512)-[A-Za-z0-9+/_-]+={0,2}(?:\?.*)?$/i;

/** Nombre maximal d'URL citées dans un détail. */
const MAX_LISTED_URLS = 10;

function hasValidIntegrity(integrity: string | null): boolean {
  return integrity !== null && splitList(integrity, /\s+/).some((token) => SRI_TOKEN.test(token));
}

/**
 * SRI exige une requête CORS : une ressource tierce qui a integrity mais pas crossorigin est
 * chargée en mode « no-cors », sa vérification échoue toujours et le navigateur la bloque.
 */
function isBlockedForLackOfCors({ integrity, crossorigin }: HtmlResource): boolean {
  return hasValidIntegrity(integrity) && crossorigin === null;
}

function hostOf(url: string): string | null {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/** Liste d'URL sans doublon, limitée à 10, puis « et N autres ». */
function listUrls(resources: HtmlResource[]): string {
  const urls = [...new Set(resources.map((resource) => resource.url))];
  const hidden = urls.length - MAX_LISTED_URLS;
  const shown = urls.slice(0, MAX_LISTED_URLS).join(", ");
  return hidden > 0 ? `${shown} et ${hidden} ${hidden > 1 ? "autres" : "autre"}` : shown;
}

/** Constats sans effet sur la note : feuilles de style, crossorigin, integrity inutilisable. */
function secondaryFindings(
  scripts: HtmlResource[],
  stylesheets: HtmlResource[],
  insecureScripts: HtmlResource[],
): string[] {
  const details: string[] = [];
  const unusable = [...scripts, ...stylesheets].filter(
    ({ integrity }) => integrity !== null && !hasValidIntegrity(integrity),
  );
  if (unusable.length > 0) {
    details.push(
      `Attribut integrity inutilisable (algorithme autre que sha256, sha384 ou sha512, ou valeur vide) : ${listUrls(unusable)}.`,
    );
  }
  const withoutCors = [...scripts, ...stylesheets].filter(isBlockedForLackOfCors);
  if (withoutCors.length > 0) {
    details.push(
      `Attribut integrity sans crossorigin, ressource bloquée par le navigateur (SRI exige une requête CORS) : ${listUrls(withoutCors)}.`,
    );
  }
  const unprotectedStyles = stylesheets.filter(({ integrity }) => !hasValidIntegrity(integrity));
  if (unprotectedStyles.length > 0) {
    details.push(
      `Feuilles de style tierces sans attribut integrity (sans effet sur la note) : ${listUrls(unprotectedStyles)}.`,
    );
  }
  if (insecureScripts.length > 0) {
    details.push(
      `Scripts tiers chargés en http://, traités par le contrôle « Contenu mixte » : ${listUrls(insecureScripts)}.`,
    );
  }
  return details;
}

const SRI_EXAMPLES: FixExample[] = [
  {
    label: "HTML",
    language: "html",
    code: `<script
  src="https://cdn.example.com/lib.min.js"
  integrity="sha384-<empreinte en base64>"
  crossorigin="anonymous"
></script>`,
  },
  {
    label: "Calcul de l'empreinte (OpenSSL)",
    language: "bash",
    code: `# Empreinte SHA-384 du fichier exact servi par le CDN (à refaire à chaque nouvelle version)
curl -s https://cdn.example.com/lib.min.js | openssl dgst -sha384 -binary | openssl base64 -A`,
  },
  {
    label: "Next.js (next/script)",
    language: "tsx",
    code: `import Script from "next/script";

export function ThirdPartyLibrary() {
  return (
    <Script
      src="https://cdn.example.com/lib.min.js"
      integrity="sha384-<empreinte en base64>"
      crossOrigin="anonymous"
    />
  );
}`,
  },
];

const CROSSORIGIN_FIX =
  'Ajoutez crossorigin="anonymous" aux ressources tierces protégées par integrity : sans lui, le navigateur les bloque.';

/** Contrôle de l'intégrité (SRI) des scripts tiers. */
export const sriCheck: CheckDefinition = {
  id: "sri",
  category: "content",
  title: "Intégrité des scripts tiers (SRI)",
  description:
    "L'attribut integrity (Subresource Integrity) indique l'empreinte cryptographique attendue d'un script. Si le fichier servi par un CDN ou un autre fournisseur est modifié, le navigateur refuse de l'exécuter. Cela protège la page contre la compromission d'un service externe (attaque de la chaîne d'approvisionnement).",
  references: [
    REFS.cheatSheets.thirdPartyJsSri,
    REFS.top10.A03,
    REFS.top10.A08,
    REFS.asvs["3.6.1"],
    REFS.mdn.sri,
  ],
  scoring: [
    { outcome: "Réponse non HTML", modifier: 0 },
    { outcome: "Aucun script tiers", modifier: 0 },
    { outcome: "Tous les scripts tiers ont un attribut integrity", modifier: 5 },
    { outcome: "Script(s) tiers sans integrity", modifier: -5 },
  ],
  evaluate(context): CheckOutcome {
    const html = context.html;
    const pageHost = context.response ? hostOf(context.response.url) : null;
    if (html === null || pageHost === null) {
      return notApplicable(
        "La réponse analysée n'est pas une page HTML : le contrôle SRI est sans objet.",
      );
    }

    const isThirdParty = (resource: HtmlResource) => hostOf(resource.url) !== pageHost;
    const scripts = html.scripts.filter((s) => s.url.startsWith("https:") && isThirdParty(s));
    const stylesheets = html.stylesheets.filter(
      (s) => s.url.startsWith("https:") && isThirdParty(s),
    );
    const insecureScripts = html.scripts.filter(
      (s) => s.url.startsWith("http:") && isThirdParty(s),
    );
    const details = secondaryFindings(scripts, stylesheets, insecureScripts);
    const corsFix = [...scripts, ...stylesheets].some(isBlockedForLackOfCors)
      ? CROSSORIGIN_FIX
      : null;

    if (scripts.length === 0) {
      return {
        status: "pass",
        scoreModifier: 0,
        summary:
          insecureScripts.length > 0
            ? "La page ne charge aucun script tiers en HTTPS (ceux en http:// relèvent du contrôle « Contenu mixte »)."
            : "La page ne charge aucun script depuis un autre domaine.",
        details,
        evidence: null,
        recommendation: corsFix,
        examples: corsFix ? SRI_EXAMPLES : undefined,
      };
    }

    const missing = scripts.filter(({ integrity }) => !hasValidIntegrity(integrity));
    if (missing.length === 0) {
      return {
        status: "pass",
        scoreModifier: 5,
        summary:
          scripts.length > 1
            ? `Les ${scripts.length} scripts tiers de la page sont protégés par un attribut integrity (SRI).`
            : "Le script tiers de la page est protégé par un attribut integrity (SRI).",
        details,
        evidence: truncateEvidence(
          scripts.map((s) => `${s.url} integrity="${s.integrity}"`).join("\n"),
        ),
        recommendation: corsFix,
        examples: corsFix ? SRI_EXAMPLES : undefined,
      };
    }

    return {
      status: "warning",
      scoreModifier: -5,
      summary: `${missing.length} script${missing.length > 1 ? "s" : ""} tiers sur ${scripts.length} ${
        missing.length > 1 ? "sont chargés" : "est chargé"
      } sans attribut integrity valide : si le fournisseur est compromis, un code modifié s'exécuterait dans la page.`,
      details: [`Scripts tiers sans integrity : ${listUrls(missing)}.`, ...details],
      evidence: truncateEvidence([...new Set(missing.map((s) => s.url))].join("\n")),
      recommendation:
        'Ajoutez à chaque script tiers un attribut integrity (empreinte SHA-384 du fichier) et crossorigin="anonymous", ou hébergez le script sur votre propre domaine. Mettez l\'empreinte à jour à chaque nouvelle version du fichier.',
      examples: SRI_EXAMPLES,
    };
  },
};
