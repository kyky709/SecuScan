// Les chiffres cités (ports autorisés, limites de débit) sont lus dans config.ts : le texte suit
// la configuration réellement appliquée.
import type { Metadata } from "next";
import type { ReactNode } from "react";
import { pageMetadata } from "@/components/layout/page-metadata";
import { ExternalLink } from "@/components/ui/external-link";
import { CARD, CONTAINER, MUTED_TEXT } from "@/components/ui/styles";
import { ALLOWED_PORTS, RATE_LIMIT_PER_CLIENT, RATE_LIMIT_PER_TARGET } from "@/lib/config";
import { SITE } from "@/lib/site";

export const metadata: Metadata = pageMetadata({
  title: "À propos",
  description:
    "SecuScan, projet personnel et open source : contexte, technologies, protections de l'outil (anti-SSRF, limitation de débit, CSP stricte), utilisation responsable et confidentialité.",
  path: "/a-propos",
});

const PROSE = "space-y-3 leading-relaxed text-zinc-700 dark:text-zinc-300";

const STACK = [
  {
    name: "Next.js 16 et React 19",
    role: "Interface et API, rendues côté serveur (App Router).",
  },
  {
    name: "TypeScript (mode strict)",
    role: "Typage de bout en bout, du moteur d'analyse jusqu'à l'interface.",
  },
  {
    name: "Node.js 24",
    role: "Requêtes HTTP, négociation TLS et requêtes DNS réalisées avec les modules natifs.",
  },
  {
    name: "zod, ipaddr.js, node-html-parser",
    role: "Validation des entrées, classification des adresses IP, lecture du HTML.",
  },
  {
    name: "Tailwind CSS 4",
    role: "Mise en forme, sans aucun style en ligne (exigence de la Content-Security-Policy).",
  },
  {
    name: "Upstash Redis",
    role: "Limitation de débit partagée entre les instances du serveur.",
  },
  {
    name: "Vitest, Testing Library et Biome",
    role: "Tests automatisés (sans accès à Internet) et qualité du code.",
  },
  { name: "Vercel", role: "Hébergement." },
] as const;

const RATE_LIMIT_WINDOW_SECONDS = RATE_LIMIT_PER_CLIENT.windowMs / 1000;

function Protections() {
  return (
    <ul className={`list-disc pl-5 ${PROSE}`}>
      <li>
        <strong>Protection contre la SSRF.</strong> Seuls les schémas http et https sont acceptés,
        sur les ports {[...ALLOWED_PORTS].join(" et ")}. Les adresses locales, privées ou réservées
        (localhost, réseaux 192.168.x.x, adresse 169.254.169.254 des métadonnées cloud…) sont
        refusées. La vérification a lieu à chaque connexion, y compris après une redirection, au
        moment même où le nom de domaine est résolu : il ne peut pas changer d'adresse entre la
        vérification et la connexion (attaque dite de DNS rebinding).
      </li>
      <li>
        <strong>Limitation de débit.</strong> Au plus {RATE_LIMIT_PER_CLIENT.limit} analyses en{" "}
        {RATE_LIMIT_WINDOW_SECONDS} secondes par visiteur, et {RATE_LIMIT_PER_TARGET.limit} par site
        analysé : SecuScan ne peut pas servir à harceler un site.
      </li>
      <li>
        <strong>Requêtes bornées.</strong> Délais stricts, taille des réponses limitée (y compris
        après décompression), et aucun cookie ni identifiant transmis au site analysé.
      </li>
      <li>
        <strong>Content-Security-Policy stricte.</strong> Tout est interdit par défaut (default-src
        'none') ; un script ne s'exécute que s'il porte un nonce aléatoire, renouvelé à chaque
        requête ; aucun style ni script en ligne, aucune ressource externe.
      </li>
      <li>
        <strong>En-têtes de sécurité.</strong> HSTS, X-Content-Type-Options, X-Frame-Options,
        Referrer-Policy, Permissions-Policy, Cross-Origin-Opener-Policy et
        Cross-Origin-Resource-Policy accompagnent chaque réponse.
      </li>
      <li>
        <strong>Validation des entrées.</strong> L'API n'accepte que de petites requêtes JSON,
        envoyées depuis le site lui-même (en-tête Origin vérifié), dont le contenu est validé avant
        tout traitement.
      </li>
    </ul>
  );
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-titre`} className="scroll-mt-6 space-y-4">
      <h2
        id={`${id}-titre`}
        className="text-2xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50"
      >
        {title}
      </h2>
      {children}
    </section>
  );
}

export default function AboutPage() {
  return (
    <div className={`${CONTAINER} py-10 sm:py-14`}>
      <div className="max-w-3xl space-y-12">
        <header className="space-y-4">
          <h1 className="text-3xl font-bold tracking-tight text-zinc-900 sm:text-4xl dark:text-zinc-50">
            À propos de SecuScan
          </h1>
          <p className={`text-lg ${MUTED_TEXT}`}>
            Un outil pour comprendre et améliorer la configuration de sécurité d'un site web.
          </p>
        </header>

        <Section id="projet" title="Un projet personnel">
          <div className={PROSE}>
            <p>
              SecuScan est un projet personnel et open source, né d'un intérêt pour la sécurité des
              applications web. Le code est ouvert et documenté : chaque verdict peut être retracé
              jusqu'à la règle qui l'a produit.
            </p>
            <p>
              Il s'inspire de MDN HTTP Observatory et de securityheaders.com : comme eux, il observe
              la configuration d'un site, attribue une note et explique comment l'améliorer, en
              s'appuyant d'abord sur les recommandations de l'OWASP.
            </p>
          </div>
        </Section>

        <Section id="technologies" title="Technologies">
          <dl className="grid gap-3 sm:grid-cols-2">
            {STACK.map((item) => (
              <div key={item.name} className={`${CARD} p-4`}>
                <dt className="font-semibold text-zinc-900 dark:text-zinc-50">{item.name}</dt>
                <dd className={`mt-1 text-sm ${MUTED_TEXT}`}>{item.role}</dd>
              </div>
            ))}
          </dl>
        </Section>

        <Section id="protections" title="Comment SecuScan se protège">
          <div className={PROSE}>
            <p>
              Un scanner envoie, depuis son serveur, des requêtes vers des adresses fournies par
              n'importe qui. C'est exactement le scénario d'une attaque SSRF (Server-Side Request
              Forgery) : sans précaution, un attaquant pourrait lui faire interroger le réseau
              interne de l'hébergeur. SecuScan applique donc plusieurs protections complémentaires,
              selon le principe de défense en profondeur :
            </p>
          </div>
          <Protections />
        </Section>

        <Section id="usage" title="Utilisation responsable">
          <div className={PROSE}>
            <p>
              N'analysez que des sites qui vous appartiennent ou que vous êtes autorisé à évaluer.
              L'analyse est passive (une dizaine de requêtes, comparables à la visite d'un
              navigateur), mais elle reste l'observation de la sécurité d'un tiers.
            </p>
            <p>
              Les requêtes de SecuScan s'identifient par leur agent utilisateur : un administrateur
              peut les reconnaître dans ses journaux. Le détail des requêtes envoyées est décrit
              dans la méthodologie.
            </p>
          </div>
        </Section>

        <Section id="confidentialite" title="Confidentialité">
          <ul className={`list-disc pl-5 ${PROSE}`}>
            <li>Aucun compte, aucun cookie, aucun outil de mesure d'audience ni traceur.</li>
            <li>
              Les rapports ne sont pas conservés : ils sont calculés à la demande, envoyés à votre
              navigateur, puis oubliés par le serveur. L'export JSON est créé directement dans votre
              navigateur.
            </li>
            <li>
              Pour la limitation de débit, votre adresse IP est transformée par une fonction de
              hachage (SHA-256) : seule cette empreinte est conservée, le temps de la fenêtre de
              limitation ({RATE_LIMIT_WINDOW_SECONDS} secondes). L'adresse elle-même n'est jamais
              enregistrée.
            </li>
            <li>
              Le journal technique du serveur note le site analysé, la note, le score et la durée de
              chaque analyse, sans adresse IP.
            </li>
            <li>L'hébergeur (Vercel) peut tenir ses propres journaux techniques.</li>
          </ul>
        </Section>

        <Section id="code-source" title="Code source">
          <p className={PROSE}>
            Le code de SecuScan est public : vous pouvez vérifier son fonctionnement, signaler un
            problème ou proposer une amélioration sur{" "}
            <ExternalLink href={SITE.repositoryUrl}>le dépôt du projet</ExternalLink>.
          </p>
        </Section>

        <Section id="credits" title="Crédits">
          <ul className={`space-y-2 ${PROSE}`}>
            <li>
              <ExternalLink href="https://developer.mozilla.org/en-US/observatory">
                MDN HTTP Observatory
              </ExternalLink>{" "}
              : règles de notation, reprises par SecuScan.
            </li>
            <li>
              <ExternalLink href="https://securityheaders.com/">securityheaders.com</ExternalLink> :
              échelle de notes de A+ à F.
            </li>
            <li>
              <ExternalLink href="https://owasp.org/">OWASP</ExternalLink> : Top 10, ASVS, Cheat
              Sheet Series, WSTG et Secure Headers Project, cités par chaque contrôle.
            </li>
            <li>
              <ExternalLink href="https://developer.mozilla.org/fr/">MDN Web Docs</ExternalLink> :
              documentation des mécanismes de sécurité du Web.
            </li>
            <li>
              <ExternalLink href="https://lucide.dev/">Lucide</ExternalLink> : icônes (licence ISC).
            </li>
            <li>
              <ExternalLink href="https://vercel.com/font">Geist et Geist Mono</ExternalLink> :
              polices de caractères (licence SIL Open Font).
            </li>
          </ul>
        </Section>
      </div>
    </div>
  );
}
