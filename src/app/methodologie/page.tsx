// Le contenu des contrôles vient du registre `CHECKS` et les exemples sont chiffrés par
// `computeScore` : la documentation ne peut pas diverger du code qui note réellement les sites.
// Les ancres `#controle-<id>` sont la cible des liens « Comment ce contrôle est noté » du rapport.
import type { Metadata } from "next";
import Link from "next/link";
import type { ReactNode } from "react";
import { pageMetadata } from "@/components/layout/page-metadata";
import { CategoryIcon } from "@/components/report/category-icon";
import { explainScore, formatScore } from "@/components/report/format";
import { GradeBadge } from "@/components/report/grade-badge";
import { ModifierBadge } from "@/components/report/modifier-badge";
import { ReferenceList } from "@/components/report/reference-list";
import { CARD, CODE_BLOCK, CONTAINER, EYEBROW, LINK, MUTED_TEXT } from "@/components/ui/styles";
import { CORS_PROBE_ORIGIN, MAX_BODY_BYTES, SCAN_TIMEOUT_MS, USER_AGENT } from "@/lib/config";
import { CHECKS } from "@/lib/scanner/checks";
import { CATEGORIES } from "@/lib/scanner/labels";
import { REFS } from "@/lib/scanner/references";
import { BASE_SCORE, BONUS_THRESHOLD, computeScore, GRADE_THRESHOLDS } from "@/lib/scanner/scoring";
import type { CheckDefinition, Reference } from "@/lib/scanner/types";

export const metadata: Metadata = pageMetadata({
  title: "Méthodologie",
  description: `Comment SecuScan analyse un site web : les sondes, les ${CHECKS.length} contrôles et leur barème, le calcul de la note de A+ à F et les limites de l'analyse.`,
  path: "/methodologie",
});

const SECTIONS = [
  { id: "principe", title: "Ce que fait SecuScan" },
  { id: "sondes", title: "Les sondes" },
  { id: "notation", title: "Calcul de la note" },
  { id: "controles", title: "Les contrôles" },
  { id: "limites", title: "Limites de l'analyse" },
  { id: "sources", title: "Sources" },
] as const;

const PROSE = "space-y-3 leading-relaxed text-zinc-700 dark:text-zinc-300";

const WORKED_EXAMPLES = [
  {
    title: "Exemple 1 : un vrai problème, des bonus ignorés",
    findings: [
      { outcome: "Aucune Content-Security-Policy", scoreModifier: -25 },
      { outcome: "X-Content-Type-Options absent", scoreModifier: -5 },
      { outcome: "X-Frame-Options: DENY (clickjacking)", scoreModifier: 5 },
      { outcome: "Referrer-Policy stricte", scoreModifier: 5 },
    ],
  },
  {
    title: "Exemple 2 : le même site, une fois sa CSP corrigée",
    findings: [
      { outcome: "CSP sans source dangereuse, avec default-src 'none'", scoreModifier: 10 },
      { outcome: "X-Content-Type-Options absent", scoreModifier: -5 },
      { outcome: "X-Frame-Options: DENY (clickjacking)", scoreModifier: 5 },
      { outcome: "Referrer-Policy stricte", scoreModifier: 5 },
    ],
  },
] as const;

const SOURCES: readonly Reference[] = [
  REFS.mdn.observatoryScoring,
  {
    kind: "other",
    label: "securityheaders.com – Analyse des en-têtes de sécurité (notes de A+ à F)",
    url: "https://securityheaders.com/",
  },
  REFS.secureHeaders.configuration,
  REFS.cheatSheets.httpHeaders,
  REFS.top10.A02,
  REFS.cheatSheets.ssrf,
];

// Scores entiers : la plage d'une note s'arrête juste sous le seuil de la note supérieure.
function gradeRanges(): Array<{
  grade: (typeof GRADE_THRESHOLDS)[number]["grade"];
  range: string;
}> {
  return GRADE_THRESHOLDS.map((threshold, index) => {
    const higher = GRADE_THRESHOLDS[index - 1];
    const range = higher
      ? `${threshold.minScore} à ${higher.minScore - 1}`
      : `${threshold.minScore} et plus`;
    return { grade: threshold.grade, range };
  });
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-titre`} className="scroll-mt-6 space-y-5">
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

function WorkedExample({ example }: { example: (typeof WORKED_EXAMPLES)[number] }) {
  const score = computeScore(example.findings);
  const { formula, bonusNote } = explainScore(score);

  return (
    <div className={`${CARD} space-y-4 p-5`}>
      <h4 className="font-semibold text-zinc-900 dark:text-zinc-50">{example.title}</h4>
      <table className="w-full text-left text-sm">
        <caption className="sr-only">{`Constats de l'${example.title.toLowerCase()}`}</caption>
        <thead className={EYEBROW}>
          <tr>
            <th scope="col" className="pb-2 font-semibold">
              Constat
            </th>
            <th scope="col" className="pb-2 text-right font-semibold">
              Effet
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
          {example.findings.map((finding) => (
            <tr key={finding.outcome}>
              <td className="py-1.5 pr-3 text-zinc-800 dark:text-zinc-200">{finding.outcome}</td>
              <td className="py-1.5 text-right">
                <ModifierBadge modifier={finding.scoreModifier} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="space-y-1 text-sm">
        <p className="text-zinc-800 dark:text-zinc-200">
          <span className="font-semibold">Calcul :</span> {formula}
        </p>
        <p className={MUTED_TEXT}>{bonusNote}</p>
      </div>
      <p className="flex items-center gap-3 text-sm font-semibold text-zinc-900 dark:text-zinc-50">
        <GradeBadge grade={score.grade} size="sm" />
        Résultat : {formatScore(score.score)}, note {score.grade}
      </p>
    </div>
  );
}

function CheckMethodology({ check }: { check: CheckDefinition }) {
  const headingId = `controle-${check.id}-titre`;

  return (
    <article
      id={`controle-${check.id}`}
      aria-labelledby={headingId}
      className={`${CARD} scroll-mt-6 space-y-4 p-5`}
    >
      <h4 id={headingId} className="font-semibold text-zinc-900 dark:text-zinc-50">
        {check.title}
      </h4>
      <p className={`text-sm leading-relaxed ${MUTED_TEXT}`}>{check.description}</p>
      <table className="w-full text-left text-sm">
        <caption className="sr-only">{`Barème du contrôle « ${check.title} »`}</caption>
        <thead className={EYEBROW}>
          <tr>
            <th scope="col" className="pb-2 font-semibold">
              Résultat observé
            </th>
            <th scope="col" className="pb-2 text-right font-semibold">
              Effet sur la note
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
          {check.scoring.map((row) => (
            <tr key={row.outcome}>
              <td className="py-1.5 pr-3 text-zinc-800 dark:text-zinc-200">{row.outcome}</td>
              <td className="py-1.5 text-right">
                <ModifierBadge modifier={row.modifier} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {check.references.length > 0 ? (
        <div className="space-y-2">
          <p className={EYEBROW}>Références</p>
          <ReferenceList references={check.references} />
        </div>
      ) : null}
    </article>
  );
}

export default function MethodologyPage() {
  return (
    <div className={`${CONTAINER} space-y-14 py-10 sm:py-14`}>
      <header className="max-w-3xl space-y-4">
        <h1 className="text-3xl font-bold tracking-tight text-zinc-900 sm:text-4xl dark:text-zinc-50">
          Méthodologie
        </h1>
        <p className={`text-lg ${MUTED_TEXT}`}>
          Comment SecuScan observe un site, ce qu'il vérifie et comment il calcule la note. Tout ce
          qui suit est généré à partir du code qui réalise réellement les analyses.
        </p>
        <nav aria-label="Sommaire de la page">
          <ol className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
            {SECTIONS.map((section) => (
              <li key={section.id}>
                <a href={`#${section.id}`} className={LINK}>
                  {section.title}
                </a>
              </li>
            ))}
          </ol>
        </nav>
      </header>

      <Section id="principe" title="Ce que fait SecuScan">
        <div className={PROSE}>
          <p>
            SecuScan réalise une <strong>analyse passive</strong> : il consulte le site comme le
            ferait un navigateur, puis examine ce que le serveur lui renvoie. Il n'envoie aucune
            donnée piégée et ne tente aucune intrusion.
          </p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div className={`${CARD} space-y-2 p-5`}>
            <h3 className="font-semibold text-zinc-900 dark:text-zinc-50">Ce que SecuScan fait</h3>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-zinc-700 dark:text-zinc-300">
              <li>
                Vérifie que le site est servi en HTTPS, avec un certificat valide et un TLS récent.
              </li>
              <li>
                Lit les en-têtes HTTP de sécurité (CSP, HSTS, anti-clickjacking…) et les cookies.
              </li>
              <li>Examine le code HTML de la page : scripts tiers, contenu chargé en clair.</li>
              <li>Consulte des informations publiques : security.txt, DNS CAA, politique CORS.</li>
            </ul>
          </div>
          <div className={`${CARD} space-y-2 p-5`}>
            <h3 className="font-semibold text-zinc-900 dark:text-zinc-50">
              Ce que SecuScan ne fait pas
            </h3>
            <ul className="list-disc space-y-1.5 pl-5 text-sm text-zinc-700 dark:text-zinc-300">
              <li>
                Aucune recherche de failles applicatives (injection SQL, XSS…) ni test d'intrusion.
              </li>
              <li>Aucune connexion à un compte : seules les pages publiques sont observées.</li>
              <li>Aucune exploration du site : une seule page est analysée, après redirections.</li>
              <li>
                Aucune conservation des rapports : ils sont envoyés à votre navigateur, puis
                oubliés.
              </li>
            </ul>
          </div>
        </div>
      </Section>

      <Section id="sondes" title="Les sondes">
        <div className={PROSE}>
          <p>
            Une analyse lance six sondes en parallèle, avec un délai global de{" "}
            {SCAN_TIMEOUT_MS / 1000} secondes. Chacune peut échouer indépendamment : les contrôles
            qui en dépendent sont alors marqués « Non vérifié » et n'ont aucun effet sur la note.
          </p>
        </div>
        <dl className="grid gap-4 md:grid-cols-2">
          {[
            {
              term: "Requête HTTPS",
              text: `GET de l'adresse en https://, redirections suivies (chaque étape est revalidée), page HTML lue jusqu'à ${MAX_BODY_BYTES / (1024 * 1024)} Mio : en-têtes, cookies et contenu.`,
            },
            {
              term: "Requête HTTP",
              text: "GET de la même adresse en http://, sans lire la page : redirection vers HTTPS et cookies envoyés en clair.",
            },
            {
              term: "Négociation TLS",
              text: "Connexion directe sur le port 443 : certificat, version et suite de chiffrement. Deux tentatives en TLS 1.0 et 1.1 vérifient que ces versions obsolètes sont refusées.",
            },
            {
              term: "Fichier security.txt",
              text: "GET de /.well-known/security.txt, le fichier où un site publie son contact de sécurité (RFC 9116).",
            },
            {
              term: "Test CORS",
              text: `GET de la page avec l'en-tête Origin: ${CORS_PROBE_ORIGIN}, une origine fictive : un serveur qui l'accepte accepte n'importe quel site.`,
            },
            {
              term: "Enregistrements DNS CAA",
              text: "Autorités de certification autorisées pour le domaine, en remontant vers les domaines parents (RFC 8659).",
            },
          ].map((probe) => (
            <div key={probe.term} className={`${CARD} p-5`}>
              <dt className="font-semibold text-zinc-900 dark:text-zinc-50">{probe.term}</dt>
              <dd className={`mt-1 text-sm ${MUTED_TEXT}`}>{probe.text}</dd>
            </div>
          ))}
        </dl>
        <div className={PROSE}>
          <p>
            Toutes les requêtes s'identifient clairement auprès du site analysé, avec l'agent
            utilisateur suivant :
          </p>
          <pre className={`${CODE_BLOCK} rounded-lg`}>{USER_AGENT}</pre>
          <p>
            Par sécurité, SecuScan refuse d'analyser les adresses locales, privées ou réservées, et
            chaque connexion est vérifiée au moment où elle s'établit (voir{" "}
            <Link href="/a-propos#protections" className={LINK}>
              comment SecuScan se protège
            </Link>
            ).
          </p>
        </div>
      </Section>

      <Section id="notation" title="Calcul de la note">
        <div className={PROSE}>
          <p>
            Chaque contrôle rend un verdict et un effet sur la note : négatif pour une pénalité,
            positif pour un bonus, nul sinon. Quand un contrôle relève plusieurs problèmes, seul le
            plus grave compte : les pénalités d'un même contrôle ne s'additionnent pas.
          </p>
          <ol className="list-decimal space-y-1.5 pl-5">
            <li>On part de {BASE_SCORE} points.</li>
            <li>On applique toutes les pénalités : c'est le score « sans bonus ».</li>
            <li>
              Si ce score atteint {BONUS_THRESHOLD}, on ajoute tous les bonus ; sinon, aucun. C'est
              du tout ou rien : un bonus ne doit jamais masquer un vrai problème.
            </li>
            <li>
              Le score ne descend pas sous 0, mais n'a pas de plafond : {formatScore(115)} est
              possible et vaut A+.
            </li>
          </ol>
          <p>
            Ces règles reprennent celles de MDN HTTP Observatory ; l'échelle à sept lettres
            s'inspire de securityheaders.com.
          </p>
        </div>

        <div className={`${CARD} max-w-md overflow-hidden`}>
          <table className="w-full text-left text-sm">
            <caption className="border-b border-zinc-200 px-4 py-3 text-left font-semibold text-zinc-900 dark:border-zinc-800 dark:text-zinc-50">
              Correspondance entre score et note
            </caption>
            <thead className={EYEBROW}>
              <tr>
                <th scope="col" className="px-4 py-2 font-semibold">
                  Note
                </th>
                <th scope="col" className="px-4 py-2 font-semibold">
                  Score
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-200 dark:divide-zinc-800">
              {gradeRanges().map(({ grade, range }) => (
                <tr key={grade}>
                  <td className="px-4 py-2">
                    <GradeBadge grade={grade} size="sm" />
                  </td>
                  <td className="px-4 py-2 text-zinc-800 tabular-nums dark:text-zinc-200">
                    {range}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-zinc-900 dark:text-zinc-50">
            Deux exemples de calcul
          </h3>
          <p className={`text-sm ${MUTED_TEXT}`}>
            Les autres contrôles sont supposés neutres (sans effet sur la note).
          </p>
          <div className="grid gap-4 lg:grid-cols-2">
            {WORKED_EXAMPLES.map((example) => (
              <WorkedExample key={example.title} example={example} />
            ))}
          </div>
        </div>
      </Section>

      <Section id="controles" title="Les contrôles">
        <p className={PROSE}>
          {CHECKS.length} contrôles, présentés famille par famille dans l'ordre du rapport, avec
          leur barème complet et les sources qui les justifient (OWASP en priorité, puis MDN et les
          RFC).
        </p>
        {CATEGORIES.map((category) => (
          <section
            key={category.id}
            aria-labelledby={`methodo-${category.id}`}
            className="space-y-4"
          >
            <div className="space-y-1">
              <h3
                id={`methodo-${category.id}`}
                className="flex items-center gap-2 text-xl font-semibold text-zinc-900 dark:text-zinc-50"
              >
                <CategoryIcon
                  category={category.id}
                  className="size-5 text-indigo-600 dark:text-indigo-400"
                />
                {category.label}
              </h3>
              <p className={`text-sm ${MUTED_TEXT}`}>{category.description}</p>
            </div>
            <div className="space-y-4">
              {CHECKS.filter((check) => check.category === category.id).map((check) => (
                <CheckMethodology key={check.id} check={check} />
              ))}
            </div>
          </section>
        ))}
      </Section>

      <Section id="limites" title="Limites de l'analyse">
        <ul className={`list-disc pl-5 ${PROSE}`}>
          <li>
            Une seule page est analysée : d'autres pages du site peuvent être configurées
            différemment.
          </li>
          <li>
            Le serveur peut répondre différemment selon le visiteur (pays, pare-feu applicatif,
            robot) : SecuScan voit ce que voit un visiteur anonyme situé chez son hébergeur.
          </li>
          <li>
            La révocation des certificats (OCSP, CRL) n'est pas vérifiée : Node.js, qui réalise la
            négociation TLS, ne la contrôle pas.
          </li>
          <li>
            L'éligibilité au préchargement HSTS est estimée d'après l'en-tête, sans consulter la
            liste de préchargement des navigateurs.
          </li>
          <li>
            Un script est dit « tiers » dès que son hôte diffère de celui de la page (règle simple
            de MDN HTTP Observatory) : un sous-domaine du même site compte donc comme tiers.
          </li>
          <li>
            Seules les politiques déclarées dans les en-têtes HTTP, ou dans les balises meta CSP et
            referrer, sont prises en compte ; une configuration appliquée par JavaScript est
            invisible.
          </li>
          <li>
            Le résultat vaut au moment de l'analyse ; une note élevée ne garantit pas l'absence de
            failles. SecuScan donne une indication et ne remplace pas un audit de sécurité.
          </li>
        </ul>
      </Section>

      <Section id="sources" title="Sources">
        <p className={PROSE}>
          La méthode s'appuie sur les sources suivantes ; chaque contrôle cite en plus les
          références qui le justifient.
        </p>
        <ReferenceList references={SOURCES} />
      </Section>
    </div>
  );
}
