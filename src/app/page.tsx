/**
 * Page d'accueil : présentation de SecuScan et formulaire d'analyse.
 *
 * Composant serveur. La partie interactive (formulaire, attente, rapport) est confiée au
 * composant client ScanApp ; les sections de présentation (« Comment ça marche », « Ce que
 * SecuScan vérifie ») sont rendues ici, côté serveur, puis transmises à ScanApp comme `children` :
 * leur texte n'alourdit pas le JavaScript envoyé au navigateur, et ScanApp les masque dès qu'une
 * analyse est en cours ou affichée.
 */
import type { Metadata } from "next";
import Link from "next/link";
import { pageMetadata } from "@/components/layout/page-metadata";
import { CategoryIcon } from "@/components/report/category-icon";
import { ScanApp } from "@/components/scan/scan-app";
import { CARD, CONTAINER, LINK, MUTED_TEXT } from "@/components/ui/styles";
import { CHECKS } from "@/lib/scanner/checks";
import { CATEGORIES } from "@/lib/scanner/labels";
import { SITE } from "@/lib/site";

export const metadata: Metadata = pageMetadata({
  title: SITE.tagline,
  description: SITE.description,
  path: "/",
});

/** Les trois étapes d'une analyse, du point de vue de l'utilisateur. */
const STEPS = [
  {
    title: "Saisissez l'adresse",
    text: "Indiquez le nom de domaine ou l'adresse de votre site, par exemple exemple.fr.",
  },
  {
    title: "SecuScan observe",
    text: "Il visite le site comme un navigateur : en-têtes HTTP, certificat TLS, cookies, redirections et quelques fichiers publics.",
  },
  {
    title: "Lisez le rapport",
    text: "Une note de A+ à F et, pour chaque contrôle, un constat, une recommandation, des exemples de configuration et des références OWASP.",
  },
] as const;

/** Section « Comment ça marche » : les trois étapes numérotées. */
function HowItWorks() {
  return (
    <section aria-labelledby="fonctionnement-titre" className="space-y-5">
      <h2
        id="fonctionnement-titre"
        className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50"
      >
        Comment ça marche
      </h2>
      <ol className="grid gap-4 sm:grid-cols-3">
        {STEPS.map((step, index) => (
          <li key={step.title} className={`${CARD} space-y-2 p-5`}>
            <span
              aria-hidden="true"
              className="inline-flex size-8 items-center justify-center rounded-full bg-indigo-600 text-sm font-semibold text-white"
            >
              {index + 1}
            </span>
            <h3 className="font-semibold text-zinc-900 dark:text-zinc-50">{step.title}</h3>
            <p className={`text-sm ${MUTED_TEXT}`}>{step.text}</p>
          </li>
        ))}
      </ol>
    </section>
  );
}

/** Section « Ce que SecuScan vérifie » : les cinq familles de contrôles. */
function WhatWeCheck() {
  return (
    <section aria-labelledby="verifications-titre" className="space-y-5">
      <div className="space-y-1">
        <h2
          id="verifications-titre"
          className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-50"
        >
          Ce que SecuScan vérifie
        </h2>
        <p className={`text-sm ${MUTED_TEXT}`}>
          {CHECKS.length} contrôles, répartis en {CATEGORIES.length} familles. Le détail des règles
          et du barème est décrit dans la{" "}
          <Link href="/methodologie" className={LINK}>
            méthodologie
          </Link>
          .
        </p>
      </div>
      <ul className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {CATEGORIES.map((category) => (
          <li key={category.id} className={`${CARD} flex gap-3 p-5`}>
            <CategoryIcon
              category={category.id}
              className="mt-0.5 size-5 shrink-0 text-indigo-600 dark:text-indigo-400"
            />
            <div className="space-y-1">
              <h3 className="font-semibold text-zinc-900 dark:text-zinc-50">{category.label}</h3>
              <p className={`text-sm ${MUTED_TEXT}`}>{category.description}</p>
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}

/** Page d'accueil. */
export default function HomePage() {
  return (
    <div className={`${CONTAINER} space-y-10 py-10 sm:py-16`}>
      <header className="mx-auto max-w-2xl space-y-3 text-center">
        <h1 className="text-3xl font-bold tracking-tight text-balance text-zinc-900 sm:text-4xl dark:text-zinc-50">
          Analysez la sécurité de votre site web
        </h1>
        <p className={`text-base text-pretty sm:text-lg ${MUTED_TEXT}`}>
          SecuScan examine les en-têtes HTTP, le chiffrement TLS, les cookies et les redirections de
          votre site, puis attribue une note de A+ à F, avec des conseils de correction référencés
          OWASP.
        </p>
      </header>
      <ScanApp>
        <HowItWorks />
        <WhatWeCheck />
      </ScanApp>
    </div>
  );
}
