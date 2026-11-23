/**
 * Mise en page racine : structure HTML commune à toutes les pages de SecuScan.
 *
 * Elle définit la langue du document (`lang="fr"`, indispensable pour que les lecteurs d'écran
 * prononcent correctement le texte), les polices, les métadonnées par défaut et les repères de
 * navigation : lien d'évitement, en-tête (`banner`), contenu principal (`main`) et pied de page
 * (`contentinfo`).
 *
 * Les polices viennent de next/font : elles sont téléchargées au moment du build et servies par
 * le site lui-même, si bien que les pages ne chargent aucune ressource externe (exigé par la
 * Content-Security-Policy, `font-src 'self'`, et préférable pour la vie privée des visiteurs).
 */
import type { Metadata, Viewport } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { connection } from "next/server";
import { BASE_OPEN_GRAPH } from "@/components/layout/page-metadata";
import { SiteFooter } from "@/components/layout/site-footer";
import { SiteHeader } from "@/components/layout/site-header";
import { SkipLink } from "@/components/layout/skip-link";
import { SITE } from "@/lib/site";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

/** Métadonnées par défaut, complétées par chaque page (voir page-metadata.ts). */
export const metadata: Metadata = {
  // Base des adresses relatives (adresse canonique, Open Graph).
  metadataBase: new URL(SITE.url),
  title: { default: `${SITE.name} · ${SITE.tagline}`, template: `%s · ${SITE.name}` },
  description: SITE.description,
  applicationName: SITE.name,
  openGraph: { ...BASE_OPEN_GRAPH, title: SITE.name, description: SITE.description, url: "/" },
};

/** Couleur de l'interface du navigateur mobile, accordée aux thèmes clair et sombre. */
export const viewport: Viewport = {
  colorScheme: "light dark",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#09090b" },
  ],
};

/** Mise en page commune à toutes les pages. */
export default async function RootLayout({ children }: LayoutProps<"/">) {
  // La Content-Security-Policy de SecuScan repose sur un nonce aléatoire, renouvelé à chaque
  // requête (src/proxy.ts) : seuls les scripts qui portent ce nonce peuvent s'exécuter. Next.js
  // l'ajoute à ses propres balises <script> pendant le rendu, à condition que la page soit rendue
  // au moment de la requête. Une page pré-rendue au build contiendrait des scripts sans nonce, que
  // le navigateur bloquerait. `await connection()` impose donc un rendu dynamique, et comme la
  // mise en page racine englobe tout le site, cela vaut pour toutes les pages.
  await connection();

  return (
    <html lang="fr" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body className="flex min-h-dvh flex-col bg-white font-sans text-zinc-900 antialiased dark:bg-zinc-950 dark:text-zinc-100">
        <SkipLink />
        <SiteHeader />
        {/* tabIndex={-1} : le lien d'évitement peut y déplacer le focus, sans l'ajouter à l'ordre de tabulation. */}
        <main id="contenu" tabIndex={-1} className="flex-1 outline-none">
          {children}
        </main>
        <SiteFooter />
      </body>
    </html>
  );
}
