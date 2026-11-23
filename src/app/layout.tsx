// Polices servies par le site lui-même (next/font, téléchargées au build) : la CSP impose
// `font-src 'self'`, et c'est préférable pour la vie privée des visiteurs.
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

export const metadata: Metadata = {
  metadataBase: new URL(SITE.url),
  title: { default: `${SITE.name} · ${SITE.tagline}`, template: `%s · ${SITE.name}` },
  description: SITE.description,
  applicationName: SITE.name,
  openGraph: { ...BASE_OPEN_GRAPH, title: SITE.name, description: SITE.description, url: "/" },
};

export const viewport: Viewport = {
  colorScheme: "light dark",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#09090b" },
  ],
};

export default async function RootLayout({ children }: LayoutProps<"/">) {
  // La CSP repose sur un nonce renouvelé à chaque requête (src/proxy.ts), que Next.js ajoute à ses
  // balises <script> seulement si la page est rendue au moment de la requête : une page pré-rendue
  // au build aurait des scripts sans nonce, bloqués par le navigateur. `connection()` impose ce
  // rendu dynamique à tout le site, puisque la mise en page racine l'englobe.
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
