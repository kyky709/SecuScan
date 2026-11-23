/**
 * Métadonnées (titre, description, Open Graph) communes aux pages de SecuScan.
 *
 * Next.js fusionne les métadonnées de la mise en page et de la page de façon superficielle :
 * si une page définit `openGraph`, celui de la mise en page est entièrement remplacé (la langue
 * `fr_FR` et le nom du site seraient perdus). Cette fonction construit donc, pour chaque page,
 * un objet complet à partir d'une base partagée.
 * Voir node_modules/next/dist/docs/01-app/03-api-reference/04-functions/generate-metadata.md.
 */
import type { Metadata } from "next";
import { SITE } from "@/lib/site";

/** Champs Open Graph identiques sur toutes les pages. */
export const BASE_OPEN_GRAPH = {
  type: "website",
  locale: "fr_FR",
  siteName: SITE.name,
} as const;

export interface PageMetadataInput {
  /** Titre de la page (le modèle « %s · SecuScan » de la mise en page y ajoute le nom du site). */
  title: string;
  description: string;
  /** Chemin de la page, ex. « /methodologie » (complété par `metadataBase`). */
  path: string;
}

/** Métadonnées d'une page : titre, description, adresse canonique et Open Graph. */
export function pageMetadata({ title, description, path }: PageMetadataInput): Metadata {
  return {
    title,
    description,
    alternates: { canonical: path },
    openGraph: { ...BASE_OPEN_GRAPH, title: `${title} · ${SITE.name}`, description, url: path },
  };
}
