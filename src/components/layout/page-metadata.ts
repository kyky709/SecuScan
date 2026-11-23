/**
 * Next.js fusionne les métadonnées de la mise en page et de la page de façon superficielle : un
 * `openGraph` défini par la page remplace entièrement celui de la mise en page (la locale et le
 * nom du site seraient perdus). Chaque page reçoit donc un objet complet.
 */
import type { Metadata } from "next";
import { SITE } from "@/lib/site";

export const BASE_OPEN_GRAPH = {
  type: "website",
  locale: "fr_FR",
  siteName: SITE.name,
} as const;

export interface PageMetadataInput {
  /** Le modèle « %s · SecuScan » de la mise en page y ajoute le nom du site. */
  title: string;
  description: string;
  path: string;
}

export function pageMetadata({ title, description, path }: PageMetadataInput): Metadata {
  return {
    title,
    description,
    alternates: { canonical: path },
    openGraph: { ...BASE_OPEN_GRAPH, title: `${title} · ${SITE.name}`, description, url: path },
  };
}
