/**
 * Fichier robots.txt (généré par Next.js à l'adresse /robots.txt) : consignes pour les robots
 * d'indexation des moteurs de recherche.
 *
 * Les pages sont indexables, mais deux familles d'adresses sont exclues :
 * - `/api/` : l'API d'analyse n'a rien à indexer ;
 * - `/?url=…` : un lien d'analyse partagé relance une analyse à chaque visite. Un robot qui
 *   suivrait ces liens déclencherait des analyses de sites tiers sans intervention humaine.
 */
import type { MetadataRoute } from "next";
import { SITE } from "@/lib/site";

/** Règles du fichier robots.txt. */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/*?url="] },
    sitemap: `${SITE.url}/sitemap.xml`,
  };
}
