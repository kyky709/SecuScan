/**
 * Plan du site (généré par Next.js à l'adresse /sitemap.xml) : la liste des pages publiques, pour
 * aider les moteurs de recherche à les découvrir.
 *
 * Pas de date de modification : une date calculée à chaque build (`new Date()`) changerait sans
 * que le contenu change, ce qui la rendrait trompeuse.
 */
import type { MetadataRoute } from "next";
import { SITE } from "@/lib/site";

/** Pages publiques, de la plus importante à la moins importante. */
const PAGES = [
  { path: "/", priority: 1 },
  { path: "/methodologie", priority: 0.8 },
  { path: "/a-propos", priority: 0.5 },
] as const;

/** Entrées du plan du site. */
export default function sitemap(): MetadataRoute.Sitemap {
  return PAGES.map((page) => ({
    url: `${SITE.url}${page.path}`,
    changeFrequency: "monthly",
    priority: page.priority,
  }));
}
