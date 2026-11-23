import type { MetadataRoute } from "next";
import { SITE } from "@/lib/site";

const PAGES = [
  { path: "/", priority: 1 },
  { path: "/methodologie", priority: 0.8 },
  { path: "/a-propos", priority: 0.5 },
] as const;

export default function sitemap(): MetadataRoute.Sitemap {
  return PAGES.map((page) => ({
    url: `${SITE.url}${page.path}`,
    // Pas de `lastModified` : une date calculée au build changerait sans que le contenu change.
    changeFrequency: "monthly",
    priority: page.priority,
  }));
}
