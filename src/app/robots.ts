import type { MetadataRoute } from "next";
import { SITE } from "@/lib/site";

// `/?url=…` relance une analyse à chaque visite : un robot qui suivrait ces liens déclencherait
// des analyses de sites tiers sans intervention humaine.
export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: "*", allow: "/", disallow: ["/api/", "/*?url="] },
    sitemap: `${SITE.url}/sitemap.xml`,
  };
}
