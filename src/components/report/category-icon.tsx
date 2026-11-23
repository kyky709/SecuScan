import { Cookie, Eye, Layers, ListChecks, Lock, type LucideIcon } from "lucide-react";
import type { CheckCategory } from "@/lib/scanner/types";

const CATEGORY_ICONS: Record<CheckCategory, LucideIcon> = {
  transport: Lock,
  headers: ListChecks,
  cookies: Cookie,
  content: Layers,
  exposure: Eye,
};

// Décorative : le nom de la famille est toujours écrit à côté.
export function CategoryIcon({
  category,
  className = "size-5",
}: {
  category: CheckCategory;
  className?: string;
}) {
  const Icon = CATEGORY_ICONS[category];
  return <Icon aria-hidden="true" className={className} />;
}
