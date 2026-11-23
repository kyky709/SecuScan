// Le moteur ouvre des connexions réseau et ne doit jamais partir dans le bundle client : côté
// interface, importer `@/lib/scanner/types` et `@/lib/scanner/labels` plutôt que ce module.
import "server-only";

export type { ApiErrorBody, ScanErrorCode } from "@/lib/scanner/errors";
export { HTTP_STATUS_BY_CODE, isScanError, ScanError } from "@/lib/scanner/errors";
export type { HostResolver, ScanDependencies } from "@/lib/scanner/scan";
export { scanSite } from "@/lib/scanner/scan";
export { computeScore, gradeFor } from "@/lib/scanner/scoring";
export { normalizeTarget } from "@/lib/scanner/target";
export type * from "@/lib/scanner/types";
