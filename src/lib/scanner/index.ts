/**
 * Point d'entrée public du moteur de scan, réservé au serveur.
 *
 * `import "server-only"` fait échouer la compilation si un composant client importe ce module :
 * le moteur ouvre des connexions réseau (node:http, node:tls, node:dns) et ne doit jamais se
 * retrouver dans le JavaScript envoyé au navigateur. Côté interface, on importe les types depuis
 * `@/lib/scanner/types` (sans code exécutable) et les libellés depuis `@/lib/scanner/labels`.
 *
 * La route `/api/scan` n'utilise que ce module : normaliser la saisie, lancer le scan, et
 * convertir une `ScanError` en réponse HTTP.
 */
import "server-only";

export type { ApiErrorBody, ScanErrorCode } from "@/lib/scanner/errors";
export { HTTP_STATUS_BY_CODE, isScanError, ScanError } from "@/lib/scanner/errors";
export type { HostResolver, ScanDependencies } from "@/lib/scanner/scan";
export { scanSite } from "@/lib/scanner/scan";
export { computeScore, gradeFor } from "@/lib/scanner/scoring";
export { normalizeTarget } from "@/lib/scanner/target";
/** Modèle de données complet (ScanReport, CheckResult, ScoreBreakdown…), types uniquement. */
export type * from "@/lib/scanner/types";
