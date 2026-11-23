/**
 * Route GET /api/health : sonde de disponibilité du service.
 *
 * Un outil de supervision, ou une vérification après déploiement, l'interroge pour savoir que
 * l'application répond et quelle version est en ligne. Elle ne lance aucun scan et n'accède pas au
 * réseau : la réponse est immédiate et sans effet de bord. Cache Components étant désactivé
 * (next.config.ts), un gestionnaire GET n'est pas mis en cache : chaque appel reflète l'état réel.
 */
import { SCANNER_NAME, SCANNER_VERSION } from "@/lib/config";

/** Corps de la réponse de /api/health. */
interface HealthStatus {
  status: "ok";
  name: string;
  version: string;
}

/** Indique que le service fonctionne, avec son nom et sa version. */
export function GET(): Response {
  const body: HealthStatus = { status: "ok", name: SCANNER_NAME, version: SCANNER_VERSION };
  return Response.json(body);
}
