// Cache Components étant désactivé (next.config.ts), ce GET n'est pas mis en cache : chaque appel
// reflète l'état réel du service.
import { SCANNER_NAME, SCANNER_VERSION } from "@/lib/config";

interface HealthStatus {
  status: "ok";
  name: string;
  version: string;
}

export function GET(): Response {
  const body: HealthStatus = { status: "ok", name: SCANNER_NAME, version: SCANNER_VERSION };
  return Response.json(body);
}
