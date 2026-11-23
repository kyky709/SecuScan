import { fileURLToPath } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

/**
 * Configuration des tests (Vitest).
 *
 * Deux « projets » partagent la même configuration de base :
 * - `node`  : logique serveur (moteur de scan, API), fichiers `*.test.ts` ;
 * - `dom`   : composants React rendus dans jsdom, fichiers `*.test.tsx`.
 */
export default defineConfig({
  plugins: [react()],
  resolve: {
    // Résout l'alias `@/*` déclaré dans tsconfig.json (support natif de Vite 8).
    tsconfigPaths: true,
    alias: {
      // `server-only` lève une erreur hors d'un Server Component : on le neutralise en test.
      "server-only": fileURLToPath(new URL("./test/stubs/server-only.ts", import.meta.url)),
    },
  },
  test: {
    testTimeout: 15_000,
    projects: [
      {
        extends: true,
        test: { name: "node", include: ["test/**/*.test.ts"], environment: "node" },
      },
      {
        extends: true,
        test: {
          name: "dom",
          include: ["test/**/*.test.tsx"],
          environment: "jsdom",
          setupFiles: ["./test/setup-dom.ts"],
        },
      },
    ],
    coverage: {
      provider: "v8",
      include: ["src/lib/**/*.ts"],
      reporter: ["text", "html", "lcov"],
      thresholds: { lines: 80, functions: 80, branches: 75, statements: 80 },
    },
  },
});
