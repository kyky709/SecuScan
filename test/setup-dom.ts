// Préparation des tests de composants (environnement jsdom).
import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Démonte les composants rendus après chaque test pour isoler les cas.
afterEach(() => {
  cleanup();
});
