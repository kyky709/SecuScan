/**
 * Tests de la carte d'attente (LoadingCard) : les étapes défilent sur un minuteur et s'arrêtent
 * sur la dernière, avec leur état lisible par les lecteurs d'écran.
 */
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { LOADING_STEPS, LoadingCard, STEP_DURATION_MS } from "@/components/scan/loading-card";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("LoadingCard", () => {
  it("affiche les cinq étapes prévues, la première en cours", () => {
    render(<LoadingCard />);

    expect(LOADING_STEPS).toEqual([
      "DNS et adresse",
      "Connexion HTTPS et TLS",
      "En-têtes et cookies",
      "Contenu de la page",
      "Calcul de la note",
    ]);
    expect(screen.getByText("Analyse en cours…")).toBeInTheDocument();
    expect(screen.getByText("DNS et adresse")).toHaveTextContent("DNS et adresse : en cours");
    expect(screen.getByText("Calcul de la note")).toHaveTextContent(": à venir");
  });

  it("passe à l'étape suivante à intervalle régulier", () => {
    render(<LoadingCard />);

    act(() => {
      vi.advanceTimersByTime(STEP_DURATION_MS);
    });

    expect(screen.getByText("DNS et adresse")).toHaveTextContent(": terminé");
    expect(screen.getByText("Connexion HTTPS et TLS")).toHaveTextContent(": en cours");
  });

  it("reste sur la dernière étape tant que la réponse n'est pas arrivée", () => {
    render(<LoadingCard />);

    act(() => {
      vi.advanceTimersByTime(STEP_DURATION_MS * 20);
    });

    expect(screen.getByText("Contenu de la page")).toHaveTextContent(": terminé");
    expect(screen.getByText("Calcul de la note")).toHaveTextContent(": en cours");
  });
});
