/**
 * Tests de la carte d'un contrôle (CheckCard) : dépliage selon le statut, contenu du détail,
 * exemples à copier et références ouvertes en toute sécurité dans un nouvel onglet.
 */

import { sampleCheck } from "@test/fixtures/sample-report";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CheckCard } from "@/components/report/check-card";
import { REFS } from "@/lib/scanner/references";
import type { CheckId } from "@/lib/scanner/types";

/** Installe un faux presse-papiers (absent de jsdom). */
function mockClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
}

/** Rend la carte d'un contrôle du rapport d'exemple et renvoie son élément <details>. */
function renderCard(id: CheckId): HTMLDetailsElement {
  const { container } = render(<CheckCard check={sampleCheck(id)} />);
  const details = container.querySelector("details");
  if (!details) throw new Error("Élément <details> introuvable");
  return details;
}

afterEach(() => {
  Reflect.deleteProperty(navigator, "clipboard");
});

describe("CheckCard", () => {
  it.each<CheckId>([
    "csp",
    "hsts",
  ])("déplie d'office un contrôle à corriger ou à améliorer (%s)", (id) => {
    expect(renderCard(id)).toHaveAttribute("open");
  });

  it.each<CheckId>([
    "tls-protocol",
    "referrer-policy",
    "caa",
  ])("laisse replié un contrôle conforme, informatif ou non vérifié (%s)", (id) => {
    expect(renderCard(id)).not.toHaveAttribute("open");
  });

  it("résume le verdict : titre, effet sur la note et statut en toutes lettres", () => {
    const summary = renderCard("csp").querySelector("summary");
    if (!summary) throw new Error("Résumé introuvable");

    expect(within(summary).getByText("Content Security Policy (CSP)")).toBeInTheDocument();
    expect(within(summary).getByText("À corriger")).toBeInTheDocument();
    expect(within(summary).getByText("−25")).toBeInTheDocument();
    // Les lecteurs d'écran reçoivent une phrase plutôt qu'un nombre signé.
    expect(summary).toHaveTextContent("pénalité de 25 points");
  });

  it("présente le rôle du mécanisme, le constat, la valeur observée et la recommandation", () => {
    renderCard("hsts");

    expect(screen.getByText("À quoi ça sert ?")).toBeInTheDocument();
    expect(screen.getByText(/impose au navigateur d'utiliser HTTPS/)).toBeInTheDocument();
    expect(screen.getByText(/max-age=86400 \(1 jour\)/)).toBeInTheDocument();
    expect(screen.getByText("Valeur observée")).toBeInTheDocument();
    expect(screen.getByText("max-age=86400", { selector: "pre" })).toBeInTheDocument();
    expect(screen.getByText("Recommandation")).toBeInTheDocument();
    expect(screen.getByText("Portez max-age à au moins 31536000 (un an).")).toBeInTheDocument();
  });

  it("liste les constats détaillés", () => {
    renderCard("csp");

    expect(
      screen.getByText("Une politique Report-Only seule n'offre aucune protection."),
    ).toBeInTheDocument();
  });

  it("n'affiche ni valeur observée, ni recommandation, ni exemple quand il n'y en a pas", () => {
    renderCard("tls-protocol");

    expect(screen.queryByText("Valeur observée")).not.toBeInTheDocument();
    expect(screen.queryByText("Recommandation")).not.toBeInTheDocument();
    expect(screen.queryByText("Exemples de configuration")).not.toBeInTheDocument();
  });

  it("propose chaque exemple de configuration avec un bouton de copie au nom distinct", () => {
    renderCard("csp");

    expect(screen.getByText("Exemples de configuration")).toBeInTheDocument();
    for (const label of ["Nginx", "Apache", "Next.js (next.config.ts)"]) {
      expect(screen.getByRole("button", { name: `Copier l'exemple ${label}` })).toBeInTheDocument();
    }
  });

  it("copie un exemple dans le presse-papiers et le confirme", async () => {
    const writeText = vi.fn((_text: string) => Promise.resolve());
    mockClipboard(writeText);
    renderCard("csp");

    fireEvent.click(screen.getByRole("button", { name: "Copier l'exemple Nginx" }));

    expect(writeText).toHaveBeenCalledWith(
      expect.stringContaining("add_header Content-Security-Policy"),
    );
    expect(await screen.findByText("Copié dans le presse-papiers.")).toBeInTheDocument();
    expect(screen.getByText("Copié")).toBeInTheDocument();
  });

  it("signale l'échec de la copie au lieu d'échouer en silence", async () => {
    mockClipboard(() => Promise.reject(new Error("Permission refusée")));
    renderCard("csp");

    fireEvent.click(screen.getByRole("button", { name: "Copier l'exemple Apache" }));

    expect(await screen.findByText("Copie impossible")).toBeInTheDocument();
    expect(screen.getByText(/La copie a échoué/)).toBeInTheDocument();
  });

  it("ouvre les références dans un nouvel onglet, sans donner accès à la page d'origine", () => {
    renderCard("csp");

    const link = screen.getByRole("link", { name: /OWASP – Content Security Policy Cheat Sheet/ });
    expect(link).toHaveAttribute("href", REFS.cheatSheets.csp.url);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    expect(link).toHaveAccessibleName(/\(nouvel onglet\)$/);
  });

  it("indique la nature de chaque référence par un badge", () => {
    renderCard("csp");

    for (const badge of ["Cheat Sheet", "OWASP Top 10", "ASVS", "MDN"]) {
      expect(screen.getByText(badge)).toBeInTheDocument();
    }
  });

  it("renvoie vers la fiche du contrôle dans la méthodologie", () => {
    renderCard("csp");

    expect(screen.getByRole("link", { name: /Comment ce contrôle est noté/ })).toHaveAttribute(
      "href",
      "/methodologie#controle-csp",
    );
  });
});
