/**
 * Tests du rapport complet (ReportView) : en-tête et focus, note et calcul, décompte par statut,
 * familles de contrôles, filtre « Problèmes seulement », panneaux techniques et actions.
 */

import { makeReport, sampleReport } from "@test/fixtures/sample-report";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { CategorySection } from "@/components/report/category-section";
import { ReportView } from "@/components/report/report-view";
import { CATEGORIES } from "@/lib/scanner/labels";
import type { ScanReport } from "@/lib/scanner/types";

/** Rend le rapport et renvoie la fonction « Nouvelle analyse » espionnée. */
function renderReport(report: ScanReport = sampleReport) {
  const onNewScan = vi.fn();
  render(<ReportView report={report} onNewScan={onNewScan} />);
  return { onNewScan };
}

/** Nombre de cartes de contrôle (éléments <details>) dans une section. */
function cardCount(section: HTMLElement): number {
  return section.querySelectorAll("details").length;
}

afterEach(() => {
  vi.restoreAllMocks();
  Reflect.deleteProperty(navigator, "clipboard");
  Reflect.deleteProperty(URL, "createObjectURL");
  Reflect.deleteProperty(URL, "revokeObjectURL");
});

describe("ReportView – en-tête et note", () => {
  it("présente le site analysé et place le focus sur le titre du rapport", () => {
    renderReport();

    const heading = screen.getByRole("heading", {
      level: 2,
      name: "Rapport d'analyse de example.com",
    });
    expect(heading).toHaveFocus();
  });

  it("indique l'adresse, l'IP contactée, la date et la durée de l'analyse", () => {
    renderReport();

    expect(screen.getByText("https://example.com/", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getByText("93.184.215.14")).toBeInTheDocument();
    expect(screen.getByText(/novembre 2026/, { selector: "time" })).toHaveAttribute(
      "datetime",
      sampleReport.scannedAt,
    );
    expect(screen.getByText(/^3,2\ss$/)).toBeInTheDocument();
    // Pas de redirection vers un autre hôte : l'adresse finale n'est pas répétée.
    expect(screen.queryByText("Adresse finale (après redirections)")).not.toBeInTheDocument();
  });

  it("mentionne l'adresse finale quand une redirection a mené ailleurs", () => {
    renderReport(
      makeReport({ target: { ...sampleReport.target, finalUrl: "https://www.example.com/" } }),
    );

    expect(screen.getByText("Adresse finale (après redirections)")).toBeInTheDocument();
    expect(screen.getByText("https://www.example.com/", { selector: "dd" })).toBeInTheDocument();
  });

  it("affiche la note, le score sur 100 et le calcul expliqué en clair", () => {
    renderReport();

    expect(screen.getByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(screen.getByText("55/100")).toBeInTheDocument();
    expect(screen.getByText("Score : 55 sur 100")).toBeInTheDocument();
    expect(screen.getByText("100 − 45 (pénalités) = 55")).toBeInTheDocument();
    expect(screen.getByText(/Les bonus \(\+5\) ne sont pas comptés/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Comment la note est calculée/ })).toHaveAttribute(
      "href",
      "/methodologie#notation",
    );
  });

  it("décompte les contrôles par statut, du plus grave au moins grave", () => {
    renderReport();

    const list = screen.getByRole("list", { name: "Nombre de contrôles par statut" });
    const items = within(list)
      .getAllByRole("listitem")
      .map((item) => item.textContent);
    expect(items).toEqual([
      "À corriger : 1",
      "À améliorer : 4",
      "Non vérifié : 1",
      "Information : 4",
      "Conforme : 8",
    ]);
  });

  it.each([
    400, 404, 503,
  ])("avertit quand la page analysée a répondu par une erreur HTTP (%i)", (status) => {
    renderReport(makeReport({ response: { status, headers: [] } }));

    expect(
      screen.getByText(`Attention : la page analysée a répondu avec le code HTTP ${status}.`),
    ).toBeInTheDocument();
  });

  it.each([200, 399])("n'affiche pas d'avertissement pour un statut %i", (status) => {
    renderReport(makeReport({ response: { status, headers: [] } }));

    expect(screen.queryByText(/a répondu avec le code HTTP/)).not.toBeInTheDocument();
  });
});

describe("ReportView – familles et filtre", () => {
  it("présente les cinq familles dans l'ordre, chacune avec ses contrôles", () => {
    renderReport();

    const titles = screen
      .getAllByRole("heading", { level: 4 })
      .slice(0, CATEGORIES.length)
      .map((heading) => heading.textContent);
    expect(titles).toEqual(CATEGORIES.map((category) => category.label));

    const expectedCounts = { transport: 4, headers: 7, cookies: 1, content: 3, exposure: 3 };
    for (const category of CATEGORIES) {
      const section = screen.getByRole("region", { name: category.label });
      expect(cardCount(section)).toBe(expectedCounts[category.id]);
    }
  });

  it("filtre les problèmes (à corriger et à améliorer), puis revient à la liste complète", () => {
    renderReport();
    const results = screen.getByRole("region", { name: "Résultats par famille" });
    const allOption = screen.getByRole("radio", { name: "Tous (18)" });
    expect(allOption).toBeChecked();
    expect(cardCount(results)).toBe(18);

    const problemsOption = screen.getByRole("radio", { name: "Problèmes seulement (5)" });
    fireEvent.click(problemsOption);

    expect(problemsOption).toBeChecked();
    expect(cardCount(results)).toBe(5);
    const exposure = screen.getByRole("region", { name: "Exposition et bonnes pratiques" });
    expect(
      within(exposure).getByText("Aucun point à corriger ou à améliorer dans cette famille."),
    ).toBeInTheDocument();

    fireEvent.click(allOption);
    expect(cardCount(results)).toBe(18);
  });

  it("explique une famille sans contrôle hors filtre", () => {
    const category = CATEGORIES[0];
    if (!category) throw new Error("Aucune famille définie");
    render(<CategorySection category={category} checks={[]} problemsOnly={false} />);

    expect(screen.getByText("Aucun contrôle dans cette famille.")).toBeInTheDocument();
  });
});

describe("ReportView – détails techniques", () => {
  it("détaille la connexion TLS et le certificat", () => {
    renderReport();

    const panel = screen.getByRole("region", { name: "Connexion TLS" });
    expect(within(panel).getByText("TLS 1.3")).toBeInTheDocument();
    expect(within(panel).getByText("TLS_AES_256_GCM_SHA384")).toBeInTheDocument();
    expect(within(panel).getByText("Let's Encrypt")).toBeInTheDocument();
    expect(within(panel).getByText("EC 256 bits")).toBeInTheDocument();
    expect(within(panel).getByText("example.com, www.example.com")).toBeInTheDocument();
    expect(within(panel).getByText(/encore 60 jours/)).toBeInTheDocument();
    expect(within(panel).getAllByText("refusé")).toHaveLength(2);
  });

  it("explique l'absence d'informations quand la négociation TLS a échoué", () => {
    renderReport(makeReport({ tls: null }));

    const panel = screen.getByRole("region", { name: "Connexion TLS" });
    expect(panel).toHaveTextContent("La négociation TLS a échoué");
  });

  it("montre les chaînes de redirections depuis http:// et https://", () => {
    renderReport();

    const panel = screen.getByRole("region", { name: "Redirections" });
    expect(within(panel).getByText("http://example.com/")).toBeInTheDocument();
    expect(within(panel).getByText(/Redirection permanente vers/)).toBeInTheDocument();
    expect(within(panel).getAllByText("Réponse finale")).toHaveLength(2);
  });

  it("liste les en-têtes bruts dans un tableau, en masquant la valeur des cookies", () => {
    renderReport();

    const panel = screen.getByRole("region", { name: "En-têtes de la réponse" });
    expect(within(panel).getByText("En-têtes reçus (7)")).toBeInTheDocument();
    // En-tête de colonnes + une ligne par en-tête reçu.
    expect(within(panel).getAllByRole("row", { hidden: true })).toHaveLength(8);
    expect(within(panel).getByText("prefs=***; Path=/; SameSite=Lax")).toBeInTheDocument();
    expect(panel).not.toHaveTextContent("theme-dark-42");
  });

  it("explique les sondes en échec, et masque le panneau quand toutes ont réussi", () => {
    renderReport();

    const panel = screen.getByRole("region", { name: "Sondes en échec" });
    expect(within(panel).getByText("Enregistrements DNS CAA")).toBeInTheDocument();
    expect(panel).toHaveTextContent("La requête DNS a dépassé le délai imparti.");
    expect(panel).toHaveTextContent("(TIMEOUT)");
  });

  it("n'affiche pas le panneau des sondes quand aucune n'a échoué", () => {
    renderReport(makeReport({ probeErrors: [] }));

    expect(screen.queryByRole("region", { name: "Sondes en échec" })).not.toBeInTheDocument();
  });
});

describe("ReportView – actions", () => {
  it("« Nouvelle analyse » prévient le composant parent", () => {
    const { onNewScan } = renderReport();

    fireEvent.click(screen.getByRole("button", { name: "Nouvelle analyse" }));

    expect(onNewScan).toHaveBeenCalledTimes(1);
  });

  it("« Copier le lien » copie l'adresse qui relance l'analyse", () => {
    const writeText = vi.fn((_text: string) => Promise.resolve());
    Object.defineProperty(navigator, "clipboard", { value: { writeText }, configurable: true });
    renderReport();

    fireEvent.click(screen.getByRole("button", { name: "Copier le lien de cette analyse" }));

    expect(writeText).toHaveBeenCalledWith(`${window.location.origin}/?url=example.com`);
  });

  it("« Exporter le JSON » télécharge le rapport sous un nom explicite", async () => {
    const createObjectURL = vi.fn((_blob: Blob) => "blob:rapport");
    const revokeObjectURL = vi.fn((_url: string) => undefined);
    Object.defineProperty(URL, "createObjectURL", { value: createObjectURL, configurable: true });
    Object.defineProperty(URL, "revokeObjectURL", { value: revokeObjectURL, configurable: true });
    const clicked: HTMLAnchorElement[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicked.push(this);
    });
    renderReport();

    fireEvent.click(screen.getByRole("button", { name: "Exporter le JSON" }));

    const blob = createObjectURL.mock.calls[0]?.[0];
    expect(blob?.type).toBe("application/json");
    expect(clicked).toHaveLength(1);
    expect(clicked[0]?.download).toBe("secuscan-example.com-2026-11-15.json");
    expect(clicked[0]?.href).toBe("blob:rapport");
    // Le lien temporaire est retiré de la page, puis l'adresse blob: est libérée.
    expect(clicked[0]?.isConnected).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:rapport");
  });
});
