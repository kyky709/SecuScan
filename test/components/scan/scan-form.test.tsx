/**
 * Tests du formulaire d'analyse (ScanForm) : étiquette et aide accessibles, validation d'une
 * saisie vide, exemples cliquables et comportement pendant une analyse.
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { EMPTY_URL_MESSAGE, EXAMPLE_SITES, ScanForm } from "@/components/scan/scan-form";

interface HarnessProps {
  onSubmit: (url: string) => void;
  isLoading?: boolean;
  initialValue?: string;
}

/** Le formulaire est contrôlé : ce petit parent garde la valeur du champ, comme ScanApp. */
function Harness({ onSubmit, isLoading = false, initialValue = "" }: HarnessProps) {
  const [value, setValue] = useState(initialValue);
  return (
    <ScanForm value={value} onValueChange={setValue} onSubmit={onSubmit} isLoading={isLoading} />
  );
}

/** Champ de saisie de l'adresse. */
function urlInput(): HTMLInputElement {
  return screen.getByLabelText("Adresse du site");
}

describe("ScanForm", () => {
  it("relie l'étiquette, l'exemple de saisie et la note « Analyse passive » au champ", () => {
    render(<Harness onSubmit={vi.fn()} />);

    const input = urlInput();
    expect(input).toHaveAttribute("placeholder", "exemple.fr");
    expect(input).toHaveAttribute("type", "text");
    expect(input).toHaveAttribute("inputmode", "url");
    expect(input).toHaveAccessibleDescription(
      "Analyse passive : SecuScan consulte votre site comme un navigateur, sans l'attaquer.",
    );
    expect(screen.getByRole("button", { name: "Analyser" })).toHaveAttribute("type", "submit");
  });

  it("transmet l'adresse saisie, sans les espaces superflus", () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} />);

    fireEvent.change(urlInput(), { target: { value: "  mozilla.org  " } });
    fireEvent.click(screen.getByRole("button", { name: "Analyser" }));

    expect(onSubmit).toHaveBeenCalledWith("mozilla.org");
  });

  it("accepte aussi la touche Entrée (envoi du formulaire)", () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} initialValue="example.com" />);

    const form = urlInput().closest("form");
    if (!form) throw new Error("Formulaire introuvable");
    fireEvent.submit(form);

    expect(onSubmit).toHaveBeenCalledWith("example.com");
  });

  it("refuse une adresse vide, l'explique et ramène le focus dans le champ", () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} initialValue="   " />);

    fireEvent.click(screen.getByRole("button", { name: "Analyser" }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(screen.getByRole("alert")).toHaveTextContent(EMPTY_URL_MESSAGE);
    const input = urlInput();
    expect(input).toHaveAttribute("aria-invalid", "true");
    expect(input).toHaveAccessibleDescription(new RegExp(EMPTY_URL_MESSAGE.replace(/\./g, "\\.")));
    expect(input).toHaveFocus();
  });

  it("efface l'erreur dès que la saisie est corrigée", () => {
    render(<Harness onSubmit={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Analyser" }));
    expect(screen.getByRole("alert")).toBeInTheDocument();

    fireEvent.change(urlInput(), { target: { value: "e" } });

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(urlInput()).not.toHaveAttribute("aria-invalid");
  });

  it("propose les trois exemples prévus", () => {
    render(<Harness onSubmit={vi.fn()} />);

    expect(EXAMPLE_SITES).toEqual(["mozilla.org", "github.com", "example.com"]);
    for (const site of EXAMPLE_SITES) {
      expect(screen.getByRole("button", { name: `Analyser ${site}` })).toBeInTheDocument();
    }
  });

  it("lance l'analyse d'un exemple en un clic et l'inscrit dans le champ", () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} />);

    fireEvent.click(screen.getByRole("button", { name: "Analyser github.com" }));

    expect(onSubmit).toHaveBeenCalledWith("github.com");
    expect(urlInput()).toHaveValue("github.com");
  });

  it("pendant une analyse, garde le bouton focalisable mais ignore les nouvelles demandes", () => {
    const onSubmit = vi.fn();
    render(<Harness onSubmit={onSubmit} isLoading initialValue="example.com" />);

    const button = screen.getByRole("button", { name: "Analyse en cours…" });
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).toBeEnabled();

    fireEvent.click(button);
    fireEvent.click(screen.getByRole("button", { name: "Analyser mozilla.org" }));

    expect(onSubmit).not.toHaveBeenCalled();
    expect(urlInput()).toHaveValue("example.com");
  });
});
