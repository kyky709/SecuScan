import { makeReport, sampleReport } from "@test/fixtures/sample-report";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { StrictMode } from "react";
import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest";
import { ScanApp } from "@/components/scan/scan-app";

function jsonResponse(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: { "Content-Type": "application/json" },
  });
}

function renderApp() {
  return render(
    <ScanApp>
      <p>Présentation du service</p>
    </ScanApp>,
  );
}

function submit(url: string) {
  fireEvent.change(screen.getByLabelText("Adresse du site"), { target: { value: url } });
  fireEvent.click(screen.getByRole("button", { name: "Analyser" }));
}

let fetchMock: Mock<typeof fetch>;

beforeEach(() => {
  window.history.replaceState(null, "", "/");
  fetchMock = vi.fn<typeof fetch>();
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ScanApp", () => {
  it("affiche la présentation tant qu'aucune analyse n'est lancée", () => {
    renderApp();

    expect(screen.getByText("Présentation du service")).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("envoie l'adresse à l'API, puis affiche la note et place le focus sur le rapport", async () => {
    fetchMock.mockResolvedValue(jsonResponse(sampleReport));
    renderApp();

    submit("example.com");

    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scan",
      expect.objectContaining({ method: "POST", body: JSON.stringify({ url: "example.com" }) }),
    );
    expect(await screen.findByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(
      screen.getByRole("heading", { level: 2, name: "Rapport d'analyse de example.com" }),
    ).toHaveFocus();
    expect(screen.getByRole("status")).toHaveTextContent(
      "Analyse terminée : note C, score de 55 sur 100.",
    );
    expect(window.location.search).toBe("?url=example.com");
    expect(screen.queryByText("Présentation du service")).not.toBeInTheDocument();
  });

  it("indique l'avancement pendant l'analyse", async () => {
    let respond: (response: Response) => void = () => {};
    fetchMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        respond = resolve;
      }),
    );
    renderApp();

    submit("example.com");

    expect(screen.getByRole("status")).toHaveTextContent("Analyse en cours…");
    expect(screen.getByRole("button", { name: "Analyse en cours…" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(screen.getByText("Connexion HTTPS et TLS")).toBeInTheDocument();
    expect(screen.queryByText("Présentation du service")).not.toBeInTheDocument();

    await act(async () => {
      respond(jsonResponse(sampleReport));
    });

    expect(await screen.findByRole("img", { name: "Note C" })).toBeInTheDocument();
    expect(screen.queryByText("Connexion HTTPS et TLS")).not.toBeInTheDocument();
  });

  it("indique quand réessayer si la limite de débit est atteinte (429)", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "RATE_LIMITED",
            message: "Trop d'analyses en peu de temps.",
            retryAfterSeconds: 42,
          },
        },
        { status: 429 },
      ),
    );
    renderApp();

    submit("example.com");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("L'analyse n'a pas pu aboutir");
    expect(alert).toHaveTextContent(
      "Trop d'analyses en peu de temps. Vous pourrez réessayer dans 42 secondes.",
    );
    expect(window.location.search).toBe("");
    expect(screen.getByText("Présentation du service")).toBeInTheDocument();
  });

  it("affiche le message de l'API pour une adresse refusée", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        {
          error: {
            code: "TARGET_NOT_ALLOWED",
            message: "Cette adresse ne peut pas être analysée.",
          },
        },
        { status: 422 },
      ),
    );
    renderApp();

    submit("localhost");

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Cette adresse ne peut pas être analysée.",
    );
  });

  it("signale une panne réseau", async () => {
    fetchMock.mockRejectedValue(new TypeError("Failed to fetch"));
    renderApp();

    submit("example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent("Impossible de joindre SecuScan.");
  });

  it("relance l'analyse d'un lien partagé (?url=) dès le chargement", async () => {
    window.history.replaceState(null, "", "/?url=github.com");
    const githubReport = makeReport({
      target: { ...sampleReport.target, input: "github.com", hostname: "github.com" },
    });
    fetchMock.mockResolvedValue(jsonResponse(githubReport));

    renderApp();

    expect(screen.getByLabelText("Adresse du site")).toHaveValue("github.com");
    expect(fetchMock).toHaveBeenCalledWith(
      "/api/scan",
      expect.objectContaining({ body: JSON.stringify({ url: "github.com" }) }),
    );
    expect(
      await screen.findByRole("heading", { level: 2, name: "Rapport d'analyse de github.com" }),
    ).toBeInTheDocument();
    expect(window.location.search).toBe("?url=github.com");
  });

  it("« Nouvelle analyse » revient au formulaire vide, prêt à la saisie", async () => {
    fetchMock.mockResolvedValue(jsonResponse(sampleReport));
    renderApp();
    submit("example.com");
    await screen.findByRole("img", { name: "Note C" });

    fireEvent.click(screen.getByRole("button", { name: "Nouvelle analyse" }));

    expect(screen.queryByRole("img", { name: "Note C" })).not.toBeInTheDocument();
    const input = screen.getByLabelText("Adresse du site");
    expect(input).toHaveValue("");
    expect(input).toHaveFocus();
    expect(window.location.search).toBe("");
    expect(screen.getByText("Présentation du service")).toBeInTheDocument();
  });

  it("annule l'analyse en cours quand l'application disparaît", () => {
    fetchMock.mockReturnValue(new Promise<Response>(() => {}));
    const { unmount } = renderApp();
    submit("example.com");
    const signal = fetchMock.mock.calls[0]?.[1]?.signal;
    expect(signal?.aborted).toBe(false);

    unmount();

    expect(signal?.aborted).toBe(true);
  });

  it("ignore la réponse d'une analyse annulée (double montage du mode strict)", async () => {
    window.history.replaceState(null, "", "/?url=example.com");
    fetchMock.mockImplementation(() => Promise.resolve(jsonResponse(sampleReport)));

    render(
      <StrictMode>
        <ScanApp />
      </StrictMode>,
    );

    // React monte, démonte puis remonte le composant : la première analyse est annulée.
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(fetchMock.mock.calls[0]?.[1]?.signal?.aborted).toBe(true);
    expect(fetchMock.mock.calls[1]?.[1]?.signal?.aborted).toBe(false);
    expect(await screen.findByRole("img", { name: "Note C" })).toBeInTheDocument();
  });
});
