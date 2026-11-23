import { describe, expect, it } from "vitest";
import { GET } from "@/app/api/health/route";
import { SCANNER_NAME, SCANNER_VERSION } from "@/lib/config";

describe("GET /api/health", () => {
  it("répond 200 en JSON avec l'état, le nom et la version du service", async () => {
    const response = GET();

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toMatch(/^application\/json/);
    expect(await response.json()).toEqual({
      status: "ok",
      name: SCANNER_NAME,
      version: SCANNER_VERSION,
    });
  });
});
