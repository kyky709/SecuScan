/**
 * Tests de `normalizeTarget` : normalisation de la saisie et premières barrières anti-SSRF.
 *
 * La politique d'adresses IP (`checkAddress`) appartient à la couche réseau, qui a ses propres
 * tests : ici, elle est remplacée par une doublure qui n'accepte que quelques adresses publiques.
 * On vérifie surtout que l'adresse contrôlée est la forme NORMALISÉE par le parseur d'URL
 * (« 2130706433 » → « 127.0.0.1 ») : c'est elle, et non la saisie brute, qui sera contactée.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_URL_LENGTH } from "@/lib/config";
import type { ScanErrorCode } from "@/lib/scanner/errors";
import { isScanError } from "@/lib/scanner/errors";
import { normalizeTarget } from "@/lib/scanner/target";

const { checkAddress } = vi.hoisted(() => {
  const publicAddresses = new Set(["1.1.1.1", "93.184.215.14", "2606:4700:4700::1111"]);
  return {
    checkAddress: vi.fn((address: string) =>
      publicAddresses.has(address)
        ? { allowed: true, address, family: address.includes(":") ? 6 : 4 }
        : { allowed: false, address, reason: "adresse non publique", range: "private" },
    ),
  };
});

vi.mock("@/lib/scanner/network/ip", () => ({ checkAddress }));

/** Code de la ScanError levée par `normalizeTarget`, ou null si la saisie est acceptée. */
function rejectionCode(input: string): ScanErrorCode | null {
  try {
    normalizeTarget(input);
    return null;
  } catch (error) {
    if (isScanError(error)) return error.code;
    throw error;
  }
}

beforeEach(() => {
  checkAddress.mockClear();
});

describe("normalizeTarget — noms de domaine acceptés", () => {
  it.each<[input: string, url: string, hostname: string]>([
    ["example.com", "https://example.com/", "example.com"],
    ["  example.com  ", "https://example.com/", "example.com"],
    ["EXAMPLE.COM", "https://example.com/", "example.com"],
    ["http://example.com", "https://example.com/", "example.com"],
    ["HTTPS://Example.COM/Page?Tri=Prix", "https://example.com/Page?Tri=Prix", "example.com"],
    ["https://example.com/a?b=c#section", "https://example.com/a?b=c", "example.com"],
    ["example.com.", "https://example.com/", "example.com"],
    ["example.com:443", "https://example.com/", "example.com"],
    ["example.com:80/contact", "https://example.com/contact", "example.com"],
    ["http://example.com:443/", "https://example.com/", "example.com"],
    ["https://example.com:443/", "https://example.com/", "example.com"],
    ["www.example.co.uk/blog/", "https://www.example.co.uk/blog/", "www.example.co.uk"],
    ["bücher.de", "https://xn--bcher-kva.de/", "xn--bcher-kva.de"],
    ["BÜCHER.DE/Prix", "https://xn--bcher-kva.de/Prix", "xn--bcher-kva.de"],
    ["пример.рф", "https://xn--e1afmkfd.xn--p1ai/", "xn--e1afmkfd.xn--p1ai"],
    ["example.com/a b", "https://example.com/a%20b", "example.com"],
    ["notlocalhost.com", "https://notlocalhost.com/", "notlocalhost.com"],
  ])("« %s » → %s", (input, url, hostname) => {
    expect(normalizeTarget(input)).toEqual({
      input: input.trim(),
      url,
      hostname,
      isIpAddress: false,
    });
  });

  it("ne soumet pas un nom de domaine à la politique d'adresses IP (vérifié après résolution DNS)", () => {
    normalizeTarget("example.com");
    expect(checkAddress).not.toHaveBeenCalled();
  });

  it("accepte une adresse de 2 048 caractères exactement", () => {
    const base = "https://example.com/";
    const input = `${base}${"a".repeat(MAX_URL_LENGTH - base.length)}`;
    expect(input).toHaveLength(MAX_URL_LENGTH);
    expect(normalizeTarget(input).url).toBe(input);
  });
});

describe("normalizeTarget — adresses IP littérales", () => {
  it.each<[input: string, url: string, hostname: string]>([
    ["1.1.1.1", "https://1.1.1.1/", "1.1.1.1"],
    ["http://1.1.1.1:80/dns", "https://1.1.1.1/dns", "1.1.1.1"],
    ["[2606:4700:4700::1111]", "https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"],
    ["2606:4700:4700::1111", "https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"],
    [
      "https://[2606:4700:4700::1111]:443/",
      "https://[2606:4700:4700::1111]/",
      "2606:4700:4700::1111",
    ],
    ["[2606:4700:4700:0:0:0:0:1111]", "https://[2606:4700:4700::1111]/", "2606:4700:4700::1111"],
  ])("adresse publique « %s » acceptée → %s", (input, url, hostname) => {
    expect(normalizeTarget(input)).toEqual({ input, url, hostname, isIpAddress: true });
    expect(checkAddress).toHaveBeenLastCalledWith(hostname);
  });

  it.each<[input: string, normalized: string]>([
    ["127.0.0.1", "127.0.0.1"],
    ["http://127.1/", "127.0.0.1"],
    ["2130706433", "127.0.0.1"],
    ["0x7f000001", "127.0.0.1"],
    ["0x7f.0.0.1", "127.0.0.1"],
    ["0177.0.0.1", "127.0.0.1"],
    ["10.0.0.1", "10.0.0.1"],
    ["http://169.254.169.254/latest/meta-data/", "169.254.169.254"],
    ["0.0.0.0", "0.0.0.0"],
    ["http://0/", "0.0.0.0"],
    ["[::1]", "::1"],
    ["::1", "::1"],
    ["[0:0:0:0:0:0:0:1]", "::1"],
    ["[::ffff:127.0.0.1]", "::ffff:7f00:1"],
    ["[fd00::1]", "fd00::1"],
    ["[fe80::1]", "fe80::1"],
  ])("adresse non publique « %s » (normalisée en %s) → TARGET_NOT_ALLOWED", (input, normalized) => {
    expect(rejectionCode(input)).toBe("TARGET_NOT_ALLOWED");
    expect(checkAddress).toHaveBeenLastCalledWith(normalized);
  });
});

describe("normalizeTarget — saisies refusées", () => {
  it.each<[input: string, code: ScanErrorCode]>([
    // Saisie vide, illisible ou mal formée
    ["", "INVALID_URL"],
    ["    ", "INVALID_URL"],
    ["exa\tmple.com", "INVALID_URL"],
    ["exa\nmple.com", "INVALID_URL"],
    ["https://", "INVALID_URL"],
    ["http://exa mple.com", "INVALID_URL"],
    ["https://example.com:99999/", "INVALID_URL"],
    // Schémas autres que http et https
    ["javascript:alert(1)", "UNSUPPORTED_PROTOCOL"],
    ["JavaScript:alert(document.cookie)", "UNSUPPORTED_PROTOCOL"],
    ["file:///etc/passwd", "UNSUPPORTED_PROTOCOL"],
    ["ftp://example.com/", "UNSUPPORTED_PROTOCOL"],
    ["gopher://example.com/", "UNSUPPORTED_PROTOCOL"],
    ["data:text/html,<script>alert(1)</script>", "UNSUPPORTED_PROTOCOL"],
    // Identifiants dans l'adresse
    ["https://user:pass@example.com/", "CREDENTIALS_IN_URL"],
    ["https://admin@example.com/", "CREDENTIALS_IN_URL"],
    ["https://:secret@example.com/", "CREDENTIALS_IN_URL"],
    ["user@example.com", "CREDENTIALS_IN_URL"],
    // « user: » ressemble à un schéma, mais l'arobase trahit des identifiants (sans « https:// »).
    ["user:pw@example.com", "CREDENTIALS_IN_URL"],
    ["admin:@example.com/page", "CREDENTIALS_IN_URL"],
    ["mailto:contact@example.com", "UNSUPPORTED_PROTOCOL"],
    ["https://example.com:443@evil.example.org/", "CREDENTIALS_IN_URL"],
    // Ports autres que 80 et 443
    ["example.com:8080", "FORBIDDEN_PORT"],
    ["https://example.com:22/", "FORBIDDEN_PORT"],
    ["http://example.com:0/", "FORBIDDEN_PORT"],
    ["localhost:3000/admin", "FORBIDDEN_PORT"],
    // Noms réservés à un usage local, privé ou de test
    ["localhost", "TARGET_NOT_ALLOWED"],
    ["LOCALHOST.", "TARGET_NOT_ALLOWED"],
    // Déguisements ramenés à « localhost » par la normalisation des URL (IDNA, %-encodage de l'hôte)
    ["ⓛⓞⓒⓐⓛⓗⓞⓢⓣ", "TARGET_NOT_ALLOWED"],
    ["localhost%2e", "TARGET_NOT_ALLOWED"],
    ["app.localhost", "TARGET_NOT_ALLOWED"],
    ["imprimante.local", "TARGET_NOT_ALLOWED"],
    ["metadata.google.internal", "TARGET_NOT_ALLOWED"],
    ["box.home.arpa", "TARGET_NOT_ALLOWED"],
    ["nas.lan", "TARGET_NOT_ALLOWED"],
    ["site.test", "TARGET_NOT_ALLOWED"],
    ["secuscan-cors-probe.invalid", "TARGET_NOT_ALLOWED"],
    ["www.example", "TARGET_NOT_ALLOWED"],
    ["exemple3xyzabc.onion", "TARGET_NOT_ALLOWED"],
    // Noms sans extension ou mal formés
    ["intranet", "INVALID_URL"],
    ["example.c", "INVALID_URL"],
    ["example.c0m", "INVALID_URL"],
    ["exa$mple.com", "INVALID_URL"],
    ["example..com", "INVALID_URL"],
    [`${"a".repeat(64)}.com`, "INVALID_URL"],
  ])("« %s » → %s", (input, code) => {
    expect(rejectionCode(input)).toBe(code);
  });

  it("refuse un nom de domaine de plus de 253 caractères", () => {
    const hostname = `${Array.from({ length: 5 }, () => "a".repeat(60)).join(".")}.com`;
    expect(hostname.length).toBeGreaterThan(253);
    expect(rejectionCode(hostname)).toBe("INVALID_URL");
  });

  it("refuse une adresse de plus de 2 048 caractères", () => {
    expect(rejectionCode(`https://example.com/${"a".repeat(MAX_URL_LENGTH)}`)).toBe("INVALID_URL");
  });

  it("refuse des identifiants saisis sans schéma (« user:pass@… »)", () => {
    expect(rejectionCode("user:pass@example.com")).not.toBeNull();
  });

  it("explique chaque refus en français", () => {
    expect(() => normalizeTarget("javascript:alert(1)")).toThrow(
      "Le protocole « javascript » n'est pas pris en charge",
    );
    expect(() => normalizeTarget("example.com:8080")).toThrow("Le port 8080 n'est pas autorisé");
    expect(() => normalizeTarget("https://user:pass@example.com")).toThrow(
      "L'adresse ne doit pas contenir d'identifiants",
    );
    expect(() => normalizeTarget("localhost")).toThrow("nom réservé à un usage local ou privé");
    expect(() => normalizeTarget("127.0.0.1")).toThrow("n'est pas une adresse publique");
    expect(() => normalizeTarget("intranet")).toThrow("il manque l'extension");
  });
});
