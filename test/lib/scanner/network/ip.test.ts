// Chaque ligne des tableaux correspond à une plage vérifiée par l'expérience (notes de recherche
// « node-ssrf-tls »), dont la règle 2000::/3 qui rattrape ce qu'ipaddr.js laisse passer.
import { describe, expect, it } from "vitest";
import {
  applyAddressPolicy,
  checkAddress,
  isIpLiteral,
  stripBrackets,
} from "@/lib/scanner/network/ip";

/** [adresse, plage attendue, pourquoi elle doit être refusée] */
type BlockedCase = [address: string, range: string, why: string];

const BLOCKED_IPV4: BlockedCase[] = [
  ["0.0.0.0", "unspecified", "désigne la machine elle-même (joignable sous macOS et Linux)"],
  ["0.1.2.3", "unspecified", "réseau 0.0.0.0/8"],
  ["10.1.2.3", "private", "réseau privé RFC 1918"],
  ["172.16.0.1", "private", "réseau privé RFC 1918"],
  ["172.31.255.255", "private", "fin de 172.16.0.0/12"],
  ["192.168.1.1", "private", "réseau privé RFC 1918"],
  ["127.0.0.1", "loopback", "bouclage (API locales, runtime Lambda)"],
  ["127.255.255.254", "loopback", "tout 127.0.0.0/8 est local"],
  ["169.254.169.254", "linkLocal", "métadonnées AWS, GCP et Azure"],
  ["169.254.170.2", "linkLocal", "identifiants des tâches AWS ECS"],
  ["100.64.0.1", "carrierGradeNat", "CGNAT (RFC 6598)"],
  ["100.100.100.200", "carrierGradeNat", "métadonnées Alibaba Cloud"],
  ["192.0.0.1", "reserved", "affectations de protocoles IETF"],
  ["192.0.2.1", "reserved", "documentation TEST-NET-1"],
  ["198.51.100.1", "reserved", "documentation TEST-NET-2"],
  ["203.0.113.1", "reserved", "documentation TEST-NET-3"],
  ["192.88.99.1", "reserved", "relais 6to4 obsolète"],
  ["198.18.0.1", "reserved", "tests de performance (198.18.0.0/15)"],
  ["240.0.0.1", "reserved", "usage futur (240.0.0.0/4)"],
  ["255.255.255.254", "reserved", "fin de 240.0.0.0/4"],
  ["224.0.0.1", "multicast", "multidiffusion"],
  ["255.255.255.255", "broadcast", "diffusion générale"],
  ["192.31.196.1", "as112", "AS112"],
  ["192.175.48.1", "as112", "AS112"],
  ["192.52.193.1", "amt", "AMT"],
];

const BLOCKED_IPV6: BlockedCase[] = [
  ["::", "unspecified", "désigne la machine elle-même"],
  ["::1", "loopback", "bouclage IPv6"],
  ["fe80::1", "linkLocal", "lien-local IPv6"],
  ["fe80::1%en0", "linkLocal", "lien-local avec identifiant de zone"],
  ["fc00::1", "uniqueLocal", "réseau privé IPv6"],
  ["fd00:ec2::254", "uniqueLocal", "métadonnées AWS en IPv6"],
  ["ff02::1", "multicast", "multidiffusion IPv6"],
  ["fec0::1", "deprecatedSiteLocal", "site-local obsolète"],
  ["64:ff9b::7f00:1", "rfc6052", "NAT64 vers 127.0.0.1"],
  ["64:ff9b::a9fe:a9fe", "rfc6052", "NAT64 vers 169.254.169.254"],
  ["64:ff9b:1::1", "rfc6052", "NAT64 local (64:ff9b:1::/48)"],
  ["2002:7f00:1::1", "6to4", "6to4 qui embarque 127.0.0.1"],
  ["2002:a9fe:a9fe::1", "6to4", "6to4 qui embarque 169.254.169.254"],
  ["2001::1", "teredo", "Teredo"],
  ["2001:0:4136:e378:8000:63bf:3fff:fdd2", "teredo", "Teredo (client 192.0.2.45)"],
  ["2001:db8::1", "reserved", "documentation IPv6"],
  ["3fff::1", "reserved", "documentation IPv6 (3fff::/20)"],
  ["100::1", "discard", "préfixe de rejet"],
  ["::ffff:0:7f00:1", "rfc6145", "IPv4 traduite (SIIT)"],
  ["5f00::1", "segmentRouting", "routage par segments"],
  ["2001:2::1", "benchmarking", "tests de performance IPv6"],
  ["2001:20::1", "orchid2", "identifiants ORCHIDv2"],
];

/** IPv4 « mappées » : converties en IPv4 puis jugées comme telles. */
const BLOCKED_MAPPED: BlockedCase[] = [
  ["::ffff:127.0.0.1", "loopback", "atteint réellement 127.0.0.1"],
  ["::ffff:7f00:1", "loopback", "même adresse, forme hexadécimale (sortie de new URL)"],
  ["::ffff:169.254.169.254", "linkLocal", "métadonnées cloud derrière IPv6"],
  ["::ffff:10.0.0.1", "private", "réseau privé derrière IPv6"],
  ["[::ffff:127.0.0.1]", "loopback", "forme entre crochets d'une URL"],
];

/** Adresses qu'ipaddr.js juge « unicast » mais qui sont hors de 2000::/3 (seul espace public IPv6). */
const OUTSIDE_GLOBAL_UNICAST: Array<[address: string, why: string]> = [
  ["::7f00:1", "IPv4 « compatible » (::/96) produite par new URL('http://[::127.0.0.1]/')"],
  ["::a9fe:a9fe", "IPv4 « compatible » vers 169.254.169.254"],
  ["100:0:0:1::1", "préfixe factice RFC 9780, inconnu d'ipaddr.js"],
  ["4000::1", "espace IPv6 non attribué"],
  ["8000::1", "espace IPv6 non attribué"],
];

/** Formes que l'analyseur d'URL normaliserait, mais qui ne sont pas des IP canoniques. */
const NOT_CANONICAL = [
  "2130706433",
  "0x7f.1",
  "0177.0.0.1",
  "127.1",
  "01.02.03.04",
  "256.0.0.1",
  "1.2.3.4.5",
  " 8.8.8.8",
  "::ffff:",
  "localhost",
  "example.com",
  "",
];

describe("checkAddress : adresses refusées", () => {
  it.each(BLOCKED_IPV4)("refuse %s (plage %s : %s)", (address, range) => {
    expect(checkAddress(address)).toMatchObject({ allowed: false, address, range });
  });

  it.each(BLOCKED_IPV6)("refuse %s (plage %s : %s)", (address, range) => {
    expect(checkAddress(address)).toMatchObject({ allowed: false, address, range });
  });

  it.each(BLOCKED_MAPPED)("refuse l'IPv4 mappée %s (plage %s : %s)", (address, range) => {
    expect(checkAddress(address)).toMatchObject({ allowed: false, range });
  });

  it.each(OUTSIDE_GLOBAL_UNICAST)("refuse %s, hors de 2000::/3 (%s)", (address) => {
    expect(checkAddress(address)).toMatchObject({
      allowed: false,
      range: "notGlobalUnicast",
    });
  });

  it.each(NOT_CANONICAL)("refuse la forme non canonique « %s »", (address) => {
    expect(checkAddress(address)).toMatchObject({ allowed: false, range: "invalid" });
  });

  it("donne un motif en français pour chaque refus", () => {
    const reasonOf = (address: string): string => {
      const verdict = checkAddress(address);
      return verdict.allowed ? "" : verdict.reason;
    };
    expect(reasonOf("169.254.169.254")).toContain("métadonnées cloud");
    expect(reasonOf("127.0.0.1")).toContain("bouclage");
    expect(reasonOf("10.1.2.3")).toContain("réseau privé");
    expect(reasonOf("64:ff9b::7f00:1")).toContain("NAT64");
    expect(reasonOf("2002:7f00:1::1")).toContain("6to4");
    expect(reasonOf("2001::1")).toContain("Teredo");
    expect(reasonOf("4000::1")).toContain("2000::/3");
    expect(reasonOf("2130706433")).toContain("non canonique");
  });
});

describe("checkAddress : adresses publiques", () => {
  it.each([
    ["8.8.8.8", 4],
    ["1.1.1.1", 4],
    ["93.184.215.14", 4],
    ["2606:4700:4700::1111", 6],
    ["2001:4860:4860::8888", 6],
    ["::ffff:8.8.8.8", 6],
  ] as const)("autorise %s (IPv%i)", (address, family) => {
    expect(checkAddress(address)).toEqual({ allowed: true, address, family });
  });

  it("accepte une IPv6 entre crochets et renvoie l'adresse nue", () => {
    expect(checkAddress("[2606:4700:4700::1111]")).toEqual({
      allowed: true,
      address: "2606:4700:4700::1111",
      family: 6,
    });
  });
});

describe("isIpLiteral et stripBrackets", () => {
  it.each([
    ["127.0.0.1", true],
    ["8.8.8.8", true],
    ["::1", true],
    ["[::1]", true],
    ["[2001:db8::1]", true],
    ["example.com", false],
    ["localhost", false],
    ["2130706433", false],
    ["[127.0.0.1]", false],
    ["[example.com]", false],
    ["", false],
  ] as const)("isIpLiteral(%j) vaut %s", (host, expected) => {
    expect(isIpLiteral(host)).toBe(expected);
  });

  it("retire seulement des crochets qui entourent l'hôte", () => {
    expect(stripBrackets("[::1]")).toBe("::1");
    expect(stripBrackets("::1")).toBe("::1");
    expect(stripBrackets("[::1")).toBe("[::1");
  });
});

describe("applyAddressPolicy : politique stricte ou politique de test", () => {
  it("sans option, applique exactement checkAddress", () => {
    expect(applyAddressPolicy("127.0.0.1")).toEqual(checkAddress("127.0.0.1"));
    expect(applyAddressPolicy("8.8.8.8")).toEqual(checkAddress("8.8.8.8"));
  });

  it("allowPrivate autorise les adresses locales (tests uniquement)", () => {
    expect(applyAddressPolicy("127.0.0.1", { allowPrivate: true })).toEqual({
      allowed: true,
      address: "127.0.0.1",
      family: 4,
    });
    expect(applyAddressPolicy("::1", { allowPrivate: true })).toMatchObject({
      allowed: true,
      family: 6,
    });
  });

  it("isAllowed remplace la politique et garde le motif précis d'un refus", () => {
    const onlyTestServer = { isAllowed: (address: string) => address === "127.0.0.1" };
    expect(applyAddressPolicy("127.0.0.1", onlyTestServer)).toMatchObject({ allowed: true });
    expect(applyAddressPolicy("10.0.0.1", onlyTestServer)).toMatchObject({
      allowed: false,
      range: "private",
    });
    expect(applyAddressPolicy("8.8.8.8", onlyTestServer)).toMatchObject({
      allowed: false,
      range: "policy",
    });
  });

  it("refuse toujours une adresse illisible, même avec allowPrivate", () => {
    expect(applyAddressPolicy("2130706433", { allowPrivate: true })).toMatchObject({
      allowed: false,
      range: "invalid",
    });
  });
});
