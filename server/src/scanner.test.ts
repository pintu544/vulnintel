import { describe, it, expect } from "vitest";
import {
  parseManifest,
  resolveVersion,
  loadFixtureVulns,
  matchVulns,
  rankFindings,
} from "./scanner.js";
import { FINDINGS_CAP } from "./types.js";

describe("resolveVersion (B-6 range semantics)", () => {
  it("keeps exact pins exact", () => {
    expect(resolveVersion("4.17.20")).toEqual({ version: "4.17.20", exact: true });
  });
  it("resolves caret/tilde ranges to their minimum bound", () => {
    expect(resolveVersion("^4.17.20")).toEqual({ version: "4.17.20", exact: false });
    expect(resolveVersion("~0.21.1")).toEqual({ version: "0.21.1", exact: false });
  });
  it("resolves comparator ranges to their minimum bound", () => {
    expect(resolveVersion(">=1.2.5 <2.0.0")).toEqual({ version: "1.2.5", exact: false });
  });
  it("never passes a range string through as an exact version", () => {
    const { version, exact } = resolveVersion("^4.17.20");
    expect(version).not.toContain("^");
    expect(exact).toBe(false);
  });
});

describe("parseManifest", () => {
  it("parses dependencies resolving semver ranges", () => {
    const m = parseManifest({ dependencies: { lodash: "^4.17.20", axios: "~0.21.1" } });
    expect(m).toEqual([
      { name: "lodash", version: "4.17.20", exact: false },
      { name: "axios", version: "0.21.1", exact: false },
    ]);
  });
  it("returns empty for missing dependencies", () => {
    expect(parseManifest({})).toEqual([]);
  });
});

describe("matchVulns", () => {
  it("matches vulnerable versions", () => {
    const vulns = loadFixtureVulns();
    const matches = matchVulns(
      [{ name: "lodash", version: "4.17.20", exact: true }],
      vulns
    );
    expect(matches.map((v) => v.id)).toContain("CVE-2021-23337");
  });
  it("does not match patched versions", () => {
    const vulns = loadFixtureVulns();
    const matches = matchVulns(
      [{ name: "lodash", version: "4.17.21", exact: true }],
      vulns
    );
    expect(matches.map((v) => v.id)).not.toContain("CVE-2021-23337");
  });
});

describe("rankFindings", () => {
  it("ranks deterministically matching fixture order", () => {
    const vulns = loadFixtureVulns();
    const inventory = [
      { name: "lodash", version: "4.17.20", exact: true },
      { name: "axios", version: "0.21.1", exact: true },
      { name: "minimist", version: "1.2.5", exact: true },
    ];
    const ranked = rankFindings(matchVulns(inventory, vulns));
    expect(ranked.map((r) => r.id)).toEqual([
      "CVE-2021-23337",
      "CVE-2021-44906",
      "CVE-2020-28168",
    ]);
  });
  it("is deterministic across runs", () => {
    const vulns = loadFixtureVulns();
    const inv = [{ name: "lodash", version: "4.17.20", exact: true }];
    const a = JSON.stringify(rankFindings(matchVulns(inv, vulns)));
    const b = JSON.stringify(rankFindings(matchVulns(inv, vulns)));
    expect(a).toBe(b);
  });
  it(`caps ranked findings at the top ${FINDINGS_CAP} (B-3)`, () => {
    const vulns = loadFixtureVulns();
    const many = Array.from({ length: 30 }, () => ({
      ...vulns[0],
      id: `CVE-2021-23337`,
    }));
    const ranked = rankFindings(many);
    expect(ranked).toHaveLength(FINDINGS_CAP);
    expect(ranked.map((r) => r.rank)).toEqual(
      Array.from({ length: FINDINGS_CAP }, (_, i) => i + 1)
    );
  });
});
