import { describe, it, expect } from "vitest";
import {
  queryOsvVulns,
  matchOsvVulns,
  osvToVulnerability,
} from "./osv.js";

/** Minimal fetch stub: route by URL to canned payloads. */
function mockFetch(
  routes: Record<string, { status?: number; body?: unknown; headers?: Record<string, string> }>
) {
  const calls: string[] = [];
  const fn = async (url: string | URL | Request, _init?: unknown) => {
    const u = String(url);
    calls.push(u);
    for (const [prefix, res] of Object.entries(routes)) {
      if (u.startsWith(prefix)) {
        const status = res.status ?? 200;
        return {
          ok: status >= 200 && status < 300,
          status,
          headers: { get: (k: string) => res.headers?.[k] ?? null },
          json: async () => res.body,
        } as unknown as Response;
      }
    }
    throw new Error(`unexpected fetch: ${u}`);
  };
  return { fn: fn as unknown as typeof fetch, calls };
}

const LODASH_GHSA = {
  id: "GHSA-35jh-r3h4-6jhm",
  aliases: ["CVE-2021-23337"],
  summary: "Command Injection in lodash",
  affected: [
    {
      package: { name: "lodash", ecosystem: "npm" },
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "0" }, { fixed: "4.17.21" }],
        },
      ],
    },
    {
      package: { name: "lodash-rails", ecosystem: "RubyGems" },
      ranges: [
        { type: "ECOSYSTEM", events: [{ introduced: "0" }, { fixed: "4.17.21" }] },
      ],
    },
  ],
  severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H" }],
  database_specific: { cwe_ids: ["CWE-77", "CWE-94"], severity: "HIGH" },
};

const OPEN_RANGE_VULN = {
  id: "GHSA-open-range",
  aliases: [],
  summary: "Unfixed issue",
  affected: [
    {
      package: { name: "leftpad", ecosystem: "npm" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "1.0.0" }] }],
    },
  ],
  database_specific: {},
};

const LAST_AFFECTED_VULN = {
  id: "GHSA-last-aff",
  aliases: [],
  summary: "Last-affected issue",
  affected: [
    {
      package: { name: "tiny", ecosystem: "npm" },
      ranges: [
        {
          type: "SEMVER",
          events: [{ introduced: "0" }, { last_affected: "4.5.0" }],
        },
      ],
    },
  ],
  database_specific: {},
};

describe("queryOsvVulns (T-7 live path, mocked transport)", () => {
  it("maps CVE aliases to display ids and parses SEMVER ranges", async () => {
    const { fn, calls } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] },
      },
      "https://api.osv.dev/v1/vulns/": { body: LODASH_GHSA },
    });
    const { vulns, hydrateFailures, hydrationCapped } = await queryOsvVulns(
      [{ name: "lodash", version: "4.17.20", exact: true }],
      fn
    );
    expect(calls[0]).toContain("querybatch");
    expect(hydrateFailures).toBe(0);
    expect(hydrationCapped).toBe(false);
    expect(vulns).toHaveLength(1);
    expect(vulns[0].id).toBe("CVE-2021-23337");
    expect(vulns[0].osvId).toBe("GHSA-35jh-r3h4-6jhm");
    expect(vulns[0].package).toBe("lodash");
    expect(vulns[0].affectedRanges).toEqual([{ introduced: "0", fixed: "4.17.21" }]);
    expect(vulns[0].severity).toBe("HIGH");
    expect(vulns[0].cwe).toBe("CWE-77");
    expect(vulns[0].cvss).toBe(0); // OSV has no numeric score — NVD fills it
  });

  it("excludes the patched version for the fixture CVE", async () => {
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] },
      },
      "https://api.osv.dev/v1/vulns/": { body: LODASH_GHSA },
    });
    const { vulns } = await queryOsvVulns(
      [{ name: "lodash", version: "4.17.21", exact: true }],
      fn
    );
    // The record exists for the package but the version is not in range.
    expect(matchOsvVulns([{ name: "lodash", version: "4.17.21" }], vulns)).toEqual([]);
    expect(
      matchOsvVulns([{ name: "lodash", version: "4.17.20" }], vulns).map((v) => v.id)
    ).toContain("CVE-2021-23337");
  });

  it("ignores non-npm ecosystem entries for the queried package", async () => {
    const rubyOnly = {
      ...LODASH_GHSA,
      affected: [
        {
          package: { name: "lodash", ecosystem: "RubyGems" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "0" }] }],
        },
      ],
    };
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: { results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }] }] },
      },
      "https://api.osv.dev/v1/vulns/": { body: rubyOnly },
    });
    const { vulns } = await queryOsvVulns(
      [{ name: "lodash", version: "4.17.20", exact: true }],
      fn
    );
    expect(vulns).toEqual([]);
  });

  it("throws on querybatch HTTP failure (caller falls back to fixtures)", async () => {
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": { status: 503, body: {} },
    });
    await expect(
      queryOsvVulns([{ name: "lodash", version: "4.17.20", exact: true }], fn)
    ).rejects.toThrow("osv querybatch: HTTP 503");
  });

  it("counts hydration failures without killing the scan", async () => {
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: {
          results: [
            { vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }, { id: "GHSA-broken" }] },
          ],
        },
      },
      "https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm": { body: LODASH_GHSA },
      "https://api.osv.dev/v1/vulns/GHSA-broken": { status: 500, body: {} },
    });
    const { vulns, hydrateFailures } = await queryOsvVulns(
      [{ name: "lodash", version: "4.17.20", exact: true }],
      fn
    );
    expect(hydrateFailures).toBe(1);
    expect(vulns.map((v) => v.id)).toEqual(["CVE-2021-23337"]);
  });

  it("handles open ranges and last_affected bounds", async () => {
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: {
          results: [
            { vulns: [{ id: "GHSA-open-range" }] },
            { vulns: [{ id: "GHSA-last-aff" }] },
          ],
        },
      },
      "https://api.osv.dev/v1/vulns/GHSA-open-range": { body: OPEN_RANGE_VULN },
      "https://api.osv.dev/v1/vulns/GHSA-last-aff": { body: LAST_AFFECTED_VULN },
    });
    const { vulns } = await queryOsvVulns(
      [
        { name: "leftpad", version: "9.9.9", exact: true },
        { name: "tiny", version: "4.5.0", exact: true },
      ],
      fn
    );
    const byId = new Map(vulns.map((v) => [v.id, v]));
    // Open range: any later version matches.
    expect(
      matchOsvVulns([{ name: "leftpad", version: "9.9.9" }], vulns).map((v) => v.id)
    ).toContain("GHSA-open-range");
    // last_affected is inclusive: 4.5.0 matches, 4.5.1 does not.
    expect(
      matchOsvVulns([{ name: "tiny", version: "4.5.0" }], vulns).map((v) => v.id)
    ).toContain("GHSA-last-aff");
    expect(matchOsvVulns([{ name: "tiny", version: "4.5.1" }], vulns)).toEqual([]);
    expect(byId.get("GHSA-last-aff")?.affectedRanges).toEqual([
      { introduced: "0", fixed: "4.5.1" },
    ]);
  });

  it("merges two OSV records aliasing the same CVE", async () => {
    const cveRecord = {
      ...LODASH_GHSA,
      id: "CVE-2021-23337",
      aliases: ["CVE-2021-23337"],
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [
            {
              type: "SEMVER",
              events: [{ introduced: "4.17.0" }, { fixed: "4.17.21" }],
            },
          ],
        },
      ],
      database_specific: {},
    };
    const { fn } = mockFetch({
      "https://api.osv.dev/v1/querybatch": {
        body: {
          results: [{ vulns: [{ id: "GHSA-35jh-r3h4-6jhm" }, { id: "CVE-2021-23337" }] }],
        },
      },
      "https://api.osv.dev/v1/vulns/GHSA-35jh-r3h4-6jhm": { body: LODASH_GHSA },
      "https://api.osv.dev/v1/vulns/CVE-2021-23337": { body: cveRecord },
    });
    const { vulns } = await queryOsvVulns(
      [{ name: "lodash", version: "4.17.20", exact: true }],
      fn
    );
    expect(vulns).toHaveLength(1);
    expect(vulns[0].affectedRanges).toHaveLength(2);
  });

  it("returns empty for an empty inventory without calling OSV", async () => {
    const { fn, calls } = mockFetch({});
    const res = await queryOsvVulns([], fn);
    expect(res).toEqual({ vulns: [], hydrateFailures: 0, hydrationCapped: false });
    expect(calls).toEqual([]);
  });
});

describe("osvToVulnerability", () => {
  it("renders the first fixed bound, or a no-fixed note", () => {
    expect(
      osvToVulnerability({
        id: "CVE-2021-23337",
        osvId: "GHSA-35jh-r3h4-6jhm",
        aliases: ["CVE-2021-23337"],
        package: "lodash",
        summary: "Command Injection in lodash",
        severity: "HIGH",
        cvss: 0,
        cwe: "CWE-77",
        affectedRanges: [{ introduced: "0", fixed: "4.17.21" }],
        sources: ["osv"],
      }).affectedVersions
    ).toBe("<4.17.21");
    expect(
      osvToVulnerability({
        id: "GHSA-open-range",
        osvId: "GHSA-open-range",
        aliases: [],
        package: "leftpad",
        summary: "Unfixed issue",
        severity: "MEDIUM",
        cvss: 0,
        cwe: "",
        affectedRanges: [{ introduced: "1.0.0", fixed: null }],
        sources: ["osv"],
      }).affectedVersions
    ).toBe("no fixed version published");
  });
});
