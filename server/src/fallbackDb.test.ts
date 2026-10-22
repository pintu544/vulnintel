import { describe, it, expect } from "vitest";
import {
  SCHEMA_SQL,
  CURATED_PACKAGES,
  ensureSchema,
  upsertVuln,
  queryVulnsByPackage,
  versionInRanges,
  fixtureToRecord,
  seedCuratedSubset,
  type PoolLike,
  type VulnRecord,
} from "./fallbackDb.js";
import { loadFixtureVulns } from "./scanner.js";

/** In-memory fake of the PoolLike surface — records statements, serves rows. */
function fakePool(rows: Record<string, unknown>[] = []) {
  const statements: { text: string; params?: unknown[] }[] = [];
  const pool: PoolLike = {
    async query(text, params) {
      statements.push({ text, params });
      return { rows };
    },
  };
  return { pool, statements };
}

const sampleRecord: VulnRecord = {
  id: "CVE-2021-23337::lodash",
  ecosystem: "npm",
  package: "lodash",
  summary: "Prototype pollution",
  severity: "HIGH",
  cvss: 7.2,
  cwe: "CWE-1321",
  affectedRanges: [{ introduced: "0.0.0", fixed: "4.17.21" }],
  sources: ["osv"],
};

describe("fallback schema", () => {
  it("creates the vuln_records table with a package index", async () => {
    const { pool, statements } = fakePool();
    await ensureSchema(pool);
    expect(statements).toHaveLength(1);
    expect(statements[0].text).toContain("CREATE TABLE IF NOT EXISTS vuln_records");
    expect(SCHEMA_SQL).toContain("idx_vuln_records_package");
  });

  it("upserts with a parameterized query (no string interpolation)", async () => {
    const { pool, statements } = fakePool();
    await upsertVuln(pool, sampleRecord);
    const { text, params } = statements[0];
    expect(text).toContain("ON CONFLICT (id) DO UPDATE");
    expect(text).not.toContain("CVE-2021-23337");
    expect(params?.[0]).toBe("CVE-2021-23337::lodash");
    expect(JSON.parse(String(params?.[7]))).toEqual([
      { introduced: "0.0.0", fixed: "4.17.21" },
    ]);
  });
});

describe("versionInRanges", () => {
  const ranges = [{ introduced: "0.0.0", fixed: "4.17.21" }];
  it("matches versions inside the range", () => {
    expect(versionInRanges("4.17.20", ranges)).toBe(true);
    expect(versionInRanges("0.0.0", ranges)).toBe(true);
  });
  it("rejects the fixed version and above", () => {
    expect(versionInRanges("4.17.21", ranges)).toBe(false);
    expect(versionInRanges("5.0.0", ranges)).toBe(false);
  });
  it("supports open-ended ranges (fixed: null)", () => {
    expect(versionInRanges("9.9.9", [{ introduced: "1.0.0", fixed: null }])).toBe(true);
    expect(versionInRanges("0.9.0", [{ introduced: "1.0.0", fixed: null }])).toBe(false);
  });
});

describe("queryVulnsByPackage", () => {
  const rows = [
    {
      id: "CVE-2021-23337::lodash",
      ecosystem: "npm",
      package: "lodash",
      summary: "x",
      severity: "HIGH",
      cvss: 7.2,
      cwe: "CWE-1321",
      affected_ranges: JSON.stringify([{ introduced: "0.0.0", fixed: "4.17.21" }]),
      sources: ["osv"],
    },
  ];
  it("returns records whose ranges contain the installed version", async () => {
    const { pool } = fakePool(rows);
    const out = await queryVulnsByPackage(pool, [{ name: "lodash", version: "4.17.20" }]);
    expect(out.map((r) => r.id)).toEqual(["CVE-2021-23337::lodash"]);
  });
  it("excludes patched versions", async () => {
    const { pool } = fakePool(rows);
    const out = await queryVulnsByPackage(pool, [{ name: "lodash", version: "4.17.21" }]);
    expect(out).toEqual([]);
  });
  it("queries only the requested packages", async () => {
    const { pool, statements } = fakePool(rows);
    await queryVulnsByPackage(pool, [
      { name: "lodash", version: "4.17.20" },
      { name: "axios", version: "0.21.1" },
    ]);
    expect(statements[0].text).toContain("WHERE package = ANY($1)");
    expect(statements[0].params?.[0]).toEqual(["lodash", "axios"]);
  });
  it("short-circuits on an empty inventory", async () => {
    const { pool, statements } = fakePool(rows);
    expect(await queryVulnsByPackage(pool, [])).toEqual([]);
    expect(statements).toHaveLength(0);
  });
});

describe("curated seed", () => {
  it("covers a bounded package list (never full NVD)", () => {
    expect(CURATED_PACKAGES.length).toBeGreaterThan(0);
    expect(CURATED_PACKAGES.length).toBeLessThanOrEqual(30);
    expect(new Set(CURATED_PACKAGES).size).toBe(CURATED_PACKAGES.length);
  });

  it("converts fixture vulns to records", () => {
    const rec = fixtureToRecord(loadFixtureVulns()[0]);
    expect(rec.id).toBe("CVE-2021-23337");
    expect(rec.package).toBe("lodash");
    expect(rec.affectedRanges).toEqual([{ introduced: "0.0.0", fixed: "4.17.21" }]);
  });

  it("seedCuratedSubset upserts fixtures and is idempotent", async () => {
    const { pool, statements } = fakePool();
    const fakeFetch = (async (url: string) => {
      if (String(url).includes("registry.npmjs.org")) {
        return { ok: true, json: async () => ({ versions: { "1.0.0": {}, "2.0.0": {} } }) };
      }
      return { ok: false, status: 500, json: async () => ({}) };
    }) as unknown as typeof fetch;
    // OSV fetch fails -> seed throws after fixtures are upserted; fixtures still land.
    await expect(
      seedCuratedSubset(pool, loadFixtureVulns(), fakeFetch)
    ).rejects.toThrow(/osv querybatch/);
    const upserts = statements.filter((s) => s.text.includes("INSERT INTO vuln_records"));
    // 3 fixture upserts (one per fixture CVE) before the OSV failure.
    expect(upserts.length).toBe(3);
  });
});
