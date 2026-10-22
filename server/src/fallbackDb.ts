/**
 * Direct-Postgres fallback plane (B-1 kickoff decision, 2026-10-22).
 *
 * When Zetaris is unreachable/unconfigured, the same query functions run
 * against Postgres directly and the scan carries a "federation degraded" note
 * (FR-4, FR-10). The store holds a CURATED SUBSET only — fixture CVEs plus
 * CVEs for the curated top-package list below — never full NVD.
 *
 * The pool is injected (PoolLike) so unit tests run without a live database;
 * production passes a real `pg.Pool` built from DATABASE_URL.
 */

import type { Vulnerability } from "./types.js";

export interface VulnRecord {
  id: string;
  ecosystem: string;
  package: string;
  summary: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss: number;
  cwe: string;
  /** JSON: [{introduced: string, fixed: string|null}] — OSV range-event shape */
  affectedRanges: { introduced: string; fixed: string | null }[];
  sources: string[];
}

/** Minimal surface of pg.Pool used here — lets tests inject a fake. */
export interface PoolLike {
  query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/**
 * Curated package list for the fallback seed: widely-used npm packages with
 * real CVE history. Bounded on purpose — the fallback is a demo-grade subset,
 * not a vulnerability database.
 */
export const CURATED_PACKAGES = [
  "lodash",
  "axios",
  "minimist",
  "express",
  "react",
  "react-dom",
  "next",
  "webpack",
  "moment",
  "jquery",
  "underscore",
  "qs",
  "semver",
  "tar",
  "node-fetch",
  "debug",
  "yargs",
  "commander",
  "chalk",
  "mkdirp",
  "rimraf",
  "glob",
  "handlebars",
  "ejs",
  "request",
];

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS vuln_records (
  id TEXT PRIMARY KEY,
  ecosystem TEXT NOT NULL DEFAULT 'npm',
  package TEXT NOT NULL,
  summary TEXT,
  severity TEXT,
  cvss REAL,
  cwe TEXT,
  affected_ranges TEXT,
  sources TEXT[],
  updated_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vuln_records_package ON vuln_records(package);
`.trim();

export async function ensureSchema(pool: PoolLike): Promise<void> {
  await pool.query(SCHEMA_SQL);
}

export async function upsertVuln(pool: PoolLike, v: VulnRecord): Promise<void> {
  await pool.query(
    `INSERT INTO vuln_records
       (id, ecosystem, package, summary, severity, cvss, cwe, affected_ranges, sources, updated_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now())
     ON CONFLICT (id) DO UPDATE SET
       summary = EXCLUDED.summary,
       severity = EXCLUDED.severity,
       cvss = EXCLUDED.cvss,
       cwe = EXCLUDED.cwe,
       affected_ranges = EXCLUDED.affected_ranges,
       sources = EXCLUDED.sources,
       updated_at = now()`,
    [
      v.id,
      v.ecosystem,
      v.package,
      v.summary,
      v.severity,
      v.cvss,
      v.cwe,
      JSON.stringify(v.affectedRanges),
      v.sources,
    ]
  );
}

function rowToRecord(row: Record<string, unknown>): VulnRecord {
  return {
    id: String(row.id),
    ecosystem: String(row.ecosystem ?? "npm"),
    package: String(row.package),
    summary: String(row.summary ?? ""),
    severity: (row.severity as VulnRecord["severity"]) ?? "LOW",
    cvss: Number(row.cvss ?? 0),
    cwe: String(row.cwe ?? ""),
    affectedRanges: JSON.parse(String(row.affected_ranges ?? "[]")),
    sources: (row.sources as string[]) ?? [],
  };
}

/** Numeric x.y.z compare: -1 | 0 | 1. */
function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return -1;
    if (x > y) return 1;
  }
  return 0;
}

/** True when `version` falls inside any of the affected ranges. */
export function versionInRanges(
  version: string,
  ranges: { introduced: string; fixed: string | null }[]
): boolean {
  return ranges.some(
    (r) =>
      cmpVersion(version, r.introduced) >= 0 &&
      (r.fixed === null || cmpVersion(version, r.fixed) < 0)
  );
}

/**
 * Fallback query: vulnerabilities affecting the given name@version inventory.
 * Matches the Zetaris federated query's contract (same inputs, same shape)
 * so the scan path swaps planes without changing shape.
 */
export async function queryVulnsByPackage(
  pool: PoolLike,
  inventory: { name: string; version: string }[]
): Promise<VulnRecord[]> {
  const names = [...new Set(inventory.map((d) => d.name))];
  if (names.length === 0) return [];
  const { rows } = await pool.query(
    `SELECT id, ecosystem, package, summary, severity, cvss, cwe, affected_ranges, sources
     FROM vuln_records WHERE package = ANY($1)`,
    [names]
  );
  const records = rows.map(rowToRecord);
  const byName = new Map(inventory.map((d) => [d.name, d.version]));
  return records.filter((r) => {
    const v = byName.get(r.package);
    return v !== undefined && versionInRanges(v, r.affectedRanges);
  });
}

/** Adapt a fixture Vulnerability (fixtures/vulns.json) into a VulnRecord. */
export function fixtureToRecord(v: Vulnerability): VulnRecord {
  // Fixture affectedVersions look like "<4.17.21".
  const m = v.affectedVersions.match(/^<(.+)$/);
  return {
    id: v.id,
    ecosystem: "npm",
    package: v.package,
    summary: v.description,
    severity: v.severity,
    cvss: v.cvss,
    cwe: v.cwe,
    affectedRanges: m ? [{ introduced: "0.0.0", fixed: m[1] }] : [],
    sources: v.sources,
  };
}

/**
 * Seed the curated subset: fixture CVEs + live OSV.dev records for the
 * curated package list. OSV's query API matches a concrete version against
 * affected ranges, so each package is probed at a sample of its historical
 * versions (from the npm registry) — one querybatch call covers the whole
 * sample set (OSV: no key, no rate limit). Idempotent — upserts never
 * duplicate, never touch user scan data (there is none in this table).
 */
export async function seedCuratedSubset(
  pool: PoolLike,
  fixtures: Vulnerability[],
  fetchFn: typeof fetch = fetch
): Promise<{ fixtures: number; osvPackages: number; osvRecords: number; probeVersions: number }> {
  await ensureSchema(pool);
  let fixtureCount = 0;
  for (const v of fixtures) {
    await upsertVuln(pool, fixtureToRecord(v));
    fixtureCount++;
  }

  // Sample historical versions per package so the OSV probes discover CVEs
  // across the package's lifetime (not just the latest release).
  const queries: { id: string; package: { name: string; ecosystem: string }; version: string }[] = [];
  for (const name of CURATED_PACKAGES) {
    const versions = await sampleVersions(name, fetchFn);
    versions.forEach((version, i) =>
      queries.push({ id: `curated-${name}-${i}`, package: { name, ecosystem: "npm" }, version })
    );
  }

  let osvRecords = 0;
  // querybatch accepts large batches; chunk defensively at 500.
  const vulnIds = new Set<string>();
  for (let i = 0; i < queries.length; i += 500) {
    const chunk = queries.slice(i, i + 500);
    const res = await fetchFn("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk }),
      signal: AbortSignal.timeout(60000),
    });
    if (!res.ok) {
      throw new Error(`osv querybatch: HTTP ${res.status}`);
    }
    const data = (await res.json()) as { results?: { vulns?: { id: string }[] }[] };
    for (const r of data.results ?? []) {
      for (const vuln of r.vulns ?? []) {
        if (vuln.id) vulnIds.add(vuln.id);
      }
    }
  }

  // Hydrate each unique vuln (querybatch returns id+modified only).
  // OSV has no rate limit; hydrate sequentially to stay polite.
  for (const id of vulnIds) {
    try {
      const res = await fetchFn(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, {
        signal: AbortSignal.timeout(15000),
      });
      if (!res.ok) continue;
      const vuln = (await res.json()) as Record<string, unknown>;
      osvRecords += await upsertOsvVuln(pool, vuln);
    } catch {
      // One bad hydration must not kill the seed.
    }
  }
  return {
    fixtures: fixtureCount,
    osvPackages: CURATED_PACKAGES.length,
    osvRecords,
    probeVersions: queries.length,
  };
}

/** Up to 12 versions spread across a package's published history. */
async function sampleVersions(name: string, fetchFn: typeof fetch): Promise<string[]> {
  try {
    const res = await fetchFn(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { versions?: Record<string, unknown> };
    const versions = Object.keys(data.versions ?? {}).filter((v) => /^\d+\.\d+\.\d+$/.test(v));
    if (versions.length === 0) return [];
    const step = Math.max(1, Math.floor(versions.length / 12));
    const sampled: string[] = [];
    for (let i = 0; i < versions.length && sampled.length < 12; i += step) {
      sampled.push(versions[i]);
    }
    if (!sampled.includes(versions[versions.length - 1])) {
      sampled.push(versions[versions.length - 1]);
    }
    return sampled;
  } catch {
    return [];
  }
}

async function upsertOsvVuln(pool: PoolLike, vuln: Record<string, unknown>): Promise<number> {
  const id = String(vuln.id ?? "");
  if (!id) return 0;
  const affected = (vuln.affected as Record<string, unknown>[] | undefined) ?? [];
  let count = 0;
  for (const aff of affected) {
    const pkg = aff.package as Record<string, string> | undefined;
    if (!pkg || pkg.ecosystem !== "npm") continue;
    const ranges = ((aff.ranges as Record<string, unknown>[] | undefined) ?? [])
      .filter((rg) => rg.type === "SEMVER")
      .flatMap((rg) => {
        const events = (rg.events as Record<string, string>[]) ?? [];
        const out: { introduced: string; fixed: string | null }[] = [];
        let introduced = "0.0.0";
        for (const e of events) {
          if (e.introduced) introduced = e.introduced;
          if (e.fixed) {
            out.push({ introduced, fixed: e.fixed });
            introduced = "0.0.0";
          }
        }
        return out;
      });
    const sev = ((vuln.severity as { type: string; score: string }[] | undefined) ?? [])
      .find((s) => s.type === "CVSS_V3" || s.type === "CVSS_V2");
    await upsertVuln(pool, {
      id: `${id}::${pkg.name}`,
      ecosystem: "npm",
      package: pkg.name,
      summary: String(
        (vuln.summary as string | undefined) ?? (vuln.details as string | undefined) ?? ""
      ),
      severity: "MEDIUM",
      cvss: sev ? parseFloat(sev.score.split("/")[0] || "0") : 0,
      cwe: "",
      affectedRanges: ranges,
      sources: ["osv"],
    });
    count++;
  }
  return count;
}
