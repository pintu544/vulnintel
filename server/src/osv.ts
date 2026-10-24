/**
 * Live OSV.dev matching (T-7).
 *
 * OSV is queried by exact name@version — NEVER by CPE (TASKS.md T-7).
 * No API key is needed and OSV publishes no rate limit; hydration is still
 * sequential and timeout-bounded to stay polite.
 *
 * Shape notes (verified live 2026-10-24):
 * - POST https://api.osv.dev/v1/querybatch {queries: [{package: {name, ecosystem: "npm"}, version}]}
 *   returns results[] aligned with queries; each result lists vulns[] with id+modified ONLY.
 * - GET https://api.osv.dev/v1/vulns/{id} returns the full record: aliases[]
 *   (CVE ids when present), summary, affected[].package (ecosystem "npm" for
 *   our packages), ranges[] of type SEMVER with introduced/fixed/last_affected
 *   events, severity[] (CVSS vector strings — no numeric score), and
 *   database_specific.cwe_ids + severity for GitHub-reviewed records.
 * - The numeric CVSS score is NOT available from OSV; NVD enrichment (nvd.ts)
 *   fills it for CVE ids. Until then cvss is 0 and severity comes from
 *   database_specific when present, MEDIUM otherwise.
 */

import { versionInRanges } from "./fallbackDb.js";
import type { Dependency, Vulnerability } from "./types.js";

export interface OsvRange {
  introduced: string;
  /** null = no fixed version published (still vulnerable at any later version) */
  fixed: string | null;
}

export interface OsvVuln {
  /** Display id: first CVE alias when present, else the OSV id. */
  id: string;
  osvId: string;
  aliases: string[];
  package: string;
  summary: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  /** 0 until NVD enrichment supplies the numeric score. */
  cvss: number;
  cwe: string;
  affectedRanges: OsvRange[];
  sources: string[];
}

export interface OsvQueryResult {
  vulns: OsvVuln[];
  /** Hydrations that failed (network or non-200) — results may be incomplete. */
  hydrateFailures: number;
  /** True when the hydration cap stopped further detail fetches. */
  hydrationCapped: boolean;
}

const QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch";
const VULN_URL = "https://api.osv.dev/v1/vulns";
const QUERY_CHUNK = 500;
const DEFAULT_MAX_HYDRATIONS = 150;

type FetchFn = typeof fetch;

/** Increment the last numeric component: "4.5.0" -> "4.5.1". */
function bumpPatch(v: string): string | null {
  const m = v.match(/^(.*\.)(\d+)([^0-9]*)$/);
  if (!m) return null;
  return `${m[1]}${Number(m[2]) + 1}${m[3]}`;
}

/**
 * Convert one OSV record's SEMVER range events for `packageName` into
 * introduced/fixed pairs. `last_affected` (inclusive) is converted to an
 * exclusive fixed bound by bumping the patch component — documented
 * approximation; OSV's own versionInRanges semantics are fixed-exclusive.
 */
function rangesForPackage(
  raw: Record<string, unknown>,
  packageName: string
): OsvRange[] {
  const out: OsvRange[] = [];
  const affected = (raw.affected as Record<string, unknown>[] | undefined) ?? [];
  for (const aff of affected) {
    const pkg = aff.package as Record<string, string> | undefined;
    if (!pkg || pkg.name !== packageName || pkg.ecosystem !== "npm") continue;
    const ranges = (aff.ranges as Record<string, unknown>[] | undefined) ?? [];
    for (const rg of ranges) {
      if (rg.type !== "SEMVER") continue;
      let introduced = "0";
      let pending = false;
      for (const e of (rg.events as Record<string, string>[]) ?? []) {
        if (e.introduced !== undefined) {
          introduced = e.introduced;
          pending = true;
        }
        if (e.fixed !== undefined) {
          out.push({ introduced, fixed: e.fixed });
          introduced = "0";
          pending = false;
        } else if (e.last_affected !== undefined) {
          const fixed = bumpPatch(e.last_affected);
          out.push({ introduced, fixed: fixed ?? null });
          introduced = "0";
          pending = false;
        }
      }
      // Open range (introduced, never fixed) — still vulnerable.
      if (pending) out.push({ introduced, fixed: null });
    }
  }
  return out;
}

function parseOsvVuln(
  raw: Record<string, unknown>,
  packageName: string
): OsvVuln | null {
  const ranges = rangesForPackage(raw, packageName);
  if (ranges.length === 0) return null;
  const osvId = String(raw.id ?? "");
  if (!osvId) return null;
  const aliases = ((raw.aliases as string[] | undefined) ?? []).filter(Boolean);
  const id = aliases.find((a) => a.startsWith("CVE-")) ?? osvId;
  const dbSpecific = (raw.database_specific as Record<string, unknown> | undefined) ?? {};
  const sevRaw = String(dbSpecific.severity ?? "");
  const severity = (
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevRaw) ? sevRaw : "MEDIUM"
  ) as OsvVuln["severity"];
  const cweIds = (dbSpecific.cwe_ids as string[] | undefined) ?? [];
  const summary = String(
    (raw.summary as string | undefined) ??
      (raw.details as string | undefined)?.slice(0, 200) ??
      ""
  );
  return {
    id,
    osvId,
    aliases,
    package: packageName,
    summary,
    severity,
    cvss: 0,
    cwe: cweIds[0] ?? "",
    affectedRanges: ranges,
    sources: ["osv"],
  };
}

function mergeVuln(into: Map<string, OsvVuln>, v: OsvVuln): void {
  const key = `${v.id}::${v.package}`;
  const existing = into.get(key);
  if (!existing) {
    into.set(key, v);
    return;
  }
  // Same CVE via two OSV records (e.g. GHSA + CVE entries): union ranges,
  // keep the first non-empty summary/cwe, keep the higher severity.
  const order = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 } as const;
  const seen = new Set(existing.affectedRanges.map((r) => `${r.introduced}@${r.fixed}`));
  for (const r of v.affectedRanges) {
    if (!seen.has(`${r.introduced}@${r.fixed}`)) {
      existing.affectedRanges.push(r);
      seen.add(`${r.introduced}@${r.fixed}`);
    }
  }
  if (!existing.summary && v.summary) existing.summary = v.summary;
  if (!existing.cwe && v.cwe) existing.cwe = v.cwe;
  if (order[v.severity] > order[existing.severity]) existing.severity = v.severity;
  for (const s of v.sources) if (!existing.sources.includes(s)) existing.sources.push(s);
}

/**
 * Query OSV for the whole inventory, then hydrate each returned id.
 * Throws on querybatch transport/HTTP failure (caller falls back to fixtures
 * and names the degradation); individual hydration failures are counted,
 * not thrown, so one bad record never kills a scan.
 */
export async function queryOsvVulns(
  inventory: Dependency[],
  fetchFn: FetchFn = fetch,
  opts: { queryTimeoutMs?: number; hydrateTimeoutMs?: number; maxHydrations?: number } = {}
): Promise<OsvQueryResult> {
  const queryTimeoutMs = opts.queryTimeoutMs ?? 60000;
  const hydrateTimeoutMs = opts.hydrateTimeoutMs ?? 15000;
  const maxHydrations = opts.maxHydrations ?? DEFAULT_MAX_HYDRATIONS;
  if (inventory.length === 0) {
    return { vulns: [], hydrateFailures: 0, hydrationCapped: false };
  }

  const queries = inventory.map((d, i) => ({
    id: `scan-${i}`,
    package: { name: d.name, ecosystem: "npm" },
    version: d.version,
  }));

  const vulnIds = new Set<string>();
  for (let i = 0; i < queries.length; i += QUERY_CHUNK) {
    const chunk = queries.slice(i, i + QUERY_CHUNK);
    const res = await fetchFn(QUERYBATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ queries: chunk }),
      signal: AbortSignal.timeout(queryTimeoutMs),
    });
    if (!res.ok) {
      throw new Error(`osv querybatch: HTTP ${res.status}`);
    }
    const data = (await res.json()) as {
      results?: { vulns?: { id: string }[] }[];
    };
    for (const r of data.results ?? []) {
      for (const v of r.vulns ?? []) {
        if (v.id) vulnIds.add(v.id);
      }
    }
  }

  const byKey = new Map<string, OsvVuln>();
  let hydrateFailures = 0;
  let hydrationCapped = false;
  let hydrated = 0;
  const names = new Set(inventory.map((d) => d.name));
  for (const id of vulnIds) {
    if (hydrated >= maxHydrations) {
      hydrationCapped = true;
      break;
    }
    hydrated++;
    let raw: Record<string, unknown>;
    try {
      const res = await fetchFn(`${VULN_URL}/${encodeURIComponent(id)}`, {
        signal: AbortSignal.timeout(hydrateTimeoutMs),
      });
      if (!res.ok) {
        hydrateFailures++;
        continue;
      }
      raw = (await res.json()) as Record<string, unknown>;
    } catch {
      hydrateFailures++;
      continue;
    }
    for (const name of names) {
      const parsed = parseOsvVuln(raw, name);
      if (parsed) mergeVuln(byKey, parsed);
    }
  }
  return { vulns: [...byKey.values()], hydrateFailures, hydrationCapped };
}

/** Keep only records whose ranges contain the inventoried version. */
export function matchOsvVulns(
  inventory: Dependency[],
  vulns: OsvVuln[]
): OsvVuln[] {
  const byName = new Map(inventory.map((d) => [d.name, d.version]));
  return vulns.filter((v) => {
    const version = byName.get(v.package);
    return version !== undefined && versionInRanges(version, v.affectedRanges);
  });
}

/** Adapt a matched OSV record to the shared Vulnerability shape for ranking. */
export function osvToVulnerability(v: OsvVuln): Vulnerability {
  const firstFixed = v.affectedRanges.find((r) => r.fixed !== null)?.fixed;
  return {
    id: v.id,
    package: v.package,
    affectedVersions: firstFixed ? `<${firstFixed}` : "no fixed version published",
    severity: v.severity,
    cvss: v.cvss,
    cwe: v.cwe,
    description: v.summary,
    sources: v.sources,
  };
}
