import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import type { Dependency, Vulnerability } from "./types.js";
import { FINDINGS_CAP } from "./types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the fixtures dir by walking up from the compiled module:
 * - local dev / tests: server/dist (or server/src) -> repo root (vulnintel/fixtures)
 * - Azure zip deploy: wwwroot/dist -> wwwroot/fixtures
 * FIXTURES_DIR env var overrides (useful for custom deploy layouts).
 */
function fixturesDir(): string {
  if (process.env.FIXTURES_DIR) return process.env.FIXTURES_DIR;
  let dir = __dirname;
  for (let i = 0; i < 5; i++) {
    try {
      readFileSync(join(dir, "fixtures", "vulns.json"), "utf-8");
      return join(dir, "fixtures");
    } catch {
      dir = join(dir, "..");
    }
  }
  return join(__dirname, "..", "..", "fixtures");
}
const FIXTURES = fixturesDir();

/** Fixtures dir resolved by the walk-up above (shared with triage seeding). */
export function resolveFixturesDir(): string {
  return FIXTURES;
}

/**
 * B-6 range semantics (kickoff decision, 2026-10-22):
 * A bare semver range is RESOLVED to an exact version BEFORE any matching —
 * a range string is never passed to OSV/matcher code as-is.
 *
 * - When a lockfile is present (Slice 2: package-lock.json input), the
 *   lockfile-resolved installed version is used (exact: true).
 * - Otherwise the range resolves to its minimum bound (exact: false),
 *   documented as an honest limitation: `^4.17.20` is evaluated as 4.17.20,
 *   so an install that resolved to 4.17.21 (patched) may false-positive.
 *   Demo fixtures and tests use exact pins.
 */
export function resolveVersion(range: string): { version: string; exact: boolean } {
  const trimmed = range.trim();
  // Exact version (no range operators) — e.g. "4.17.20"
  if (/^\d+\.\d+\.\d+(-[\w.]+)?(\+[\w.]+)?$/.test(trimmed)) {
    return { version: trimmed, exact: true };
  }
  // Bare range: strip leading operators (^, ~, >=, >, <=, <, =, x-ranges)
  // and take the first version-like token as the minimum bound.
  const m = trimmed.match(/(\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?)/);
  if (m) {
    return { version: m[1], exact: false };
  }
  // Unparseable (e.g. "*", "latest", git URLs) — pass through verbatim so the
  // matcher can reject it explicitly rather than silently matching nothing.
  return { version: trimmed, exact: false };
}

/** Parse package.json dependencies into a name@version inventory. */
export function parseManifest(manifest: Record<string, unknown>): Dependency[] {
  const deps = manifest.dependencies as Record<string, string> | undefined;
  if (!deps || typeof deps !== "object") return [];
  return Object.entries(deps).map(([name, range]) => {
    const { version, exact } = resolveVersion(String(range));
    return { name, version, exact };
  });
}

/** Load fixture vulnerabilities (deterministic, for tests and demo). */
export function loadFixtureVulns(): Vulnerability[] {
  const raw = readFileSync(join(FIXTURES, "vulns.json"), "utf-8");
  return JSON.parse(raw).vulnerabilities;
}

/** Simple semver "less than" check for affected-range matching. */
function versionLt(v: string, bound: string): boolean {
  const pa = v.split(".").map(Number);
  const pb = bound.split(".").map(Number);
  for (let i = 0; i < 3; i++) {
    const a = pa[i] ?? 0;
    const b = pb[i] ?? 0;
    if (a < b) return true;
    if (a > b) return false;
  }
  return false;
}

/** Match inventory against vulnerabilities (fixture-backed for Slice 1-2). */
export function matchVulns(
  inventory: Dependency[],
  vulns: Vulnerability[]
): Vulnerability[] {
  const matches: Vulnerability[] = [];
  for (const dep of inventory) {
    for (const v of vulns) {
      if (v.package !== dep.name) continue;
      // affectedVersions like "<4.17.21"
      const m = v.affectedVersions.match(/^<(.+)$/);
      if (m && versionLt(dep.version, m[1])) {
        matches.push(v);
      }
    }
  }
  return matches;
}

/**
 * Rank by severity × CVSS (deterministic).
 * B-3 (kickoff decision, 2026-10-22): findings are capped at the top 25
 * (FINDINGS_CAP) — the caller records the truncation in degradedNotes.
 * Slice 1: severity × CVSS only; exploitability × reachability arrive at T-11.
 */
export function rankFindings(vulns: Vulnerability[]) {
  const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
  return [...vulns]
    .sort((a, b) => order[b.severity] - order[a.severity] || b.cvss - a.cvss)
    .slice(0, FINDINGS_CAP)
    .map((v, i) => ({
      ...v,
      rank: i + 1,
      score: order[v.severity] * 10 + v.cvss,
      evidence: v.sources.map((s) => ({
        source: s,
        detail: `${v.id} reported by ${s}`,
      })),
    }));
}
