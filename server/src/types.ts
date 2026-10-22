export interface Dependency {
  name: string;
  version: string;
  /** true when resolved from a lockfile (exact installed version); false = bare range resolved to its minimum bound */
  exact?: boolean;
}

export interface Vulnerability {
  id: string;
  package: string;
  affectedVersions: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  cvss: number;
  cwe: string;
  description: string;
  sources: string[];
}

export interface RankedFinding extends Vulnerability {
  rank: number;
  score: number;
  evidence: { source: string; detail: string }[];
}

/**
 * Scan job lifecycle (DESIGN §API Contracts).
 * queued → running → done | partial | failed
 * partial = finished with degraded paths (timeout, source fallback); never a silent empty success.
 */
export interface ScanJob {
  id: string;
  status: "queued" | "running" | "done" | "partial" | "failed";
  /** sha256 of the submitted manifest string (dedup key for future slices) */
  manifestHash?: string;
  /** 0..100 */
  progress: number;
  /** every degraded path is named here — no silent gaps (FR-10) */
  degradedNotes: string[];
  manifest?: Record<string, string>;
  inventory?: Dependency[];
  findings?: RankedFinding[];
  error?: string;
  createdAt: string;
}

/** DESIGN cap: never return more than the top 25 findings in one response. */
export const FINDINGS_CAP = 25;
