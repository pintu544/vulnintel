/**
 * NVD enrichment (T-8): CVSS metrics, CWE, and description per matched CVE.
 *
 * API: GET https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={id}
 * Rate limits (TASKS.md): 50 req/30s with a free API key, 5 req/30s without.
 * The limiter below enforces a sliding window per those budgets; on HTTP 429
 * it honors Retry-After (or exponential backoff) for up to `maxRetries`,
 * then skips that CVE with a degraded note — enrichment never fails a scan.
 *
 * Only CVE ids are enriched (NVD has no GHSA records). NVD values are
 * authoritative for cvss/cwe/severity and overwrite OSV-derived ones;
 * description is overwritten only when the current one is empty, so curated
 * fixture text survives.
 *
 * The API key comes from process.env.NVD_API_KEY at runtime (set from Doppler
 * by whoever deploys; never hardcoded, never logged). Without it the client
 * runs keyless at the 5 req/30s budget.
 */

import type { Vulnerability } from "./types.js";

export interface NvdEnrichOptions {
  apiKey?: string;
  fetchFn?: typeof fetch;
  /** Override the default budget (keyed 50/30s, keyless 5/30s). Tests inject small windows. */
  rateLimit?: { maxRequests: number; windowMs: number };
  sleepFn?: (ms: number) => Promise<void>;
  timeoutMs?: number;
  maxRetries?: number;
}

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const WINDOW_MS = 30000;
const KEYED_LIMIT = 50;
const KEYLESS_LIMIT = 5;

type FetchFn = typeof fetch;

const sleepDefault = (ms: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, ms));

function severityForScore(score: number): Vulnerability["severity"] {
  if (score >= 9) return "CRITICAL";
  if (score >= 7) return "HIGH";
  if (score >= 4) return "MEDIUM";
  if (score > 0) return "LOW";
  return "MEDIUM";
}

/** Pick the newest CVSS metric set present, V3.1 > V3.0 > V2. */
function pickMetric(
  metrics: Record<string, unknown> | undefined
): { baseScore: number; baseSeverity: string } | null {
  if (!metrics) return null;
  for (const key of ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const arr = metrics[key] as { cvssData?: { baseScore?: number; baseSeverity?: string } }[] | undefined;
    const first = arr?.[0]?.cvssData;
    if (first && typeof first.baseScore === "number") {
      return { baseScore: first.baseScore, baseSeverity: first.baseSeverity ?? "" };
    }
  }
  return null;
}

function parseNvdRecord(
  data: Record<string, unknown>
): { cvss: number; severity: Vulnerability["severity"]; cwe: string; description: string } | null {
  const vulns = data.vulnerabilities as { cve?: Record<string, unknown> }[] | undefined;
  const cve = vulns?.[0]?.cve;
  if (!cve) return null;
  const metric = pickMetric(cve.metrics as Record<string, unknown> | undefined);
  const weaknesses = (cve.weaknesses as { type?: string; description?: { value?: string }[] }[] | undefined) ?? [];
  const primary =
    weaknesses.find((w) => w.type === "Primary") ?? weaknesses[0];
  const cweRaw = primary?.description?.[0]?.value ?? "";
  const cwe = /^CWE-\d+$/.test(cweRaw) ? cweRaw : "";
  const descriptions = (cve.descriptions as { lang?: string; value?: string }[] | undefined) ?? [];
  const description = descriptions.find((d) => d.lang === "en")?.value ?? "";
  if (!metric) {
    return { cvss: 0, severity: "MEDIUM", cwe, description };
  }
  const sevRaw = metric.baseSeverity;
  const severity = (
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(sevRaw)
      ? sevRaw
      : severityForScore(metric.baseScore)
  ) as Vulnerability["severity"];
  return { cvss: metric.baseScore, severity, cwe, description };
}

/**
 * Enrich CVE findings with NVD data. Returns the enriched list plus notes
 * for every CVE that could not be enriched (callers surface these as
 * degradedNotes — no silent gaps, FR-10).
 */
export async function enrichWithNvd(
  vulns: Vulnerability[],
  opts: NvdEnrichOptions = {}
): Promise<{ enriched: Vulnerability[]; notes: string[] }> {
  const fetchFn: FetchFn = opts.fetchFn ?? fetch;
  const sleepFn = opts.sleepFn ?? sleepDefault;
  const timeoutMs = opts.timeoutMs ?? 15000;
  const maxRetries = opts.maxRetries ?? 3;
  const limit = opts.rateLimit ?? {
    maxRequests: opts.apiKey ? KEYED_LIMIT : KEYLESS_LIMIT,
    windowMs: WINDOW_MS,
  };

  // Sliding-window limiter state.
  let windowStart = 0;
  let windowCount = 0;
  async function takeSlot(): Promise<void> {
    const now = Date.now();
    if (windowStart === 0 || now - windowStart >= limit.windowMs) {
      windowStart = now;
      windowCount = 0;
    }
    if (windowCount >= limit.maxRequests) {
      const waitMs = windowStart + limit.windowMs - Date.now();
      if (waitMs > 0) await sleepFn(waitMs);
      windowStart = Date.now();
      windowCount = 0;
    }
    windowCount++;
  }

  async function fetchOne(id: string): Promise<Record<string, unknown> | null> {
    let attempt = 0;
    for (;;) {
      await takeSlot();
      let res: Response;
      try {
        res = await fetchFn(`${NVD_URL}?cveId=${encodeURIComponent(id)}`, {
          headers: {
            ...(opts.apiKey ? { apiKey: opts.apiKey } : {}),
            "User-Agent": "VulnIntel-hackathon-demo",
          },
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch {
        return null;
      }
      if (res.status === 429 && attempt < maxRetries) {
        const retryAfter = res.headers.get("Retry-After");
        const waitMs = retryAfter
          ? Math.max(0, Number(retryAfter) * 1000 || 0)
          : 1000 * 2 ** attempt;
        attempt++;
        await sleepFn(waitMs);
        continue;
      }
      if (!res.ok) return null;
      return (await res.json()) as Record<string, unknown>;
    }
  }

  const notes: string[] = [];
  const enriched: Vulnerability[] = [];
  for (const v of vulns) {
    if (!v.id.startsWith("CVE-")) {
      enriched.push(v);
      continue;
    }
    const data = await fetchOne(v.id);
    const parsed = data ? parseNvdRecord(data) : null;
    if (!parsed) {
      notes.push(`NVD enrichment unavailable for ${v.id}; OSV-derived values kept`);
      enriched.push(v);
      continue;
    }
    enriched.push({
      ...v,
      cvss: parsed.cvss || v.cvss,
      severity: parsed.cvss ? parsed.severity : v.severity,
      cwe: parsed.cwe || v.cwe,
      description: v.description || parsed.description,
    });
  }
  return { enriched, notes };
}
