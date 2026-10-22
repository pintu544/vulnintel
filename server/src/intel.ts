/**
 * Bright Data intel enrichment — DEAD STUB (declared in PREP-REPORT 2026-10-20).
 * NOT imported anywhere; hand-rolls a SERP-zone REST call instead of the
 * @brightdata/sdk (bdclient) design in DESIGN.md / T-9.
 * T-9 (Slice 3) REPLACES this file — do not extend it.
 */

export interface IntelResult {
  cveId: string;
  hasLiveIntel: boolean;
  sources: string[];
  summary?: string;
}

const BRIGHTDATA_API = "https://api.brightdata.com/request";

export async function fetchIntel(
  cveId: string,
  apiKey?: string
): Promise<IntelResult> {
  // No key → graceful degradation (FR-10: visible, not silent)
  if (!apiKey) {
    return { cveId, hasLiveIntel: false, sources: [] };
  }

  try {
    // SERP search for exploit chatter
    const res = await fetch(BRIGHTDATA_API, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        zone: "serp",
        url: `https://www.google.com/search?q=${encodeURIComponent(cveId + " exploit")}`,
        format: "json",
      }),
      signal: AbortSignal.timeout(15000),
    });

    if (!res.ok) {
      return { cveId, hasLiveIntel: false, sources: [] };
    }

    const data = await res.json();
    const results = data.results ?? data.organic ?? [];
    const hasIntel = results.length > 0;

    return {
      cveId,
      hasLiveIntel: hasIntel,
      sources: hasIntel ? ["brightdata-serp"] : [],
      summary: hasIntel
        ? `${results.length} live mentions found`
        : undefined,
    };
  } catch {
    return { cveId, hasLiveIntel: false, sources: [] };
  }
}
