import { describe, it, expect } from "vitest";
import { enrichWithNvd } from "./nvd.js";
import type { Vulnerability } from "./types.js";

function vuln(id: string, overrides: Partial<Vulnerability> = {}): Vulnerability {
  return {
    id,
    package: "lodash",
    affectedVersions: "<4.17.21",
    severity: "MEDIUM",
    cvss: 0,
    cwe: "",
    description: "",
    sources: ["osv"],
    ...overrides,
  };
}

function nvdPayload(opts: {
  score?: number;
  severity?: string;
  cwe?: string;
  description?: string;
  metricKey?: string;
} = {}) {
  const {
    score = 7.2,
    severity = "HIGH",
    cwe = "CWE-94",
    description = "Lodash versions prior to 4.17.21 are vulnerable to Command Injection.",
    metricKey = "cvssMetricV31",
  } = opts;
  return {
    vulnerabilities: [
      {
        cve: {
          id: "CVE-2021-23337",
          descriptions: [{ lang: "en", value: description }],
          weaknesses: [
            { type: "Primary", description: [{ lang: "en", value: cwe }] },
          ],
          metrics: {
            [metricKey]: [{ cvssData: { baseScore: score, baseSeverity: severity } }],
          },
        },
      },
    ],
  };
}

/** Queue-based fetch stub: each call consumes the next response. */
function mockFetchSequence(
  responses: (
    | { status: number; body?: unknown; headers?: Record<string, string> }
    | Error
  )[]
) {
  const seenHeaders: Record<string, string>[] = [];
  const calls: string[] = [];
  const fn = async (url: string | URL | Request, init?: { headers?: Record<string, string> }) => {
    calls.push(String(url));
    seenHeaders.push({ ...(init?.headers ?? {}) });
    const next = responses.shift();
    if (next instanceof Error) throw next;
    if (!next) throw new Error("mock fetch exhausted");
    const status = next.status;
    return {
      ok: status >= 200 && status < 300,
      status,
      headers: { get: (k: string) => next.headers?.[k] ?? null },
      json: async () => next.body,
    } as unknown as Response;
  };
  return { fn: fn as unknown as typeof fetch, calls, seenHeaders };
}

describe("enrichWithNvd (T-8, mocked transport)", () => {
  it("enriches a CVE with CVSS + CWE and leaves non-CVEs untouched", async () => {
    const { fn } = mockFetchSequence([{ status: 200, body: nvdPayload() }]);
    const { enriched, notes } = await enrichWithNvd(
      [vuln("CVE-2021-23337"), vuln("GHSA-xxxx", { package: "leftpad" })],
      { fetchFn: fn, apiKey: "test-key" }
    );
    expect(notes).toEqual([]);
    expect(enriched[0].cvss).toBe(7.2);
    expect(enriched[0].severity).toBe("HIGH");
    expect(enriched[0].cwe).toBe("CWE-94");
    expect(enriched[0].description).toContain("Command Injection");
    expect(enriched[1].id).toBe("GHSA-xxxx");
    expect(enriched[1].cvss).toBe(0); // never sent to NVD
  });

  it("prefers V3.1 metrics over V2", async () => {
    const payload = nvdPayload({ score: 7.2 });
    (payload.vulnerabilities[0].cve.metrics as Record<string, unknown>).cvssMetricV2 = [
      { cvssData: { baseScore: 5.0, baseSeverity: "MEDIUM" } },
    ];
    const { fn } = mockFetchSequence([{ status: 200, body: payload }]);
    const { enriched } = await enrichWithNvd([vuln("CVE-2021-23337")], { fetchFn: fn });
    expect(enriched[0].cvss).toBe(7.2);
    expect(enriched[0].severity).toBe("HIGH");
  });

  it("derives severity from the score band when baseSeverity is absent", async () => {
    // Empty baseSeverity falls through to the score-band mapping.
    const payload = nvdPayload({ score: 5.0, severity: "" });
    const { fn } = mockFetchSequence([{ status: 200, body: payload }]);
    const { enriched } = await enrichWithNvd([vuln("CVE-2021-23337")], { fetchFn: fn });
    expect(enriched[0].cvss).toBe(5.0);
    expect(enriched[0].severity).toBe("MEDIUM");
  });

  it("retries a 429 (honoring Retry-After) and then succeeds", async () => {
    const sleeps: number[] = [];
    const { fn, calls } = mockFetchSequence([
      { status: 429, body: {}, headers: { "Retry-After": "2" } },
      { status: 200, body: nvdPayload() },
    ]);
    const { enriched, notes } = await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: fn,
      sleepFn: async (ms) => {
        sleeps.push(ms);
      },
    });
    expect(calls).toHaveLength(2);
    expect(sleeps).toEqual([2000]);
    expect(notes).toEqual([]);
    expect(enriched[0].cvss).toBe(7.2);
  });

  it("gives up after maxRetries on repeated 429s, keeps the original, notes it", async () => {
    const { fn } = mockFetchSequence([
      { status: 429, body: {} },
      { status: 429, body: {} },
      { status: 429, body: {} },
    ]);
    const { enriched, notes } = await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: fn,
      maxRetries: 2,
      sleepFn: async () => {},
    });
    expect(enriched[0].cvss).toBe(0);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toContain("CVE-2021-23337");
  });

  it("notes and keeps the original on non-429 failures", async () => {
    const { fn } = mockFetchSequence([{ status: 404, body: {} }]);
    const { enriched, notes } = await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: fn,
    });
    expect(enriched[0].cvss).toBe(0);
    expect(notes[0]).toContain("NVD enrichment unavailable");
  });

  it("waits when the rate window is exhausted", async () => {
    const sleeps: number[] = [];
    const { fn, calls } = mockFetchSequence([
      { status: 200, body: nvdPayload() },
      { status: 200, body: nvdPayload() },
    ]);
    await enrichWithNvd(
      [vuln("CVE-2021-23337"), vuln("CVE-2020-28168", { package: "axios" })],
      {
        fetchFn: fn,
        rateLimit: { maxRequests: 1, windowMs: 60000 },
        sleepFn: async (ms) => {
          sleeps.push(ms);
        },
      }
    );
    expect(calls).toHaveLength(2);
    expect(sleeps).toHaveLength(1);
    expect(sleeps[0]).toBeGreaterThan(0);
  });

  it("sends the apiKey header only when a key is provided", async () => {
    const withKey = mockFetchSequence([{ status: 200, body: nvdPayload() }]);
    await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: withKey.fn,
      apiKey: "test-key",
    });
    expect(withKey.seenHeaders[0].apiKey).toBe("test-key");

    const withoutKey = mockFetchSequence([{ status: 200, body: nvdPayload() }]);
    await enrichWithNvd([vuln("CVE-2021-23337")], { fetchFn: withoutKey.fn });
    expect(withoutKey.seenHeaders[0].apiKey).toBeUndefined();
  });

  it("keeps a curated description, fills an empty one from NVD", async () => {
    const { fn } = mockFetchSequence([
      { status: 200, body: nvdPayload() },
      { status: 200, body: nvdPayload() },
    ]);
    const { enriched } = await enrichWithNvd(
      [
        vuln("CVE-2021-23337", { description: "Curated fixture text." }),
        vuln("CVE-2020-28168", { package: "axios", description: "" }),
      ],
      { fetchFn: fn }
    );
    expect(enriched[0].description).toBe("Curated fixture text.");
    expect(enriched[1].description).toContain("Command Injection");
  });
});
