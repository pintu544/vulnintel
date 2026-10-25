import { describe, it, expect, vi } from "vitest";
import { queryOsvVulns } from "./osv.js";
import { enrichWithNvd } from "./nvd.js";
import { synthesizeRanking, type OpenAiCompatibleClient, type RankInput } from "./ranking.js";
import { ZetarisAdapter } from "./zetaris.js";
import type { Vulnerability } from "./types.js";

/**
 * S5 (T-13) fault-injection tests. Each test proves one fault degrades
 * visibly (named note or thrown error for the caller to name) instead of
 * failing silently. Transport-level tests follow the mocked-fetch pattern
 * already used by osv.test.ts / nvd.test.ts; job-level behaviour is
 * verified separately in the local fault matrix (S5-PLAN.md).
 */

function vuln(id: string): Vulnerability {
  return {
    id,
    package: "lodash",
    affectedVersions: "<4.17.21",
    severity: "MEDIUM",
    cvss: 0,
    cwe: "",
    description: "OSV-derived description",
    sources: ["osv"],
  };
}

function rankFinding(id: string): RankInput {
  return {
    id,
    package: "pkg",
    affectedVersions: "<1.0.0",
    severity: "HIGH",
    cvss: 7.2,
    cwe: "CWE-94",
    description: "Test finding",
    sources: ["osv"],
  };
}

function failingChat() {
  return { chat: vi.fn(async () => { throw new Error("provider down"); }) } as unknown as OpenAiCompatibleClient;
}

describe("OSV transport faults", () => {
  it("querybatch throw surfaces to the caller (index.ts falls back to fixtures + note)", async () => {
    const throwing = async () => { throw new Error("network down"); };
    await expect(
      queryOsvVulns([{ name: "lodash", version: "4.17.20", exact: true }], throwing as unknown as typeof fetch)
    ).rejects.toThrow("network down");
  });

  it("querybatch HTTP 500 surfaces as a named error", async () => {
    const stub = async () => ({ ok: false, status: 500, json: async () => ({}) }) as unknown as Response;
    await expect(
      queryOsvVulns([{ name: "lodash", version: "4.17.20", exact: true }], stub as unknown as typeof fetch)
    ).rejects.toThrow("osv querybatch: HTTP 500");
  });
});

describe("NVD enrichment faults", () => {
  it("transport failure keeps OSV values and names the degradation", async () => {
    const throwing = async () => { throw new Error("nvd unreachable"); };
    const { enriched, notes } = await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: throwing as unknown as typeof fetch,
      apiKey: "test-key",
      sleepFn: async () => {},
    });
    expect(enriched[0].description).toBe("OSV-derived description");
    expect(notes.join(" ")).toMatch(/NVD enrichment unavailable for CVE-2021-23337; OSV-derived values kept/);
  });

  it("malformed-JSON 200 keeps OSV values and names the degradation (QA M1)", async () => {
    const badJson = async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      json: async () => { throw new Error("unexpected token"); },
    }) as unknown as Response;
    const { enriched, notes } = await enrichWithNvd([vuln("CVE-2021-23337")], {
      fetchFn: badJson as unknown as typeof fetch,
      apiKey: "test-key",
      sleepFn: async () => {},
    });
    expect(enriched[0].description).toBe("OSV-derived description");
    expect(notes.join(" ")).toMatch(/NVD enrichment unavailable for CVE-2021-23337; OSV-derived values kept/);
  });
});

describe("LLM synthesis faults", () => {
  it("primary and fallback both failing keeps deterministic order with a named note", async () => {
    const { ranked, llmUsed, notes } = await synthesizeRanking(
      [rankFinding("CVE-B"), rankFinding("CVE-A")],
      { llm: failingChat(), fallbackLlm: failingChat() }
    );
    expect(llmUsed).toBe(false);
    expect(notes.join(" ")).toMatch(/primary and fallback failed\); deterministic ranking used/);
    expect(ranked.map((r) => r.id)).toEqual(["CVE-A", "CVE-B"]);
  });

  it("unparseable LLM reply keeps deterministic order with a named note", async () => {
    const garbage = { chat: vi.fn(async () => "this is not a JSON array") } as unknown as OpenAiCompatibleClient;
    const { llmUsed, notes } = await synthesizeRanking([rankFinding("CVE-A")], { llm: garbage });
    expect(llmUsed).toBe(false);
    expect(notes.join(" ")).toMatch(/unparseable reply; deterministic ranking used/);
  });
});

describe("Zetaris adapter faults", () => {
  it("unreachable endpoint throws visibly (caller falls back, never silent)", async () => {
    const adapter = new ZetarisAdapter({ baseUrl: "http://127.0.0.1:9", apiKey: "x", orgId: "y" });
    await expect(adapter.query("select 1")).rejects.toThrow();
  });
});
