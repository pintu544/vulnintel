import { describe, it, expect, vi } from "vitest";
import {
  synthesizeRanking,
  OpenAiCompatibleClient,
  deterministicScore,
  parseSummaryArray,
} from "./ranking.js";
import type { RankInput } from "./ranking.js";

function finding(over: Partial<RankInput> & { id: string }): RankInput {
  return {
    package: "pkg",
    affectedVersions: "<1.0.0",
    severity: "MEDIUM",
    cvss: 5.0,
    cwe: "CWE-1321",
    description: "Test finding",
    sources: ["osv"],
    ...over,
  };
}

function mockChat(content: string) {
  return {
    chat: vi.fn(async () => content),
  } as unknown as OpenAiCompatibleClient;
}

describe("deterministicScore", () => {
  it("severity × cvss × exploitability × reachability; intel found bumps exploitability", () => {
    const base = deterministicScore({ severity: "HIGH", cvss: 7.2 });
    const withIntel = deterministicScore({ severity: "HIGH", cvss: 7.2, liveIntelStatus: "found" });
    expect(base.exploitability).toBeCloseTo(0.72);
    expect(withIntel.exploitability).toBeCloseTo(0.87);
    expect(withIntel.score).toBeGreaterThan(base.score);
    expect(base.reachability).toBe(1);
  });
});

describe("synthesizeRanking order", () => {
  it("orders by score, then cvss, then id (fully deterministic)", async () => {
    const { ranked } = await synthesizeRanking([
      finding({ id: "CVE-B", severity: "MEDIUM", cvss: 5.0 }),
      finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 }),
      finding({ id: "CVE-C", severity: "HIGH", cvss: 7.2 }),
    ]);
    expect(ranked.map((r) => r.id)).toEqual(["CVE-A", "CVE-C", "CVE-B"]);
    expect(ranked[0].rank).toBe(1);
    expect(ranked[0].score).toBeGreaterThan(ranked[2].score);
  });

  it("attaches triage + intel evidence refs", async () => {
    const { ranked } = await synthesizeRanking([
      finding({
        id: "CVE-2021-23337",
        package: "lodash",
        severity: "HIGH",
        cvss: 7.2,
        liveIntelStatus: "found",
        liveIntelExcerpts: ["Exploit chatter seen"],
        triageMemory: {
          signature: "lodash@<4.17.21|prototype-pollution",
          decision: "fix-now",
          rationale: "Remotely triggerable",
          match: "exact",
        },
      }),
    ]);
    const sources = ranked[0].evidence.map((e) => e.source);
    expect(sources).toContain("brightdata-serp");
    expect(sources).toContain("triage-memory");
    expect(ranked[0].exploitability).toBeCloseTo(0.87);
  });
});

describe("LLM summaries", () => {
  it("attaches summaries without changing order", async () => {
    const llm = mockChat(
      JSON.stringify([
        { id: "CVE-A", summary: "Critical RCE, patch now" },
        { id: "CVE-B", summary: "Moderate issue" },
      ])
    );
    const { ranked, llmUsed, notes } = await synthesizeRanking(
      [
        finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 }),
        finding({ id: "CVE-B", severity: "MEDIUM", cvss: 5.0 }),
      ],
      { llm }
    );
    expect(llmUsed).toBe(true);
    expect(notes).toEqual([]);
    expect(ranked.map((r) => r.id)).toEqual(["CVE-A", "CVE-B"]);
    expect(ranked[0].evidenceSummary).toBe("Critical RCE, patch now");
  });

  it("provider swap changes nothing structurally", async () => {
    const a = await synthesizeRanking([finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 })], {
      llm: mockChat(JSON.stringify([{ id: "CVE-A", summary: "Provider A wording" }])),
    });
    const b = await synthesizeRanking([finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 })], {
      llm: mockChat(JSON.stringify([{ id: "CVE-A", summary: "Provider B wording" }])),
    });
    expect(a.ranked.map((r) => ({ id: r.id, rank: r.rank, score: r.score }))).toEqual(
      b.ranked.map((r) => ({ id: r.id, rank: r.rank, score: r.score }))
    );
  });

  it("LLM failure falls back to deterministic ranking with a note", async () => {
    const failing = { chat: vi.fn(async () => { throw new Error("boom"); }) } as unknown as OpenAiCompatibleClient;
    const { ranked, llmUsed, notes } = await synthesizeRanking(
      [finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 })],
      { llm: failing }
    );
    expect(llmUsed).toBe(false);
    expect(ranked[0].evidenceSummary).toBeUndefined();
    expect(notes.join(" ")).toMatch(/deterministic ranking used/);
  });

  it("fallback provider is tried when primary fails", async () => {
    const failing = { chat: vi.fn(async () => { throw new Error("down"); }) } as unknown as OpenAiCompatibleClient;
    const fallback = mockChat(JSON.stringify([{ id: "CVE-A", summary: "via fallback" }]));
    const { llmUsed } = await synthesizeRanking(
      [finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 })],
      { llm: failing, fallbackLlm: fallback }
    );
    expect(llmUsed).toBe(true);
    expect(fallback.chat).toHaveBeenCalledTimes(1);
  });

  it("no LLM configured means deterministic only, no note", async () => {
    const { ranked, llmUsed, notes } = await synthesizeRanking([
      finding({ id: "CVE-A", severity: "HIGH", cvss: 7.2 }),
    ]);
    expect(llmUsed).toBe(false);
    expect(notes).toEqual([]);
    expect(ranked[0].rank).toBe(1);
  });
});

describe("parseSummaryArray", () => {
  it("parses fenced JSON and rejects garbage", () => {
    expect(
      parseSummaryArray('```json\n[{"id":"X","summary":"s"}]\n```')
    ).toEqual([{ id: "X", summary: "s" }]);
    expect(() => parseSummaryArray("no json here")).toThrow();
  });
});

describe("OpenAiCompatibleClient", () => {
  it("requires an apiKey", () => {
    expect(
      () => new OpenAiCompatibleClient({ baseUrl: "https://x/v1", apiKey: "", model: "m" })
    ).toThrow();
  });
});
