/**
 * Ranking synthesis — T-11 (Slice 3).
 *
 * Determinism is a T-11 requirement ("deterministically ordered ranked list"),
 * so the LLM NEVER reorders findings: order comes from a closed-form score
 * (severity × exploitability × reachability), and the LLM contributes only
 * per-finding evidence summaries. Swapping the provider key therefore changes
 * nothing structurally (same ranks, scores, evidence refs) — verified in tests.
 *
 * Score: severityWeight(CRITICAL 4 / HIGH 3 / MEDIUM 2 / LOW 1) × cvss ×
 * exploitability × reachability. Exploitability starts at cvss/10 and gains
 * +0.15 when live intel actually found exploit chatter (capped at 1).
 * Reachability is 1.0: manifest dependencies are direct by construction
 * (parseManifest only reads `dependencies`); transitive reachability analysis
 * is documented future work, not silently invented here.
 *
 * LLM failure (primary + one fallback attempt) degrades to summaries-omitted
 * with a named note — the scan still succeeds (T-13 "LLM primary down"
 * fault shape). No LLM key configured means deterministic-only ranking with
 * no note: that is the baseline, not a degradation.
 */

import type { RankedFinding, Vulnerability } from "./types.js";
import type { LiveIntelStatus } from "./types.js";

export interface LlmProviderConfig {
  baseUrl: string;
  apiKey: string;
  model: string;
}

export class LlmError extends Error {
  constructor(
    message: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = "LlmError";
  }
}

/** Minimal OpenAI-compatible chat client (NVIDIA / Meterless / FastRouter). */
export class OpenAiCompatibleClient {
  constructor(
    private readonly config: LlmProviderConfig,
    private readonly fetchFn: typeof fetch = fetch
  ) {
    if (!config.apiKey) throw new LlmError("llm: apiKey is required");
    this.baseUrl = config.baseUrl.replace(/\/+$/, "");
  }

  private readonly baseUrl: string;

  /** List available models (GET {base}/models) — used to pick a real id. */
  async listModels(): Promise<string[]> {
    const res = await this.fetchFn(`${this.baseUrl}/models`, {
      headers: { Authorization: `Bearer ${this.config.apiKey}` },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) throw new LlmError(`llm: models HTTP ${res.status}`, res.status);
    const data = (await res.json()) as { data?: { id?: string }[] };
    return (data.data ?? []).map((m) => m.id ?? "").filter(Boolean);
  }

  /** One chat completion; returns the assistant message content. */
  async chat(
    messages: { role: string; content: string }[],
    opts?: { temperature?: number; timeoutMs?: number }
  ): Promise<string> {
    const res = await this.fetchFn(`${this.baseUrl}/chat/completions`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.config.apiKey}`,
      },
      body: JSON.stringify({
        model: this.config.model,
        messages,
        temperature: opts?.temperature ?? 0,
      }),
      signal: AbortSignal.timeout(opts?.timeoutMs ?? 60000),
    });
    if (!res.ok) throw new LlmError(`llm: chat HTTP ${res.status}`, res.status);
    const data = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const content = data.choices?.[0]?.message?.content;
    if (!content) throw new LlmError("llm: empty completion");
    return content;
  }
}

export const SEVERITY_WEIGHT = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;

export function exploitabilityOf(
  cvss: number,
  liveIntelStatus?: LiveIntelStatus
): number {
  const bonus = liveIntelStatus === "found" ? 0.15 : 0;
  return Math.min(1, Math.max(0, cvss / 10 + bonus));
}

/** Manifest dependencies are direct by construction — see module doc. */
export function reachabilityOf(): number {
  return 1;
}

export function deterministicScore(f: {
  severity: keyof typeof SEVERITY_WEIGHT;
  cvss: number;
  liveIntelStatus?: LiveIntelStatus;
}): { score: number; exploitability: number; reachability: number } {
  const exploitability = exploitabilityOf(f.cvss, f.liveIntelStatus);
  const reachability = reachabilityOf();
  return {
    score: SEVERITY_WEIGHT[f.severity] * f.cvss * exploitability * reachability,
    exploitability,
    reachability,
  };
}

export type RankInput = Vulnerability & {
  liveIntelStatus?: LiveIntelStatus;
  liveIntelExcerpts?: string[];
  triageMemory?: RankedFinding["triageMemory"];
};

export interface RankedWithReasoning extends RankedFinding {
  exploitability: number;
  reachability: number;
  evidenceSummary?: string;
}

/** Extract a JSON array from an LLM reply, tolerating code fences. */
export function parseSummaryArray(text: string): { id: string; summary: string }[] {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const candidate = fenced ? fenced[1] : text;
  const start = candidate.indexOf("[");
  const end = candidate.lastIndexOf("]");
  if (start === -1 || end === -1 || end <= start) {
    throw new LlmError("llm: no JSON array in completion");
  }
  const parsed = JSON.parse(candidate.slice(start, end + 1)) as unknown;
  if (!Array.isArray(parsed)) throw new LlmError("llm: completion is not an array");
  return parsed
    .filter(
      (e): e is { id: string; summary: string } =>
        typeof (e as { id?: unknown }).id === "string" &&
        typeof (e as { summary?: unknown }).summary === "string"
    )
    .map((e) => ({ id: e.id, summary: e.summary.slice(0, 200) }));
}

export interface SynthesizeOptions {
  llm?: OpenAiCompatibleClient;
  fallbackLlm?: OpenAiCompatibleClient;
}

export interface SynthesizeResult {
  ranked: RankedWithReasoning[];
  notes: string[];
  llmUsed: boolean;
}

/**
 * Rank findings deterministically; attach LLM evidence summaries when a
 * provider is available. Order never depends on the LLM.
 */
export async function synthesizeRanking(
  findings: RankInput[],
  opts: SynthesizeOptions = {}
): Promise<SynthesizeResult> {
  const notes: string[] = [];
  const scored = findings.map((f) => {
    const { score, exploitability, reachability } = deterministicScore(f);
    return { f, score, exploitability, reachability };
  });
  scored.sort(
    (a, b) =>
      b.score - a.score ||
      b.f.cvss - a.f.cvss ||
      a.f.id.localeCompare(b.f.id)
  );
  const ranked: RankedWithReasoning[] = scored.map((s, i) => {
    const evidence = s.f.sources.map((src) => ({
      source: src,
      detail: `${s.f.id} reported by ${src}`,
    }));
    if (s.f.liveIntelExcerpts?.length) {
      for (const ex of s.f.liveIntelExcerpts) {
        evidence.push({ source: "brightdata-serp", detail: ex });
      }
    }
    if (s.f.triageMemory) {
      evidence.push({
        source: "triage-memory",
        detail: `${s.f.triageMemory.decision} (${s.f.triageMemory.match}): ${s.f.triageMemory.rationale}`,
      });
    }
    return {
      ...s.f,
      rank: i + 1,
      score: s.score,
      exploitability: s.exploitability,
      reachability: s.reachability,
      evidence,
    };
  });

  let llmUsed = false;
  if (opts.llm) {
    const promptFindings = ranked.map((r) => ({
      id: r.id,
      package: r.package,
      version: r.affectedVersions,
      severity: r.severity,
      cvss: r.cvss,
      cwe: r.cwe,
      liveIntel: r.liveIntelStatus ?? "not checked",
      triage: r.triageMemory?.decision ?? null,
    }));
    const messages = [
      {
        role: "system",
        content:
          "You are a vulnerability triage assistant. Return ONLY a JSON array of {id, summary} with one entry per finding, each summary at most 200 characters explaining why this finding matters. No other text.",
      },
      { role: "user", content: JSON.stringify(promptFindings) },
    ];
    let summaryText: string | null = null;
    try {
      summaryText = await opts.llm.chat(messages);
    } catch {
      if (opts.fallbackLlm) {
        try {
          summaryText = await opts.fallbackLlm.chat(messages);
        } catch {
          summaryText = null;
        }
      }
    }
    if (summaryText) {
      try {
        const summaries = new Map(parseSummaryArray(summaryText).map((s) => [s.id, s.summary]));
        for (const r of ranked) {
          const s = summaries.get(r.id);
          if (s) r.evidenceSummary = s;
        }
        llmUsed = true;
      } catch {
        notes.push("LLM ranking synthesis returned an unparseable reply; deterministic ranking used");
      }
    } else {
      notes.push("LLM ranking synthesis unavailable (primary and fallback failed); deterministic ranking used");
    }
  } else {
    // S5, D2: no LLM configured at all is a named degradation, not a
    // silent omission — local keyless runs previously dropped summaries
    // with no note anywhere.
    notes.push("LLM not configured; summaries omitted");
  }

  return { ranked, notes, llmUsed };
}
