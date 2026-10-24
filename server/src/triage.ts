/**
 * H-MEM triage memory — T-10 (Slice 3).
 *
 * Contract note (honest): the vendored H-MEM reference (vendor/hmem) hard-wires
 * its hash-mock embedder — `embed` is imported directly in memoryStore.ts /
 * memoryRetrieval.ts with no injection point — while DESIGN + the T-5 decision
 * require the hash mock to be REPLACED with the locked Cohere embedder. The
 * vendored README itself says implementations replace every piece with their
 * stack while the contracts stay the same. So this module implements the
 * H-MEM contract (add / query / feedback, JSON persistence, upsert by
 * signature) with the Cohere embedder, and the vendor tree is left untouched
 * (pin preserved). Seed decisions come from fixtures/triage-memory.json.
 *
 * Signature = package + version-range + CVE class (DESIGN data model).
 * Recall order: exact signature → same package + class → semantic
 * (Cohere cosine, only when an embedder is supplied).
 */

import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import { cosineSimilarity } from "./cohere.js";

export type TriageDecisionValue = "fix-now" | "defer" | "ignore";

export interface TriageDecision {
  signature: string;
  decision: TriageDecisionValue;
  rationale: string;
  createdAt: string;
  source: string;
}

export type TriageMatch = "exact" | "package-class" | "semantic";

export interface TriageRecall {
  decision: TriageDecision;
  match: TriageMatch;
  score: number;
}

/** CWE → CVE class (DESIGN signature taxonomy). Unknown CWEs fall back to
 * description-keyword matching in classFromDescription. */
const CWE_CLASS: Record<string, string> = {
  "CWE-1321": "prototype-pollution",
  "CWE-918": "ssrf",
  "CWE-94": "code-injection",
  "CWE-79": "xss",
  "CWE-89": "sql-injection",
  "CWE-787": "out-of-bounds-write",
  "CWE-125": "out-of-bounds-read",
  "CWE-119": "buffer-overflow",
  "CWE-20": "improper-input-validation",
  "CWE-200": "information-exposure",
  "CWE-269": "privilege-escalation",
  "CWE-22": "path-traversal",
  "CWE-400": "denial-of-service",
  "CWE-434": "unrestricted-upload",
};

const DESCRIPTION_CLASS: [RegExp, string][] = [
  [/prototype pollution/i, "prototype-pollution"],
  [/server-side request forgery|\bssrf\b/i, "ssrf"],
  [/cross-site scripting|\bxss\b/i, "xss"],
  [/sql injection/i, "sql-injection"],
  [/code injection|remote code execution|\brce\b/i, "code-injection"],
  [/denial of service|\bdos\b/i, "denial-of-service"],
  [/path traversal|directory traversal/i, "path-traversal"],
  [/buffer overflow/i, "buffer-overflow"],
  [/out-of-bounds write/i, "out-of-bounds-write"],
  [/out-of-bounds read/i, "out-of-bounds-read"],
];

export function classFromCwe(cwe: string): string | null {
  const normalized = cwe.startsWith("CWE-") ? cwe : `CWE-${cwe}`;
  return CWE_CLASS[normalized] ?? null;
}

export function classFromDescription(description: string): string | null {
  for (const [re, cls] of DESCRIPTION_CLASS) {
    if (re.test(description)) return cls;
  }
  return null;
}

/** Derive a finding's triage signature. Class comes from CWE, else description. */
export function findingSignature(
  pkg: string,
  affectedVersions: string,
  cwe: string,
  description: string
): string {
  const cls = classFromCwe(cwe) ?? classFromDescription(description) ?? "unknown";
  return `${pkg}@${affectedVersions}|${cls}`;
}

/** Split a signature into package / range / class. */
export function parseSignature(signature: string): {
  pkg: string;
  range: string;
  cls: string;
} | null {
  const m = signature.match(/^(.+)@([^|]+)\|(.+)$/);
  if (!m) return null;
  return { pkg: m[1], range: m[2], cls: m[3] };
}

export type EmbedderFn = (
  texts: string[],
  inputType: "search_document" | "search_query"
) => Promise<number[][]>;

export interface TriageMemoryOptions {
  /** Optional Cohere-style embedder for semantic recall. */
  embedder?: EmbedderFn;
  /** Cosine threshold for semantic recall (conservative default). */
  semanticThreshold?: number;
  /** Optional JSON file for persistence (mkdir -p + write on add). */
  storePath?: string;
}

const DEFAULT_SEMANTIC_THRESHOLD = 0.5;

export class TriageMemory {
  private decisions = new Map<string, TriageDecision>();
  /** Cached document vectors per signature (semantic recall only). */
  private vectors = new Map<string, number[]>();
  private readonly threshold: number;

  constructor(private readonly opts: TriageMemoryOptions = {}) {
    this.threshold = opts.semanticThreshold ?? DEFAULT_SEMANTIC_THRESHOLD;
  }

  /** Seed from fixtures/triage-memory.json content ({decisions: [...]}). */
  seedFromJson(data: unknown): void {
    const list = (data as { decisions?: TriageDecision[] } | null)?.decisions;
    if (!Array.isArray(list)) return;
    for (const d of list) this.add(d, false);
    this.persist();
  }

  /** Load a seed file from disk (returns false when unreadable — never fatal). */
  seedFromFile(path: string): boolean {
    try {
      this.seedFromJson(JSON.parse(readFileSync(path, "utf-8")) as unknown);
      return true;
    } catch {
      return false;
    }
  }

  /** Upsert by signature (seed refresh never duplicates). */
  add(d: TriageDecision, persist = true): void {
    this.decisions.set(d.signature, { ...d });
    this.vectors.delete(d.signature);
    if (persist) this.persist();
  }

  all(): TriageDecision[] {
    return [...this.decisions.values()];
  }

  /** Synchronous recall: exact signature, else same package + class. */
  recall(pkg: string, affectedVersions: string, cwe: string, description: string): TriageRecall | null {
    const sig = findingSignature(pkg, affectedVersions, cwe, description);
    const exact = this.decisions.get(sig);
    if (exact) return { decision: exact, match: "exact", score: 1 };
    const parsed = parseSignature(sig);
    if (parsed) {
      for (const d of this.decisions.values()) {
        const p = parseSignature(d.signature);
        if (!p) continue;
        if ((p.pkg === parsed.pkg || p.pkg === "*") && p.cls === parsed.cls) {
          return { decision: d, match: "package-class", score: 0.8 };
        }
      }
    }
    return null;
  }

  /** Semantic recall via the embedder (Cohere). Returns null without one.
   * Document vectors are embedded in a single batched call and cached. */
  async recallSemantic(queryText: string): Promise<TriageRecall | null> {
    const embedder = this.opts.embedder;
    if (!embedder || this.decisions.size === 0) return null;
    const [queryVec] = await embedder([queryText], "search_query");
    const uncached = [...this.decisions.values()].filter(
      (d) => !this.vectors.has(d.signature)
    );
    if (uncached.length > 0) {
      const vecs = await embedder(
        uncached.map((d) => `${d.signature} ${d.rationale}`),
        "search_document"
      );
      uncached.forEach((d, i) => this.vectors.set(d.signature, vecs[i]));
    }
    let best: TriageRecall | null = null;
    for (const d of this.decisions.values()) {
      const vec = this.vectors.get(d.signature);
      if (!vec) continue;
      const score = cosineSimilarity(queryVec, vec);
      if (score >= this.threshold && (!best || score > best.score)) {
        best = { decision: d, match: "semantic", score };
      }
    }
    return best;
  }

  /** Recall with semantic fallback: exact → package-class → semantic. */
  async recallWithSemantic(
    pkg: string,
    affectedVersions: string,
    cwe: string,
    description: string
  ): Promise<TriageRecall | null> {
    const hit = this.recall(pkg, affectedVersions, cwe, description);
    if (hit) return hit;
    return this.recallSemantic(`${pkg} ${cwe} ${description}`);
  }

  private persist(): void {
    const path = this.opts.storePath;
    if (!path) return;
    try {
      mkdirSync(dirname(path), { recursive: true });
      writeFileSync(path, JSON.stringify({ decisions: this.all() }, null, 2));
    } catch {
      // Persistence is best-effort; memory still works in-process.
    }
  }
}
