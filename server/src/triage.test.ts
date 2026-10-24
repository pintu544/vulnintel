import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import {
  TriageMemory,
  findingSignature,
  classFromCwe,
  classFromDescription,
  parseSignature,
} from "./triage.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const seedPath = join(__dirname, "..", "..", "fixtures", "triage-memory.json");

function seeded(): TriageMemory {
  const m = new TriageMemory();
  m.seedFromFile(seedPath);
  return m;
}

describe("signature derivation", () => {
  it("maps CWE-1321 to prototype-pollution and builds the DESIGN signature", () => {
    expect(findingSignature("lodash", "<4.17.21", "CWE-1321", "Prototype pollution")).toBe(
      "lodash@<4.17.21|prototype-pollution"
    );
    expect(classFromCwe("CWE-918")).toBe("ssrf");
    expect(classFromCwe("1321")).toBe("prototype-pollution");
    expect(classFromDescription("SSRF in axios via crafted URL")).toBe("ssrf");
    expect(classFromDescription("Something entirely unrelated")).toBeNull();
  });

  it("parses signatures and rejects malformed ones", () => {
    expect(parseSignature("lodash@<4.17.21|prototype-pollution")).toEqual({
      pkg: "lodash",
      range: "<4.17.21",
      cls: "prototype-pollution",
    });
    expect(parseSignature("garbage")).toBeNull();
  });
});

describe("seed fixture", () => {
  it("loads exactly the 5 v1.0.1 seed decisions", () => {
    const raw = JSON.parse(readFileSync(seedPath, "utf-8")) as { decisions: unknown[]; version: string };
    expect(raw.version).toBe("1.0.1");
    const m = seeded();
    expect(m.all()).toHaveLength(5);
    expect(m.all().filter((d) => d.decision === "fix-now")).toHaveLength(2);
  });

  it("re-seeding never duplicates (upsert by signature)", () => {
    const m = seeded();
    m.seedFromFile(seedPath);
    expect(m.all()).toHaveLength(5);
  });
});

describe("recall", () => {
  it("exact signature recall wins (T-10 acceptance: seed lodash decision, NVD shape)", () => {
    const m = seeded();
    const hit = m.recall("lodash", "<4.17.21", "CWE-94", "Command Injection in lodash");
    expect(hit?.match).toBe("exact");
    expect(hit?.decision.decision).toBe("fix-now");
  });

  it("package-class recall fires when the range differs (similar finding)", () => {
    const m = seeded();
    const hit = m.recall("lodash", "<4.17.20", "CWE-94", "Command Injection in lodash");
    expect(hit?.match).toBe("package-class");
    expect(hit?.decision.decision).toBe("fix-now");
  });

  it("no recall for unrelated package/class", () => {
    const m = seeded();
    expect(m.recall("react", "<18.0.0", "CWE-79", "Cross-site scripting")).toBeNull();
  });

  it("POST-style add upserts and is recalled on rescan", () => {
    const m = seeded();
    m.add({
      signature: "lodash@<4.17.21|code-injection",
      decision: "defer",
      rationale: "e2e test override",
      createdAt: new Date().toISOString(),
      source: "api",
    });
    const hit = m.recall("lodash", "<4.17.21", "CWE-94", "Command Injection in lodash");
    expect(hit?.decision.decision).toBe("defer");
    expect(m.all()).toHaveLength(5); // upsert, not a duplicate
  });

  it("validation: decisions are one of the three values (enforced at API layer)", () => {
    const m = seeded();
    m.add({
      signature: "x@<1|y",
      decision: "fix-now",
      rationale: "",
      createdAt: new Date().toISOString(),
      source: "api",
    });
    expect(m.all()).toHaveLength(6);
  });
});

describe("semantic recall (mock embedder)", () => {
  // Deterministic 3-dim vectors: doc A ~ query, doc B orthogonal.
  const mockEmbedder = async (texts: string[]) =>
    texts.map((t) =>
      t.includes("lodash")
        ? [1, 0, 0]
        : t.includes("axios")
          ? [0, 1, 0]
          : t.includes("zzz")
            ? [0, 0, 1]
            : [1, 1, 0]
    );

  it("recalls the semantically closest decision above threshold", async () => {
    const m = new TriageMemory({ embedder: mockEmbedder, semanticThreshold: 0.5 });
    m.seedFromFile(seedPath);
    const hit = await m.recallSemantic("lodash command injection template function");
    expect(hit?.match).toBe("semantic");
    expect(hit?.decision.signature).toContain("lodash");
  });

  it("returns null below threshold and without an embedder", async () => {
    // Isolated memory: doc vector [1,0,0], query vector [0,1,0] → cosine 0.
    const strict = new TriageMemory({ embedder: mockEmbedder, semanticThreshold: 0.99 });
    strict.add({
      signature: "zzz@<1|qqq",
      decision: "ignore",
      rationale: "zzz",
      createdAt: new Date().toISOString(),
      source: "test",
    });
    await expect(strict.recallSemantic("cooking recipe")).resolves.toBeNull();
    const noEmbedder = seeded();
    await expect(noEmbedder.recallSemantic("lodash")).resolves.toBeNull();
  });

  it("recallWithSemantic prefers exact over semantic", async () => {
    const m = new TriageMemory({ embedder: mockEmbedder });
    m.seedFromFile(seedPath);
    const hit = await m.recallWithSemantic("lodash", "<4.17.21", "CWE-94", "Command Injection in lodash");
    expect(hit?.match).toBe("exact");
  });
});
