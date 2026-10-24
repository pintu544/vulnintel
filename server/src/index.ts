import express from "express";
import cors from "cors";
import { randomBytes, createHash } from "crypto";
import { join } from "path";
import { Pool } from "pg";
import { parseManifest, loadFixtureVulns, matchVulns, resolveFixturesDir } from "./scanner.js";
import { FINDINGS_CAP } from "./types.js";
import type { ScanJob, Vulnerability, LiveIntelStatus } from "./types.js";
import { queryOsvVulns, matchOsvVulns, osvToVulnerability } from "./osv.js";
import { enrichWithNvd } from "./nvd.js";
import { BrightDataClient } from "./brightdata.js";
import { TriageMemory } from "./triage.js";
import { embedCohere } from "./cohere.js";
import { synthesizeRanking, OpenAiCompatibleClient } from "./ranking.js";
import { ensureSchema, seedCuratedSubset, type PoolLike } from "./fallbackDb.js";
import { ZetarisAdapter } from "./zetaris.js";

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const jobs = new Map<string, ScanJob>();

/**
 * GET /api/health — liveness probe.
 * T-2 ships the simple shape; the DESIGN contract shape
 * ({ok, zetaris, brightdata, llm}) lands by T-13 fault-injection.
 */
app.get("/api/health", (_req, res) => {
  res.json({ ok: true, service: "vulnintel-server", version: "0.1.0" });
});

/**
 * POST /api/scan — DESIGN contract (B-2 kickoff decision).
 * Body: {manifest: string} (raw package.json text).
 * Returns 202 {jobId}; the job runs asynchronously and is polled via GET /api/scan/:id.
 * Statuses: queued → running → done | partial | failed.
 */
app.post("/api/scan", (req, res) => {
  const manifestText = req.body?.manifest;
  if (typeof manifestText !== "string" || manifestText.trim() === "") {
    return res
      .status(400)
      .json({ error: "body must be {manifest: string} (package.json text)" });
  }

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(manifestText);
  } catch {
    return res.status(400).json({ error: "manifest is not valid JSON" });
  }
  if (typeof manifest !== "object" || manifest === null || Array.isArray(manifest)) {
    return res.status(400).json({ error: "manifest must be a package.json object" });
  }

  const deps = manifest.dependencies as Record<string, string> | undefined;
  if (deps !== undefined && (typeof deps !== "object" || Array.isArray(deps))) {
    return res.status(400).json({ error: "dependencies must be an object" });
  }

  const id = randomBytes(8).toString("hex");
  const job: ScanJob = {
    id,
    status: "queued",
    manifestHash: createHash("sha256").update(manifestText).digest("hex"),
    progress: 0,
    degradedNotes: [],
    manifest: (deps as Record<string, string>) ?? {},
    createdAt: new Date().toISOString(),
  };
  jobs.set(id, job);

  // Cap in-memory jobs (prevent exhaustion)
  if (jobs.size > 1000) {
    const oldest = [...jobs.values()].sort((a, b) =>
      a.createdAt.localeCompare(b.createdAt)
    )[0];
    jobs.delete(oldest.id);
  }

  // Process asynchronously so the client can poll progress.
  setImmediate(() => runScanJob(job, manifest));

  res.status(202).json({ jobId: id });
});

function runScanJob(job: ScanJob, manifest: Record<string, unknown>) {
  void (async () => {
  try {
    job.status = "running";
    job.progress = 10;

    const inventory = parseManifest(manifest);
    job.inventory = inventory;
    job.progress = 30;

    // B-3 (kickoff decision): >200 deps is NOT a 400 — scan proceeds,
    // findings capped at top 25, and the cap is named in degradedNotes.
    if (inventory.length > 200) {
      job.degradedNotes.push(
        `manifest has ${inventory.length} dependencies (>200): ranked findings capped at top ${FINDINGS_CAP}`
      );
    }

    // Slice 2: live OSV querybatch matching (T-7) + NVD enrichment (T-8).
    // Fixtures remain as fallback when OSV is unreachable — named in
    // degradedNotes, never a silent gap (FR-10).
    job.progress = 55;
    let matches: Vulnerability[];
    try {
      const { vulns, hydrateFailures, hydrationCapped } =
        await queryOsvVulns(inventory);
      if (hydrateFailures > 0) {
        job.degradedNotes.push(
          `OSV detail hydration failed for ${hydrateFailures} record(s); results may be incomplete`
        );
      }
      if (hydrationCapped) {
        job.degradedNotes.push(
          "OSV hydration capped; results may be incomplete"
        );
      }
      matches = matchOsvVulns(inventory, vulns).map(osvToVulnerability);
    } catch (e) {
      job.degradedNotes.push(
        `live OSV unavailable (${e instanceof Error ? e.message : String(e)}); fixture fallback used`
      );
      matches = matchVulns(inventory, loadFixtureVulns());
    }
    job.progress = 80;
    // NVD enrichment is best-effort: keyed (50 req/30s) when NVD_API_KEY is
    // set, keyless (5 req/30s) otherwise; failures are noted, never fatal.
    const { enriched, notes } = await enrichWithNvd(matches, {
      apiKey: process.env.NVD_API_KEY,
    });
    job.degradedNotes.push(...notes);

    // Slice 3, T-10: attach recalled triage decisions (seed fixture +
    // POST /api/triage records). Semantic recall runs only when a Cohere
    // key is configured; memory failures never fail a scan.
    job.progress = 85;
    const withTriage = [];
    for (const v of enriched) {
      try {
        const recall = await triageMemory().recallWithSemantic(
          v.package,
          v.affectedVersions,
          v.cwe,
          v.description
        );
        withTriage.push({
          ...v,
          triageMemory: recall
            ? {
                signature: recall.decision.signature,
                decision: recall.decision.decision,
                rationale: recall.decision.rationale,
                match: recall.match,
              }
            : undefined,
        });
      } catch {
        withTriage.push({ ...v });
      }
    }

    // Slice 3, T-9: Bright Data live intel for the top 5 findings only
    // (1 credit per SERP call; the cap is named, never silent). One client
    // per scan job, closed after. Unconfigured or failed intel is a named
    // degradation, never a silent gap (FR-10).
    job.progress = 90;
    const INTEL_TOP_N = 5;
    const bdToken = process.env.BRIGHTDATA_API_TOKEN;
    let withIntel: Array<(typeof withTriage)[number] & { liveIntelStatus: LiveIntelStatus; liveIntelExcerpts?: string[] }> =
      withTriage.map((v) => ({ ...v, liveIntelStatus: "not checked" as LiveIntelStatus }));
    if (!bdToken) {
      withIntel = withTriage.map((v) => ({ ...v, liveIntelStatus: "unavailable" as LiveIntelStatus }));
      job.degradedNotes.push("Bright Data not configured; live intel unavailable");
    } else {
      const bd = new BrightDataClient({
        apiKey: bdToken,
      });
      try {
        const order = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 } as const;
        const top = [...withTriage]
          .sort((a, b) => order[b.severity] - order[a.severity] || b.cvss - a.cvss)
          .slice(0, INTEL_TOP_N);
        withIntel = withTriage.map((v) => ({
          ...v,
          liveIntelStatus: "not checked" as LiveIntelStatus,
        }));
        for (const t of top) {
          try {
            const intel = await bd.serpExploitIntel(t.id);
            const key = `${t.package}@${t.id}`;
            const idx = withIntel.findIndex((v) => `${v.package}@${v.id}` === key);
            if (idx >= 0) {
              withIntel[idx] = {
                ...withIntel[idx],
                liveIntelStatus: intel.hits.length > 0 ? "found" : "no live intel found",
                liveIntelExcerpts: intel.hits.map((h) => `${h.title} — ${h.snippet}`.trim()),
              };
            }
          } catch {
            const key = `${t.package}@${t.id}`;
            const idx = withIntel.findIndex((v) => `${v.package}@${v.id}` === key);
            if (idx >= 0) withIntel[idx] = { ...withIntel[idx], liveIntelStatus: "unavailable" };
          }
        }
        job.liveIntelCredits = bd.creditsUsed;
        if (withTriage.length > INTEL_TOP_N) {
          job.degradedNotes.push(
            `live intel checked for top ${INTEL_TOP_N} findings only (credit discipline); rest marked "not checked"`
          );
        }
      } catch (e) {
        job.degradedNotes.push(
          `Bright Data intel unavailable (${e instanceof Error ? e.message : String(e)})`
        );
      } finally {
        await bd.close();
      }
    }

    // Slice 3, T-11: deterministic ranking + optional LLM evidence summaries.
    // Order never depends on the LLM; failure degrades to summaries-omitted.
    job.progress = 95;
    const llmKey = process.env.LLM_API_KEY ?? process.env.NVIDIA_API_KEY;
    const llm = llmKey
      ? new OpenAiCompatibleClient({
          baseUrl: process.env.LLM_BASE_URL ?? "https://integrate.api.nvidia.com/v1",
          apiKey: llmKey,
          model: process.env.LLM_MODEL ?? "nvidia/llama-3.1-nemotron-70b-instruct",
        })
      : undefined;
    const fallbackKey = process.env.LLM_FALLBACK_API_KEY ?? process.env.FASTROUTER_API_KEY1;
    const fallbackLlm = fallbackKey
      ? new OpenAiCompatibleClient({
          baseUrl: process.env.LLM_FALLBACK_BASE_URL ?? "https://go.fastrouter.ai/api/v1",
          apiKey: fallbackKey,
          model: process.env.LLM_FALLBACK_MODEL ?? "openai/gpt-5.2",
        })
      : undefined;
    const { ranked, notes: rankNotes } = await synthesizeRanking(withIntel, { llm, fallbackLlm });
    job.degradedNotes.push(...rankNotes);
    if (ranked.length > FINDINGS_CAP) {
      job.degradedNotes.push(
        `${ranked.length} findings matched; returning top ${FINDINGS_CAP} by score`
      );
    }
    job.findings = ranked.slice(0, FINDINGS_CAP);
    job.progress = 100;
    job.status = job.degradedNotes.length > 0 ? "partial" : "done";
  } catch (e) {
    job.status = "failed";
    job.error = String(e);
    job.progress = 100;
  }
  })();
}

/**
 * GET /api/scan/:id — poll job state.
 * Response: {id, status, progress, findings?, degradedNotes[], inventory?, error?, liveIntelCredits?}
 */
app.get("/api/scan/:id", (req, res) => {
  const job = jobs.get(req.params.id);
  if (!job) return res.status(404).json({ error: "scan not found" });
  res.json({
    id: job.id,
    status: job.status,
    progress: job.progress,
    findings: job.findings,
    degradedNotes: job.degradedNotes,
    inventory: job.inventory,
    error: job.error,
    liveIntelCredits: job.liveIntelCredits,
  });
});

// ---- Triage memory (Slice 3, T-10) ----

let _triage: TriageMemory | null = null;

/** Singleton triage memory, seeded from fixtures/triage-memory.json at boot.
 * Semantic recall is wired only when a Cohere key is configured. */
function triageMemory(): TriageMemory {
  if (!_triage) {
    const cohereKey = process.env.COHERE_API_KEY1;
    _triage = new TriageMemory({
      storePath: process.env.TRIAGE_STORE_PATH || undefined,
      embedder: cohereKey
        ? (texts, inputType) => embedCohere(texts, { apiKey: cohereKey, inputType })
        : undefined,
    });
    _triage.seedFromFile(join(resolveFixturesDir(), "triage-memory.json"));
  }
  return _triage;
}

/**
 * POST /api/triage — record a triage decision (DESIGN contract).
 * Body: {signature: string, decision: fix-now|defer|ignore, rationale?: string}
 * Upserts by signature; a later rescan surfaces it on similar findings.
 */
app.post("/api/triage", (req, res) => {
  const { signature, decision, rationale } = req.body ?? {};
  if (typeof signature !== "string" || signature.trim() === "") {
    return res.status(400).json({ error: "signature must be a non-empty string" });
  }
  if (decision !== "fix-now" && decision !== "defer" && decision !== "ignore") {
    return res.status(400).json({ error: "decision must be fix-now|defer|ignore" });
  }
  if (rationale !== undefined && typeof rationale !== "string") {
    return res.status(400).json({ error: "rationale must be a string" });
  }
  triageMemory().add({
    signature,
    decision,
    rationale: rationale ?? "",
    createdAt: new Date().toISOString(),
    source: "api",
  });
  res.json({ ok: true });
});

// ---- Data-plane admin (build-window seeding; not part of the scan API) ----

let _pool: Pool | null = null;
function pool(): PoolLike {
  if (!_pool) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is not set");
    _pool = new Pool({ connectionString: url, max: 3 });
  }
  return _pool as unknown as PoolLike;
}

/**
 * POST /api/admin/seed — seed the curated fallback subset
 * (fixture CVEs + top-package CVEs from OSV.dev; never full NVD).
 * Protected by the ADMIN_KEY env var (header x-admin-key).
 * The App Service has clean egress, so seeding runs here — the build VM's
 * egress proxy breaks direct Postgres SSL.
 */
app.post("/api/admin/seed", async (req, res) => {
  const adminKey = process.env.ADMIN_KEY;
  if (!adminKey || req.headers["x-admin-key"] !== adminKey) {
    return res.status(adminKey ? 403 : 503).json({ error: "admin seeding is not enabled" });
  }
  try {
    const p = pool();
    await ensureSchema(p);
    const counts = await seedCuratedSubset(p, loadFixtureVulns());
    // Prime the Zetaris adapter state for the health check (no throw when unconfigured).
    const zetaris = new ZetarisAdapter();
    res.json({ ok: true, ...counts, zetarisConfigured: zetaris.isConfigured() });
  } catch (e) {
    res.status(500).json({ error: String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`vulnintel-server on :${PORT}`);
});
