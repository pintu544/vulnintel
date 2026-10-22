import express from "express";
import cors from "cors";
import { randomBytes, createHash } from "crypto";
import { Pool } from "pg";
import { parseManifest, loadFixtureVulns, matchVulns, rankFindings } from "./scanner.js";
import { FINDINGS_CAP } from "./types.js";
import type { ScanJob } from "./types.js";
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

    // Slice 1: fixture-backed matching. T-7 swaps in OSV querybatch behind
    // the same function boundary; T-8 adds NVD enrichment.
    const vulns = loadFixtureVulns();
    job.progress = 55;
    const matches = matchVulns(inventory, vulns);
    job.progress = 80;
    const ranked = rankFindings(matches);
    if (matches.length > FINDINGS_CAP) {
      job.degradedNotes.push(
        `${matches.length} findings matched; returning top ${FINDINGS_CAP} by score`
      );
    }
    job.findings = ranked;
    job.progress = 100;
    job.status = job.degradedNotes.length > 0 ? "partial" : "done";
  } catch (e) {
    job.status = "failed";
    job.error = String(e);
    job.progress = 100;
  }
}

/**
 * GET /api/scan/:id — poll job state.
 * Response: {id, status, progress, findings?, degradedNotes[], inventory?, error?}
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
  });
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
