import { useState } from "react";

interface Finding {
  id: string;
  package: string;
  severity: string;
  cvss: number;
  cwe: string;
  description: string;
  rank: number;
  score: number;
  evidence: { source: string; detail: string }[];
  // Slice 3 fields (all ride on the scan response; none reorders ranks).
  evidenceSummary?: string;
  liveIntelStatus?: string;
  liveIntelExcerpts?: string[];
  triageMemory?: {
    signature: string;
    decision: string;
    rationale: string;
    match: string;
  };
  exploitability?: number;
  reachability?: number;
}

interface ScanResult {
  id: string;
  status: "queued" | "running" | "done" | "partial" | "failed";
  progress: number;
  inventory?: { name: string; version: string }[];
  findings?: Finding[];
  degradedNotes?: string[];
  error?: string;
  liveIntelCredits?: number;
}

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: "#ff4444",
  HIGH: "#ff8800",
  MEDIUM: "#ffbb33",
  LOW: "#00c851",
};

const TERMINAL = new Set(["done", "partial", "failed"]);

// Deployed API base: set VITE_API_URL at build time (Vercel). In local dev
// the Vite proxy forwards /api to the server on :4000, so this stays empty.
const API_BASE = import.meta.env.VITE_API_URL ?? "";
const api = (path: string) => `${API_BASE}${path}`;

export default function App() {
  const [manifest, setManifest] = useState(
    '{\n  "dependencies": {\n    "lodash": "4.17.20",\n    "axios": "0.21.1",\n    "minimist": "1.2.5"\n  }\n}'
  );
  const [result, setResult] = useState<ScanResult | null>(null);
  const [progress, setProgress] = useState(0);
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [error, setError] = useState("");

  async function runScan() {
    setLoading(true);
    setError("");
    setResult(null);
    setProgress(0);
    try {
      // Validate locally first so the server only ever sees JSON text.
      JSON.parse(manifest);
      // DESIGN contract: {manifest: string} → 202 {jobId}, then poll.
      const res = await fetch(api("/api/scan"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ manifest }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error ?? `HTTP ${res.status}`);
      }
      const { jobId } = await res.json();
      // Poll until a terminal status. A vanished job (server restart wipes
      // the in-memory store) 404s: retry once after a short wait, then say
      // so plainly instead of looping forever. 10 min overall guard.
      const deadline = Date.now() + 10 * 60 * 1000;
      let retried404 = false;
      for (;;) {
        if (Date.now() > deadline) throw new Error("scan timed out after 10 minutes");
        const poll = await fetch(api(`/api/scan/${jobId}`));
        if (!poll.ok) {
          if (poll.status === 404 && !retried404) {
            retried404 = true;
            await new Promise((r) => setTimeout(r, 1500));
            continue;
          }
          if (poll.status === 404) {
            throw new Error("scan was lost on the server (restart); please rescan");
          }
          throw new Error(`poll HTTP ${poll.status}`);
        }
        const data: ScanResult = await poll.json();
        setProgress(data.progress ?? 0);
        if (TERMINAL.has(data.status)) {
          setResult(data);
          break;
        }
        await new Promise((r) => setTimeout(r, 400));
      }
    } catch (e) {
      setError(String(e));
    }
    setLoading(false);
  }

  function toggle(i: number) {
    const next = new Set(expanded);
    if (next.has(i)) next.delete(i);
    else next.add(i);
    setExpanded(next);
  }

  return (
    <div className="max-w-3xl mx-auto px-6 py-8 font-sans">
      <h1 className="text-3xl font-bold">🛡️ VulnIntel</h1>
      <p className="text-neutral-500">
        Paste a package.json — get ranked vulnerability intel with evidence.
      </p>

      <h3 className="mt-6 font-semibold">1. Dependency manifest</h3>
      <textarea
        value={manifest}
        onChange={(e) => setManifest(e.target.value)}
        rows={8}
        className="w-full font-mono text-sm p-3 border rounded mt-2"
      />
      <div className="mt-2 text-sm text-neutral-500">
        or upload a package.json:{" "}
        <input
          type="file"
          accept=".json,application/json"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = () => setManifest(String(reader.result ?? ""));
            reader.readAsText(file);
          }}
        />
      </div>
      <br />
      <button
        onClick={runScan}
        disabled={loading}
        className="mt-2 px-6 py-2.5 text-[15px] bg-neutral-900 text-white rounded hover:bg-neutral-700 disabled:opacity-50 cursor-pointer"
      >
        {loading ? `Scanning… ${progress}%` : "🔍 Scan for vulnerabilities"}
      </button>
      {loading && (
        <div className="h-2 bg-neutral-200 rounded mt-3 overflow-hidden">
          <div
            className="h-full bg-neutral-800 transition-all"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}
      {error && <p className="text-red-600 mt-2">{error}</p>}

      {result && (
        <>
          <h3 className="mt-6 font-semibold">
            2. Findings ({result.findings?.length ?? 0})
            {result.inventory && (
              <span className="font-normal text-neutral-500 text-sm">
                {" "}— {result.inventory.length} dependencies scanned
              </span>
            )}
            {result.liveIntelCredits !== undefined && (
              <span className="font-normal text-neutral-500 text-sm">
                {" "}· live intel credits used: {result.liveIntelCredits}
              </span>
            )}
          </h3>

          {(result.degradedNotes?.length ?? 0) > 0 && (
            <div className="mt-3 p-3 bg-amber-50 border border-amber-200 rounded text-sm text-amber-900">
              <strong>Degraded:</strong>
              <ul className="list-disc ml-5 mt-1">
                {result.degradedNotes!.map((n, i) => (
                  <li key={i}>{n}</li>
                ))}
              </ul>
            </div>
          )}

          {result.status === "failed" && (
            <p className="text-red-600 mt-2">Scan failed: {result.error}</p>
          )}

          {result.findings?.length === 0 && result.status !== "failed" && (
            <p className="text-green-700 mt-2">✅ No known vulnerabilities found.</p>
          )}

          {result.findings?.map((f, i) => (
            <div
              key={f.id}
              className="border border-neutral-200 rounded-lg p-4 mb-3 mt-3"
            >
              <div
                onClick={() => toggle(i)}
                className="cursor-pointer flex items-center gap-3"
              >
                <span
                  style={{ background: SEVERITY_COLOR[f.severity] ?? "#888" }}
                  className="text-white px-2.5 py-0.5 rounded-full text-xs font-bold"
                >
                  {f.severity}
                </span>
                <strong>#{f.rank} {f.id}</strong>
                <span className="text-neutral-500">
                  {f.package} · CVSS {f.cvss}
                </span>
                <span className="ml-auto text-neutral-400">
                  {expanded.has(i) ? "▼" : "▶"}
                </span>
              </div>
              <p className="mt-2 text-neutral-700">{f.description}</p>
              {f.evidenceSummary && (
                <p className="mt-2 text-sm text-neutral-700">
                  <strong>AI summary:</strong> {f.evidenceSummary}
                </p>
              )}
              {expanded.has(i) && (
                <div className="mt-3 pt-3 border-t border-neutral-100">
                  <strong>Why this ranks #{f.rank}:</strong>
                  <ul className="my-2">
                    {(f.evidence ?? []).map((e, j) => (
                      <li key={j} className="text-sm text-neutral-600">
                        <strong>{e.source}:</strong> {e.detail}
                      </li>
                    ))}
                  </ul>
                  {f.liveIntelStatus && (
                    <p className="text-sm text-neutral-600 mt-2">
                      <strong>Live intel:</strong> {f.liveIntelStatus}
                      {f.liveIntelStatus === "not checked" &&
                        " (top-5 findings per scan only)"}
                    </p>
                  )}
                  {(f.liveIntelExcerpts?.length ?? 0) > 0 && (
                    <ul className="my-2">
                      {f.liveIntelExcerpts!.map((ex, j) => (
                        <li key={j} className="text-sm text-neutral-600">
                          {ex}
                        </li>
                      ))}
                    </ul>
                  )}
                  {f.triageMemory && (
                    <p className="text-sm text-neutral-600 mt-2">
                      <strong>Triage memory ({f.triageMemory.match}):</strong>{" "}
                      {f.triageMemory.decision} — {f.triageMemory.rationale}
                    </p>
                  )}
                  <div className="text-xs text-neutral-500 mt-2">
                    CWE: {f.cwe} · Score: {f.score.toFixed(1)}
                    {f.exploitability !== undefined &&
                      ` · Exploitability: ${f.exploitability.toFixed(2)}`}
                    {f.reachability !== undefined &&
                      ` · Reachability: ${f.reachability.toFixed(2)}`}
                  </div>
                </div>
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
}
