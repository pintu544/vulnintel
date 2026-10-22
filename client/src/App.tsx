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
}

interface ScanResult {
  id: string;
  status: "queued" | "running" | "done" | "partial" | "failed";
  progress: number;
  inventory?: { name: string; version: string }[];
  findings?: Finding[];
  degradedNotes?: string[];
  error?: string;
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
      // Poll until a terminal status.
      for (;;) {
        const poll = await fetch(api(`/api/scan/${jobId}`));
        if (!poll.ok) throw new Error(`poll HTTP ${poll.status}`);
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
              {expanded.has(i) && (
                <div className="mt-3 pt-3 border-t border-neutral-100">
                  <strong>Why this ranks #{f.rank}:</strong>
                  <ul className="my-2">
                    {f.evidence.map((e, j) => (
                      <li key={j} className="text-sm text-neutral-600">
                        <strong>{e.source}:</strong> {e.detail}
                      </li>
                    ))}
                  </ul>
                  <div className="text-xs text-neutral-500">
                    CWE: {f.cwe} · Score: {f.score.toFixed(1)}
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
