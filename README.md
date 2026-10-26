# VulnIntel — Open Agent Hackathon 2026 (Track 01)

Unified vulnerability intelligence: paste a `package.json`, get ranked,
evidence-backed findings on what to fix first and why.

**Live demo:** https://vulnintel-two.vercel.app
**API:** https://vulnintel-api.azurewebsites.net · **Health:** `/api/health`

Built solo for the Open Agent Hackathon 2026 (GenAI Works), Track 01
(Solving Fragmented Intelligence). Every commit in this repo is in-window
(first commit Oct 22, 2026); the only third-party code is the vendored
Meterless H-MEM tree (see below).

## What it does

Vulnerability intelligence is fragmented: NVD/CVE records, OSV/GHSA
advisories, live exploit chatter, and a team's own triage history live in
different places, and a raw CVE list doesn't say what to fix first.
VulnIntel unifies them into one ranked list with an evidence trail:

1. **Parse** — a `package.json` manifest (paste or upload).
2. **Match** — live OSV `querybatch` matching against the inventory
   (fixture fallback, named, when OSV is unreachable).
3. **Enrich** — NVD enrichment (keyed 50 req/30s, keyless 5 req/30s);
   failures keep OSV-derived values and are named per finding.
4. **Recall** — H-MEM triage memory: exact, package-class, then semantic
   recall of past triage decisions (fix-now / defer / ignore + rationale).
5. **Rank** — deterministic order: severity weight × CVSS × exploitability
   × reachability. The LLM never reorders; it only adds ≤200-character
   evidence summaries. If the LLM is down, the order stands and the
   summaries are omitted with a named note.
6. **Live intel** — Bright Data SERP excerpts for the top 5 findings
   (1 credit each, cap named in the UI).

Results are capped at the top 25 findings; a manifest with >200
dependencies still scans, with the cap named. A scan never fails
silently: any degraded path ends in status `partial` with a named note
in the degraded banner, never an empty success.

## Quick start

```bash
npm install
npm run dev        # server :4000 + client :5173
npm test           # vitest suite (server workspace)
```

## API

| Endpoint | Shape |
| --- | --- |
| `POST /api/scan` `{manifest: string}` | `202 {jobId}` — async job |
| `GET /api/scan/:id` | `{status, progress, findings?, degradedNotes[], liveIntelCredits?}` |
| `GET /api/health` | `{ok, service, version, zetaris: {configured}, brightdata: {configured}, llm: {primary, fallback}}` — flags only, no live pings, no key material |
| `POST /api/triage` | `{signature, decision, rationale}` → `{ok: true}` — requires `x-admin-key: ADMIN_KEY` |
| `POST /api/admin/seed` | admin-only fixture seed — requires `ADMIN_KEY` |

Job statuses: `queued → running → done | partial | failed`.
A vanished job (server restart wipes the in-memory store) returns
`404 {error: "scan not found"}`; the client retries once, then shows a
plain "scan was lost, please rescan" message.

## Configuration (names only — values live in the deployment, never here)

`PORT`, `NVD_API_KEY`, `BRIGHTDATA_API_TOKEN`,
`LLM_API_KEY` (or `NVIDIA_API_KEY`), `LLM_FALLBACK_API_KEY` (or
`FASTROUTER_API_KEY1`), `COHERE_API_KEY1`, `ADMIN_KEY`,
`TRIAGE_STORE_PATH`, `FIXTURES_DIR`, `DATABASE_URL`.

## Tests

108 tests green: 98 server tests + 10 vendor H-MEM smoke tests
(`npm test`). Slice 5 added a 14-row fault matrix (unit + live local
runs): OSV/NVD/Bright Data/LLM failure modes, malformed and oversize
manifests, 250-dependency manifests, and an all-upstreams-down run —
each producing the specified visible degradation.

## Architecture notes

- `server/` — Express + TypeScript API. `scanner.ts` (manifest parsing,
  range resolution, matching, deterministic ranking), `osv.ts`,
  `nvd.ts`, `brightdata.ts` (official `@brightdata/sdk`), `triage.ts`
  (H-MEM contract), `ranking.ts` (LLM evidence synthesis, primary +
  fallback), `zetaris.ts` (adapter), `fallbackDb.ts` (direct-Postgres
  fallback plane).
- `client/` — Vite + React + Tailwind UI: paste or upload a manifest,
  poll progress, expandable evidence per finding (AI summary, live
  intel excerpts, triage decision/rationale/match, exploitability,
  reachability), live-intel credits in the header, degraded banner.
- `fixtures/` — versioned CVE fixtures + triage-memory seed (5 decisions).

## Sponsor technologies — honest status

- **Bright Data — live.** Real SERP calls via the official SDK, 1
  credit per finding, top-5 cap. Verified live on Azure (found intel
  with 5 excerpts per finding; intermittent empty SERP results are
  upstream variance, not a parser gap).
- **Meterless — real.** Triage memory is built on Meterless's H-MEM
  engine spec (vendored tree, pin
  `1742dec56a66e58eef9dda2d2b865823758ca8cd`, untouched). Deviation,
  disclosed: the vendor tree hard-wires a hash-mock embedder with no
  injection point, so the contract is implemented with the Cohere
  `embed-english-v3.0` embedder (1024 dims) rather than forking the
  vendor tree.
- **NVIDIA Nemotron — live as primary.** The original primary
  (`nvidia/llama-3.1-nemotron-70b-instruct`) returns 404 "Function …
  Not found for account" on chat completions although the id still
  lists in `/v1/models` — NVIDIA staff confirmed in Dec 2025 that the
  Llama 3.1 Nemotron 70B model is no longer hosted on the serverless
  API. The primary was therefore switched Oct 25 to
  `nvidia/nemotron-3.5-lightning-30b-a3b`, verified live the same day
  (direct probe HTTP 200, then an Azure spot-check scan: 5/5 findings
  with evidence summaries, 5 Bright Data credits). FastRouter remains
  the fallback if the primary ever fails. The LLM never reorders
  findings either way.
- **Zetaris — adapter-ready, not live-integrated.** The adapter
  (base URL + API key + org ID, Bearer + `X-Org-ID`) and the
  direct-Postgres fallback plane are implemented, but no Zetaris API
  key exists in the Cloud console and the scan path never calls it.
  The provisioned cluster is not wired into scans.
- **Cursor — not used.** This build was developed with Muse, not
  Cursor, so the event's Cursor mandate (Rules §5) cannot be claimed
  as satisfied. Stated here and in the submission write-up rather
  than implied otherwise.

## Known limitations

- No job-level timeout: per-stage timeouts exist, but a hung upstream
  can leave a job `running` past the client's 10-minute guard (which
  gives the user a visible outcome). A proper deadline mechanism is
  documented future work, not silently missing.
- Jobs live in memory: a server restart loses in-progress and finished
  jobs (client handles it visibly).
- Manifest dependencies are treated as direct: transitive reachability
  is documented future work (reachability is 1.0 for manifest deps).
- Range-resolved versions (e.g. `^4.17.20` evaluated as `4.17.20`) are
  not surfaced as evaluated versions in the finding drawer yet.
- `POST /api/scan` is unauthenticated by design (public demo), so
  Bright Data credits (5/scan) are spendable by anyone reaching the
  API; the demo is short-lived.
