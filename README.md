# VulnIntel — Open Agent Hackathon 2026 (Track 01)

Unified vulnerability intelligence: paste a `package.json`, get ranked,
evidence-backed findings on what to fix first and why.

## Quick start

```bash
npm install
npm run dev        # server :4000 + client :5173
npm test           # vitest suite (11 tests)
```

## Architecture

- `server/` — Express + TypeScript API
  - `POST /api/scan` `{manifest: string}` → `202 {jobId}` (async job)
  - `GET /api/scan/:id` → `{status, progress, findings?, degradedNotes[]}`
  - statuses: `queued → running → done | partial | failed`
  - `src/scanner.ts` — manifest parsing, B-6 range resolution, vuln matching,
    deterministic ranking (top-25 cap per B-3)
  - `src/intel.ts` — DEAD STUB; replaced by @brightdata/sdk at T-9
- `client/` — Vite + React + Tailwind UI, polls scan progress, expandable evidence per finding
- `fixtures/` — versioned CVE fixtures + test manifest (deterministic)

## Current state

Slice 1 (Oct 22, in-window): DESIGN API contract landed; `npm run dev` serves
both; fixture-backed matching (OSV.dev `querybatch` + NVD enrichment arrive in
Slice 2). 11/11 tests green.

## Hackathon

- Event: Open Agent Hackathon 2026 (GenAI Works), Track 01
- Build window: Oct 22–27, 2026
