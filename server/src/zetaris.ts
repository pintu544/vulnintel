/**
 * Zetaris data plane — thin in-harness adapter over the verified REST endpoint.
 *
 * Verified REST shape (research-part2-zetaris.md, 2026-10-12):
 *   POST {base}/api/v1.0/sql-editor/sqls/run
 *   headers: Authorization: Bearer <key>, X-Org-ID: <org>, X-Request-ID: <uuid>
 *   body:    { queryId, sql, source: "SqlEditor", limit }
 *   returns: { headers: string[], data: string[][], total, timeUsed }
 * Constraints: one statement per call, no trailing semicolon, all values
 * arrive as strings.
 *
 * The adapter is also exposed in an MCP-tool shape (`zetarisQueryTool`) so the
 * agent harness speaks MCP regardless of whether Zetaris's official MCP
 * server materialises — per DESIGN's "thin in-harness MCP adapter" decision.
 * When Zetaris is unreachable/unconfigured, callers fall back to the direct-
 * Postgres functions in fallbackDb.ts and surface a "federation degraded"
 * note (FR-4, FR-10).
 */

import { randomUUID } from "crypto";

export interface ZetarisConfig {
  baseUrl: string;
  apiKey: string;
  orgId: string;
}

export interface ZetarisResult {
  headers: string[];
  /** every cell is a string (Zetaris REST returns all values as strings) */
  rows: string[][];
  total: number;
  timeUsedMs: number;
}

export function zetarisConfigFromEnv(env: NodeJS.ProcessEnv = process.env): ZetarisConfig | null {
  const baseUrl = env.ZETARIS_BASE_URL;
  const apiKey = env.ZETARIS_API_KEY;
  const orgId = env.ZETARIS_ORG_ID;
  if (!baseUrl || !apiKey || !orgId) return null;
  return { baseUrl: baseUrl.replace(/\/+$/, ""), apiKey, orgId };
}

export class ZetarisAdapter {
  private config: ZetarisConfig | null;

  constructor(config?: ZetarisConfig | null) {
    this.config = config ?? zetarisConfigFromEnv();
  }

  /** false when credentials are absent — caller must use the fallback plane. */
  isConfigured(): boolean {
    return this.config !== null;
  }

  /**
   * Run one federated SQL statement. Throws on transport/API errors so the
   * caller can degrade visibly (never silently).
   */
  async query(sql: string, limit = 1000): Promise<ZetarisResult> {
    if (!this.config) {
      throw new Error("zetaris: not configured (ZETARIS_BASE_URL/API_KEY/ORG_ID)");
    }
    // One statement per call, no trailing semicolon (verified API constraint).
    const clean = sql.trim().replace(/;+\s*$/, "");
    const res = await fetch(`${this.config.baseUrl}/api/v1.0/sql-editor/sqls/run`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.config.apiKey}`,
        "X-Org-ID": this.config.orgId,
        "X-Request-ID": randomUUID(),
      },
      body: JSON.stringify({
        queryId: randomUUID(),
        sql: clean,
        source: "SqlEditor",
        limit,
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`zetaris: HTTP ${res.status} ${body.slice(0, 200)}`);
    }
    const data = (await res.json()) as {
      headers?: string[];
      data?: string[][];
      total?: number;
      timeUsed?: number;
    };
    return {
      headers: data.headers ?? [],
      rows: data.data ?? [],
      total: data.total ?? (data.data ?? []).length,
      timeUsedMs: data.timeUsed ?? 0,
    };
  }
}

/**
 * MCP-tool-shaped contract for the agent harness.
 * A real stdio MCP server can wrap `handle`; until then the harness calls it
 * directly — the tool name and schema stay stable either way.
 */
export const zetarisQueryTool = {
  name: "zetaris_query",
  description:
    "Run federated SQL across the registered vulnerability-intel stores " +
    "(nvd, osv, ghsa, inventory) via Zetaris. One statement per call, no trailing semicolon. " +
    "All values return as strings. Throws when Zetaris is unreachable — degrade visibly.",
  inputSchema: {
    type: "object",
    properties: {
      sql: { type: "string", description: "Single SELECT statement, no trailing semicolon" },
      limit: { type: "number", description: "Row cap (default 1000)", default: 1000 },
    },
    required: ["sql"],
  },
  async handle(
    adapter: ZetarisAdapter,
    args: { sql: string; limit?: number }
  ): Promise<ZetarisResult> {
    return adapter.query(args.sql, args.limit ?? 1000);
  },
};
