import { describe, it, expect, vi, afterEach } from "vitest";
import {
  ZetarisAdapter,
  zetarisConfigFromEnv,
  zetarisQueryTool,
} from "./zetaris.js";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("zetarisConfigFromEnv", () => {
  it("returns null when any credential is missing", () => {
    expect(zetarisConfigFromEnv({})).toBeNull();
    expect(
      zetarisConfigFromEnv({ ZETARIS_BASE_URL: "https://x", ZETARIS_API_KEY: "k" })
    ).toBeNull();
  });
  it("builds config and strips trailing slashes", () => {
    const c = zetarisConfigFromEnv({
      ZETARIS_BASE_URL: "https://zetaris.example//",
      ZETARIS_API_KEY: "k",
      ZETARIS_ORG_ID: "org",
    });
    expect(c).toEqual({ baseUrl: "https://zetaris.example", apiKey: "k", orgId: "org" });
  });
});

describe("ZetarisAdapter", () => {
  it("isConfigured() is false without credentials", () => {
    expect(new ZetarisAdapter(null).isConfigured()).toBe(false);
  });

  it("throws a clear error when querying unconfigured", async () => {
    await expect(new ZetarisAdapter(null).query("SELECT 1")).rejects.toThrow(
      /not configured/
    );
  });

  it("posts the verified REST shape and parses the response", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        headers: ["id", "package"],
        data: [["CVE-2021-23337", "lodash"]],
        total: 1,
        timeUsed: 42,
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    const adapter = new ZetarisAdapter({
      baseUrl: "https://zetaris.example",
      apiKey: "k",
      orgId: "org",
    });
    // Trailing semicolon must be stripped (verified API constraint).
    const result = await adapter.query("SELECT * FROM nvd.cves;", 10);

    expect(result).toEqual({
      headers: ["id", "package"],
      rows: [["CVE-2021-23337", "lodash"]],
      total: 1,
      timeUsedMs: 42,
    });
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("https://zetaris.example/api/v1.0/sql-editor/sqls/run");
    expect(opts.method).toBe("POST");
    expect(opts.headers["Authorization"]).toBe("Bearer k");
    expect(opts.headers["X-Org-ID"]).toBe("org");
    expect(opts.headers["X-Request-ID"]).toMatch(/^[0-9a-f-]{36}$/);
    const body = JSON.parse(opts.body);
    expect(body.sql).toBe("SELECT * FROM nvd.cves");
    expect(body.source).toBe("SqlEditor");
    expect(body.limit).toBe(10);
  });

  it("throws visibly on HTTP errors (never silent)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({ ok: false, status: 503, text: async () => "down" })
    );
    const adapter = new ZetarisAdapter({
      baseUrl: "https://zetaris.example",
      apiKey: "k",
      orgId: "org",
    });
    await expect(adapter.query("SELECT 1")).rejects.toThrow(/HTTP 503/);
  });
});

describe("zetarisQueryTool", () => {
  it("exposes a stable MCP-tool contract delegating to the adapter", async () => {
    expect(zetarisQueryTool.name).toBe("zetaris_query");
    expect(zetarisQueryTool.inputSchema.required).toEqual(["sql"]);
    const adapter = new ZetarisAdapter(null);
    const spy = vi.spyOn(adapter, "query").mockResolvedValue({
      headers: [],
      rows: [],
      total: 0,
      timeUsedMs: 1,
    });
    await zetarisQueryTool.handle(adapter, { sql: "SELECT 1" });
    expect(spy).toHaveBeenCalledWith("SELECT 1", 1000);
  });
});
