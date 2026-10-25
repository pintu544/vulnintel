import { describe, it, expect, vi } from "vitest";
import {
  BrightDataClient,
  BrightDataError,
  parseSerpHits,
  type BrightDataSdkLike,
} from "./brightdata.js";

function fakeSdk(over: Partial<BrightDataSdkLike> = {}): BrightDataSdkLike & {
  closeSpy: ReturnType<typeof vi.fn>;
} {
  const closeSpy = vi.fn(async () => undefined);
  return {
    search: {
      google: vi.fn(async () => ({
        organic: [{ title: "Exploit DB", link: "https://e", snippet: "poc" }],
      })),
    },
    scrapeUrl: vi.fn(async () => "# Advisory\n\nSome markdown content here."),
    close: closeSpy,
    closeSpy,
    ...over,
  } as unknown as BrightDataSdkLike & { closeSpy: ReturnType<typeof vi.fn> };
}

describe("parseSerpHits", () => {
  it("parses organic results and caps at 5", () => {
    const data = {
      organic: Array.from({ length: 7 }, (_, i) => ({
        title: `Hit ${i}`,
        link: `https://example.com/${i}`,
        snippet: `snip ${i}`,
      })),
    };
    const hits = parseSerpHits(data);
    expect(hits).toHaveLength(5);
    expect(hits[0]).toEqual({ title: "Hit 0", link: "https://example.com/0", snippet: "snip 0" });
  });

  it("returns empty for unrecognized shapes", () => {
    expect(parseSerpHits({})).toEqual([]);
    expect(parseSerpHits(null)).toEqual([]);
  });

  it("accepts a top-level array", () => {
    expect(parseSerpHits([{ title: "T", link: "https://x", snippet: "S" }])).toEqual([
      { title: "T", link: "https://x", snippet: "S" },
    ]);
  });

  it("unwraps the live /request wrapper whose body is a JSON string", () => {
    const wrapper = {
      status_code: 200,
      headers: {},
      body: JSON.stringify({
        general: { results_cnt: 9, query: "CVE-2021-23337 exploit vulnerability" },
        organic: [
          { title: "CVE-2021-23337", link: "https://example.com/cve-2021-23337", description: "Command injection flaw." },
        ],
      }),
    };
    expect(parseSerpHits(wrapper)).toEqual([
      { title: "CVE-2021-23337", link: "https://example.com/cve-2021-23337", snippet: "Command injection flaw." },
    ]);
  });

  it("unwraps a fully stringified wrapper", () => {
    const wrapper = JSON.stringify({
      status_code: 200,
      body: JSON.stringify({
        organic: [{ title: "T", link: "https://x", description: "D" }],
      }),
    });
    expect(parseSerpHits(wrapper)).toEqual([{ title: "T", link: "https://x", snippet: "D" }]);
  });

  it("returns empty for an unparseable body string", () => {
    expect(parseSerpHits({ status_code: 200, body: "not json {" })).toEqual([]);
  });
});

describe("BrightDataClient (SDK shape)", () => {
  it("serpExploitIntel returns hits and counts 1 credit", async () => {
    const sdk = fakeSdk();
    const bd = new BrightDataClient({ sdk });
    const intel = await bd.serpExploitIntel("CVE-2021-23337");
    expect(intel.hits).toHaveLength(1);
    expect(intel.creditsUsed).toBe(1);
    expect(bd.creditsUsed).toBe(1);
    const google = sdk.search.google as ReturnType<typeof vi.fn>;
    expect(String(google.mock.calls[0][0])).toContain("CVE-2021-23337");
    expect(google.mock.calls[0][1]).toEqual({ format: "json" });
  });

  it("serpExploitIntel with zero hits reports empty (caller marks no live intel found)", async () => {
    const sdk = fakeSdk({
      search: { google: vi.fn(async () => ({ organic: [] })) },
    });
    const bd = new BrightDataClient({ sdk });
    const intel = await bd.serpExploitIntel("CVE-2099-00001");
    expect(intel.hits).toEqual([]);
  });

  it("SDK errors surface as BrightDataError and consume no credit", async () => {
    const sdk = fakeSdk({
      search: { google: vi.fn(async () => { throw new Error("402 insufficient credits"); }) },
    });
    const bd = new BrightDataClient({ sdk });
    await expect(bd.serpExploitIntel("CVE-2021-23337")).rejects.toBeInstanceOf(BrightDataError);
    expect(bd.creditsUsed).toBe(0);
  });

  it("close() closes the SDK and blocks further calls", async () => {
    const sdk = fakeSdk();
    const bd = new BrightDataClient({ sdk });
    await bd.close();
    expect(sdk.closeSpy).toHaveBeenCalledTimes(1);
    await expect(bd.serpExploitIntel("CVE-2021-23337")).rejects.toBeInstanceOf(BrightDataError);
    await bd.close(); // idempotent
    expect(sdk.closeSpy).toHaveBeenCalledTimes(1);
  });

  it("fetchAdvisory returns markdown excerpt capped at 500 chars", async () => {
    const sdk = fakeSdk({
      scrapeUrl: vi.fn(async () => `# Advisory\n\n${"x".repeat(800)}`),
    });
    const bd = new BrightDataClient({ sdk });
    const adv = await bd.fetchAdvisory("https://nvd.nist.gov/vuln/detail/CVE-2021-23337");
    expect(adv.excerpt.startsWith("# Advisory")).toBe(true);
    expect(adv.excerpt.length).toBeLessThanOrEqual(500);
    expect(adv.creditsUsed).toBe(1);
    const scrape = sdk.scrapeUrl as ReturnType<typeof vi.fn>;
    expect(scrape.mock.calls[0][1]).toEqual({ dataFormat: "markdown" });
  });

  it("requires an apiKey or an sdk", () => {
    expect(() => new BrightDataClient({})).toThrow(BrightDataError);
  });
});
