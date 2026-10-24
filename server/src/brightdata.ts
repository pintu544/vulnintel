/**
 * Bright Data live-intel tools — T-9 (Slice 3). Replaces the dead stub in
 * intel.ts (deleted in this slice).
 *
 * DESIGN + researched SDK shape (spec/research-part2-brightdata.md): the
 * official @brightdata/sdk (`bdclient`) manages zones itself — hand-rolled
 * /request calls with guessed zone names FAIL (verified live: zone "serp"
 * not found on this account). So this module uses the SDK:
 *   - serpExploitIntel → client.search.google(query, {format: 'json'})
 *   - fetchAdvisory     → client.scrapeUrl(url, {dataFormat: 'markdown'})
 * Discipline: SERP + Unlocker only, 1 credit per call, one client per scan
 * job, close() after. Never the Browser API (excluded from the free tier).
 *
 * For tests, pass a fake `sdk` object with the same two methods + close();
 * production constructs the real bdclient from the apiKey.
 */

import { bdclient } from "@brightdata/sdk";
import type { LiveIntelStatus } from "./types.js";

export type { LiveIntelStatus };

export class BrightDataError extends Error {
  constructor(
    message: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = "BrightDataError";
  }
}

export interface SerpHit {
  title: string;
  link: string;
  snippet: string;
}

export interface SerpIntel {
  cveId: string;
  hits: SerpHit[];
  /** DESIGN: 1 credit per tool call. */
  creditsUsed: number;
}

export interface AdvisoryFetch {
  url: string;
  excerpt: string;
  creditsUsed: number;
}

/** Minimal structural surface of bdclient used here (real client or fake). */
export interface BrightDataSdkLike {
  search: {
    google: (query: string, options?: { format?: string }) => Promise<unknown>;
  };
  scrapeUrl: (url: string, options?: { dataFormat?: string }) => Promise<unknown>;
  close: () => Promise<unknown> | unknown;
}

/** Parse SDK SERP output tolerantly: array of hits, or {organic|results}. */
export function parseSerpHits(data: unknown): SerpHit[] {
  const root = data as Record<string, unknown> | null;
  const arr = Array.isArray(data)
    ? data
    : ((root?.organic ?? root?.results ?? (root?.body as Record<string, unknown> | undefined)?.organic) as unknown[]);
  if (!Array.isArray(arr)) return [];
  return arr
    .slice(0, 5)
    .map((h) => {
      const hit = h as Record<string, unknown>;
      return {
        title: String(hit.title ?? hit.name ?? ""),
        link: String(hit.link ?? hit.url ?? ""),
        snippet: String(hit.snippet ?? hit.description ?? ""),
      };
    })
    .filter((h) => h.title !== "" || h.link !== "");
}

export interface BrightDataClientOptions {
  apiKey?: string;
  /** Injectable SDK (tests). When absent, the real bdclient is built. */
  sdk?: BrightDataSdkLike;
}

export class BrightDataClient {
  private closed = false;
  /** Credits spent by this client (1 per tool call, DESIGN). */
  creditsUsed = 0;
  private readonly sdk: BrightDataSdkLike;

  constructor(opts: BrightDataClientOptions) {
    if (opts.sdk) {
      this.sdk = opts.sdk;
    } else if (opts.apiKey) {
      this.sdk = new bdclient({ apiKey: opts.apiKey }) as unknown as BrightDataSdkLike;
    } else {
      throw new BrightDataError("brightdata: apiKey or sdk is required");
    }
  }

  private assertOpen(): void {
    if (this.closed) throw new BrightDataError("brightdata: client is closed");
  }

  /** One client per scan job; close() after the job — further calls throw. */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.sdk.close();
  }

  /** T-9 tool 1: SERP search for exploit chatter about a CVE. */
  async serpExploitIntel(cveId: string): Promise<SerpIntel> {
    this.assertOpen();
    let data: unknown;
    try {
      data = await this.sdk.search.google(`${cveId} exploit vulnerability`, { format: "json" });
    } catch (e) {
      throw new BrightDataError(
        `brightdata: SERP failed (${e instanceof Error ? e.message : String(e)})`
      );
    }
    this.creditsUsed += 1;
    return { cveId, hits: parseSerpHits(data), creditsUsed: this.creditsUsed };
  }

  /** T-9 tool 2: fetch an advisory page through the Web Unlocker (markdown). */
  async fetchAdvisory(url: string): Promise<AdvisoryFetch> {
    this.assertOpen();
    let data: unknown;
    try {
      data = await this.sdk.scrapeUrl(url, { dataFormat: "markdown" });
    } catch (e) {
      throw new BrightDataError(
        `brightdata: Unlocker failed (${e instanceof Error ? e.message : String(e)})`
      );
    }
    this.creditsUsed += 1;
    const text = typeof data === "string" ? data : JSON.stringify(data);
    return { url, excerpt: text.slice(0, 500), creditsUsed: this.creditsUsed };
  }
}
