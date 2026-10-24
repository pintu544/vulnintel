import { describe, it, expect, vi } from "vitest";
import {
  embedCohere,
  parseCohereEmbeddings,
  cosineSimilarity,
  COHERE_DIMS,
  COHERE_MODEL,
} from "./cohere.js";

function mockFetch(body: unknown, status = 200) {
  return vi.fn(async (_url: string, init?: { body?: unknown; headers?: Record<string, string> }) => ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }));
}

const vec = (v: number[]) => {
  const out = new Array<number>(COHERE_DIMS).fill(0);
  v.forEach((x, i) => (out[i] = x));
  return out;
};

describe("parseCohereEmbeddings", () => {
  it("parses float[][] directly", () => {
    expect(parseCohereEmbeddings({ embeddings: [vec([1, 0])] })).toHaveLength(1);
  });

  it("parses {float: float[][]} shape", () => {
    expect(parseCohereEmbeddings({ embeddings: { float: [vec([0, 1])] } })).toHaveLength(1);
  });

  it("rejects empty or malformed payloads", () => {
    expect(() => parseCohereEmbeddings({})).toThrow();
    expect(() => parseCohereEmbeddings({ embeddings: [] })).toThrow();
    expect(() => parseCohereEmbeddings({ embeddings: [["a"]] })).toThrow();
  });
});

describe("embedCohere", () => {
  it("posts model + input_type and validates 1024 dims", async () => {
    const fetchFn = mockFetch({ embeddings: [vec([1]), vec([0, 1])] });
    const out = await embedCohere(["a", "b"], {
      apiKey: "test-key",
      inputType: "search_document",
      fetchFn: fetchFn as unknown as typeof fetch,
    });
    expect(out).toHaveLength(2);
    expect(out[0]).toHaveLength(COHERE_DIMS);
    const call = fetchFn.mock.calls[0];
    expect(call[0]).toContain("cohere");
    const body = JSON.parse(String(call[1]?.body));
    expect(body.model).toBe(COHERE_MODEL);
    expect(body.input_type).toBe("search_document");
    expect((call[1]?.headers as Record<string, string> | undefined)?.Authorization).toBe("Bearer test-key");
  });

  it("rejects wrong dims", async () => {
    const fetchFn = mockFetch({ embeddings: [[1, 2, 3]] });
    await expect(
      embedCohere(["a"], { apiKey: "test-key", inputType: "search_query", fetchFn: fetchFn as unknown as typeof fetch })
    ).rejects.toThrow(/1024/);
  });

  it("throws on HTTP errors", async () => {
    const fetchFn = mockFetch({ message: "unauthorized" }, 401);
    await expect(
      embedCohere(["a"], { apiKey: "bad", inputType: "search_query", fetchFn: fetchFn as unknown as typeof fetch })
    ).rejects.toMatchObject({ status: 401 });
  });

  it("returns [] without calling for empty input", async () => {
    const fetchFn = mockFetch({ embeddings: [] });
    await expect(
      embedCohere([], { apiKey: "test-key", inputType: "search_query", fetchFn: fetchFn as unknown as typeof fetch })
    ).resolves.toEqual([]);
    expect(fetchFn).not.toHaveBeenCalled();
  });
});

describe("cosineSimilarity", () => {
  it("is 1 for identical vectors, 0 for orthogonal, 0 for zero vectors", () => {
    expect(cosineSimilarity(vec([1, 0]), vec([1, 0]))).toBeCloseTo(1);
    expect(cosineSimilarity(vec([1, 0]), vec([0, 1]))).toBeCloseTo(0);
    expect(cosineSimilarity(vec([0]), vec([1]))).toBe(0);
  });
});
