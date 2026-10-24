/**
 * Cohere embeddings — T-5-locked embedder for H-MEM triage memory (T-10).
 *
 * Model: embed-english-v3.0 (1024 dims). `search_document` for adds,
 * `search_query` for queries (T-5 decision, 2026-10-22).
 * fetchFn is injectable so tests never touch the network.
 */

export type CohereInputType = "search_document" | "search_query";

const COHERE_URL = "https://api.cohere.ai/v1/embed";
export const COHERE_MODEL = "embed-english-v3.0";
export const COHERE_DIMS = 1024;

export class CohereError extends Error {
  constructor(
    message: string,
    public readonly status?: number
  ) {
    super(message);
    this.name = "CohereError";
  }
}

/** Parse the embeddings payload tolerantly: v1 returns float[][] directly,
 * or {float: float[][]} when embedding_types is requested. */
export function parseCohereEmbeddings(data: unknown): number[][] {
  const raw = (data as { embeddings?: unknown } | null)?.embeddings;
  const arr = Array.isArray(raw) ? raw : (raw as { float?: unknown } | null)?.float;
  if (!Array.isArray(arr) || arr.length === 0) {
    throw new CohereError("cohere: unexpected embeddings payload");
  }
  for (const vec of arr) {
    if (!Array.isArray(vec) || vec.length === 0 || vec.some((v) => typeof v !== "number")) {
      throw new CohereError("cohere: unexpected embedding vector shape");
    }
  }
  return arr as number[][];
}

/** Embed texts with Cohere. Throws CohereError on HTTP or shape failures. */
export async function embedCohere(
  texts: string[],
  opts: {
    apiKey: string;
    inputType: CohereInputType;
    fetchFn?: typeof fetch;
    timeoutMs?: number;
  }
): Promise<number[][]> {
  if (texts.length === 0) return [];
  const fetchFn = opts.fetchFn ?? fetch;
  const res = await fetchFn(COHERE_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${opts.apiKey}`,
    },
    body: JSON.stringify({
      model: COHERE_MODEL,
      texts,
      input_type: opts.inputType,
      truncate: "END",
    }),
    signal: AbortSignal.timeout(opts.timeoutMs ?? 30000),
  });
  if (!res.ok) {
    throw new CohereError(`cohere: HTTP ${res.status}`, res.status);
  }
  const vecs = parseCohereEmbeddings(await res.json());
  if (vecs[0].length !== COHERE_DIMS) {
    throw new CohereError(
      `cohere: expected ${COHERE_DIMS} dims, got ${vecs[0].length}`
    );
  }
  return vecs;
}

/** Cosine similarity for unit-ish vectors (dot product with normalization). */
export function cosineSimilarity(a: number[], b: number[]): number {
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}
