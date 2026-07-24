/**
 * canonical.ts — VENDORED VERBATIM from byte/packages/screen-before-you-pay/src/canonical.ts
 * (@foreseal/screen-before-you-pay). Copied, not re-implemented, so the byte-exact slice logic is
 * identical to the shipped verifier. Only `extractTopLevelValue` (+ its helpers) is used here; the
 * `pythonCanonicalJson` re-serialize fallback is retained for fidelity but this example NEVER
 * re-serializes — it hashes the exact captured wire bytes.
 *
 * Why byte-exact slicing (not JSON.stringify): live PayPerByte feeds sign
 * `json.dumps(answer, separators=(",",":"))` in INSERTION order with Python's default
 * ensure_ascii=True (data-feeds/broadcast_helper.py:187). JavaScript's JSON.stringify does NOT
 * reproduce Python's \uXXXX escapes, so re-serializing yields the wrong bytes / wrong keccak. The
 * only safe path is to hash the exact bytes as they came off the wire.
 */

const WS = new Set([" ", "\t", "\n", "\r"]);

/** Scan a JSON string token starting at `i` (raw[i] === '"').
 *  Returns the index just past the closing quote, or -1 if malformed. */
function scanString(raw: string, i: number): number {
  if (raw[i] !== '"') return -1;
  i++;
  while (i < raw.length) {
    const c = raw[i];
    if (c === "\\") i += 2;
    else if (c === '"') return i + 1;
    else i++;
  }
  return -1;
}

/** Scan any JSON value starting at `i`. Returns the index just past the
 *  value, or -1 if malformed. String-aware for objects/arrays. */
function scanValue(raw: string, i: number): number {
  const c = raw[i];
  if (c === '"') return scanString(raw, i);
  if (c === "{" || c === "[") {
    let depth = 0;
    let inStr = false;
    while (i < raw.length) {
      const ch = raw[i];
      if (inStr) {
        if (ch === "\\") i++;
        else if (ch === '"') inStr = false;
      } else if (ch === '"') inStr = true;
      else if (ch === "{" || ch === "[") depth++;
      else if (ch === "}" || ch === "]") {
        depth--;
        if (depth === 0) return i + 1;
      }
      i++;
    }
    return -1;
  }
  // primitive: number / true / false / null — scan to a delimiter
  let j = i;
  while (j < raw.length && !WS.has(raw[j]!) && raw[j] !== "," && raw[j] !== "}" && raw[j] !== "]") j++;
  return j === i ? -1 : j;
}

/**
 * Extract the raw text of the FIRST value bound to `targetKey` at the TOP
 * level of a JSON object body. First-match (not JSON.parse's last-match)
 * is deliberate: on a duplicate-key envelope the bytes we hash and the
 * object we later act on are BOTH taken from this same slice, so a
 * "genuine-first, tampered-second" duplicate cannot split them.
 * Returns null on anything malformed — callers fail closed.
 */
export function extractTopLevelValue(raw: string, targetKey: string): string | null {
  const n = raw.length;
  let i = 0;
  while (i < n && WS.has(raw[i]!)) i++;
  if (raw[i] !== "{") return null;
  i++;
  for (;;) {
    while (i < n && WS.has(raw[i]!)) i++;
    if (i >= n || raw[i] === "}") return null; // end of object, key not found
    if (raw[i] !== '"') return null;
    const keyStart = i;
    i = scanString(raw, i);
    if (i < 0) return null;
    let key: string;
    try {
      key = JSON.parse(raw.slice(keyStart, i)) as string;
    } catch {
      return null;
    }
    while (i < n && WS.has(raw[i]!)) i++;
    if (raw[i] !== ":") return null;
    i++;
    while (i < n && WS.has(raw[i]!)) i++;
    const valStart = i;
    i = scanValue(raw, i);
    if (i < 0) return null;
    if (key === targetKey) return raw.slice(valStart, i);
    while (i < n && WS.has(raw[i]!)) i++;
    if (raw[i] === ",") {
      i++;
      continue;
    }
    return null; // "}" or malformed — key not found
  }
}
