/**
 * Shared, dependency-free lexical helpers used by the confidentiality
 * analyzer. Solidity source is analyzed structurally rather than through a full
 * parser, so the analyzer reads the raw text and relies on these helpers to
 * neutralize comments and strings, to map character offsets back to line
 * numbers, and to match bracket pairs. Keeping them here ensures every pass
 * uses identical lexical semantics.
 */

/**
 * Replace the contents of comments and string literals with spaces, preserving
 * both the overall length and every newline so that character offsets computed
 * over the returned text remain aligned with the original source. Line and
 * block comments and single- and double-quoted strings (with backslash escapes)
 * are all neutralized; code outside them is left untouched. Blanking rather
 * than deleting lets a later pass search the code for structural tokens without
 * matching a keyword that merely appears inside a comment or a string.
 */
export function blankNonCode(source: string): string {
  const out = source.split("");
  const n = source.length;
  const put = (a: number, b: number): void => {
    for (let k = a; k < b; k++) {
      if (out[k] !== "\n") {
        out[k] = " ";
      }
    }
  };
  let i = 0;
  while (i < n) {
    const c = source[i];
    const d = source[i + 1];
    if (c === "/" && d === "/") {
      let j = i + 2;
      while (j < n && source[j] !== "\n") {
        j++;
      }
      put(i, j);
      i = j;
    } else if (c === "/" && d === "*") {
      let j = i + 2;
      while (j < n && !(source[j] === "*" && source[j + 1] === "/")) {
        j++;
      }
      j = Math.min(n, j + 2);
      put(i, j);
      i = j;
    } else if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && source[j] !== c) {
        if (source[j] === "\\") {
          j++;
        }
        j++;
      }
      j = Math.min(n, j + 1);
      put(i, j);
      i = j;
    } else {
      i++;
    }
  }
  return out.join("");
}

/**
 * Build a function that maps a character offset in the source to a one-based
 * line number. The line-start offsets are precomputed once, so each lookup is a
 * binary search over them; callers use this to report the line of a finding
 * without re-scanning the source each time.
 */
export function lineMapper(source: string): (index: number) => number {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\n") {
      starts.push(i + 1);
    }
  }
  return function lineAt(index: number): number {
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) {
        lo = mid;
      } else {
        hi = mid - 1;
      }
    }
    return lo + 1;
  };
}

/**
 * Given the index of an opening bracket (one of `(`, `[`, or `{`), return the
 * index of the matching closing bracket, accounting for nesting, or `-1` when
 * no match is found. The source passed in should already have had its comments
 * and strings neutralized by {@link blankNonCode} so that a bracket inside a
 * comment or string does not perturb the depth count.
 */
export function matchBracket(source: string, openIndex: number): number {
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  const open = source[openIndex];
  const close = pairs[open];
  let depth = 0;
  for (let i = openIndex; i < source.length; i++) {
    if (source[i] === open) {
      depth++;
    } else if (source[i] === close) {
      depth--;
      if (depth === 0) {
        return i;
      }
    }
  }
  return -1;
}

/**
 * Split a string on a single-character separator, but only where that separator
 * appears at bracket depth zero, so that separators nested inside parentheses,
 * brackets, or braces are preserved. Used to split a parameter or argument list
 * into its top-level members without being confused by nested types such as a
 * `mapping(...)` or a tuple.
 */
export function splitTopLevel(source: string, separator = ","): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = "";
  for (const ch of source) {
    if (ch === "(" || ch === "[" || ch === "{") {
      depth++;
    } else if (ch === ")" || ch === "]" || ch === "}") {
      depth--;
    }
    if (ch === separator && depth === 0) {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim() !== "") {
    parts.push(cur);
  }
  return parts;
}
