/**
 * The parsing half of the AST front-end.
 *
 * Where the lexical engine reads Solidity with regular expressions and bracket
 * matching, this front-end delegates to a real Solidity grammar —
 * `@solidity-parser/parser`, the ANTLR-based parser used by prettier-solidity
 * and solhint — and analyzes the resulting syntax tree. That removes the
 * approximations a lexer must make: nested calls, unusual formatting, and
 * complex expressions parse exactly as the compiler would see them.
 *
 * This module wraps the parser (returning a tree and any parse diagnostics
 * rather than throwing) and resolves the `// @aps:` access-policy annotations,
 * which live in comments the grammar discards, by mapping each to the
 * declaration it precedes.
 */

import { parse } from "@solidity-parser/parser";
import type { SourceUnit } from "@solidity-parser/parser/dist/src/ast-types";

/** The outcome of parsing: a syntax tree when possible, plus any diagnostics. */
export interface ParseResult {
  unit: SourceUnit | null;
  errors: string[];
}

/** An APS access policy, or `clear` for an acknowledged public disclosure. */
export type ApsPolicy = "Open" | "Restricted" | "Locked" | "clear";

/**
 * Parse Solidity source into a syntax tree. The parser runs in tolerant mode,
 * so a recoverable error yields a tree plus diagnostics rather than nothing; an
 * unrecoverable error is returned as a diagnostic with a null tree, never
 * thrown, so callers can fall back to the lexical engine.
 */
export function parseSolidity(source: string): ParseResult {
  try {
    const unit = parse(source, { loc: true, range: true, tolerant: true });
    // The parser attaches an error list only when it recovers from a problem.
    const raw = (unit as { errors?: { message: string }[] }).errors;
    const errors = (raw ?? []).map((e) => e.message);
    return { unit, errors };
  } catch (e) {
    return { unit: null, errors: [String(e)] };
  }
}

const POLICY_RE = /@aps:\s*(Open|Restricted|Locked|clear)\b/i;

function normalize(word: string): ApsPolicy {
  const lower = word.toLowerCase();
  if (lower === "open") return "Open";
  if (lower === "restricted") return "Restricted";
  if (lower === "locked") return "Locked";
  return "clear";
}

/**
 * Build a resolver from source line to the APS policy that governs a
 * declaration starting on it. A policy annotation applies to the next
 * declaration, so the resolver first checks the declaration's own line for a
 * trailing annotation, then scans upward over comment and blank lines — stopping
 * at the first line of code — for an `// @aps:` comment.
 */
export function apsAnnotations(
  source: string,
): (startLine: number) => ApsPolicy | null {
  const lines = source.split("\n");
  const isCommentOrBlank = (t: string): boolean =>
    t === "" || t.startsWith("//") || t.startsWith("/*") || t.startsWith("*");

  return (startLine: number): ApsPolicy | null => {
    const own = lines[startLine - 1];
    if (own !== undefined) {
      const m = own.match(POLICY_RE);
      if (m !== null) return normalize(m[1]);
    }
    for (let i = startLine - 2; i >= 0; i--) {
      const t = lines[i].trim();
      const m = t.match(POLICY_RE);
      if (m !== null) return normalize(m[1]);
      if (!isCommentOrBlank(t)) return null;
    }
    return null;
  };
}
