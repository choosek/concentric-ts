/**
 * Project-level confidentiality analysis.
 *
 * A real contract is rarely a single self-contained file: it is split across
 * files that import one another, and its behavior is the sum of the base
 * contracts it inherits from. This module links such a project into one model
 * before analyzing it. Every contract is *flattened* — its transitively
 * inherited members are folded in — so that an inherited getter or a function
 * that reads inherited confidential state is analyzed in the context that
 * actually deploys it. The flattening is lexical, in keeping with the rest of
 * the analyzer, and a line map is retained so that every finding is reported at
 * its true file and line rather than at a position in the linked text.
 *
 * On top of the analysis it adds the controls a continuous-integration gate
 * needs: rules can be disabled, findings below a chosen severity can be
 * dropped, and a finding can be suppressed at its site with a
 * `// concentric-disable-next-line` or `// concentric-disable-line` comment.
 */

import { analyzeContractAst } from "../ast/analyze";
import { lineMapper as _lineMapper } from "../common";
import { severityRank } from "../report";
import {
  type AnalysisOk,
  analyzeContract,
  type Finding,
  parseContracts,
  type Severity,
  type Summary,
} from "./solidity";

/** A source file supplied to the project analyzer. */
export interface SourceFile {
  path: string;
  content: string;
}

/** Options controlling a project analysis. */
export interface ProjectOptions {
  /** Rule identifiers to omit from the result entirely. */
  disabledRules?: readonly string[];
  /** Drop findings less severe than this from the result. */
  minSeverity?: Severity;
  /**
   * Which parsing front-end to use. `"ast"` (the default) parses with a real
   * Solidity grammar for precise dataflow and inheritance; `"lexical"` selects
   * the dependency-free structural reader. The AST front-end falls back to the
   * lexical engine automatically if a source cannot be parsed.
   */
  frontend?: "ast" | "lexical";
  /**
   * Restrict which files a finding may be reported against. Every file is still
   * linked so inheritance resolves, but a finding whose origin file does not
   * satisfy this predicate is dropped. This is how a build-info analysis links
   * dependencies (OpenZeppelin, libraries) for resolution while reporting only
   * the project's own sources. A finding that cannot be mapped to a file is
   * always kept.
   */
  include?: (file: string) => boolean;
}

/** A parsed contract header and the facts linking needs about it. */
interface Header {
  file: string;
  name: string;
  kind: string;
  bases: string[];
  bodyText: string;
  bodyStartLine: number;
  declLine: number;
}

/** A position in an original source file. */
interface Origin {
  file: string;
  line: number;
}

/** An inline suppression parsed from a source comment. */
interface Suppression {
  file: string;
  line: number;
  ids: Set<string> | null;
}

/** The linked project: the combined source and the map back to origins. */
export interface LinkedProject {
  /** The flattened source of every contract, concatenated. */
  source: string;
  /** The origin of each line of {@link source}, one entry per line. */
  origin: Origin[];
  /** Every contract header found across the files. */
  headers: Header[];
  /** Declared inheritance edges as `[child, parent]` pairs. */
  edges: [string, string][];
  /** Non-fatal linking problems, such as a cycle or an unresolved base. */
  errors: string[];
}

/** A finding located in a specific source file. */
export interface ProjectFinding extends Finding {
  file: string | null;
}

/** Summary of the linked project's structure. */
export interface ProjectSummary {
  files: string[];
  contracts: { name: string; kind: string; file: string; bases: string[] }[];
  edges: [string, string][];
  errors: string[];
}

/** The result of {@link analyzeProject}. */
export interface ProjectResult {
  ok: boolean;
  error?: string;
  findings: ProjectFinding[];
  summary: Partial<Summary>;
  assumptions: readonly string[];
  project: ProjectSummary;
}

/** Extract the base-contract names from a contract header. */
function parseBases(headText: string): string[] {
  const m = headText.match(/\bis\b([\s\S]*)$/);
  if (!m) {
    return [];
  }
  return m[1]
    .split(",")
    .map((s) => s.trim().replace(/\(.*$/, "").trim())
    .filter((x) => /^[A-Za-z_]\w*$/.test(x));
}

/** Parse every contract header across the files. */
function collectHeaders(files: readonly SourceFile[]): Header[] {
  const headers: Header[] = [];
  for (const f of files) {
    const { contracts } = parseContracts(f.content);
    const lineAt = _lineMapper(f.content);
    for (const c of contracts) {
      headers.push({
        file: f.path,
        name: c.name,
        kind: c.kind,
        bases: parseBases(f.content.slice(c.start, c.bodyStart - 1)),
        bodyText: f.content.slice(c.bodyStart, c.bodyEnd),
        bodyStartLine: lineAt(c.bodyStart),
        declLine: lineAt(c.start),
      });
    }
  }
  return headers;
}

/**
 * The transitively-inherited base contracts of a contract, deepest first and
 * de-duplicated. Cycles and unresolved bases are recorded in `errors` and do
 * not stop the traversal.
 */
function baseOrder(
  start: Header,
  byName: Map<string, Header>,
  errors: string[],
): Header[] {
  const order: Header[] = [];
  const visiting = new Set<string>();
  const done = new Set<string>();
  const visit = (h: Header): void => {
    for (const b of h.bases) {
      if (visiting.has(b)) {
        errors.push(`Inheritance cycle involving ${b}.`);
        continue;
      }
      if (done.has(b)) {
        continue;
      }
      const hb = byName.get(b);
      if (hb === undefined) {
        errors.push(`Unresolved base contract ${b} inherited by ${h.name}.`);
        continue;
      }
      visiting.add(b);
      visit(hb);
      visiting.delete(b);
      done.add(b);
      order.push(hb);
    }
  };
  visiting.add(start.name);
  visit(start);
  return order;
}

/** Emit a contract body's lines into the combined source with their origins. */
function emitBody(h: Header, lines: string[], origin: Origin[]): void {
  const bodyLines = h.bodyText.split("\n");
  for (let i = 0; i < bodyLines.length; i++) {
    lines.push(bodyLines[i]);
    origin.push({ file: h.file, line: h.bodyStartLine + i });
  }
}

/**
 * Link a set of source files into one analyzable model. Each contract is
 * emitted with its inherited members folded in ahead of its own, so that the
 * analyzer sees the contract as deployed. A line map from the combined source
 * back to each contributing file is returned alongside it.
 */
export function linkProject(files: readonly SourceFile[]): LinkedProject {
  const headers = collectHeaders(files);
  const byName = new Map<string, Header>();
  for (const h of headers) {
    if (!byName.has(h.name)) {
      byName.set(h.name, h);
    }
  }
  const errors: string[] = [];
  const edges: [string, string][] = [];
  const lines: string[] = [];
  const origin: Origin[] = [];
  for (const h of headers) {
    const decl: Origin = { file: h.file, line: h.declLine };
    lines.push(`${h.kind} ${h.name} {`);
    origin.push(decl);
    for (const base of baseOrder(h, byName, errors)) {
      emitBody(base, lines, origin);
    }
    emitBody(h, lines, origin);
    lines.push("}");
    origin.push(decl);
    for (const b of h.bases) {
      edges.push([h.name, b]);
    }
  }
  return { source: lines.join("\n"), origin, headers, edges, errors };
}

/** Parse the rule identifiers from a suppression comment's trailing text. */
function parseIds(rest: string): Set<string> | null {
  const toks = rest
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => /^APS-[A-Za-z0-9]+$/i.test(t))
    .map((t) => t.toUpperCase());
  return toks.length > 0 ? new Set(toks) : null;
}

/** Collect every inline suppression across the files. */
function collectSuppressions(files: readonly SourceFile[]): Suppression[] {
  const out: Suppression[] = [];
  const re = /\/\/\s*concentric-disable(-next-line|-line)\b([^\n]*)/;
  for (const f of files) {
    const lines = f.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(re);
      if (m === null) {
        continue;
      }
      const targetLine = m[1] === "-next-line" ? i + 2 : i + 1;
      out.push({ file: f.path, line: targetLine, ids: parseIds(m[2]) });
    }
  }
  return out;
}

/** Whether a finding is suppressed by any inline comment. */
function isSuppressed(
  f: ProjectFinding,
  supp: readonly Suppression[],
): boolean {
  const id = f.id.toUpperCase();
  return supp.some(
    (s) =>
      s.file === f.file &&
      s.line === f.line &&
      (s.ids === null || s.ids.has(id)),
  );
}

/** Count the findings at a given severity. */
function countSeverity(
  findings: readonly ProjectFinding[],
  sev: Severity,
): number {
  return findings.filter((f) => f.severity === sev).length;
}

/**
 * Analyze a project. The files are linked (with inheritance flattened), the
 * analyzer is run over the linked source, and each finding is mapped back to
 * its true file and line. Findings at the same rule, file, line, and sink are
 * de-duplicated, since a base member folded into several contracts would
 * otherwise be reported once per contract. Suppressions, disabled rules, and
 * the minimum-severity filter are then applied, and the summary is recounted
 * from what remains.
 */
export function analyzeProject(
  files: readonly SourceFile[],
  options: ProjectOptions = {},
): ProjectResult {
  const linked = linkProject(files);
  const projectMeta: ProjectSummary = {
    files: files.map((f) => f.path),
    contracts: linked.headers.map((h) => ({
      name: h.name,
      kind: h.kind,
      file: h.file,
      bases: h.bases,
    })),
    edges: linked.edges,
    errors: linked.errors,
  };

  if (linked.headers.length === 0) {
    return {
      ok: false,
      error: "No contract, interface, or library found in the sources.",
      findings: [],
      summary: {},
      assumptions: [],
      project: projectMeta,
    };
  }

  // Run the chosen front-end. The linked source always contains at least one
  // contract, so the lexical engine cannot fail; the assertion documents that
  // invariant. The AST front-end may decline a source it cannot parse, in which
  // case we fall back to the lexical engine so analysis always proceeds.
  const frontend = options.frontend ?? "ast";
  let res: {
    findings: Finding[];
    summary: Partial<Summary>;
    assumptions: readonly string[];
  };
  if (frontend === "ast") {
    const astRes = analyzeContractAst(linked.source);
    res = astRes.ok ? astRes : (analyzeContract(linked.source) as AnalysisOk);
  } else {
    res = analyzeContract(linked.source) as AnalysisOk;
  }

  const seen = new Set<string>();
  let findings: ProjectFinding[] = [];
  for (const f of res.findings) {
    const loc =
      f.line >= 1 && f.line <= linked.origin.length
        ? linked.origin[f.line - 1]
        : null;
    const file = loc === null ? null : loc.file;
    const line = loc === null ? f.line : loc.line;
    const key = `${f.id}|${file}|${line}|${f.sink}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    findings.push({ ...f, file, line });
  }

  const supp = collectSuppressions(files);
  findings = findings.filter((f) => !isSuppressed(f, supp));

  const disabled = options.disabledRules;
  if (disabled !== undefined && disabled.length > 0) {
    findings = findings.filter((f) => !disabled.includes(f.id));
  }

  const min = options.minSeverity;
  if (min !== undefined) {
    const bar = severityRank(min);
    findings = findings.filter((f) => severityRank(f.severity) >= bar);
  }

  const include = options.include;
  if (include !== undefined) {
    findings = findings.filter((f) => f.file === null || include(f.file));
  }

  const summary: Partial<Summary> = {
    ...res.summary,
    high: countSeverity(findings, "high" as Severity),
    medium: countSeverity(findings, "medium" as Severity),
    low: countSeverity(findings, "low" as Severity),
    info: countSeverity(findings, "info" as Severity),
    ok: countSeverity(findings, "ok" as Severity),
  };

  return {
    ok: true,
    findings,
    summary,
    assumptions: res.assumptions,
    project: projectMeta,
  };
}
