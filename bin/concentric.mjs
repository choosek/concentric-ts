#!/usr/bin/env node
/**
 * Concentric command-line interface.
 *
 * Reads Solidity files from the given paths, links them into one project (with
 * imports and inheritance resolved), analyzes the confidentiality boundary, and
 * reports the findings — as a readable terminal report, as SARIF 2.1.0 for a
 * code-scanning surface, or as JSON. It exits non-zero when a finding at or
 * above a chosen severity is present, so it can gate a pull request.
 *
 * All of the analysis lives in the library (`@choosek/concentric`); this file is
 * only the file-system and argument shell around it. It imports the built
 * package, so run `pnpm build` (or `npm run build`) in the library first.
 *
 * Usage:
 *   concentric check <path...> [options]
 *
 * Options:
 *   --sarif                 Emit SARIF 2.1.0 to stdout.
 *   --json                  Emit a JSON report to stdout.
 *   --fail-on <severity>    Exit non-zero at/above this severity (default: high).
 *   --min-severity <sev>    Drop findings below this severity from the report.
 *   --disable <ids>         Comma-separated rule ids to disable (repeatable).
 *   --build-info <path>     Analyze solc build-info (file or dir) instead of .sol.
 *   --include-deps          With --build-info, also report dependency findings.
 *   --version               Print the analyzer version and exit.
 *   --help                  Print this help and exit.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import {
  analyzeBuildInfo,
  analyzeProject,
  exceedsThreshold,
  toJsonReport,
  toSarif,
} from "../dist/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(readFileSync(join(here, "..", "package.json"), "utf8"));
const VERSION = pkg.version;

const SEVERITIES = ["ok", "info", "low", "medium", "high"];
const COLORS = {
  high: "\x1b[31m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
  ok: "\x1b[32m",
  dim: "\x1b[90m",
  bold: "\x1b[1m",
  reset: "\x1b[0m",
};

const USAGE = `Concentric ${VERSION} — static confidentiality analysis for Arc Privacy Sector contracts

Usage:
  concentric check <path...> [options]

Options:
  --sarif                 Emit SARIF 2.1.0 to stdout (for code scanning).
  --json                  Emit a JSON report to stdout.
  --fail-on <severity>    Exit non-zero at or above this severity (default: high).
  --min-severity <sev>    Drop findings below this severity from the report.
  --disable <ids>         Comma-separated rule ids to disable, e.g. APS-6,APS-9.
  --build-info <path>     Analyze a solc build-info file or directory instead of
                          .sol paths (Foundry out/build-info, Hardhat
                          artifacts/build-info). Repeatable.
  --include-deps          With --build-info, also report findings in dependency
                          sources (node_modules, lib/, @scope). Off by default.
  --version               Print the analyzer version and exit.
  --help                  Print this help and exit.

Severities: ${SEVERITIES.join(", ")}.`;

function fail(message) {
  process.stderr.write(`concentric: ${message}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const opts = {
    paths: [],
    format: "text",
    failOn: "high",
    minSeverity: undefined,
    disabled: [],
    buildInfo: [],
    includeDeps: false,
    help: false,
    version: false,
  };
  // Accept an optional leading `check` subcommand: `concentric check <path>`.
  const args = argv[0] === "check" ? argv.slice(1) : argv;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--help" || a === "-h") {
      opts.help = true;
    } else if (a === "--version" || a === "-v") {
      opts.version = true;
    } else if (a === "--sarif") {
      opts.format = "sarif";
    } else if (a === "--json") {
      opts.format = "json";
    } else if (a === "--fail-on") {
      opts.failOn = args[++i];
    } else if (a === "--min-severity") {
      opts.minSeverity = args[++i];
    } else if (a === "--disable") {
      opts.disabled.push(...String(args[++i] ?? "").split(","));
    } else if (a === "--build-info") {
      opts.buildInfo.push(args[++i]);
    } else if (a === "--include-deps") {
      opts.includeDeps = true;
    } else if (a.startsWith("-")) {
      fail(`unknown option: ${a}`);
    } else {
      opts.paths.push(a);
    }
  }
  return opts;
}

function collectSolFiles(paths) {
  const files = [];
  const seen = new Set();
  const walk = (p) => {
    let st;
    try {
      st = statSync(p);
    } catch {
      fail(`no such file or directory: ${p}`);
      return;
    }
    if (st.isDirectory()) {
      for (const entry of readdirSync(p)) {
        if (entry === "node_modules" || entry.startsWith(".")) {
          continue;
        }
        walk(join(p, entry));
      }
    } else if (p.endsWith(".sol") && !seen.has(p)) {
      seen.add(p);
      files.push({
        path: relative(process.cwd(), p),
        content: readFileSync(p, "utf8"),
      });
    }
  };
  for (const p of paths) {
    walk(p);
  }
  return files;
}

function collectJsonFiles(paths) {
  const blobs = [];
  const seen = new Set();
  const walk = (p) => {
    let st;
    try {
      st = statSync(p);
    } catch {
      fail(`no such file or directory: ${p}`);
      return;
    }
    if (st.isDirectory()) {
      for (const entry of readdirSync(p)) {
        if (entry === "node_modules" || entry.startsWith(".")) {
          continue;
        }
        walk(join(p, entry));
      }
    } else if (p.endsWith(".json") && !seen.has(p)) {
      seen.add(p);
      blobs.push(readFileSync(p, "utf8"));
    }
  };
  for (const p of paths) {
    walk(p);
  }
  return blobs;
}

function paint(text, color) {
  if (!process.stdout.isTTY) {
    return text;
  }
  return `${color}${text}${COLORS.reset}`;
}

function severityRank(s) {
  return SEVERITIES.indexOf(s);
}

function renderText(result, failOn) {
  const out = [];
  const p = result.project;
  const solc = result.solcVersion ? `, solc ${result.solcVersion}` : "";
  out.push(
    paint(`Concentric ${VERSION}`, COLORS.bold) +
      paint(
        ` — ${p.files.length} file(s), ${p.contracts.length} contract(s)${solc}`,
        COLORS.dim,
      ),
  );
  for (const e of p.errors) {
    out.push(paint(`  linking: ${e}`, COLORS.info));
  }
  if (!result.ok) {
    out.push(paint(`✗ ${result.error}`, COLORS.high));
    return out.join("\n");
  }

  const findings = [...result.findings].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      String(a.file).localeCompare(String(b.file)) ||
      a.line - b.line,
  );

  const reportable = findings.filter((f) => f.severity !== "ok");
  if (reportable.length === 0) {
    out.push(paint("✓ No confidentiality findings.", COLORS.ok));
  } else {
    out.push("");
    for (const f of reportable) {
      const loc = f.file ? `${f.file}:${f.line}` : f.contract;
      const tag = paint(f.severity.toUpperCase().padEnd(6), COLORS[f.severity]);
      out.push(
        `${tag} ${paint(f.id, COLORS.bold)}  ${paint(loc, COLORS.dim)}  ${f.title}`,
      );
      out.push(`       ${f.detail}`);
      if (f.fix) {
        out.push(paint(`       fix: ${f.fix}`, COLORS.dim));
      }
    }
  }

  const s = result.summary;
  out.push("");
  out.push(
    paint(
      `high: ${s.high ?? 0}  medium: ${s.medium ?? 0}  low: ${s.low ?? 0}  info: ${s.info ?? 0}`,
      COLORS.dim,
    ),
  );
  const failing = exceedsThreshold(result.findings, failOn);
  out.push(
    failing
      ? paint(
          `✗ Failing — a finding at or above ${failOn} is present.`,
          COLORS.high,
        )
      : paint(`✓ Passing — no finding at or above ${failOn}.`, COLORS.ok),
  );
  return out.join("\n");
}

function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help) {
    process.stdout.write(`${USAGE}\n`);
    return 0;
  }
  if (opts.version) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  if (!SEVERITIES.includes(opts.failOn)) {
    fail(`invalid --fail-on severity: ${opts.failOn}`);
  }
  if (
    opts.minSeverity !== undefined &&
    !SEVERITIES.includes(opts.minSeverity)
  ) {
    fail(`invalid --min-severity: ${opts.minSeverity}`);
  }
  const useBuildInfo = opts.buildInfo.length > 0;
  if (!useBuildInfo && opts.paths.length === 0) {
    process.stderr.write(`${USAGE}\n`);
    process.exit(2);
  }

  const disabled = opts.disabled.map((d) => d.trim()).filter(Boolean);
  let result;
  if (useBuildInfo) {
    const blobs = collectJsonFiles(opts.buildInfo);
    if (blobs.length === 0) {
      fail("no build-info .json files found in the given paths");
    }
    result = analyzeBuildInfo(blobs, {
      disabledRules: disabled,
      minSeverity: opts.minSeverity,
      includeDependencies: opts.includeDeps,
    });
  } else {
    const files = collectSolFiles(opts.paths);
    if (files.length === 0) {
      fail("no .sol files found in the given paths");
    }
    result = analyzeProject(files, {
      disabledRules: disabled,
      minSeverity: opts.minSeverity,
    });
  }

  if (opts.format === "sarif") {
    process.stdout.write(
      `${JSON.stringify(toSarif(result.findings, { version: VERSION }), null, 2)}\n`,
    );
  } else if (opts.format === "json") {
    process.stdout.write(
      `${JSON.stringify(
        {
          ...toJsonReport({
            summary: result.summary,
            findings: result.findings,
            assumptions: result.assumptions,
          }),
          project: result.project,
        },
        null,
        2,
      )}\n`,
    );
  } else {
    process.stdout.write(`${renderText(result, opts.failOn)}\n`);
  }

  if (!result.ok) {
    return 2;
  }
  return exceedsThreshold(result.findings, opts.failOn) ? 1 : 0;
}

process.exit(main());
