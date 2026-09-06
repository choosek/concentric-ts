/**
 * Reporting for analysis results: severity ordering and threshold checks that a
 * continuous-integration gate uses, and two exporters — SARIF 2.1.0, the
 * interchange format that code-scanning surfaces such as GitHub render natively,
 * and a stable JSON shape for programmatic consumers. The exporters are pure
 * functions of the findings and add no information of their own beyond the rule
 * catalog they publish as tool metadata.
 */

import type { Finding, Severity, Summary } from "./analysis/solidity";
import { RULES, ruleHelpUri } from "./rules";

/**
 * The severities from least to most severe. A finding's rank is its index here,
 * so that two severities can be compared and a threshold applied.
 */
export const SEVERITY_ORDER: readonly Severity[] = [
  "ok",
  "info",
  "low",
  "medium",
  "high",
] as Severity[];

/** A finding located in a specific source file, as a project analysis reports it. */
export interface LocatedFinding extends Finding {
  /** The path of the file the finding is in, if known. */
  file?: string | null;
}

/** The rank of a severity: higher is more severe. */
export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

/** The most severe severity among the findings, or `"ok"` when there are none. */
export function worstSeverity(
  findings: readonly { severity: Severity }[],
): Severity {
  let worst: Severity = "ok" as Severity;
  for (const f of findings) {
    if (severityRank(f.severity) > severityRank(worst)) {
      worst = f.severity;
    }
  }
  return worst;
}

/**
 * Whether any finding is at least as severe as the threshold — the predicate a
 * CI gate fails on. A threshold of `"medium"`, for example, is exceeded by any
 * medium- or high-severity finding.
 */
export function exceedsThreshold(
  findings: readonly { severity: Severity }[],
  threshold: Severity,
): boolean {
  const bar = severityRank(threshold);
  return findings.some((f) => severityRank(f.severity) >= bar);
}

/** The SARIF level corresponding to a severity. */
function sarifLevel(severity: Severity): string {
  switch (severity) {
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "note";
    case "info":
      return "note";
    default:
      return "none";
  }
}

/** Options controlling the SARIF export. */
export interface SarifOptions {
  /** The tool version to record in the SARIF run. */
  version: string;
}

/**
 * Export findings as a SARIF 2.1.0 log. The tool's whole rule catalog is
 * published as `driver.rules` so that every result can be linked to its rule
 * definition; each result carries a level, a message, the rule identifier, and
 * a physical location when the finding is tied to a file and line. Positive
 * (`ok`) results are omitted, since a code-scanning surface has nothing to show
 * for them.
 */
export function toSarif(
  findings: readonly LocatedFinding[],
  options: SarifOptions,
): object {
  const rules = RULES.map((r) => ({
    id: r.id,
    name: r.name,
    shortDescription: { text: r.summary },
    defaultConfiguration: { level: sarifLevel(r.defaultSeverity) },
    helpUri: ruleHelpUri(r.id),
  }));

  const results = findings
    .filter((f) => f.severity !== ("ok" as Severity))
    .map((f) => {
      const result: Record<string, unknown> = {
        ruleId: f.id,
        level: sarifLevel(f.severity),
        message: { text: `${f.title}. ${f.detail}` },
      };
      if (f.file !== undefined && f.file !== null && f.line > 0) {
        result.locations = [
          {
            physicalLocation: {
              artifactLocation: { uri: f.file },
              region: { startLine: f.line },
            },
          },
        ];
      }
      return result;
    });

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "Concentric",
            informationUri: "https://github.com/choosek/concentric-ts",
            version: options.version,
            rules,
          },
        },
        results,
      },
    ],
  };
}

/** A finding as it appears in the JSON report. */
export interface JsonFinding {
  id: string;
  severity: Severity;
  contract: string;
  function: string;
  file: string | null;
  line: number;
  title: string;
  detail: string;
  fix: string;
  sink: string;
}

/** The JSON report shape. */
export interface JsonReport {
  summary: Partial<Summary>;
  findings: JsonFinding[];
  assumptions: readonly string[];
}

/**
 * Export an analysis as a stable JSON object suitable for a machine consumer:
 * the headline summary, the findings flattened to a fixed shape, and the
 * assumptions the analysis rests on.
 */
export function toJsonReport(input: {
  summary: Partial<Summary>;
  findings: readonly LocatedFinding[];
  assumptions: readonly string[];
}): JsonReport {
  return {
    summary: input.summary,
    findings: input.findings.map((f) => ({
      id: f.id,
      severity: f.severity,
      contract: f.contract,
      function: f.fnName,
      file: f.file ?? null,
      line: f.line,
      title: f.title,
      detail: f.detail,
      fix: f.fix,
      sink: f.sink,
    })),
    assumptions: input.assumptions,
  };
}
