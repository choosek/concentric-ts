/**
 * Ingest solc build-info.
 *
 * Foundry (`forge build`, under `out/build-info/*.json`) and Hardhat (under
 * `artifacts/build-info/*.json`) both persist the Standard-JSON input they hand
 * to solc, and that input carries the full set of sources the compiler saw —
 * the project's own files together with every dependency it resolved
 * (OpenZeppelin, libraries) after remappings. Feeding those sources to the
 * project analyzer gives inheritance, libraries, and modifiers exactly as
 * compiled, without Concentric having to resolve imports or remappings itself.
 *
 * By default only the project's own sources are reported against; dependency
 * sources are still linked so a contract that inherits from OpenZeppelin
 * resolves, but findings intrinsic to a dependency are not surfaced as the
 * project's problem.
 */

import {
  analyzeProject,
  type ProjectOptions,
  type ProjectResult,
  type SourceFile,
} from "../analysis/project";

/** The subset of a build-info file this module reads. */
interface RawBuildInfo {
  solcVersion?: unknown;
  solcLongVersion?: unknown;
  input?: { sources?: unknown };
}

/** Sources and metadata recovered from one or more build-info blobs. */
export interface BuildInfoSources {
  /** The recovered sources, keyed uniquely by path. */
  sources: SourceFile[];
  /** The solc version the build-info reports, if any. */
  solcVersion: string | null;
  /** Non-fatal problems encountered while reading the blobs. */
  errors: string[];
}

/** Options for a build-info analysis — the project options plus dependency control. */
export interface BuildInfoOptions extends ProjectOptions {
  /**
   * Report findings in dependency sources too. Off by default: dependencies are
   * linked for resolution but not flagged. Ignored when an explicit `include`
   * predicate is supplied.
   */
  includeDependencies?: boolean;
}

/** The result of a build-info analysis: a project result plus the solc version. */
export interface BuildInfoResult extends ProjectResult {
  solcVersion: string | null;
}

const asString = (v: unknown): string | null =>
  typeof v === "string" ? v : null;

/**
 * Whether a source path belongs to a dependency rather than the project. Covers
 * the conventional dependency roots: `node_modules/` (Hardhat/npm), `lib/`
 * (Foundry), and scoped-package specifiers such as `@openzeppelin/...`.
 */
export function isDependencyPath(path: string): boolean {
  return (
    /(^|\/)node_modules\//.test(path) ||
    /(^|\/)lib\//.test(path) ||
    /^@[^/]+\//.test(path)
  );
}

/**
 * Recover the input sources from one or more solc build-info blobs. Each blob is
 * parsed leniently: one that is not valid JSON, or that carries no input
 * sources, contributes an error rather than aborting the rest. Sources are keyed
 * by path and the first occurrence wins, so overlapping build-info files never
 * duplicate a source.
 */
export function readBuildInfo(
  blobs: string | readonly string[],
): BuildInfoSources {
  const texts = typeof blobs === "string" ? [blobs] : blobs;
  const byPath = new Map<string, string>();
  const errors: string[] = [];
  let solcVersion: string | null = null;
  texts.forEach((text, i) => {
    let parsed: RawBuildInfo;
    try {
      parsed = JSON.parse(text) as RawBuildInfo;
    } catch {
      errors.push(`build-info #${i + 1}: not valid JSON`);
      return;
    }
    const version =
      asString(parsed.solcLongVersion) ?? asString(parsed.solcVersion);
    if (version !== null && solcVersion === null) {
      solcVersion = version;
    }
    const sources = parsed.input?.sources;
    if (sources === null || typeof sources !== "object") {
      errors.push(`build-info #${i + 1}: no input.sources`);
      return;
    }
    for (const [path, entryRaw] of Object.entries(sources)) {
      const content = asString(
        (entryRaw as { content?: unknown } | null)?.content,
      );
      if (content === null) {
        continue;
      }
      if (!byPath.has(path)) {
        byPath.set(path, content);
      }
    }
  });
  const sources = [...byPath].map(([path, content]) => ({ path, content }));
  return { sources, solcVersion, errors };
}

/**
 * Analyze a project directly from its solc build-info. All sources solc saw are
 * linked; by default only the project's own sources are reported against, with
 * dependencies linked for resolution. Pass `includeDependencies` to report on
 * everything, or an explicit `include` predicate to choose.
 */
export function analyzeBuildInfo(
  blobs: string | readonly string[],
  options: BuildInfoOptions = {},
): BuildInfoResult {
  const { sources, solcVersion, errors } = readBuildInfo(blobs);
  if (sources.length === 0) {
    const detail = errors.length > 0 ? ` (${errors.join("; ")})` : "";
    return {
      ok: false,
      error: `No sources recovered from build-info${detail}.`,
      findings: [],
      summary: {},
      assumptions: [],
      project: { files: [], contracts: [], edges: [], errors },
      solcVersion,
    };
  }
  const { includeDependencies, include, ...projectOptions } = options;
  const gate =
    include ??
    (includeDependencies ? undefined : (f: string) => !isDependencyPath(f));
  const result = analyzeProject(sources, { ...projectOptions, include: gate });
  const project = {
    ...result.project,
    errors: [...errors, ...result.project.errors],
  };
  return { ...result, project, solcVersion };
}
