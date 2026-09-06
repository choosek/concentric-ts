// The confidentiality analyzer is re-exported here so that the library's single
// public entry point covers the whole surface. A single contract is analyzed
// with `analyzeContract`; a multi-file project — with its imports and
// inheritance linked — is analyzed with `analyzeProject`. The reporting layer
// (`toSarif`, `toJsonReport`, and the severity helpers) and the rule catalog
// (`RULES`) turn a result into the artifacts a continuous-integration gate and
// a code-scanning surface consume. The individual parsing and scanning
// functions are exported alongside these so that a single stage may be driven
// or inspected on its own.

export * from "./analysis/project";
export * from "./analysis/solidity";
export * from "./ast/analyze";
export * from "./ast/parse";
export * from "./ingest/buildinfo";
export * from "./report";
export * from "./rules";
