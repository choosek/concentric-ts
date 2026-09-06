/**
 * The rule catalog: stable identifiers and metadata for every confidentiality
 * rule the analyzer can report. It is the single source of truth a report
 * consumer reads to describe a finding independently of the run that produced
 * it — the SARIF exporter, for instance, publishes it as the tool's rule
 * definitions so that a code-scanning surface can render each finding with its
 * name, default severity, and a link to its documentation.
 */

import { Severity } from "./analysis/solidity";

/** The base URL under which each rule's documentation is published. */
export const HELP_BASE = "https://concentric.choosek.com/rules/";

/** Documentation and default classification for a single rule. */
export interface RuleInfo {
  /** The rule identifier, for example `APS-1`. */
  id: string;
  /** A short human-readable name. */
  name: string;
  /** The severity the rule reports by default; some rules vary by context. */
  defaultSeverity: Severity;
  /** One sentence stating what the rule detects. */
  summary: string;
}

/**
 * Every rule the analyzer emits, in ascending identifier order. The two
 * positive results — a correctly gated read and a clean bill — are included so
 * that a consumer can describe them as well; a report exporter that omits
 * informational or positive results simply skips them.
 */
export const RULES: readonly RuleInfo[] = [
  {
    id: "APS-1",
    name: "Open function returns confidential state",
    defaultSeverity: Severity.High,
    summary:
      "A function any caller can reach returns a value read from confidential storage.",
  },
  {
    id: "APS-2",
    name: "Confidential value emitted in an event",
    defaultSeverity: Severity.High,
    summary:
      "An emitted event carries a confidential value or amount to every authorized viewer of the transaction.",
  },
  {
    id: "APS-2b",
    name: "Event reveals transaction metadata",
    defaultSeverity: Severity.Info,
    summary:
      "An emitted event exposes a counterparty or timing, though no confidential amount.",
  },
  {
    id: "APS-3",
    name: "Confidential value bridged to the public EVM",
    defaultSeverity: Severity.High,
    summary:
      "A confidential value is moved across the boundary onto the public ledger.",
  },
  {
    id: "APS-4",
    name: "Over-broad trust grant",
    defaultSeverity: Severity.High,
    summary:
      "Trust is granted to an arbitrary or third-party contract, exposing introspection and Restricted entrypoints.",
  },
  {
    id: "APS-4ok",
    name: "Trust granted to a compliance party",
    defaultSeverity: Severity.Info,
    summary:
      "Trust is granted to a named auditor or regulator — a deliberate, policy-driven disclosure.",
  },
  {
    id: "APS-5",
    name: "Public state variable auto-generates a getter",
    defaultSeverity: Severity.Medium,
    summary:
      "A public state variable exposes confidential storage through its implicit getter.",
  },
  {
    id: "APS-6",
    name: "External function has no access policy",
    defaultSeverity: Severity.Info,
    summary:
      "An externally visible function carries no APS access policy and is unreachable under default-deny.",
  },
  {
    id: "APS-7",
    name: "Confidential value in immutable or constant",
    defaultSeverity: Severity.Low,
    summary:
      "A confidential value is placed in an immutable or constant, which may live in bytecode.",
  },
  {
    id: "APS-8",
    name: "Open function echoes a calldata argument",
    defaultSeverity: Severity.Low,
    summary:
      "A function any caller can reach returns a value derived from its arguments.",
  },
  {
    id: "APS-9",
    name: "Restricted function returns confidential state to grant-holders",
    defaultSeverity: Severity.Info,
    summary:
      "A grant-holder-reachable function returns confidential state to every holder of a grant.",
  },
  {
    id: "APS-10",
    name: "Confidential value passed to an external contract",
    defaultSeverity: Severity.High,
    summary:
      "A confidential value is handed as an argument to a contract outside the boundary.",
  },
  {
    id: "APS-12",
    name: "Confidential value indexed in an event",
    defaultSeverity: Severity.Medium,
    summary:
      "A confidential value is declared indexed, placing it in a queryable log topic.",
  },
  {
    id: "APS-14",
    name: "Confidential value copied into a public variable",
    defaultSeverity: Severity.High,
    summary:
      "A confidential value is assigned into a public or cleared variable, exposing it through that variable's getter.",
  },
  {
    id: "APS-T",
    name: "Transitive exposure through a trusted contract",
    defaultSeverity: Severity.Medium,
    summary:
      "An Open forwarder re-exposes the confidential state of a contract that trusts it.",
  },
  {
    id: "APS-H",
    name: "Confidential value disclosed as a commitment",
    defaultSeverity: Severity.Info,
    summary:
      "A confidential value is disclosed only through a cryptographic hash rather than in the clear.",
  },
  {
    id: "APS-OK",
    name: "Owner-gated confidential read",
    defaultSeverity: Severity.Ok,
    summary:
      "A confidential read is correctly gated so each caller reads only their own entry.",
  },
  {
    id: "APS-CLEAN",
    name: "No confidentiality findings",
    defaultSeverity: Severity.Ok,
    summary:
      "No reachable path exposes a confidential value beyond what is appropriately disclosed.",
  },
];

/** The documentation URL for a rule, whether or not it is in the catalog. */
export function ruleHelpUri(id: string): string {
  return `${HELP_BASE}${id.toLowerCase()}`;
}

/** Look up a rule's metadata by identifier, or `undefined` if unknown. */
export function ruleById(id: string): RuleInfo | undefined {
  return RULES.find((r) => r.id === id);
}
