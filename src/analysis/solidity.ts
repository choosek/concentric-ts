/**
 * TypeScript library for static confidentiality analysis of Solidity contracts
 * targeted at the Arc Privacy Sector (APS), Circle's opt-in confidential
 * execution environment.
 *
 * In APS, contract storage is confidential by default and exposure is opt-in,
 * declared per function through an access policy. This library reasons about
 * the resulting *confidentiality boundary*: given a contract and its access
 * policy, it determines what confidential state an external party can learn and
 * through which path — a function's return value, an emitted event, a bridge to
 * the public EVM, a trust grant, or an argument handed to another contract.
 *
 * The analysis is deterministic, dependency-free, and side-effect-free: it
 * reads a contract expressed as Solidity source and returns a plain data
 * structure. No network access, compilation, or signing is performed. The
 * analyzer models the published APS specification rather than the live
 * protocol; the assumptions on which it rests are enumerated in
 * {@link ASSUMPTIONS} and are returned with every analysis. It reasons about
 * application-level disclosure, not the security of the enclaves or the
 * cryptography beneath them.
 */

import {
  blankNonCode as _blankNonCode,
  lineMapper as _lineMapper,
  matchBracket as _matchBracket,
  splitTopLevel as _splitTopLevel,
} from "../common";

/**
 * The assumptions the analyzer makes about APS, returned with every analysis so
 * that a consumer can surface them. Each states a property of the published
 * specification that the findings depend on; where the specification is silent
 * or a value is carried over from a comparable confidential VM, the analyzer
 * reports a caution rather than asserting a conclusion.
 */
export const ASSUMPTIONS: readonly string[] = [
  "All contract storage in APS is confidential by default; exposure is opt-in.",
  "A function's reachability is set by its APS access policy: Open (any caller), Restricted (grant-holders), Locked (nobody). An external or public function with no policy is treated as unset — unreachable under default-deny until a policy is configured.",
  "The public ledger observes only that an APS precompile call occurred, a predefined gas cost, and an acknowledgement — never return values, results, or logs.",
  "A confidential value is exposed when it reaches the return value of a reachable function, an emitted event (visible to every party authorized to view the transaction), a bridge to the public EVM, or an argument to an untrusted external contract.",
  "Trust domains (addTrustee) grant a counterparty introspection — BALANCE, EXTCODEHASH, and EXTCODESIZE become non-zero — and the ability to reach Restricted entrypoints. Trust is powerful, unidirectional, and revocable, so it is transitive through whatever the trustee re-exposes.",
];

/**
 * Ordinal ranking of severities, used both to sort findings from most to least
 * severe and to compare the severities of two findings that concern the same
 * function.
 */
const SEVERITY_RANK: Record<Severity, number> = {
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  ok: -1,
};

/**
 * Heuristic recognizer for an identifier that denotes a monetary or otherwise
 * quantity-bearing value. A confidential amount escaping through an event or a
 * getter is materially worse than an opaque identifier doing so, so several
 * rules consult this to raise or lower a finding's severity.
 */
const AMOUNT_NAME =
  /(amount|amt|value|val|price|salary|wage|qty|quantity|sum|total|balance|nav|cost|fee|pay|share)/i;

/**
 * Recognizer for a type fragment that denotes an integer quantity, used to
 * decide whether a state variable or parameter is amount-like independently of
 * its name.
 */
const AMOUNT_TYPE = /\b(u?int\d*)\b/;

/**
 * Recognizer for the APS access-policy and clearance annotations. A policy
 * annotation (`@aps:Open`, `@aps:Restricted`, `@aps:Locked`) associates the
 * following function with a reachability; a clearance annotation
 * (`@aps:clear`) marks a state variable as a deliberate, acknowledged
 * disclosure so that it is not reported.
 */
const POLICY_ANNOTATION = /@aps:\s*(open|restricted|locked|clear)\b/gi;

/**
 * Recognizer for the leading keywords of a declaration that is not a state
 * variable, used to skip such declarations when scanning a contract body for
 * its top-level storage.
 */
const RESERVED_TYPE_STARTS =
  /^(function|constructor|receive|fallback|modifier|event|error|struct|enum|using|pragma|import|contract|interface|library|abstract)\b/;

/**
 * Recognizer for the precompile methods by which a confidential value is
 * settled onto the public EVM. A value flowing into one of these crosses the
 * confidentiality boundary by construction.
 */
const BRIDGE_METHOD =
  /\b(bridgeToPublic|revealToPublic|toPublic|publishPublic)\s*\(/g;

/**
 * Recognizer for the cryptographic hash functions through which a confidential
 * value may be disclosed as a commitment rather than in the clear.
 */
const HASH_CALL = /\b(keccak256|sha256|ripemd160|sha3|blake2b|blake2s)\s*\(/;

/**
 * Recognizer for a party whose name suggests a compliance role — a deliberate,
 * policy-driven disclosure target — as distinct from an arbitrary third party.
 */
const AUDITOR_NAME = /(auditor|regulator|compliance|examiner|supervisor)/i;

/**
 * Recognizer for a party whose name suggests an arbitrary third-party contract,
 * to which a blanket trust grant is rarely appropriate.
 */
const THIRD_PARTY_NAME =
  /(router|marketplace|market|broker|dex|aggregator|relayer|bridge|external|partner|vendor|counterparty|oracle)/i;

/**
 * The APS access policy declared for a function. A function with no annotation
 * has a policy of `null`, meaning unset.
 */
export enum Policy {
  Open = "open",
  Restricted = "restricted",
  Locked = "locked",
}

/**
 * The set of callers able to reach a function, derived from its visibility and
 * its APS access policy. `Unset` denotes an externally visible function with no
 * policy, which default-deny renders unreachable until one is configured.
 */
export enum Reach {
  Anyone = "anyone",
  Grantees = "grantees",
  Nobody = "nobody",
  Unset = "unset",
  Internal = "internal",
  Modifier = "modifier",
  Constructor = "constructor",
}

/**
 * The severity of a finding, from `High` (a confidential value is world- or
 * broadly-readable) down through advisory `Info` to `Ok` (a positive
 * observation, such as a correctly gated getter or a clean bill).
 */
export enum Severity {
  High = "high",
  Medium = "medium",
  Low = "low",
  Info = "info",
  Ok = "ok",
}

/**
 * Whether an expression carries a confidential value and, if so, of which
 * provenance: `"state"` for confidential storage, `"param"` for confidential
 * calldata, or `null` for neither.
 */
export type Taint = "state" | "param" | null;

/** A single parameter of a function or event. */
export interface Param {
  type: string;
  name: string;
  raw: string;
  indexed: boolean;
}

/** A declared state variable and the confidentiality-relevant facts about it. */
export interface StateVar {
  name: string;
  type: string;
  visibility: string | null;
  constImm: string | null;
  isMapping: boolean;
  amountLike: boolean;
  decl: string;
  offset: number;
  clear: boolean;
  lineNo: number;
}

/** A declared event and its parameters, used to detect indexed disclosures. */
export interface EventDecl {
  name: string;
  params: Param[];
  offset: number;
  line: number;
}

/** A return expression together with its taint and whether it is a commitment. */
export interface ReturnExpr {
  expr: string;
  taint: Taint;
  committed: boolean;
  offset: number;
}

/** An emitted event together with the confidentiality of its arguments. */
export interface EmitSite {
  event: string;
  args: string;
  taint: Taint;
  hasAmount: boolean;
  committed: boolean;
  offset: number;
}

/** A call bridging a value to the public EVM. */
export interface BridgeSite {
  fn: string;
  args: string;
  taint: Taint;
  offset: number;
}

/** A trust grant made through `addTrustee`. */
export interface TrusteeSite {
  arg: string;
  offset: number;
}

/** A call into another contract of the form `Type(addr).method(args)`. */
export interface ExternalCall {
  calleeType: string;
  method: string;
  args: string;
  taint: Taint;
}

/** An assignment of a confidential value into a public or cleared variable. */
export interface AliasWrite {
  target: string;
  source: string[];
  offset: number;
}

/** The result of scanning a function body for confidentiality-relevant flow. */
export interface BodyScan {
  reads: string[];
  writes: string[];
  returnsExprs: ReturnExpr[];
  emits: EmitSite[];
  bridges: BridgeSite[];
  trustees: TrusteeSite[];
  extCalls: ExternalCall[];
  aliasWrites: AliasWrite[];
  ownerGate: string | null;
  stateTainted: string[];
  paramTainted: string[];
}

/** A function (or constructor, receive, fallback, or modifier) of a contract. */
export interface FunctionInfo {
  kind: string;
  name: string;
  sig: string;
  params: Param[];
  visibility: string | null;
  mutability: string | null;
  returns: Param[];
  start: number;
  headerEnd: number;
  bodyStart: number;
  bodyEnd: number;
  body: string;
  lineStart: number;
  lineEnd: number;
  policy: Policy | null;
  reach: Reach;
  contract: string;
  stateVarNames: string[];
  scan: BodyScan;
}

/** A contract, interface, or library and its members. */
export interface ContractInfo {
  name: string;
  kind: string;
  vars: StateVar[];
  fns: FunctionInfo[];
  events: EventDecl[];
  line: number;
}

/** A single confidentiality finding. */
export interface Finding {
  id: string;
  severity: Severity;
  contract: string;
  fnName: string;
  line: number;
  title: string;
  detail: string;
  sink: string;
  fix: string;
  rule: string;
  refVars?: string[];
}

/** A confidential value that leaks, as summarized for the observer view. */
export interface LeakLine {
  sev: Severity;
  text: string;
}

/** What each of three observers can learn from a representative call. */
export interface Observers {
  public: string[];
  authorized: string[];
  leaked: LeakLine[];
}

/** Headline counts describing an analysis. */
export interface Summary {
  high: number;
  medium: number;
  low: number;
  info: number;
  ok: number;
  contracts: number;
  functions: number;
  exposedFns: number;
  stateVars: number;
}

/** The parsed model of the analyzed source. */
export interface Model {
  assumptions: readonly string[];
  contracts: ContractInfo[];
}

/** The focus function whose call drives the observer view. */
export interface Focus {
  contract: string;
  name: string;
  sig: string;
}

/**
 * The result of a successful analysis: the parsed model, the findings, the
 * observer view, the focus function, the headline summary, and the assumptions.
 */
export interface AnalysisOk {
  ok: true;
  model: Model;
  findings: Finding[];
  observers: Observers;
  focus: Focus | null;
  summary: Summary;
  assumptions: readonly string[];
}

/** The result of an analysis that could not proceed, carrying a reason. */
export interface AnalysisError {
  ok: false;
  error: string;
  findings: Finding[];
  summary: Partial<Summary>;
}

/** The result of {@link analyzeContract}: either a full analysis or an error. */
export type AnalysisResult = AnalysisOk | AnalysisError;

/** A contract header located during a first structural pass over the source. */
interface RawContract {
  kind: string;
  name: string;
  start: number;
  bodyStart: number;
  bodyEnd: number;
}

/** An APS annotation located in the source, with its kind and offset. */
interface Annotation {
  kind: string;
  offset: number;
}

/** An empty body scan, filled in once a function body has been analyzed. */
function emptyScan(): BodyScan {
  return {
    reads: [],
    writes: [],
    returnsExprs: [],
    emits: [],
    bridges: [],
    trustees: [],
    extCalls: [],
    aliasWrites: [],
    ownerGate: null,
    stateTainted: [],
    paramTainted: [],
  };
}

/**
 * Locate every contract, interface, and library in the source, returning the
 * comment- and string-neutralized text alongside a header for each. A
 * declaration whose body brace cannot be matched is skipped so that a
 * malformed fragment never interrupts the analysis of the rest.
 */
export function parseContracts(raw: string): {
  blanked: string;
  contracts: RawContract[];
} {
  const blanked = _blankNonCode(raw);
  const contracts: RawContract[] = [];
  const re = /\b(contract|interface|library)\s+([A-Za-z_]\w*)/g;
  let m: RegExpExecArray | null = re.exec(blanked);
  while (m !== null) {
    const brace = blanked.indexOf("{", m.index);
    const end = brace < 0 ? -1 : _matchBracket(blanked, brace);
    if (brace >= 0 && end >= 0) {
      contracts.push({
        kind: m[1],
        name: m[2],
        start: m.index,
        bodyStart: brace + 1,
        bodyEnd: end,
      });
      re.lastIndex = end;
    }
    m = re.exec(blanked);
  }
  return { blanked, contracts };
}

/**
 * Split a parameter or return list into typed parameters, recovering the name
 * (when present), the type, and whether the parameter is `indexed`. The
 * `indexed` keyword is recognized and removed from the type so that an indexed
 * event parameter is not mistaken for one of a different type.
 */
export function parseParams(input: string): Param[] {
  const str = input.trim();
  if (str === "") {
    return [];
  }
  return _splitTopLevel(str, ",")
    .map((part) => {
      const toks = part.trim().split(/\s+/);
      const indexed = toks.includes("indexed");
      const kept = toks.filter((t) => t !== "indexed");
      const name = kept.length > 1 ? kept[kept.length - 1] : "";
      const type = kept.length > 1 ? kept.slice(0, -1).join(" ") : kept[0];
      return { type, name, raw: part.trim(), indexed };
    })
    .filter((p) => p.type !== undefined && p.type !== "");
}

/**
 * Parse the functions, constructors, receive and fallback functions, and
 * modifiers declared directly in a contract body. Each is returned with its
 * signature, parameters, visibility, mutability, declared return parameters,
 * and the offsets of its header and body; the reachability, contract, and body
 * scan are filled in later by {@link analyzeContract}. A bodiless declaration
 * (as in an interface) is retained with a body start of `-1`.
 */
export function parseFunctions(
  raw: string,
  blanked: string,
  c: RawContract,
): FunctionInfo[] {
  const body = blanked.slice(c.bodyStart, c.bodyEnd);
  const fns: FunctionInfo[] = [];
  const re =
    /\b(function\s+([A-Za-z_]\w*)|constructor|receive|fallback|modifier\s+([A-Za-z_]\w*))\s*\(/g;
  let m: RegExpExecArray | null = re.exec(body);
  while (m !== null) {
    const openParen = c.bodyStart + m.index + m[0].length - 1;
    const closeParen = _matchBracket(blanked, openParen);
    if (closeParen < 0) {
      m = re.exec(body);
      continue;
    }
    const params = raw.slice(openParen + 1, closeParen);
    let j = closeParen + 1;
    while (j < c.bodyEnd && blanked[j] !== "{" && blanked[j] !== ";") {
      j++;
    }
    const modRegion = blanked.slice(closeParen + 1, j);
    let bodyStart = -1;
    let bodyEnd = -1;
    let bodyText = "";
    if (blanked[j] === "{") {
      bodyStart = j;
      bodyEnd = _matchBracket(blanked, j);
      bodyText = blanked.slice(bodyStart + 1, bodyEnd);
    }
    const kind = m[1].startsWith("function")
      ? "function"
      : m[1].startsWith("modifier")
        ? "modifier"
        : m[1];
    const name = m[2] || m[3] || kind;
    const vis =
      (modRegion.match(/\b(external|public|internal|private)\b/) || [])[1] ||
      null;
    const mut = (modRegion.match(/\b(view|pure|payable)\b/) || [])[1] || null;
    let returns = "";
    const rm = modRegion.match(/\breturns\s*\(/);
    if (rm && rm.index !== undefined) {
      const rp = closeParen + 1 + rm.index + rm[0].length - 1;
      const rc = _matchBracket(blanked, rp);
      if (rc > 0) {
        returns = raw.slice(rp + 1, rc);
      }
    }
    fns.push({
      kind,
      name,
      sig: `${name}(${parseParams(params)
        .map((p) => p.type)
        .join(",")})`,
      params: parseParams(params),
      visibility: vis,
      mutability: mut,
      returns: parseParams(returns),
      start: c.bodyStart + m.index,
      headerEnd: j,
      bodyStart,
      bodyEnd,
      body: bodyText,
      lineStart: 0,
      lineEnd: 0,
      policy: null,
      reach: Reach.Unset,
      contract: "",
      stateVarNames: [],
      scan: emptyScan(),
    });
    re.lastIndex = (bodyEnd > 0 ? bodyEnd : j) - c.bodyStart;
    m = re.exec(body);
  }
  return fns;
}

/**
 * Parse the state variables declared directly in a contract body. The bodies of
 * the contract's functions are first neutralized so that only top-level
 * declarations remain; the remainder is split on semicolons and each fragment
 * that names a variable is decoded into its type, name, visibility, and
 * constant/immutable qualifier. The `=>` of a `mapping` type is masked before
 * an initializer `=` is sought, so that a mapping declaration is not truncated.
 */
export function parseStateVars(
  _raw: string,
  blanked: string,
  c: RawContract,
  fns: FunctionInfo[],
): StateVar[] {
  const arr = blanked.slice(c.bodyStart, c.bodyEnd).split("");
  for (const f of fns) {
    if (f.bodyStart >= 0) {
      for (let k = f.bodyStart; k <= f.bodyEnd; k++) {
        const idx = k - c.bodyStart;
        if (arr[idx] !== "\n") {
          arr[idx] = " ";
        }
      }
    }
  }
  const top = arr.join("");
  const vars: StateVar[] = [];
  let pos = 0;
  for (const frag of top.split(";")) {
    const start = c.bodyStart + pos;
    pos += frag.length + 1;
    const t = frag.trim();
    if (t === "" || RESERVED_TYPE_STARTS.test(t)) {
      continue;
    }
    const scan = t.replace(/=>/g, "  ");
    const eq = scan.search(/=(?!=)/);
    const head = (eq >= 0 ? t.slice(0, eq) : t).trim();
    const toks = head.split(/\s+/);
    if (toks.length < 2) {
      continue;
    }
    const name = toks[toks.length - 1];
    if (!/^[A-Za-z_]\w*$/.test(name)) {
      continue;
    }
    const rest = toks.slice(0, -1);
    const vis =
      rest.find((x) => /^(public|private|internal|external)$/.test(x)) || null;
    const constImm = rest.find((x) => /^(constant|immutable)$/.test(x)) || null;
    const type = rest
      .filter(
        (x) =>
          !/^(public|private|internal|external|constant|immutable)$/.test(x),
      )
      .join(" ");
    if (type === "") {
      continue;
    }
    const varOffset = start + frag.lastIndexOf(name);
    vars.push({
      name,
      type,
      visibility: vis,
      constImm,
      isMapping: /^mapping\b/.test(type),
      amountLike: AMOUNT_TYPE.test(type),
      decl: t,
      offset: varOffset,
      clear: false,
      lineNo: 0,
    });
  }
  return vars;
}

/**
 * Parse the events declared in a contract body, recovering each event's name
 * and parameters (including which are `indexed`). Indexed parameters are stored
 * in a transaction's topics and are therefore a distinct, more directly
 * queryable disclosure surface than ordinary event data.
 */
export function parseEvents(
  raw: string,
  blanked: string,
  c: RawContract,
): EventDecl[] {
  const body = blanked.slice(c.bodyStart, c.bodyEnd);
  const events: EventDecl[] = [];
  const re = /\bevent\s+([A-Za-z_]\w*)\s*\(/g;
  let m: RegExpExecArray | null = re.exec(body);
  while (m !== null) {
    const openParen = c.bodyStart + m.index + m[0].length - 1;
    const closeParen = _matchBracket(blanked, openParen);
    if (closeParen >= 0) {
      events.push({
        name: m[1],
        params: parseParams(raw.slice(openParen + 1, closeParen)),
        offset: c.bodyStart + m.index,
        line: 0,
      });
      re.lastIndex = closeParen;
    }
    m = re.exec(body);
  }
  return events;
}

/**
 * Collect every APS annotation in the source with its kind and offset. A fresh
 * regular expression is used so that the module-level pattern's lastIndex is
 * never shared across calls.
 */
export function collectAnnotations(raw: string): Annotation[] {
  const anns: Annotation[] = [];
  const re = new RegExp(POLICY_ANNOTATION.source, "gi");
  let m: RegExpExecArray | null = re.exec(raw);
  while (m !== null) {
    anns.push({ kind: m[1].toLowerCase(), offset: m.index });
    m = re.exec(raw);
  }
  return anns;
}

/**
 * Associate each function with the policy annotation that precedes it and each
 * state variable with any clearance annotation on or immediately above it. A
 * function's policy is the nearest policy annotation that lies before the
 * function and after the previous member, so that an annotation is not claimed
 * by a member other than the one it labels.
 */
export function assignPolicies(
  fns: FunctionInfo[],
  vars: StateVar[],
  anns: Annotation[],
  lineAt: (index: number) => number,
): void {
  const items = [
    ...fns.map((f) => ({ kind: "fn" as const, offset: f.start, fn: f })),
    ...vars.map((v) => ({ kind: "var" as const, offset: v.offset, fn: null })),
  ].sort((a, b) => a.offset - b.offset);

  const policyAnns = anns.filter((a) => a.kind !== "clear");
  const clearAnns = anns.filter((a) => a.kind === "clear");

  for (let i = 0; i < items.length; i++) {
    const it = items[i];
    const prevEnd = i > 0 ? items[i - 1].offset : 0;
    if (it.kind === "fn" && it.fn) {
      let chosen: Annotation | null = null;
      for (const a of policyAnns) {
        if (a.offset < it.offset && a.offset > prevEnd) {
          chosen = a;
        }
      }
      it.fn.policy = chosen ? (chosen.kind as Policy) : null;
    }
  }
  for (const v of vars) {
    v.lineNo = lineAt(v.offset);
    for (const a of clearAnns) {
      const aLine = lineAt(a.offset);
      if (
        aLine === v.lineNo ||
        (a.offset < v.offset && v.offset - a.offset < 80)
      ) {
        v.clear = true;
      }
    }
  }
}

/**
 * Remove the sub-expressions enclosed by cryptographic hash calls, replacing
 * each `keccak256(...)`, `sha256(...)`, and the like with a neutral literal.
 * Re-evaluating an expression's taint after this transformation reveals whether
 * a confidential value was disclosed only as a commitment: if the value's
 * identifier survives the stripping, it is disclosed in the clear; if it does
 * not, it was disclosed only through a hash.
 */
function stripHashCalls(expr: string): string {
  let out = expr;
  let guard = 0;
  while (guard < 8) {
    guard++;
    const m = HASH_CALL.exec(out);
    if (m === null) {
      break;
    }
    const open = m.index + m[0].length - 1;
    const close = _matchBracket(out, open);
    if (close < 0) {
      break;
    }
    out = `${out.slice(0, m.index)}0x0${out.slice(close + 1)}`;
  }
  return out;
}

/**
 * Scan a function body for the flow of confidential values. Reads and writes of
 * state are recorded; local variables are tainted by a fixpoint over their
 * assignments, so that a value copied from confidential state or confidential
 * calldata into a local is tracked to wherever the local is subsequently used.
 * The scan then records each sink through which a value may escape — a return
 * expression, an emitted event, a bridge call, a trust grant, and a call into
 * another contract — annotating each with the taint that reaches it and whether
 * a confidential value is disclosed only as a commitment. It also records any
 * assignment of a confidential value into a public or cleared variable, and an
 * owner check of the form `require(msg.sender == x)`.
 */
export function scanBody(fn: FunctionInfo, vars: StateVar[]): BodyScan {
  const body = fn.body || "";
  const varNames = vars.map((v) => v.name);
  const confidentialNames = vars
    .filter((v) => v.visibility !== "public" && !v.clear)
    .map((v) => v.name);
  const exposedNames = vars
    .filter((v) => v.visibility === "public" || v.clear)
    .map((v) => v.name);
  const reads = new Set<string>();
  const writes = new Set<string>();

  for (const v of vars) {
    const re = new RegExp(
      `\\b${v.name}\\b\\s*(\\[[^\\]]*\\])?\\s*(\\+=|-=|=(?!=)|\\+\\+|--)?`,
      "g",
    );
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      const op = m[2];
      if (op === "=") {
        writes.add(v.name);
      } else if (op) {
        writes.add(v.name);
        reads.add(v.name);
      } else {
        reads.add(v.name);
      }
      m = re.exec(body);
    }
  }

  const paramNames = fn.params.map((p) => p.name).filter((x) => x !== "");
  const stateTainted = new Set<string>();
  const paramTainted = new Set<string>();
  const hits = (expr: string, name: string): boolean =>
    new RegExp(`\\b${name}\\b`).test(expr);
  const containsState = (expr: string): boolean =>
    varNames.some((n) => hits(expr, n)) ||
    [...stateTainted].some((n) => hits(expr, n));
  const containsParam = (expr: string): boolean =>
    paramNames.some((n) => hits(expr, n)) ||
    [...paramTainted].some((n) => hits(expr, n));

  const assignRe =
    /(?:^|[;{])\s*(?:[A-Za-z_][\w.[\]]*\s+)?([A-Za-z_]\w*)\s*=\s*([^;]+);/g;
  for (let pass = 0; pass < 4; pass++) {
    assignRe.lastIndex = 0;
    let m: RegExpExecArray | null = assignRe.exec(body);
    while (m !== null) {
      const lhs = m[1];
      const rhs = m[2];
      if (!varNames.includes(lhs)) {
        if (containsState(rhs)) {
          stateTainted.add(lhs);
        } else if (containsParam(rhs)) {
          paramTainted.add(lhs);
        }
      }
      m = assignRe.exec(body);
    }
  }

  const taintOf = (expr: string): Taint =>
    containsState(expr) ? "state" : containsParam(expr) ? "param" : null;
  const committedOf = (expr: string, taint: Taint): boolean =>
    taint !== null && taintOf(stripHashCalls(expr)) === null;

  const hasAmountArg = (args: string): boolean => {
    const parts = _splitTopLevel(args, ",").map((s) => s.trim());
    return parts.some((p) => {
      if (vars.some((v) => v.amountLike && hits(p, v.name))) {
        return true;
      }
      const pp = fn.params.find((x) => x.name !== "" && hits(p, x.name));
      return (
        pp !== undefined &&
        (/uint|int/.test(pp.type) || AMOUNT_NAME.test(pp.name))
      );
    });
  };

  const returnsExprs: ReturnExpr[] = [];
  {
    const re = /\breturn\b([^;]*);/g;
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      const expr = m[1].trim();
      if (expr !== "") {
        const taint = taintOf(expr);
        returnsExprs.push({
          expr,
          taint,
          committed: committedOf(expr, taint),
          offset: fn.bodyStart + 1 + m.index,
        });
      }
      m = re.exec(body);
    }
  }

  const emits: EmitSite[] = [];
  {
    const re = /\bemit\s+([A-Za-z_]\w*)\s*\(([^;]*)\)\s*;/g;
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      const args = m[2];
      const taint = taintOf(args);
      emits.push({
        event: m[1],
        args,
        taint,
        hasAmount: hasAmountArg(args),
        committed: committedOf(args, taint),
        offset: fn.bodyStart + 1 + m.index,
      });
      m = re.exec(body);
    }
  }

  const bridges: BridgeSite[] = [];
  {
    const re = new RegExp(`${BRIDGE_METHOD.source}([^;]*)\\)`, "g");
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      const args = m[2];
      bridges.push({
        fn: m[1],
        args,
        taint: taintOf(args),
        offset: fn.bodyStart + 1 + m.index,
      });
      m = re.exec(body);
    }
  }

  const trustees: TrusteeSite[] = [];
  {
    const re = /\baddTrustee\s*\(([^)]*)\)/g;
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      trustees.push({ arg: m[1].trim(), offset: fn.bodyStart + 1 + m.index });
      m = re.exec(body);
    }
  }

  const extCalls: ExternalCall[] = [];
  {
    const re =
      /\b([A-Z]\w*)\s*\(\s*([^)]*)\)\s*\.\s*([A-Za-z_]\w*)\s*\(([^;)]*)\)/g;
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      extCalls.push({
        calleeType: m[1],
        method: m[3],
        args: m[4],
        taint: taintOf(m[4]),
      });
      m = re.exec(body);
    }
  }

  const aliasWrites: AliasWrite[] = [];
  if (exposedNames.length > 0 && confidentialNames.length > 0) {
    const re =
      /(?:^|[;{}])\s*([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*=(?!=)\s*([^;]+);/g;
    let m: RegExpExecArray | null = re.exec(body);
    while (m !== null) {
      const target = m[1];
      const rhs = m[2];
      if (exposedNames.includes(target)) {
        const source = confidentialNames.filter((n) => hits(rhs, n));
        if (source.length > 0) {
          aliasWrites.push({
            target,
            source,
            offset: fn.bodyStart + 1 + m.index,
          });
        }
      }
      m = re.exec(body);
    }
  }

  const ownerGate =
    (body.match(/require\s*\(\s*msg\.sender\s*==\s*([A-Za-z_]\w*)/) || [])[1] ||
    null;

  return {
    reads: [...reads],
    writes: [...writes],
    returnsExprs,
    emits,
    bridges,
    trustees,
    extCalls,
    aliasWrites,
    ownerGate,
    stateTainted: [...stateTainted],
    paramTainted: [...paramTainted],
  };
}

/**
 * Determine who can reach a function. A modifier, constructor, or internal or
 * private function is classified as such; an externally visible function is
 * placed by its APS access policy, with an absent policy yielding `Unset`
 * (unreachable under default-deny).
 */
export function reachability(fn: FunctionInfo): Reach {
  if (fn.kind === "modifier") {
    return Reach.Modifier;
  }
  if (fn.kind === "constructor") {
    return Reach.Constructor;
  }
  if (fn.visibility === "internal" || fn.visibility === "private") {
    return Reach.Internal;
  }
  switch (fn.policy) {
    case Policy.Open:
      return Reach.Anyone;
    case Policy.Restricted:
      return Reach.Grantees;
    case Policy.Locked:
      return Reach.Nobody;
    default:
      return Reach.Unset;
  }
}

/** The state-variable names referenced by an expression. */
function varsIn(expr: string, vs: StateVar[]): string[] {
  return vs
    .filter((v) => new RegExp(`\\b${v.name}\\b`).test(expr))
    .map((v) => v.name);
}

/**
 * Analyze a Solidity contract for the confidential state it exposes. The source
 * is parsed into a model of its contracts, functions, state variables, and
 * events; each function's reachability and information flow are derived; and a
 * fixed set of rules is applied to report every path by which a confidential
 * value can cross the boundary. The result is the model, the findings ordered
 * from most to least severe, an observer view of a representative call, and a
 * headline summary. When the source contains no contract the analysis returns
 * an error rather than throwing.
 */
export function analyzeContract(source: string): AnalysisResult {
  const findings: Finding[] = [];
  const parsed = parseContracts(source);
  if (parsed.contracts.length === 0) {
    return {
      ok: false,
      error: "No contract, interface, or library found in the source.",
      findings: [],
      summary: {},
    };
  }

  const lineAt = _lineMapper(source);
  const anns = collectAnnotations(source);
  const model: Model = { assumptions: ASSUMPTIONS, contracts: [] };
  const allFns: FunctionInfo[] = [];

  for (const c of parsed.contracts) {
    const fns = parseFunctions(source, parsed.blanked, c);
    const vars = parseStateVars(source, parsed.blanked, c, fns);
    const events = parseEvents(source, parsed.blanked, c);
    for (const ev of events) {
      ev.line = lineAt(ev.offset);
    }
    assignPolicies(fns, vars, anns, lineAt);
    for (const f of fns) {
      f.lineStart = lineAt(f.start);
      f.lineEnd = f.bodyEnd > 0 ? lineAt(f.bodyEnd) : f.lineStart;
      f.scan = scanBody(f, vars);
      f.reach = reachability(f);
      f.contract = c.name;
      f.stateVarNames = vars.map((v) => v.name);
      allFns.push(f);
    }
    model.contracts.push({
      name: c.name,
      kind: c.kind,
      vars,
      fns,
      events,
      line: lineAt(c.start),
    });
  }

  const add = (o: Finding): void => {
    findings.push(o);
  };
  const refList = (names: string[]): string =>
    names.map((x) => `\`${x}\``).join(", ");
  const commitmentNote = (
    f: FunctionInfo,
    which: string[],
    offset: number,
  ): void => {
    add({
      id: "APS-H",
      severity: Severity.Info,
      contract: f.contract,
      fnName: f.name,
      line: lineAt(offset),
      title: "Confidential value disclosed as a commitment",
      detail: `${f.contract}.${f.name} discloses ${refList(which)} only through a cryptographic hash — a commitment — rather than in the clear. This is the recommended way to make a confidential value verifiable without revealing it. Confirm the pre-image is high-entropy or salted: a hash of a low-entropy value, such as a salary drawn from a narrow range, can be recovered by brute force.`,
      sink: "commitment",
      refVars: which,
      fix: "If the pre-image is low-entropy, salt it — hash the value together with a secret nonce — so the commitment cannot be brute-forced.",
      rule: "A hash of a confidential value discloses a commitment, not the value, subject to the entropy of the pre-image.",
    });
  };

  // ---- per-function rules ----
  for (const cm of model.contracts) {
    for (const f of cm.fns) {
      if (f.bodyStart < 0) {
        continue;
      }
      const vars = cm.vars;

      // APS-1 / APS-8: a reachable-by-anyone function returns a confidential value.
      if (f.reach === Reach.Anyone) {
        for (const r of f.scan.returnsExprs) {
          if (r.taint === "state") {
            const which = varsIn(r.expr, vars);
            if (r.committed) {
              commitmentNote(f, which, r.offset);
              continue;
            }
            const balanceLike = vars.some(
              (v) => which.includes(v.name) && v.isMapping,
            );
            add({
              id: "APS-1",
              severity: Severity.High,
              contract: f.contract,
              fnName: f.name,
              line: lineAt(f.start),
              title: "Open function returns confidential state",
              detail: `${f.contract}.${f.name} has access policy Open, so any caller may invoke it. It returns ${refList(which)}, which is confidential storage. ${balanceLike ? "Because the source is a mapping keyed per account, this makes every account's confidential value readable by anyone who supplies the key." : "This makes the confidential value world-readable."}`,
              sink: "return value",
              refVars: which,
              fix: `Set ${f.name}'s policy to Restricted and grant read access only to the intended readers, for example the account owner or a named auditor. If a self-service getter is required, gate it with require(msg.sender == <key>) so a caller can only read their own entry.`,
              rule: "Reachability Open implies the return value is visible to all callers.",
            });
          } else if (r.taint === "param") {
            if (r.committed) {
              continue;
            }
            add({
              id: "APS-8",
              severity: Severity.Low,
              contract: f.contract,
              fnName: f.name,
              line: lineAt(f.start),
              title: "Open function echoes a calldata argument",
              detail: `${f.contract}.${f.name} (Open) returns a value derived from its arguments. Calldata is confidential in APS; echoing it back through an Open function exposes it to any caller.`,
              sink: "return value",
              fix: "Avoid returning sensitive inputs from Open functions, or restrict the function.",
              rule: "Open implies the return value is visible to all callers.",
            });
          }
        }
      }

      // APS-OK / APS-9: a grant-holder-reachable function returns confidential state.
      if (f.reach === Reach.Grantees) {
        for (const r of f.scan.returnsExprs) {
          if (r.taint === "state") {
            const which = varsIn(r.expr, vars);
            if (r.committed) {
              commitmentNote(f, which, r.offset);
              continue;
            }
            const gatedKey = f.scan.ownerGate;
            const mappingKeyedByGate =
              gatedKey !== null &&
              new RegExp(`\\[[^\\]]*\\b${gatedKey}\\b[^\\]]*\\]`).test(r.expr);
            if (gatedKey !== null && mappingKeyedByGate) {
              add({
                id: "APS-OK",
                severity: Severity.Ok,
                contract: f.contract,
                fnName: f.name,
                line: lineAt(f.start),
                title: "Owner-gated confidential read",
                detail: `${f.contract}.${f.name} returns confidential ${refList(which)} but requires msg.sender == ${gatedKey}, so a caller can only read their own entry. This is a correct confidential getter.`,
                sink: "return value (owner-gated)",
                refVars: which,
                fix: "",
                rule: "Restricted with an owner check implies each caller reads only their own state.",
              });
            } else {
              add({
                id: "APS-9",
                severity: Severity.Info,
                contract: f.contract,
                fnName: f.name,
                line: lineAt(f.start),
                title:
                  "Restricted function returns confidential state to all grant-holders",
                detail: `${f.contract}.${f.name} (Restricted) returns ${refList(which)}. Every address holding a grant for this function can read it. Restricted narrows the audience but is not per-record; confirm the grant list is the intended reader set.`,
                sink: "return value",
                refVars: which,
                fix: "Keep the grant list minimal, or add a per-record check such as requiring that msg.sender owns the record.",
                rule: "Restricted implies the return value is visible to every grant-holder.",
              });
            }
          }
        }
      }

      // APS-2 / APS-2b: a confidential value or identifier is emitted in an event.
      for (const e of f.scan.emits) {
        if (e.taint === "state" || (e.taint === "param" && e.hasAmount)) {
          const evVars = varsIn(e.args, vars);
          const evAmt = f.params
            .filter(
              (p) =>
                p.name !== "" &&
                new RegExp(`\\b${p.name}\\b`).test(e.args) &&
                (/uint|int/.test(p.type) || AMOUNT_NAME.test(p.name)),
            )
            .map((p) => p.name);
          const evRefs = evVars.concat(evAmt);
          if (e.committed) {
            commitmentNote(f, evRefs, e.offset);
            continue;
          }
          const sevHigh = e.taint === "state" && f.reach === Reach.Anyone;
          add({
            id: "APS-2",
            severity: sevHigh ? Severity.High : Severity.Medium,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(e.offset),
            title: "Confidential value emitted in an event",
            detail: `${f.contract}.${f.name} emits ${e.event}(${e.args.trim()}). ${e.taint === "state" ? "An argument carries confidential state. " : "An argument carries a confidential amount from calldata. "}Events are not on the public ledger, but they are retrievable by every party authorized to view this transaction — which for a shared application can be a far broader set than intended.`,
            sink: "event log",
            refVars: evRefs,
            fix: "Omit the sensitive argument, or emit a commitment (hash) instead of the value. If observers legitimately need the value, scope who can view the transaction's results.",
            rule: "Emitted events are readable by all authorized viewers of the transaction.",
          });
        } else if (e.taint === "param") {
          add({
            id: "APS-2b",
            severity: Severity.Info,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(e.offset),
            title: "Event reveals transaction metadata",
            detail: `${f.contract}.${f.name} emits ${e.event}(${e.args.trim()}); the arguments, such as a counterparty address, are visible to all authorized viewers. No amount is exposed, but the relationship and timing are.`,
            sink: "event log",
            fix: "Emit only what observers need. Consider indexing a commitment rather than raw identifiers.",
            rule: "Emitted events are readable by all authorized viewers of the transaction.",
          });
        }
      }

      // APS-3: a confidential value is bridged to the public EVM.
      for (const br of f.scan.bridges) {
        if (br.taint === "state" || br.taint === "param") {
          add({
            id: "APS-3",
            severity: Severity.High,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(br.offset),
            title: "Confidential value bridged to the public EVM",
            detail: `${f.contract}.${f.name} calls ${br.fn}(${br.args.trim()}), moving a confidential value across the boundary into public state. The amount becomes public by construction; the confidentiality of everything upstream is lost at this call.`,
            sink: "public bridge",
            refVars: f.scan.reads.slice(),
            fix: "Confirm this crossing is intended. If only a net or aggregate must settle publicly, bridge the aggregate rather than per-transaction amounts, or settle inside APS and bridge a zero-knowledge attestation instead of the raw value.",
            rule: "Bridging to the public EVM reveals the value on the public ledger.",
          });
        }
      }

      // APS-10: a confidential value is passed as an argument to another contract.
      for (const ec of f.scan.extCalls) {
        if (ec.taint === "state") {
          const which = varsIn(ec.args, vars);
          add({
            id: "APS-10",
            severity: Severity.High,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(f.start),
            title: "Confidential value passed to an external contract",
            detail: `${f.contract}.${f.name} passes ${which.length > 0 ? refList(which) : "a confidential value"} to ${ec.calleeType}.${ec.method}. Handing confidential state to another contract discloses it to that contract in full; unless ${ec.calleeType} is itself confidential and trusted, the value has left the boundary.`,
            sink: "external call argument",
            refVars: which,
            fix: `Do not pass confidential state to contracts outside the boundary. If ${ec.calleeType} must act on the value, pass a commitment, or perform the computation inside a confidential contract you control.`,
            rule: "An argument to an external call is disclosed to the callee.",
          });
        }
      }

      // APS-4 / APS-4ok: a trust grant.
      for (const t of f.scan.trustees) {
        const arg = t.arg;
        const isAuditor = AUDITOR_NAME.test(arg);
        const isThirdParty = THIRD_PARTY_NAME.test(arg);
        if (isAuditor && !isThirdParty) {
          add({
            id: "APS-4ok",
            severity: Severity.Info,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(t.offset),
            title: "Trust granted to a compliance party",
            detail: `${f.contract}.${f.name} grants trust to \`${arg}\`. This is a deliberate disclosure to an auditor or regulator. Trust is revocable; ensure it is scoped and time-bounded per policy.`,
            sink: "trust domain",
            fix: "Prefer granting access to specific Restricted functions over a blanket trust relationship where the API allows it.",
            rule: "addTrustee exposes introspection and Restricted entrypoints to the trustee.",
          });
        } else {
          add({
            id: "APS-4",
            severity: Severity.High,
            contract: f.contract,
            fnName: f.name,
            line: lineAt(t.offset),
            title: "Over-broad trust grant",
            detail: `${f.contract}.${f.name} grants trust to \`${arg}\`${isThirdParty ? " — a third-party contract." : "."} A trustee sees non-zero results from BALANCE, EXTCODEHASH, and EXTCODESIZE on this contract and can reach its Restricted entrypoints, so any confidential state those entrypoints expose is now readable by the trustee, and by anything the trustee re-exposes.`,
            sink: "trust domain",
            fix: "Remove untrusted trustees. Grant trust only to contracts whose bytecode you have reviewed, prefer function-scoped grants over blanket trust, and revoke as soon as the interaction completes.",
            rule: "addTrustee exposes introspection and Restricted entrypoints to the trustee.",
          });
        }
      }

      // APS-14: a confidential value is copied into a public or cleared variable.
      for (const aw of f.scan.aliasWrites) {
        add({
          id: "APS-14",
          severity: Severity.High,
          contract: f.contract,
          fnName: f.name,
          line: lineAt(aw.offset),
          title: "Confidential value copied into a public variable",
          detail: `${f.contract}.${f.name} assigns confidential ${refList(aw.source)} into \`${aw.target}\`, which is public or marked clear. The value is exposed through \`${aw.target}\`'s implicit getter regardless of ${f.name}'s own policy — a confidential value laundered into a public slot.`,
          sink: "public storage",
          refVars: aw.source,
          fix: `Do not copy confidential state into public storage. Keep \`${aw.target}\` confidential, or store a commitment (hash) if a public marker is required.`,
          rule: "A confidential value written to a public or cleared variable is exposed through that variable's getter.",
        });
      }
    }
  }

  // APS-5 / APS-7: variable-level exposures.
  for (const cm of model.contracts) {
    for (const v of cm.vars) {
      if (v.visibility === "public" && !v.clear) {
        add({
          id: "APS-5",
          severity: v.amountLike ? Severity.Medium : Severity.Low,
          contract: cm.name,
          fnName: v.name,
          line: v.lineNo,
          title: "Public state variable auto-generates a getter",
          detail: `\`${v.name}\` in ${cm.name} is declared public. Solidity synthesizes a public getter for it; in APS that getter is an exposure point subject to access policy. Since storage is confidential by default, an unrestricted implicit getter reveals ${v.amountLike ? "this confidential amount" : "this value"} to callers.`,
          sink: "implicit getter",
          refVars: [v.name],
          fix: `Make \`${v.name}\` non-public and expose it through a Restricted function, or confirm the access policy Locks or Restricts the implicit getter. If the value is not sensitive, annotate it // @aps:clear to acknowledge the disclosure.`,
          rule: "A public state variable has an implicit getter, which is subject to access policy.",
        });
      }
      if (v.constImm !== null && v.amountLike && !v.clear) {
        add({
          id: "APS-7",
          severity: Severity.Low,
          contract: cm.name,
          fnName: v.name,
          line: v.lineNo,
          title: "Confidential value in immutable or constant — verify storage",
          detail: `\`${v.name}\` is ${v.constImm}. On some confidential VMs, immutables and constants live in contract bytecode rather than encrypted storage, so a secret placed there can leak. Confirm APS encrypts constructor-embedded values before relying on this for confidentiality.`,
          sink: "bytecode",
          fix: "Keep secrets in regular, encrypted storage set after construction, not in immutable or constant, unless APS documents otherwise.",
          rule: "Caution carried over from TEE-EVMs such as Sapphire; confirm against APS documentation.",
        });
      }
    }
  }

  // APS-12: an event indexes a confidential value into a queryable topic.
  for (const cm of model.contracts) {
    for (const ev of cm.events) {
      for (const p of ev.params) {
        if (
          p.indexed &&
          (AMOUNT_TYPE.test(p.type) || AMOUNT_NAME.test(p.name))
        ) {
          add({
            id: "APS-12",
            severity: Severity.Medium,
            contract: cm.name,
            fnName: ev.name,
            line: ev.line,
            title: "Confidential value indexed in an event",
            detail: `Event \`${ev.name}\` in ${cm.name} declares \`${p.name}\` as indexed. Indexed parameters are stored in the transaction's log topics, where they are directly filterable by any party authorized to view the transaction. Indexing a confidential amount makes it not merely visible but queryable.`,
            sink: "event topic",
            refVars: [p.name],
            fix: `Remove indexed from \`${p.name}\`, or index a commitment (hash) rather than the raw value.`,
            rule: "Indexed event parameters are stored in queryable log topics.",
          });
        }
      }
    }
  }

  // APS-6: an externally visible function has no access policy.
  for (const f of allFns) {
    if (f.bodyStart < 0) {
      continue;
    }
    if (
      f.reach === Reach.Unset &&
      (f.visibility === "external" || f.visibility === "public")
    ) {
      add({
        id: "APS-6",
        severity: Severity.Info,
        contract: f.contract,
        fnName: f.name,
        line: lineAt(f.start),
        title: "External function has no APS access policy",
        detail: `${f.contract}.${f.name} is ${f.visibility} but carries no APS access policy. Under default-deny it is currently unreachable by external callers — safe, but likely a bug if it is meant to be callable.`,
        sink: "reachability",
        fix: "Annotate the function with its intended policy: // @aps:Open, // @aps:Restricted, or // @aps:Locked.",
        rule: "No policy implies default-deny, which implies the function is unreachable externally.",
      });
    }
  }

  // APS-T: an Open forwarder re-exposes a trusted contract's confidential state.
  for (const f of allFns) {
    if (f.reach !== Reach.Anyone) {
      continue;
    }
    for (const ec of f.scan.extCalls) {
      const target = allFns.find(
        (g) => g.contract === ec.calleeType && g.name === ec.method,
      );
      if (!target) {
        continue;
      }
      const targetRevealsState = target.scan.returnsExprs.some(
        (r) => r.taint === "state",
      );
      if (
        targetRevealsState &&
        (target.reach === Reach.Grantees || target.reach === Reach.Anyone)
      ) {
        const tRefs = target.stateVarNames.filter((n) =>
          target.scan.returnsExprs.some((r) =>
            new RegExp(`\\b${n}\\b`).test(r.expr),
          ),
        );
        add({
          id: "APS-T",
          severity: Severity.Medium,
          contract: f.contract,
          fnName: f.name,
          line: lineAt(f.start),
          refVars: tRefs,
          title: "Transitive exposure through a trusted contract",
          detail: `${f.contract}.${f.name} is Open and calls ${ec.calleeType}.${ec.method}, which returns confidential state from ${ec.calleeType}. If ${f.contract} is a trustee of ${ec.calleeType}, this Open forwarder re-exposes ${ec.calleeType}'s confidential state to anyone who calls ${f.name} — the trust boundary is only as tight as the least-restricted function behind it.`,
          sink: "transitive return",
          fix: `Do not grant trust to a contract with Open forwarders. Restrict ${f.name}, or have ${ec.calleeType} expose a purpose-built, tightly-granted function instead of a general getter.`,
          rule: "Trust is transitive through whatever the trustee re-exposes.",
        });
      }
    }
  }

  // ---- clean bill ----
  const hasHM = findings.some(
    (f) => f.severity === Severity.High || f.severity === Severity.Medium,
  );
  if (!hasHM) {
    add({
      id: "APS-CLEAN",
      severity: Severity.Ok,
      contract: model.contracts[0].name,
      fnName: "",
      line: 0,
      title: "No confidentiality findings",
      detail:
        "Default-deny holds and no reachable path exposes confidential state, amounts, or metadata beyond what is explicitly and appropriately disclosed. Reads of confidential state are internal, Locked, owner-gated, or limited to a named party. Open functions that move value do not return, emit, or bridge that value, so amounts stay sealed.",
      sink: "",
      fix: "",
      rule: "",
    });
  }

  const focus = pickFocus(allFns);
  const observers = buildObservers(focus, findings, model);

  const summary: Summary = {
    high: findings.filter((f) => f.severity === Severity.High).length,
    medium: findings.filter((f) => f.severity === Severity.Medium).length,
    low: findings.filter((f) => f.severity === Severity.Low).length,
    info: findings.filter((f) => f.severity === Severity.Info).length,
    ok: findings.filter((f) => f.severity === Severity.Ok).length,
    contracts: model.contracts.length,
    functions: allFns.filter((f) => f.kind === "function").length,
    exposedFns: allFns.filter(
      (f) => f.reach === Reach.Anyone || f.reach === Reach.Grantees,
    ).length,
    stateVars: model.contracts.reduce((n, c) => n + c.vars.length, 0),
  };

  findings.sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity],
  );

  return {
    ok: true,
    model,
    findings,
    observers,
    focus: focus
      ? { contract: focus.contract, name: focus.name, sig: focus.sig }
      : null,
    summary,
    assumptions: ASSUMPTIONS,
  };
}

/**
 * Choose the function whose call best illustrates the contract's disclosure
 * surface for the observer view: an Open function that reveals state if one
 * exists, otherwise any Open function, otherwise a grant-holder-reachable
 * function, otherwise any externally visible function.
 */
export function pickFocus(fns: FunctionInfo[]): FunctionInfo | null {
  const openRevealing = fns.find(
    (f) =>
      f.reach === Reach.Anyone &&
      f.scan.returnsExprs.some((r) => r.taint === "state"),
  );
  if (openRevealing) {
    return openRevealing;
  }
  const anyOpen = fns.find(
    (f) => f.reach === Reach.Anyone && f.kind === "function",
  );
  if (anyOpen) {
    return anyOpen;
  }
  const anyGrantees = fns.find(
    (f) => f.reach === Reach.Grantees && f.kind === "function",
  );
  if (anyGrantees) {
    return anyGrantees;
  }
  return (
    fns.find(
      (f) =>
        f.kind === "function" &&
        f.visibility !== null &&
        f.visibility !== "internal" &&
        f.visibility !== "private",
    ) || null
  );
}

/**
 * Reconstruct what three observers learn from a representative call: the public
 * ledger (which sees only an opaque precompile invocation), an authorized
 * viewer (who sees the decrypted call and its state effects), and the set of
 * confidential values that leak more widely despite APS confidentiality.
 */
export function buildObservers(
  focus: FunctionInfo | null,
  findings: Finding[],
  _model: Model,
): Observers {
  const publicView = [
    "APS precompile call (opaque ciphertext calldata)",
    "Predefined gas cost",
    "Acknowledgement",
    "No return values, no results, no event logs",
  ];
  const authorized: string[] = [];
  if (focus) {
    const writes = focus.scan.writes;
    const reads = focus.scan.reads;
    authorized.push(
      `call ${focus.contract}.${focus.name}(${focus.params
        .map((p) => p.name || p.type)
        .join(", ")})`,
    );
    if (writes.length > 0) {
      authorized.push(`state written: ${writes.join(", ")}`);
    }
    if (reads.length > 0) {
      authorized.push(`state read: ${reads.join(", ")}`);
    }
    if (focus.scan.emits.length > 0) {
      authorized.push(
        `events: ${focus.scan.emits.map((e) => e.event).join(", ")}`,
      );
    }
    if (writes.length === 0 && reads.length === 0) {
      authorized.push("no confidential state touched");
    }
  } else {
    authorized.push(
      "decrypted call, state delta, and events (with the transaction hash and authorization)",
    );
  }
  const leaked: LeakLine[] = findings
    .filter(
      (f) => f.severity === Severity.High || f.severity === Severity.Medium,
    )
    .map((f) => ({ sev: f.severity, text: leakLine(f) }));
  return { public: publicView, authorized, leaked };
}

/** One-line summary of a leaking finding for the observer view. */
export function leakLine(f: Finding): string {
  switch (f.id) {
    case "APS-1":
      return `Anyone can call ${f.contract}.${f.fnName} and read confidential state`;
    case "APS-2":
      return `Event in ${f.fnName} carries a confidential amount to all transaction viewers`;
    case "APS-3":
      return `${f.fnName} bridges a confidential amount to the public EVM`;
    case "APS-4":
      return `Trustee added in ${f.fnName}; a third party can read confidential state`;
    case "APS-5":
      return `Public getter on ${f.fnName} makes the value readable by callers`;
    case "APS-10":
      return `${f.fnName} passes a confidential value to an external contract`;
    case "APS-12":
      return `Event ${f.fnName} indexes a confidential value into a queryable topic`;
    case "APS-14":
      return `${f.fnName} copies a confidential value into a public variable`;
    case "APS-T":
      return `Open forwarder ${f.fnName} re-exposes a trusted contract's state`;
    default:
      return `${f.title} (${f.contract}.${f.fnName})`;
  }
}
