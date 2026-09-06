/**
 * The analysis half of the AST front-end.
 *
 * It walks the syntax tree produced by {@link parseSolidity}, resolves each
 * contract's inherited members, tracks the flow of confidential values through
 * expressions, and applies the confidentiality rules — emitting findings with
 * the same identifiers and severities as the lexical engine. Because it works
 * from a real parse tree rather than text, its dataflow follows nested calls
 * and complex expressions exactly, and its inheritance is resolved rather than
 * flattened by hand.
 *
 * The rule identifiers are the same as the lexical engine's (documented in the
 * rule catalog), so a report reads identically whichever front-end produced it;
 * only the finding prose is phrased independently here.
 */

import { visit } from "@solidity-parser/parser";
import type {
  ASTNode,
  BaseASTNode,
  ContractDefinition,
  EventDefinition,
  FunctionCall,
  FunctionDefinition,
  StateVariableDeclaration,
} from "@solidity-parser/parser/dist/src/ast-types";
import {
  ASSUMPTIONS,
  type Finding,
  type Focus,
  leakLine,
  type Observers,
  Severity,
  type Summary,
  type Taint,
} from "../analysis/solidity";
import { type ApsPolicy, apsAnnotations, parseSolidity } from "./parse";

/** A function as the render layer needs it: signature, policy, and reachability. */
export interface AstFnView {
  kind: string;
  name: string;
  visibility: string;
  policy: string | null;
  reach: string;
  params: { type: string }[];
}

/** A contract and its functions, for the exposure surface. */
export interface AstContractView {
  name: string;
  fns: AstFnView[];
}

/** The parsed model the render layer consumes. */
export interface AstModel {
  contracts: AstContractView[];
}

/**
 * The result of an AST analysis. On success it carries the findings, a summary,
 * the assumptions, and — so the browser can render the same views as the
 * lexical engine — a model of the contracts, a three-observer view of a
 * representative call, and that focus function.
 */
export interface AstAnalysis {
  ok: boolean;
  error?: string;
  findings: Finding[];
  summary: Partial<Summary>;
  assumptions: readonly string[];
  model?: AstModel;
  observers?: Observers;
  focus?: Focus | null;
}

const ASSIGN_OPS = new Set([
  "=",
  "+=",
  "-=",
  "*=",
  "/=",
  "%=",
  "|=",
  "^=",
  "&=",
  "<<=",
  ">>=",
]);
const HASH_FNS = new Set(["keccak256", "sha256", "ripemd160", "sha3"]);
const TRUST_FNS = new Set([
  "addTrustee",
  "grantTrust",
  "addTrustedContract",
  "trust",
]);
const AMOUNT_RE =
  /amount|amt|balance|\bbal\b|nav|price|value|salary|deal|invoice|wage|\bfee\b|debt|principal|payment|deposit|withdraw|total|supply|shares?/i;
const AUDITOR_RE = /audit|regulator|compliance|examiner|supervisor/i;
const GLOBAL_BASES = new Set(["msg", "block", "tx", "abi"]);
const CAST_TYPES = new Set(["address", "payable"]);

function combine(a: Taint, b: Taint): Taint {
  if (a === "state" || b === "state") return "state";
  if (a === "param" || b === "param") return "param";
  return null;
}

/** Narrowing guards for the loosely-typed `subNodes`/`children` arrays. */
const isContract = (n: BaseASTNode): n is ContractDefinition =>
  n.type === "ContractDefinition";
const isFunction = (n: BaseASTNode): n is FunctionDefinition =>
  n.type === "FunctionDefinition";
const isStateVar = (n: BaseASTNode): n is StateVariableDeclaration =>
  n.type === "StateVariableDeclaration";
const isEvent = (n: BaseASTNode): n is EventDefinition =>
  n.type === "EventDefinition";

/** Source line of a node; `loc` is always present because we parse with loc. */
const lineOf = (n: { loc?: { start: { line: number } } }): number =>
  (n.loc as { start: { line: number } }).start.line;
/** Start offset of a node; `range` is always present because we parse with range. */
const rangeStart = (n: { range?: [number, number] }): number =>
  (n.range as [number, number])[0];

/** Confidentiality facts about one state variable. */
interface VarInfo {
  confidential: boolean;
  amountLike: boolean;
  isPublicOrClear: boolean;
  isImmutable: boolean;
}

/** A contract, its resolved members, and derived facts. */
interface Ctx {
  name: string;
  node: ContractDefinition;
  stateVars: Map<string, VarInfo>;
  events: Map<string, EventDefinition>;
  returnsState: Set<string>;
  returnsStateVars: Map<string, string[]>;
}

/** Whether a function call is a cryptographic hash, i.e. a commitment. */
function isHashCall(e: ASTNode): boolean {
  return (
    e.type === "FunctionCall" &&
    e.expression.type === "Identifier" &&
    HASH_FNS.has(e.expression.name)
  );
}

/** All identifier names mentioned in an expression subtree. */
function identNames(node: ASTNode | BaseASTNode): string[] {
  const names: string[] = [];
  visit(node as ASTNode, {
    Identifier(n) {
      names.push(n.name);
    },
  });
  return names;
}

/** A parameter's type rendered as a short string for the exposure surface. */
function paramType(tn: ASTNode): string {
  if (tn.type === "ElementaryTypeName") return tn.name;
  if (tn.type === "UserDefinedTypeName") return tn.namePath;
  return "";
}

export function analyzeContractAst(source: string): AstAnalysis {
  const { unit } = parseSolidity(source);
  if (unit === null) {
    return {
      ok: false,
      error: "Source could not be parsed.",
      findings: [],
      summary: {},
      assumptions: ASSUMPTIONS,
    };
  }

  const contracts: ContractDefinition[] = [];
  for (const child of unit.children) {
    if (isContract(child)) contracts.push(child);
  }
  if (contracts.length === 0) {
    return {
      ok: false,
      error: "No contract, interface, or library found in the source.",
      findings: [],
      summary: {},
      assumptions: ASSUMPTIONS,
    };
  }

  const policyAt = apsAnnotations(source);
  const byName = new Map<string, ContractDefinition>();
  for (const c of contracts) {
    if (!byName.has(c.name)) byName.set(c.name, c);
  }

  // Transitive base contracts of a contract (deepest first, cycle-guarded).
  const ancestorsOf = (c: ContractDefinition): ContractDefinition[] => {
    const out: ContractDefinition[] = [];
    const seen = new Set<string>([c.name]);
    const visitBases = (cur: ContractDefinition): void => {
      for (const b of cur.baseContracts) {
        const name = b.baseName.namePath;
        if (seen.has(name)) continue;
        const base = byName.get(name);
        if (base === undefined) continue;
        seen.add(name);
        out.push(base);
        visitBases(base);
      }
    };
    visitBases(c);
    return out;
  };

  const varInfo = (
    v: StateVariableDeclaration["variables"][number],
  ): VarInfo => {
    const vis = v.visibility;
    const isClear = policyAt(lineOf(v)) === "clear";
    return {
      confidential: !v.isDeclaredConst && !isClear,
      amountLike: AMOUNT_RE.test(String(v.name)),
      isPublicOrClear: vis === "public" || isClear,
      isImmutable: v.isImmutable === true,
    };
  };

  // Build the per-contract context, resolving inherited members.
  const ctxOf = (c: ContractDefinition): Ctx => {
    const chain = [...ancestorsOf(c)].reverse(); // bases first, then self overrides
    const stateVars = new Map<string, VarInfo>();
    const events = new Map<string, EventDefinition>();
    for (const src of [...chain, c]) {
      for (const s of src.subNodes) {
        if (isStateVar(s)) {
          for (const v of s.variables) {
            stateVars.set(v.name as string, varInfo(v));
          }
        } else if (isEvent(s)) {
          events.set(s.name, s);
        }
      }
    }
    return {
      name: c.name,
      node: c,
      stateVars,
      events,
      returnsState: new Set(),
      returnsStateVars: new Map(),
    };
  };

  const ctxs = contracts.map(ctxOf);
  const ctxByName = new Map(ctxs.map((x) => [x.name, x]));

  // Taint of an expression given the enclosing contract's state vars, the
  // function's parameter names, and the local-variable taint environment.
  const taintOf = (
    e: ASTNode | BaseASTNode | null | undefined,
    ctx: Ctx,
    params: Set<string>,
    env: Map<string, Taint>,
  ): Taint => {
    if (e == null) return null;
    const n = e as ASTNode;
    switch (n.type) {
      case "Identifier": {
        const sv = ctx.stateVars.get(n.name);
        if (sv !== undefined) return sv.confidential ? "state" : null;
        if (params.has(n.name)) return "param";
        return env.get(n.name) ?? null;
      }
      case "IndexAccess":
        return taintOf(n.base, ctx, params, env);
      case "MemberAccess": {
        if (
          n.expression.type === "Identifier" &&
          GLOBAL_BASES.has(n.expression.name)
        ) {
          return null;
        }
        return taintOf(n.expression, ctx, params, env);
      }
      case "BinaryOperation": {
        if (ASSIGN_OPS.has(n.operator))
          return taintOf(n.right, ctx, params, env);
        return combine(
          taintOf(n.left, ctx, params, env),
          taintOf(n.right, ctx, params, env),
        );
      }
      case "UnaryOperation":
        return taintOf(n.subExpression, ctx, params, env);
      case "TupleExpression": {
        let t: Taint = null;
        for (const c of n.components)
          t = combine(t, taintOf(c, ctx, params, env));
        return t;
      }
      case "FunctionCall": {
        if (isHashCall(n)) return null; // a commitment hides its pre-image
        const callee = n.expression;
        if (callee.type === "Identifier" && CAST_TYPES.has(callee.name)) {
          return taintOf(n.arguments[0], ctx, params, env);
        }
        if (callee.type === "ElementaryTypeName") {
          return taintOf(n.arguments[0], ctx, params, env);
        }
        if (
          callee.type === "MemberAccess" &&
          callee.expression.type === "Identifier" &&
          callee.expression.name === "abi"
        ) {
          let t: Taint = null;
          for (const a of n.arguments)
            t = combine(t, taintOf(a, ctx, params, env));
          return t;
        }
        return null; // an ordinary call's result is not assumed confidential
      }
      default:
        return null;
    }
  };

  // Whether an expression is a hash of a confidential value (a commitment).
  const isCommitmentOf = (
    e: ASTNode | BaseASTNode,
    ctx: Ctx,
    params: Set<string>,
    env: Map<string, Taint>,
  ): boolean => {
    const n = e as ASTNode;
    if (!isHashCall(n) || n.type !== "FunctionCall") return false;
    let t: Taint = null;
    for (const a of n.arguments) t = combine(t, taintOf(a, ctx, params, env));
    return t !== null;
  };

  const paramNames = (fn: FunctionDefinition): Set<string> => {
    const s = new Set<string>();
    for (const p of fn.parameters) {
      if (p.name !== null) s.add(p.name);
    }
    return s;
  };

  // Collect the return expressions, emit statements, calls, and assignments in
  // a function body, in source order, using the parser's traversal.
  interface Collected {
    returns: ASTNode[];
    emits: FunctionCall[];
    calls: FunctionCall[];
    ordered: { pos: number; node: ASTNode }[];
  }
  const collect = (body: ASTNode | null): Collected => {
    const c: Collected = { returns: [], emits: [], calls: [], ordered: [] };
    if (body === null) return c;
    visit(body, {
      ReturnStatement(n) {
        if (n.expression !== null) c.returns.push(n.expression);
      },
      EmitStatement(n) {
        c.emits.push(n.eventCall);
      },
      FunctionCall(n) {
        c.calls.push(n);
      },
      VariableDeclarationStatement(n) {
        c.ordered.push({ pos: rangeStart(n), node: n });
      },
      BinaryOperation(n) {
        if (ASSIGN_OPS.has(n.operator))
          c.ordered.push({ pos: rangeStart(n), node: n });
      },
    });
    c.ordered.sort((a, b) => a.pos - b.pos);
    // An emit's event-call is also visited as a FunctionCall; drop it so an
    // event emission is never mistaken for an external contract call.
    c.calls = c.calls.filter((call) => !c.emits.includes(call));
    return c;
  };

  // Build the local-variable taint environment by a forward fixpoint over the
  // ordered declarations and assignments.
  const buildEnv = (
    ordered: { pos: number; node: ASTNode }[],
    ctx: Ctx,
    params: Set<string>,
  ): Map<string, Taint> => {
    const env = new Map<string, Taint>();
    for (let pass = 0; pass < 2; pass++) {
      for (const { node } of ordered) {
        if (node.type === "VariableDeclarationStatement") {
          const target = node.variables[0] as
            | { name?: string | null }
            | null
            | undefined;
          if (target?.name != null) {
            env.set(target.name, taintOf(node.initialValue, ctx, params, env));
          }
        } else if (
          node.type === "BinaryOperation" &&
          node.left.type === "Identifier"
        ) {
          env.set(node.left.name, taintOf(node.right, ctx, params, env));
        }
      }
    }
    return env;
  };

  // The keys a function gates on its caller, e.g. require(msg.sender == who).
  const gatedKeys = (calls: ASTNode[]): Set<string> => {
    const keys = new Set<string>();
    for (const call of calls) {
      if (
        call.type !== "FunctionCall" ||
        call.expression.type !== "Identifier" ||
        call.expression.name !== "require"
      ) {
        continue;
      }
      const cond = call.arguments[0];
      if (
        cond === undefined ||
        cond.type !== "BinaryOperation" ||
        cond.operator !== "=="
      ) {
        continue;
      }
      const sides = [cond.left, cond.right];
      const isSender = (n: ASTNode): boolean =>
        n.type === "MemberAccess" &&
        n.expression.type === "Identifier" &&
        n.expression.name === "msg" &&
        n.memberName === "sender";
      if (isSender(sides[0]) && sides[1].type === "Identifier")
        keys.add(sides[1].name);
      if (isSender(sides[1]) && sides[0].type === "Identifier")
        keys.add(sides[0].name);
    }
    return keys;
  };

  // Whether a return expression reads its own account, i.e. mapping[msg.sender]
  // or mapping[k] where the function requires msg.sender == k.
  const isOwnerScoped = (e: ASTNode, keys: Set<string>): boolean => {
    if (e.type !== "IndexAccess") return false;
    const idx = e.index;
    if (
      idx.type === "MemberAccess" &&
      idx.expression.type === "Identifier" &&
      idx.expression.name === "msg" &&
      idx.memberName === "sender"
    ) {
      return true;
    }
    return idx.type === "Identifier" && keys.has(idx.name);
  };

  // Pass A: which functions return confidential state (for transitive analysis).
  const returnExprs = (fn: FunctionDefinition): ASTNode[] =>
    collect(fn.body).returns;
  for (const ctx of ctxs) {
    for (const s of ctx.node.subNodes) {
      if (!isFunction(s)) continue;
      const params = paramNames(s);
      if (s.name === null) continue;
      for (const r of returnExprs(s)) {
        if (taintOf(r, ctx, params, new Map()) === "state") {
          ctx.returnsState.add(s.name);
          const refs = identNames(r).filter(
            (n) => ctx.stateVars.get(n)?.confidential,
          );
          const prev = ctx.returnsStateVars.get(s.name) ?? [];
          ctx.returnsStateVars.set(s.name, [...new Set([...prev, ...refs])]);
        }
      }
    }
  }

  const findings: Finding[] = [];
  const push = (f: Finding): void => {
    findings.push(f);
  };

  // The contract a member-call is made on, if it resolves to a known contract.
  const calleeContract = (
    base: ASTNode,
    fnParams: Map<string, string>,
  ): Ctx | null => {
    if (base.type === "FunctionCall" && base.expression.type === "Identifier") {
      return ctxByName.get(base.expression.name) ?? null; // C(addr).f()
    }
    if (base.type === "Identifier") {
      const typeName = fnParams.get(base.name);
      if (typeName !== undefined) return ctxByName.get(typeName) ?? null;
    }
    return null;
  };

  // Pass B: analyze each function of each contract and emit findings.
  for (const ctx of ctxs) {
    for (const s of ctx.node.subNodes) {
      // APS-5 / APS-7: exposure of confidential state through a variable.
      if (isStateVar(s)) {
        for (const v of s.variables) {
          const info = varInfo(v);
          const vname = v.name as string;
          if (info.confidential && v.visibility === "public") {
            push({
              id: "APS-5",
              severity: info.amountLike ? Severity.Medium : Severity.Low,
              contract: ctx.name,
              fnName: vname,
              line: lineOf(v),
              title: "Public state variable auto-generates a getter",
              detail: `${ctx.name}.${vname} is public, so Solidity generates a getter that exposes confidential storage to any caller.`,
              sink: "implicit getter",
              fix: "Make the variable private or internal; expose it through a policy-gated function if a read is needed.",
              rule: "APS-5",
              refVars: [vname],
            });
          }
          if (info.confidential && info.isImmutable && info.amountLike) {
            push({
              id: "APS-7",
              severity: Severity.Low,
              contract: ctx.name,
              fnName: vname,
              line: lineOf(v),
              title: "Confidential value in immutable or constant",
              detail: `${ctx.name}.${vname} is immutable; immutables may be stored in public bytecode. Confirm APS keeps it confidential.`,
              sink: "bytecode",
              fix: "Store confidential values in regular storage and verify against current APS documentation.",
              rule: "APS-7",
              refVars: [vname],
            });
          }
        }
        continue;
      }
      if (!isFunction(s) || s.body === null) continue;

      const fn = s;
      const policy: ApsPolicy | null = policyAt(lineOf(fn));
      const vis = fn.visibility;
      const externalish =
        vis === "external" || vis === "public" || vis === "default";
      const special = fn.isConstructor || fn.isFallback || fn.isReceiveEther;
      const anyone = externalish && policy === "Open";
      const grantHolders = externalish && policy === "Restricted";
      const reachable = anyone || grantHolders;
      const fnName = fn.name ?? (fn.isConstructor ? "constructor" : "fallback");

      // APS-6: an external function with no access policy (unreachable, but likely unintended).
      if (externalish && !special && policy === null) {
        push({
          id: "APS-6",
          severity: Severity.Info,
          contract: ctx.name,
          fnName,
          line: lineOf(fn),
          title: "External function has no access policy",
          detail: `${ctx.name}.${fnName} is externally visible but carries no APS access policy; under default-deny it is unreachable.`,
          sink: "unset policy",
          fix: "Add an explicit @aps:Open, @aps:Restricted, or @aps:Locked annotation to state intent.",
          rule: "APS-6",
        });
      }

      const params = paramNames(fn);
      const paramTypes = new Map<string, string>();
      for (const p of fn.parameters) {
        if (p.name !== null && p.typeName?.type === "UserDefinedTypeName") {
          paramTypes.set(p.name, p.typeName.namePath);
        }
      }
      const col = collect(fn.body);
      const env = buildEnv(col.ordered, ctx, params);
      const keys = gatedKeys(col.calls);

      // Returns.
      for (const r of col.returns) {
        const t = taintOf(r, ctx, params, env);
        const refs = identNames(r).filter(
          (n) => ctx.stateVars.get(n)?.confidential,
        );
        if (t === "state") {
          if (isOwnerScoped(r, keys)) {
            push({
              id: "APS-OK",
              severity: Severity.Ok,
              contract: ctx.name,
              fnName,
              line: lineOf(fn),
              title: "Owner-gated confidential read",
              detail: `${ctx.name}.${fnName} returns confidential state scoped to the caller's own entry.`,
              sink: "return",
              fix: "No action needed.",
              rule: "APS-OK",
              refVars: refs,
            });
          } else if (anyone) {
            push({
              id: "APS-1",
              severity: Severity.High,
              contract: ctx.name,
              fnName,
              line: lineOf(fn),
              title: "Open function returns confidential state",
              detail: `${ctx.name}.${fnName} is Open, so any caller may invoke it, and it returns confidential state${refs.length > 0 ? ` (${refs.join(", ")})` : ""}.`,
              sink: "return",
              fix: "Make the function Restricted, or gate it with require(msg.sender == <key>) so a caller reads only its own entry.",
              rule: "APS-1",
              refVars: refs,
            });
          } else if (grantHolders) {
            push({
              id: "APS-9",
              severity: Severity.Info,
              contract: ctx.name,
              fnName,
              line: lineOf(fn),
              title:
                "Restricted function returns confidential state to grant-holders",
              detail: `${ctx.name}.${fnName} is Restricted and returns confidential state; every grant-holder can read it.`,
              sink: "return",
              fix: "Keep the grant list minimal, or add a per-record check such as require(msg.sender == <key>).",
              rule: "APS-9",
              refVars: refs,
            });
          }
        } else if (t === "param" && anyone) {
          push({
            id: "APS-8",
            severity: Severity.Low,
            contract: ctx.name,
            fnName,
            line: lineOf(fn),
            title: "Open function echoes a calldata argument",
            detail: `${ctx.name}.${fnName} is Open and returns a value derived from its arguments; calldata is confidential in APS.`,
            sink: "return",
            fix: "Avoid returning sensitive inputs from Open functions, or restrict the function.",
            rule: "APS-8",
          });
        }
      }

      // Emits.
      if (reachable) {
        for (const call of col.emits) {
          const evName =
            call.expression.type === "Identifier" ? call.expression.name : "";
          const ev = ctx.events.get(evName);
          call.arguments.forEach((arg, i) => {
            const commit = isCommitmentOf(arg, ctx, params, env);
            if (commit) {
              push({
                id: "APS-H",
                severity: Severity.Info,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Confidential value disclosed as a commitment",
                detail: `${ctx.name}.${fnName} emits a hash of a confidential value; a commitment is only as strong as the entropy of its pre-image.`,
                sink: "event log",
                fix: "Salt low-entropy pre-images so the commitment cannot be brute-forced.",
                rule: "APS-H",
              });
              return;
            }
            const t = taintOf(arg, ctx, params, env);
            if (t === null) return;
            const evParam = ev?.parameters[i];
            const indexed = evParam?.isIndexed === true;
            const amountLike =
              (evParam?.name != null && AMOUNT_RE.test(evParam.name)) ||
              identNames(arg).some((n) => AMOUNT_RE.test(n));
            if (t === "state" && indexed) {
              push({
                id: "APS-12",
                severity: Severity.Medium,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Confidential value indexed in an event",
                detail: `${ctx.name}.${fnName} emits a confidential value as an indexed topic, making it queryable by authorized viewers.`,
                sink: "event topic",
                fix: "Do not index confidential values; index a commitment if filtering is needed.",
                rule: "APS-12",
                refVars: [...new Set(identNames(arg))],
              });
            } else if (amountLike) {
              push({
                id: "APS-2",
                severity: Severity.Medium,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Confidential value emitted in an event",
                detail: `${ctx.name}.${fnName} emits a confidential amount, disclosing it to every party authorized to view the transaction.`,
                sink: "event log",
                fix: "Omit the value or emit a commitment; scope who can view the transaction's results.",
                rule: "APS-2",
                refVars: [...new Set(identNames(arg))],
              });
            } else {
              push({
                id: "APS-2b",
                severity: Severity.Info,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Event reveals transaction metadata",
                detail: `${ctx.name}.${fnName} emits a confidential identifier or relationship; the counterparty and timing are visible to authorized viewers.`,
                sink: "event log",
                fix: "Emit only what observers need; consider a commitment rather than raw identifiers.",
                rule: "APS-2b",
              });
            }
          });
        }
      }

      // Calls: bridges, trust grants, external hand-offs, and transitive exposure.
      if (reachable) {
        for (const call of col.calls) {
          const callee = call.expression;
          const stateArgs = [
            ...new Set(
              call.arguments
                .filter((a) => taintOf(a, ctx, params, env) === "state")
                .flatMap((a) => identNames(a)),
            ),
          ];

          if (callee.type === "Identifier" && TRUST_FNS.has(callee.name)) {
            const arg = call.arguments[0];
            const argName =
              arg !== undefined && arg.type === "Identifier" ? arg.name : "";
            const auditor = AUDITOR_RE.test(argName);
            push(
              auditor
                ? {
                    id: "APS-4ok",
                    severity: Severity.Info,
                    contract: ctx.name,
                    fnName,
                    line: lineOf(fn),
                    title: "Trust granted to a compliance party",
                    detail: `${ctx.name}.${fnName} grants trust to ${argName}, a named compliance party — a deliberate, revocable disclosure.`,
                    sink: "trust grant",
                    fix: "Prefer function-scoped grants over blanket trust, and keep the grant revocable.",
                    rule: "APS-4ok",
                  }
                : {
                    id: "APS-4",
                    severity: Severity.High,
                    contract: ctx.name,
                    fnName,
                    line: lineOf(fn),
                    title: "Over-broad trust grant",
                    detail: `${ctx.name}.${fnName} grants trust to ${argName || "a caller-supplied contract"}; a trustee gains introspection and reaches Restricted entrypoints.`,
                    sink: "trust grant",
                    fix: "Grant trust only to reviewed bytecode; prefer function-scoped grants and revoke promptly.",
                    rule: "APS-4",
                  },
            );
            continue;
          }

          if (callee.type === "MemberAccess") {
            if (
              callee.expression.type === "Identifier" &&
              GLOBAL_BASES.has(callee.expression.name)
            ) {
              continue;
            }
            const member = callee.memberName;
            if (/^bridge/i.test(member) && stateArgs.length > 0) {
              push({
                id: "APS-3",
                severity: Severity.High,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Confidential value bridged to the public EVM",
                detail: `${ctx.name}.${fnName} bridges a confidential value (${stateArgs.join(", ")}) to the public chain, where it becomes public by construction.`,
                sink: "public EVM",
                fix: "Bridge an aggregate or a zero-knowledge attestation rather than the raw value.",
                rule: "APS-3",
                refVars: stateArgs,
              });
              continue;
            }
            const target = calleeContract(callee.expression, paramTypes);
            if (target?.returnsState.has(member) && anyone) {
              push({
                id: "APS-T",
                severity: Severity.Medium,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Transitive exposure through a trusted contract",
                detail: `${ctx.name}.${fnName} is Open and forwards to ${target.name}.${member}, which returns confidential state; the trust boundary is only as tight as this forwarder.`,
                sink: "transitive",
                fix: "Do not expose an Open forwarder to a trusted contract; restrict it or expose a purpose-built function.",
                rule: "APS-T",
                refVars: target.returnsStateVars.get(member),
              });
            } else if (stateArgs.length > 0) {
              push({
                id: "APS-10",
                severity: Severity.High,
                contract: ctx.name,
                fnName,
                line: lineOf(fn),
                title: "Confidential value passed to an external contract",
                detail: `${ctx.name}.${fnName} passes confidential state (${stateArgs.join(", ")}) to an external contract, outside the boundary.`,
                sink: "external call",
                fix: "Keep confidential values inside the boundary; pass a commitment or the minimum needed.",
                rule: "APS-10",
                refVars: stateArgs,
              });
            }
          }
        }
      }

      // Assignments into a public or cleared variable.
      for (const { node } of col.ordered) {
        if (node.type !== "BinaryOperation" || !ASSIGN_OPS.has(node.operator))
          continue;
        const lhs = node.left;
        const targetName =
          lhs.type === "Identifier"
            ? lhs.name
            : lhs.type === "IndexAccess" && lhs.base.type === "Identifier"
              ? lhs.base.name
              : "";
        const target = ctx.stateVars.get(targetName);
        if (
          target?.isPublicOrClear &&
          taintOf(node.right, ctx, params, env) !== null
        ) {
          push({
            id: "APS-14",
            severity: Severity.High,
            contract: ctx.name,
            fnName,
            line: lineOf(fn),
            title: "Confidential value copied into a public variable",
            detail: `${ctx.name}.${fnName} assigns a confidential value into ${targetName}, which is exposed through its getter.`,
            sink: "public variable",
            fix: "Keep the destination private, or do not copy confidential state into it.",
            rule: "APS-14",
            refVars: [targetName],
          });
        }
      }
    }
  }

  const count = (sev: Severity): number =>
    findings.filter((f) => f.severity === sev).length;
  const high = count(Severity.High);
  const medium = count(Severity.Medium);
  if (high === 0 && medium === 0) {
    push({
      id: "APS-CLEAN",
      severity: Severity.Ok,
      contract: contracts[0].name,
      fnName: "",
      line: 0,
      title: "No confidentiality findings",
      detail:
        "No reachable path exposes a confidential value beyond appropriate disclosure. This models the published specification and is an aid to review, not a guarantee.",
      sink: "none",
      fix: "No action needed.",
      rule: "APS-CLEAN",
    });
  }

  let functions = 0;
  let exposedFns = 0;
  let stateVars = 0;
  for (const ctx of ctxs) {
    for (const s of ctx.node.subNodes) {
      if (isStateVar(s)) {
        stateVars += s.variables.length;
      } else if (isFunction(s)) {
        functions++;
        const pol = policyAt(lineOf(s));
        const vis = s.visibility;
        const externalish =
          vis === "external" || vis === "public" || vis === "default";
        if (externalish && (pol === "Open" || pol === "Restricted"))
          exposedFns++;
      }
    }
  }

  // Build the browser-facing model, then a representative call and the
  // three-observer view of it, so the in-browser verifier renders from this
  // engine exactly as it did from the lexical one.
  interface Focusable {
    contract: string;
    name: string;
    kind: string;
    visibility: string;
    reach: string;
    returnsState: boolean;
    params: { name: string; type: string }[];
    writes: string[];
    reads: string[];
    emits: string[];
  }
  const modelContracts: AstContractView[] = [];
  const focusable: Focusable[] = [];
  for (const ctx of ctxs) {
    const fns: AstFnView[] = [];
    for (const s of ctx.node.subNodes) {
      if (!isFunction(s)) continue;
      const kind = s.isConstructor
        ? "constructor"
        : s.isReceiveEther
          ? "receive"
          : s.isFallback
            ? "fallback"
            : "function";
      const name = s.name ?? kind;
      const vis = s.visibility as string;
      const pol = policyAt(lineOf(s));
      const policy =
        pol === "Open"
          ? "open"
          : pol === "Restricted"
            ? "restricted"
            : pol === "Locked"
              ? "locked"
              : null;
      const reach =
        vis === "internal" || vis === "private"
          ? "unset"
          : pol === "Open"
            ? "anyone"
            : pol === "Restricted"
              ? "grantees"
              : pol === "Locked"
                ? "nobody"
                : "unset";
      const params = s.parameters.map((prm) => ({
        name: prm.name ?? "",
        type: paramType(prm.typeName as ASTNode),
      }));
      fns.push({
        kind,
        name,
        visibility: vis,
        policy,
        reach,
        params: params.map((prm) => ({ type: prm.type })),
      });
      const col = collect(s.body);
      const writes = [
        ...new Set(
          col.ordered.flatMap((o) => {
            const n = o.node;
            if (n.type !== "BinaryOperation" || !ASSIGN_OPS.has(n.operator))
              return [];
            const lhs = n.left;
            const nm =
              lhs.type === "Identifier"
                ? lhs.name
                : lhs.type === "IndexAccess" && lhs.base.type === "Identifier"
                  ? lhs.base.name
                  : "";
            return ctx.stateVars.has(nm) ? [nm] : [];
          }),
        ),
      ];
      const emits = [
        ...new Set(
          col.emits
            .map((e) =>
              e.type === "FunctionCall" && e.expression.type === "Identifier"
                ? e.expression.name
                : "",
            )
            .filter((n) => n !== ""),
        ),
      ];
      const reads =
        s.body === null
          ? []
          : [
              ...new Set(
                identNames(s.body).filter((n) => ctx.stateVars.has(n)),
              ),
            ];
      focusable.push({
        contract: ctx.name,
        name,
        kind,
        visibility: vis,
        reach,
        returnsState: ctx.returnsState.has(name),
        params,
        writes,
        reads,
        emits,
      });
    }
    modelContracts.push({ name: ctx.name, fns });
  }

  const focusFn =
    focusable.find((f) => f.reach === "anyone" && f.returnsState) ??
    focusable.find((f) => f.reach === "anyone" && f.kind === "function") ??
    focusable.find((f) => f.reach === "grantees" && f.kind === "function") ??
    focusable.find(
      (f) =>
        f.kind === "function" &&
        f.visibility !== "internal" &&
        f.visibility !== "private",
    ) ??
    null;

  const focus: Focus | null = focusFn
    ? {
        contract: focusFn.contract,
        name: focusFn.name,
        sig: `${focusFn.name}(${focusFn.params.map((prm) => prm.type).join(",")})`,
      }
    : null;

  const authorized: string[] = [];
  if (focusFn) {
    authorized.push(
      `call ${focusFn.contract}.${focusFn.name}(${focusFn.params
        .map((prm) => prm.name || prm.type)
        .join(", ")})`,
    );
    if (focusFn.writes.length > 0)
      authorized.push(`state written: ${focusFn.writes.join(", ")}`);
    if (focusFn.reads.length > 0)
      authorized.push(`state read: ${focusFn.reads.join(", ")}`);
    if (focusFn.emits.length > 0)
      authorized.push(`events: ${focusFn.emits.join(", ")}`);
    if (focusFn.writes.length === 0 && focusFn.reads.length === 0)
      authorized.push("no confidential state touched");
  } else {
    authorized.push(
      "decrypted call, state delta, and events (with the transaction hash and authorization)",
    );
  }
  const observers: Observers = {
    public: [
      "APS precompile call (opaque ciphertext calldata)",
      "Predefined gas cost",
      "Acknowledgement",
      "No return values, no results, no event logs",
    ],
    authorized,
    leaked: findings
      .filter(
        (f) => f.severity === Severity.High || f.severity === Severity.Medium,
      )
      .map((f) => ({ sev: f.severity, text: leakLine(f) })),
  };

  const summary: Partial<Summary> = {
    high,
    medium,
    low: count(Severity.Low),
    info: count(Severity.Info),
    ok: count(Severity.Ok),
    contracts: contracts.length,
    functions,
    exposedFns,
    stateVars,
  };

  return {
    ok: true,
    findings,
    summary,
    assumptions: ASSUMPTIONS,
    model: { contracts: modelContracts },
    observers,
    focus,
  };
}
