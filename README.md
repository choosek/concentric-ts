# concentric-ts

[![npm](https://badge.fury.io/js/@choosek%2Fconcentric.svg)](https://www.npmjs.com/package/@choosek/concentric)
[![lint-check-test-cover](https://github.com/choosek/concentric-ts/actions/workflows/lint-check-test-cover.yaml/badge.svg)](https://github.com/choosek/concentric-ts/actions)
[![coveralls](https://coveralls.io/repos/github/choosek/concentric-ts/badge.svg?branch=main)](https://coveralls.io/github/choosek/concentric-ts)

Library for static confidentiality analysis of [Solidity](https://soliditylang.org/) contracts targeted at the [Arc Privacy Sector (APS)](https://docs.arc.io/arc/concepts/opt-in-privacy), [Circle](https://www.circle.com/)'s opt-in confidential execution environment on the [Arc](https://www.arc.network/) L1. The library automates the analysis of the boundary between what a contract keeps confidential and what it discloses.

## Purpose

In APS, contract storage is confidential by default and exposure is opt-in, declared per function through an access policy. Confidentiality is therefore not a property of a contract in isolation but of the *boundary* its policies draw: the same state that is sealed to one caller is legible to another, and a single unguarded return, event, or bridge can move a value from one side of the boundary to the other. This library reads a contract and reconstructs that boundary: given the source and the access policy attached to each function, it determines what confidential state an external party can learn and through which path.

The analysis is a pure, deterministic function of the source supplied as a string. It performs no network access, no compilation, and no signing; it reads Solidity, models the flow of confidential values through it, and returns a plain data structure. It ships two interchangeable front-ends over one rule set: an **AST front-end** (the default), which parses with a real Solidity grammar (the vetted [`@solidity-parser/parser`](https://github.com/solidity-parser/parser)) for precise dataflow and inheritance, and a dependency-free **lexical engine**, which reads the source structurally and serves as an automatic fallback when a source cannot be parsed. `analyzeProject` selects the AST front-end unless given `{ frontend: "lexical" }`. What it computes is determined entirely by the [published APS specification](https://docs.arc.io/arc/concepts/opt-in-privacy): the assumptions on which every finding rests are enumerated in `ASSUMPTIONS` and returned with each analysis, so a consumer can see exactly which properties of the specification a result depends on. The library models the specification rather than the live protocol, and it reasons about application-level disclosure — the paths a contract's own code opens — not the security of the enclaves or the cryptography beneath them.

### Confidentiality Boundary

APS makes storage confidential and exposure opt-in, so the analysis is organized around the ways a value crosses from the confidential side of the boundary to a more public one. The [public ledger](https://docs.arc.io/arc/concepts/opt-in-privacy) observes only that a precompile call occurred, a predefined gas cost, and an acknowledgement. It never observes a return value, a result, or a log. A confidential value is therefore *exposed* not when it is used but when it reaches one of a small number of surfaces: the return value of a function some caller can reach, an emitted event (retrievable by every party authorized to view the transaction), a bridge to the public EVM, or an argument handed to a contract outside the boundary. Each surface is legible to a different audience, and the severity a value's escape carries is a function of how broad that audience is.

### Reachability

Every external or public function carries an APS access policy that fixes the set of callers able to reach it: `Open` (any caller), `Restricted` (holders of a grant), or `Locked` (no caller). A function with no policy is treated as *unset* — under [default-deny](https://en.wikipedia.org/wiki/Fail-safe) it is unreachable by external callers until a policy is configured, which is safe but is frequently a mistake. The reachability of a function is the first determinant of whether a value it exposes has escaped: an `Open` getter over confidential balances is world-readable, whereas the same getter behind an owner check discloses to each caller only their own entry. The analyzer records reachability from a function's visibility and its policy, and a policy is expressed in the source as an annotation comment — `// @aps:Open`, `// @aps:Restricted`, or `// @aps:Locked` — preceding the function; a `// @aps:clear` annotation on a state variable marks a deliberate, acknowledged disclosure so that it is not reported.

### Information Flow

Whether a value that reaches a surface is *confidential* is determined by a [taint analysis](https://en.wikipedia.org/wiki/Taint_checking). Confidential storage and confidential calldata are the two taint sources; a local variable is tainted by a fixpoint over its assignments, so that a value copied from confidential state into a local is tracked to wherever the local is subsequently used. A return, event, bridge, or external call is a sink, and each is reported together with the taint that reaches it. A value disclosed only through a cryptographic hash (*i.e.*, a [commitment](https://en.wikipedia.org/wiki/Commitment_scheme)) is recognized as such and is not reported as a leak of the value, though the analysis notes that the disclosure is a commitment and is only as strong as the entropy of its pre-image.

### Trust

A contract may extend a [trust domain](https://docs.arc.io/arc/concepts/opt-in-privacy) to a counterparty through `addTrustee`, which grants that counterparty introspection — `BALANCE`, `EXTCODEHASH`, and `EXTCODESIZE` return non-zero to a trustee — and the ability to reach the contract's `Restricted` entrypoints. Trust is powerful, unidirectional, and revocable, and it is *transitive*: it extends through whatever the trustee re-exposes. A blanket grant to an arbitrary third-party contract is therefore rarely appropriate, whereas a grant to a named compliance party is a deliberate, policy-driven disclosure; the analysis distinguishes the two and reports an `Open` forwarder behind a trust boundary as re-exposing the trusted contract's state to any caller.

### Rules

The rules below are each applied to the reconstructed model. Every rule is a pure predicate over a function, a variable, or an event, and each finding carries a severity, the confidential values it concerns, and a suggested remediation.

| Rule      | Severity        | Condition                                                                                      |
|-----------|-----------------|------------------------------------------------------------------------------------------------|
| APS-1     | high            | An `Open` function returns confidential state.                                                 |
| APS-2     | high/medium     | A confidential value or amount is emitted in an event.                                         |
| APS-2b    | info            | An event reveals transaction metadata (a counterparty or timing) but no amount.                |
| APS-3     | high            | A confidential value is bridged to the public EVM.                                             |
| APS-4     | high            | Trust is granted to an arbitrary third party.                                                  |
| APS-4ok   | info            | Trust is granted to a named compliance party.                                                  |
| APS-5     | medium/low      | A public state variable auto-generates an implicit getter over confidential storage.           |
| APS-6     | info            | An externally visible function carries no access policy and is unreachable under default-deny. |
| APS-7     | low             | A confidential value is placed in an immutable or constant, which may live in bytecode.        |
| APS-8     | low             | An `Open` function echoes a confidential calldata argument.                                    |
| APS-9     | info            | A `Restricted` function returns confidential state to every grant-holder.                      |
| APS-10    | high            | A confidential value is passed as an argument to a contract outside the boundary.              |
| APS-12    | medium          | A confidential value is `indexed` in an event, placing it in a queryable log topic.            |
| APS-14    | high            | A confidential value is copied into a public or cleared variable.                              |
| APS-T     | medium          | An `Open` forwarder re-exposes a trusted contract's confidential state.                        |
| APS-H     | info            | A confidential value is disclosed as a commitment (a hash) rather than in the clear.           |
| APS-OK    | ok              | A confidential read is correctly gated so each caller reads only their own entry.              |
| APS-CLEAN | ok              | No reachable path exposes a confidential value beyond what is appropriately disclosed.         |

## Package Installation and Usage

The package can be installed using [pnpm](https://pnpm.io/):
```shell
corepack enable
pnpm install
```
The library can be imported in the usual way:
```ts
import * as concentric from "@choosek/concentric";
```
The library exposes `analyzeContractAst` (the default AST front-end) and `analyzeContract` (the lexical engine); each takes a contract expressed as Solidity source and returns a plain analysis object. Its one runtime dependency is the Solidity grammar the AST front-end parses with. The enumerations, interfaces, and the individual parsing and scanning functions are exported alongside the entry points so that a single stage may be driven or inspected on its own.

`analyzeContract(source)` parses the source into a model of its contracts, functions, state variables, and events; derives each function's reachability and information flow; and applies the rules described above. It returns a discriminated result: on success, the parsed `model`, the `findings` ordered from most to least severe, an `observers` view of a representative call, the `focus` function that view describes, a headline `summary`, and the `assumptions`; when the source contains no contract, an error result carrying a reason. No exception is thrown for malformed input.

### Examples

The example below analyzes a confidential salary token whose balance getter is declared `Open`, so that any caller may read any account's confidential balance:
```ts
import * as concentric from "@choosek/concentric";

const source = `
pragma solidity ^0.8.24;
contract ConfidentialPayroll {
    mapping(address => uint256) private balances; // confidential
    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}`;

const result = concentric.analyzeContract(source);
if (result.ok) {
  console.log(result.summary.high);         // 1
  console.log(result.findings[0].id);       // "APS-1"
  console.log(result.findings[0].severity); // "high"
}
```

The example below contrasts a value disclosed in the clear with the same value disclosed as a commitment. The first emits a confidential amount and is reported; the second emits a hash of it and is recognized as a commitment rather than a leak:
```ts
const leaks = concentric.analyzeContract(`
pragma solidity ^0.8.24;
contract A {
    uint256 private nav;
    event E(uint256 v);
    /// @aps:Open
    function f() external { emit E(nav); } // APS-2, high
}`);

const commits = concentric.analyzeContract(`
pragma solidity ^0.8.24;
contract B {
    uint256 private nav;
    event E(bytes32 c);
    /// @aps:Restricted
    function f() external { emit E(keccak256(abi.encode(nav))); } // APS-H, info
}`);
```

The example below reads the observer view, which reconstructs what each of three parties learns from a representative call — the public ledger, an authorized viewer, and the set of values that leak more widely than intended:
```ts
const result = concentric.analyzeContract(source);
if (result.ok) {
  console.log(result.observers.public);     // the opaque precompile view
  console.log(result.observers.authorized); // the decrypted call and its effects
  console.log(result.observers.leaked);     // one line per high/medium finding
}
```

### Project Analysis

A real contract is rarely a single self-contained file. `analyzeProject` takes an array of `{ path, content }` sources, links them into one model — resolving inheritance across files and flattening each contract's transitively-inherited members into it — and runs the same analysis, so an inherited getter or a function that reads inherited confidential state is analyzed in the context that actually deploys it. The flattening is lexical, and a line map is retained, so every finding is reported at its true `file` and `line` rather than at a position in the linked text.

```ts
import * as concentric from "@choosek/concentric";

const base = `pragma solidity ^0.8.24;
contract ERC20Confidential { mapping(address => uint256) internal _balances; }`;

const token = `pragma solidity ^0.8.24;
import "./base.sol";
contract PayrollToken is ERC20Confidential {
    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return _balances[who]; // reads confidential state declared in base.sol
    }
}`;

const result = concentric.analyzeProject([
  { path: "base.sol", content: base },
  { path: "token.sol", content: token },
]);
console.log(result.findings[0].id);   // "APS-1"
console.log(result.findings[0].file); // "token.sol" — the getter's true location
console.log(result.project.edges);    // [["PayrollToken", "ERC20Confidential"]]
```

Inheritance cycles and unresolved bases are recorded in `result.project.errors` rather than throwing or looping. `linkProject` is exported on its own for inspecting the combined source and its line map.

### From Build Output (Foundry and Hardhat)

`analyzeBuildInfo` reads a project straight from its solc build-info — the Standard-JSON input `forge build` writes under `out/build-info/` and Hardhat writes under `artifacts/build-info/`. That input carries every source the compiler saw, dependencies and remapped imports included, so inheritance, libraries, and modifiers resolve exactly as compiled without the analyzer resolving imports itself. It accepts one blob or several, links them all with `analyzeProject`, and by default reports only the project's own sources — dependency sources (under `node_modules/`, `lib/`, or a scoped specifier such as `@openzeppelin/...`) are linked for resolution but not flagged. Pass `{ includeDependencies: true }` to report on everything, or an explicit `include` predicate to choose; `readBuildInfo` exposes the recovered sources and solc version on their own, and `isDependencyPath` the default classification. `analyzeProject` itself gained the same `include` predicate: link every file, report against a chosen subset.

```ts
import { analyzeBuildInfo } from "@choosek/concentric";
import { readFileSync } from "node:fs";

const result = analyzeBuildInfo(readFileSync("out/build-info/abc.json", "utf8"));
// result.findings are located at their true file:line; result.solcVersion is reported too.
```

### Reports, Suppressions, and Configuration

A `ProjectResult` can be exported for a machine consumer. `toSarif(findings, { version })` produces a [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) log — the whole rule catalog (`RULES`) is published as the tool's rule definitions, and each non-positive finding becomes a result with a level and a physical location — and `toJsonReport({ summary, findings, assumptions })` produces a stable JSON shape. The severity helpers `worstSeverity` and `exceedsThreshold` are the predicates a CI gate uses.

`analyzeProject` accepts options: `disabledRules` removes named rules, and `minSeverity` drops findings below a chosen severity. A finding can also be suppressed at its site with a comment — `// concentric-disable-next-line APS-2` silences one rule on the following line, and `// concentric-disable-line` (with no id) silences every finding on its own line — so an accepted disclosure stays documented in the source while no longer failing a build.

## Command Line

The package ships a CLI. It reads every `.sol` file under the given paths, links them with `analyzeProject`, and reports the findings; it exits non-zero when a finding at or above a chosen severity is present, so it can gate a pull request. Given `--build-info <path>` it instead reads a solc build-info file or directory and analyzes through `analyzeBuildInfo`, linking dependencies for resolution while reporting only the project's own sources unless `--include-deps` is passed.

```shell
npx @choosek/concentric check ./contracts
```

Options: `--sarif` and `--json` select machine-readable output; `--fail-on <severity>` sets the exit threshold (default `high`); `--min-severity <severity>` hides findings below a floor; and `--disable APS-6,APS-9` turns off individual rules. The CLI is the file-system shell around the library — all analysis is the library's — so build the package first (`pnpm build`) when running from a checkout. Try it against the bundled fixtures:

```shell
npx @choosek/concentric check examples/contracts   # one HIGH finding, one clean contract
```

## GitHub Action

This repository is also a composite GitHub Action, so a contracts repository can run the analysis on every pull request, upload the results to code scanning, and block a merge on any HIGH finding. A minimal workflow (also in [`examples/confidentiality.yml`](./examples/confidentiality.yml)):

```yaml
name: Confidentiality
on: [pull_request]
permissions:
  contents: read
  security-events: write # to upload SARIF to code scanning
jobs:
  concentric:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: choosek/concentric-ts@v0
        with:
          path: contracts
          fail-on: high
```

The Action runs the analysis to SARIF and uploads it (so results always reach the Security tab), then enforces the threshold in a separate step, leaving a full report behind even when a merge is blocked.

## Development

Use of [pnpm](https://pnpm.io/) is recommended for typical development tasks.

### Testing and Conventions

All unit tests are executed and their coverage measured with [vitest](https://vitest.dev/):
```shell
pnpm test
```
Style conventions are enforced using [biomejs](https://biomejs.dev/):
```shell
pnpm lint
```
Type checking can be performed:
```shell
pnpm typecheck
```
The distribution files can also be checked:
```shell
pnpm attw
```
The tests are of two kinds. The functional tests analyze a set of representative contracts — four carrying a distinct, realistic confidentiality defect, one written correctly, and one per rule introduced beyond the original set — and assert the findings each produces, including that an `Open` function which moves value without disclosing it is not reported. The structural tests confirm invariants that hold of every analysis: that findings are ordered by descending severity, that the summary counts agree with the findings, and that the observer view reports exactly the high- and medium-severity findings as leaks. Coverage is complete on lines, statements, functions, and branches.

### Contributions

In order to contribute to the source code, open an issue or submit a pull request on the [GitHub page](https://github.com/choosek/concentric-ts) for this library. To enforce conventions, git hooks are provided and can be installed:
```shell
pnpm install-hooks
```

### Versioning

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).
