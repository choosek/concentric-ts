/**
 * Coverage-completing unit tests.
 *
 * These exercise the lexical helpers directly and drive the analyzer over
 * small, single-purpose contracts that reach the source encodings, statement
 * shapes, and defensive fallbacks the functional suite does not: the block- and
 * string-neutralizing branches of the lexer, the parser guards on malformed
 * source, every assignment operator, each visibility and member kind, the
 * name- and type-based paths of the indexed-event rule, both trust branches,
 * the commitment-suppressed variants of the return and event rules, the focus
 * selection fallbacks, and the transitive-exposure edges. Each test targets a
 * specific branch so that the analyzer is covered in full.
 */

import { describe, expect, test } from "vitest";
import * as common from "#/common";
import * as concentric from "#/lib";

function analyze(source: string): concentric.AnalysisOk {
  const r = concentric.analyzeContract(source);
  if (!r.ok) {
    throw new Error(`unexpected error: ${r.error}`);
  }
  return r;
}
const ids = (r: concentric.AnalysisOk): string[] => r.findings.map((f) => f.id);

/* ======================================================================== */
/* Lexical helpers (common.ts)                                              */
/* ======================================================================== */

describe("blankNonCode", () => {
  test("neutralizes line comments, block comments, and string and char literals", () => {
    const src = 'x /* b */ y // c\nz "a\\"b" w \'q\' v';
    const out = common.blankNonCode(src);
    expect(out.length).toBe(src.length);
    expect(out).not.toContain("b */");
    expect(out).not.toContain("//");
    expect(out).not.toContain("a\\");
    // Code tokens and the newline survive.
    expect(out).toContain("x");
    expect(out).toContain("z");
    expect(out.split("\n").length).toBe(2);
  });

  test("tolerates an unterminated block comment and string", () => {
    expect(() => common.blankNonCode("a /* unterminated")).not.toThrow();
    expect(() => common.blankNonCode('a "unterminated')).not.toThrow();
  });
});

describe("matchBracket", () => {
  test("matches each bracket kind and reports -1 when unbalanced", () => {
    expect(common.matchBracket("(a[b]c)", 0)).toBe(6);
    expect(common.matchBracket("[x]", 0)).toBe(2);
    expect(common.matchBracket("{y}", 0)).toBe(2);
    expect(common.matchBracket("(a", 0)).toBe(-1);
  });
});

describe("splitTopLevel", () => {
  test("splits only at depth zero and keeps nested separators", () => {
    expect(common.splitTopLevel("a,(b,c),d")).toEqual(["a", "(b,c)", "d"]);
    expect(common.splitTopLevel("mapping(a=>b) m, uint x").length).toBe(2);
    expect(common.splitTopLevel("")).toEqual([]);
    expect(common.splitTopLevel("only")).toEqual(["only"]);
  });
});

describe("lineMapper", () => {
  test("maps offsets to one-based line numbers", () => {
    const at = common.lineMapper("a\nbb\nccc");
    expect(at(0)).toBe(1);
    expect(at(2)).toBe(2);
    expect(at(5)).toBe(3);
  });
});

/* ======================================================================== */
/* Parser guards (solidity.ts) on malformed source                          */
/* ======================================================================== */

describe("parser guards", () => {
  test("a contract header with no body brace is skipped", () => {
    expect(concentric.parseContracts("contract X").contracts.length).toBe(0);
  });

  test("a contract with an unterminated body brace is skipped", () => {
    expect(concentric.parseContracts("contract X {").contracts.length).toBe(0);
  });

  test("a function with an unterminated parameter list is skipped", () => {
    const r = concentric.analyzeContract("contract Y { function f(uint256 a }");
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.model.contracts[0].fns.length).toBe(0);
    }
  });

  test("a return expression with an unbalanced hash call is handled", () => {
    const src =
      "pragma solidity ^0.8.24;\n" +
      "contract Broken {\n" +
      "    /// @aps:Open\n" +
      "    function h(uint256 x) external pure returns (bytes32) {\n" +
      "        return keccak256(abi.encode(x);\n" +
      "    }\n" +
      "}";
    expect(() => concentric.analyzeContract(src)).not.toThrow();
  });

  test("parseParams returns an empty list for empty input", () => {
    expect(concentric.parseParams("   ")).toEqual([]);
  });

  test("collectAnnotations finds every annotation kind", () => {
    const anns = concentric.collectAnnotations(
      "// @aps:Open\n// @aps:Restricted\n// @aps:Locked\n// @aps:clear",
    );
    expect(anns.map((a) => a.kind).sort()).toEqual([
      "clear",
      "locked",
      "open",
      "restricted",
    ]);
  });
});

/* ======================================================================== */
/* Statement shapes and member kinds                                        */
/* ======================================================================== */

describe("state-write operators and declarations", () => {
  test("all assignment operators on state are recognized as writes", () => {
    const src = `pragma solidity ^0.8.24;
contract Ops {
    uint256 private a;
    uint256 private b;
    uint256 private c;
    uint256 private d;
    /// @aps:Restricted
    function f(uint256 g) external {
        a += 1;
        b -= 1;
        c++;
        d = 2;
        d--;
        uint256 e = a;
        e = e;
        uint256 p = g;
        uint256 z = 5;
    }
}`;
    const r = analyze(src);
    const f = r.model.contracts[0].fns.find((x) => x.name === "f");
    expect(f?.scan.writes.sort()).toEqual(["a", "b", "c", "d"]);
  });

  test("reserved declarations, mappings, and initializers are parsed without error", () => {
    const src = `pragma solidity ^0.8.24;
contract Decls {
    struct S { uint256 x; }
    enum E { A, B }
    using SafeMath for uint256;
    error Bad();
    uint256 private counter = 7;
    mapping(address => uint256) private m;
    uint256 public scale = 1;
    uint256;
    public flag;
    uint256 2bad;
}`;
    const r = analyze(src);
    const names = r.model.contracts[0].vars.map((v) => v.name).sort();
    expect(names).toContain("counter");
    expect(names).toContain("m");
    expect(names).toContain("scale");
  });
});

describe("member kinds and reachability", () => {
  test("constructor, receive, fallback, modifier, and internal members are classified", () => {
    const src = `pragma solidity ^0.8.24;
contract Members {
    uint256 private v;
    constructor() { v = 1; }
    modifier onlyEven() { _; }
    receive() external payable {}
    fallback() external {}
    function helper() internal view returns (uint256) { return v; }
}`;
    const r = analyze(src);
    const byName = (n: string): concentric.FunctionInfo | undefined =>
      r.model.contracts[0].fns.find((f) => f.name === n);
    expect(byName("constructor")?.reach).toBe(concentric.Reach.Constructor);
    expect(byName("onlyEven")?.reach).toBe(concentric.Reach.Modifier);
    expect(byName("helper")?.reach).toBe(concentric.Reach.Internal);
  });
});

/* ======================================================================== */
/* Rule-branch coverage                                                     */
/* ======================================================================== */

describe("return and event rule branches", () => {
  test("an Open scalar return is HIGH and not treated as a per-account leak", () => {
    const src = `pragma solidity ^0.8.24;
contract Scalar {
    uint256 private total;
    /// @aps:Open
    function get() external view returns (uint256) { return total; }
}`;
    const r = analyze(src);
    const aps1 = r.findings.find((f) => f.id === "APS-1");
    expect(aps1?.severity).toBe("high");
    expect(aps1?.detail).toContain("world-readable");
  });

  test("an Open function returning a hash of calldata is a suppressed commitment", () => {
    const src = `pragma solidity ^0.8.24;
contract Echo {
    /// @aps:Open
    function h(uint256 x) external pure returns (bytes32) {
        return keccak256(abi.encode(x));
    }
}`;
    const r = analyze(src);
    expect(ids(r)).not.toContain("APS-8");
  });

  test("a Restricted function returning a hash of state is a suppressed commitment", () => {
    const src = `pragma solidity ^0.8.24;
contract Sealed {
    uint256 private nav;
    /// @aps:Restricted
    function pc() external view returns (bytes32) {
        return keccak256(abi.encode(nav));
    }
}`;
    const r = analyze(src);
    expect(ids(r)).toContain("APS-H");
    expect(ids(r)).not.toContain("APS-9");
  });

  test("emitting a hash of state is a suppressed commitment", () => {
    const src = `pragma solidity ^0.8.24;
contract Ev {
    uint256 private nav;
    event C(bytes32 c);
    /// @aps:Restricted
    function e() external { emit C(keccak256(abi.encode(nav))); }
}`;
    const r = analyze(src);
    expect(ids(r)).toContain("APS-H");
    expect(ids(r)).not.toContain("APS-2");
  });

  test("emitting a bare identifier reveals metadata only (APS-2b)", () => {
    const src = `pragma solidity ^0.8.24;
contract Meta {
    event M(address who);
    /// @aps:Restricted
    function m(address who) external { emit M(who); }
}`;
    const r = analyze(src);
    expect(r.findings.find((f) => f.id === "APS-2b")?.severity).toBe("info");
  });
});

describe("bridge, trust, and indexed-event branches", () => {
  test("bridging a calldata amount is HIGH via the parameter path", () => {
    const src = `pragma solidity ^0.8.24;
interface P { function bridgeToPublic(address t, uint256 a) external; }
contract B2 {
    P constant AP = P(address(0x801));
    /// @aps:Restricted
    function s(uint256 amt) external { AP.bridgeToPublic(address(0), amt); }
}`;
    const r = analyze(src);
    expect(r.findings.find((f) => f.id === "APS-3")?.severity).toBe("high");
  });

  test("a trust grant to a non-auditor, non-third-party is still over-broad", () => {
    const src = `pragma solidity ^0.8.24;
contract T2 {
    /// @aps:Restricted
    function g(address bob) external { addTrustee(bob); }
    function addTrustee(address a) internal {}
}`;
    const r = analyze(src);
    const aps4 = r.findings.find((f) => f.id === "APS-4");
    expect(aps4?.severity).toBe("high");
    expect(aps4?.detail).not.toContain("third-party");
  });

  test("an indexed amount is caught by name as well as by type", () => {
    const src = `pragma solidity ^0.8.24;
contract Named {
    event Y(address indexed salary);
    /// @aps:Restricted
    function r(address salary) external {}
}`;
    const r = analyze(src);
    expect(r.findings.find((f) => f.id === "APS-12")?.refVars).toContain(
      "salary",
    );
  });
});

describe("variable-level and unset-policy branches", () => {
  test("a non-amount public variable is LOW and an unset external function is INFO", () => {
    const src = `pragma solidity ^0.8.24;
contract Pub {
    bool public flag;
    function open() external {}
}`;
    const r = analyze(src);
    expect(r.findings.find((f) => f.id === "APS-5")?.severity).toBe("low");
    expect(ids(r)).toContain("APS-6");
  });

  test("an amount-like immutable is flagged for bytecode storage", () => {
    const src = `pragma solidity ^0.8.24;
contract Imm {
    uint256 immutable secret;
    constructor(uint256 s) { secret = s; }
}`;
    const r = analyze(src);
    expect(r.findings.find((f) => f.id === "APS-7")?.severity).toBe("low");
  });
});

describe("focus selection and observer fallbacks", () => {
  test("a contract with only internal members has no focus and a generic observer view", () => {
    const src = `pragma solidity ^0.8.24;
contract OnlyInternal {
    uint256 private v;
    function h() internal view returns (uint256) { return v; }
}`;
    const r = analyze(src);
    expect(r.focus).toBe(null);
    expect(r.observers.authorized[0]).toContain("decrypted call");
  });

  test("a contract whose only external member is Locked selects it as focus", () => {
    const src = `pragma solidity ^0.8.24;
contract OnlyLocked {
    uint256 private v;
    /// @aps:Locked
    function set(uint256 x) external { v = x; }
}`;
    const r = analyze(src);
    expect(r.focus?.name).toBe("set");
  });
});

describe("transitive-exposure edges", () => {
  test("an Open forwarder to an undefined contract is not reported", () => {
    const src = `pragma solidity ^0.8.24;
contract Fwd {
    /// @aps:Open
    function f(address g) external view returns (uint256) {
        return Ghost(g).get();
    }
}`;
    const r = analyze(src);
    expect(ids(r)).not.toContain("APS-T");
  });

  test("an Open forwarder to an Open state getter is transitively exposed", () => {
    const src = `pragma solidity ^0.8.24;
contract Src3 {
    uint256 private w;
    /// @aps:Open
    function getW() external view returns (uint256) { return w; }
}
contract Caller3 {
    uint256 private c3;
    /// @aps:Open
    function pull3(address s) external { c3 = Src3(s).getW(); }
}`;
    const r = analyze(src);
    expect(
      r.findings.some((f) => f.id === "APS-T" && f.contract === "Caller3"),
    ).toBe(true);
  });

  test("an Open forwarder to a Locked getter is not transitively exposed", () => {
    const src = `pragma solidity ^0.8.24;
contract Src4 {
    uint256 private y;
    /// @aps:Locked
    function getY() external view returns (uint256) { return y; }
}
contract Caller4 {
    uint256 private c4;
    /// @aps:Open
    function pull4(address s) external { c4 = Src4(s).getY(); }
}`;
    const r = analyze(src);
    expect(
      r.findings.some((f) => f.id === "APS-T" && f.contract === "Caller4"),
    ).toBe(false);
  });

  test("an Open forwarder to an in-source function returning no state is not reported", () => {
    const src = `pragma solidity ^0.8.24;
contract Source {
    /// @aps:Open
    function constantValue() external pure returns (uint256) { return 42; }
}
contract Caller {
    /// @aps:Open
    function f(address s) external view returns (uint256) {
        return Source(s).constantValue();
    }
}`;
    const r = analyze(src);
    expect(ids(r)).not.toContain("APS-T");
  });
});

describe("annotation proximity, public policy, and unnamed parameters", () => {
  test("a clear annotation on the line above a variable clears it", () => {
    const src = `pragma solidity ^0.8.24;
contract ClearAbove {
    // @aps:clear
    uint256 public marked;
}`;
    const r = analyze(src);
    expect(r.findings.some((f) => f.id === "APS-5")).toBe(false);
  });

  test("a public function with no policy is unset and reported", () => {
    const src = `pragma solidity ^0.8.24;
contract Pub2 {
    function p2() public {}
}`;
    const r = analyze(src);
    expect(r.findings.some((f) => f.id === "APS-6")).toBe(true);
  });

  test("an unnamed parameter is described by its type in the observer view", () => {
    const src = `pragma solidity ^0.8.24;
contract Unnamed {
    uint256 private v;
    /// @aps:Open
    function get(uint256) external view returns (uint256) { return v; }
}`;
    const r = analyze(src);
    expect(r.focus?.name).toBe("get");
    expect(r.observers.authorized[0]).toContain("uint256");
  });
});

describe("event-amount and external-argument value branches", () => {
  test("an Open function emitting confidential state is HIGH", () => {
    const src = `pragma solidity ^0.8.24;
contract Leaky {
    uint256 private nav;
    event E(uint256 v);
    /// @aps:Open
    function e() external { emit E(nav); }
}`;
    const r = analyze(src);
    const aps2 = r.findings.find((f) => f.id === "APS-2");
    expect(aps2?.severity).toBe("high");
    expect(aps2?.detail).toContain("confidential state");
  });

  test("a state-tainted local passed to an external call is reported generically", () => {
    const src = `pragma solidity ^0.8.24;
contract Reporter2 {
    mapping(address => uint256) private balances;
    /// @aps:Restricted
    function report(address who, address oracle) external {
        uint256 amt = balances[who];
        Oracle(oracle).push(amt);
    }
}`;
    const r = analyze(src);
    const aps10 = r.findings.find((f) => f.id === "APS-10");
    expect(aps10?.severity).toBe("high");
    expect(aps10?.detail).toContain("a confidential value");
  });
});

describe("observer summary helper", () => {
  test("leakLine falls back to the title for an unrecognized finding id", () => {
    const line = concentric.leakLine({
      id: "APS-Z",
      severity: concentric.Severity.Medium,
      contract: "C",
      fnName: "fn",
      line: 1,
      title: "Some finding",
      detail: "",
      sink: "",
      fix: "",
      rule: "",
    });
    expect(line).toBe("Some finding (C.fn)");
  });
});
