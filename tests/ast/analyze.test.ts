import { describe, expect, it } from "vitest";
import { analyzeContractAst } from "#/ast/analyze";

const ids = (src: string): string[] => {
  const r = analyzeContractAst(src);
  return r.findings.map((f) => f.id);
};

describe("analyzeContractAst — entry and error paths", () => {
  it("declines a source the parser cannot handle", () => {
    const r = analyzeContractAst("contract C { function f() external { 0x } }");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/parsed/);
    expect(r.findings).toEqual([]);
  });

  it("declines a source with no contract", () => {
    const r = analyzeContractAst("pragma solidity ^0.8.0;");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/No contract/);
  });
});

describe("returns", () => {
  const src = `
    contract R {
      mapping(address => uint256) private bal;
      uint256 private nav;
      uint256 constant MAX = 100;
      enum Status { Active, Closed }
      /// @aps:Open
      function open1(address who) external view returns (uint256) { return bal[who]; }
      /// @aps:Restricted
      function r1() external view returns (uint256) { return nav; }
      /// @aps:Restricted
      function ownSender() external view returns (uint256) { return bal[msg.sender]; }
      /// @aps:Open
      function ownKey(address who) external view returns (uint256) {
        require(msg.sender == who);
        return bal[who];
      }
      /// @aps:Open
      function echo(uint256 amt) external pure returns (uint256) { return amt; }
      /// @aps:Open
      function echo2(uint256 p, uint256 q) external pure returns (uint256) { return p + q; }
      /// @aps:Open
      function konst() external pure returns (uint256) { return MAX; }
      /// @aps:Open
      function status() external pure returns (Status) { return Status.Active; }
      /// @aps:Open
      function viaLocal(address who) external view returns (uint256) { uint256 v = bal[who]; return v; }
      /// @aps:Restricted
      function hashRet() external view returns (bytes32) { return keccak256(abi.encode(nav)); }
      /// @aps:Open
      function ownKey2(address who) external view returns (uint256) {
        require(who == msg.sender);
        return bal[who];
      }
    }`;
  const got = ids(src);

  it("flags an Open function returning confidential state (APS-1)", () => {
    expect(got).toContain("APS-1");
  });
  it("flags a Restricted function returning state to grant-holders (APS-9)", () => {
    expect(got).toContain("APS-9");
  });
  it("accepts an owner-scoped read via msg.sender or a gated key (APS-OK)", () => {
    expect(got.filter((x) => x === "APS-OK").length).toBeGreaterThanOrEqual(2);
  });
  it("flags an Open function echoing a calldata argument (APS-8)", () => {
    expect(got).toContain("APS-8");
  });
  it("does not treat a constant or an unknown identifier as confidential", () => {
    const r = analyzeContractAst(src);
    expect(r.findings.some((f) => f.fnName === "konst")).toBe(false);
    expect(r.findings.some((f) => f.fnName === "status")).toBe(false);
  });
});

describe("emits", () => {
  const src = `
    contract E {
      uint256 private nav;
      bytes32 private secretHash;
      event Paid(address indexed employee);
      event Withdrawal(address indexed to, uint256 amount);
      event Secret(uint256 indexed v);
      event Commit(bytes32 h);
      /// @aps:Restricted
      function pay(address e2, uint256 amt) external { emit Paid(e2); }
      /// @aps:Restricted
      function wd(address to, uint256 amount) external { emit Withdrawal(to, amount); }
      /// @aps:Restricted
      function leakIndexed() external { emit Secret(nav); }
      /// @aps:Restricted
      function commitHash() external { emit Commit(keccak256(abi.encode(nav))); }
      /// @aps:Open
      function unknownEvent() external { emit Ghost(secretHash); }
      /// @aps:Restricted
      function qualEmit() external { emit Lib.Ev(nav); }
      /// @aps:Restricted
      function emitClean() external { emit Paid(address(0)); }
    }`;
  const got = ids(src);

  it("flags a confidential amount in an event as Medium (APS-2)", () => {
    const r = analyzeContractAst(src);
    const aps2 = r.findings.find((f) => f.id === "APS-2");
    expect(aps2?.severity).toBe("medium");
  });
  it("flags an indexed confidential value (APS-12)", () => {
    expect(got).toContain("APS-12");
  });
  it("treats a hash of a confidential value as a commitment (APS-H)", () => {
    expect(got).toContain("APS-H");
    const commit = analyzeContractAst(src).findings.filter(
      (f) => f.fnName === "commitHash",
    );
    expect(commit.every((f) => f.id === "APS-H")).toBe(true);
  });
  it("reports event metadata for non-amount identifiers (APS-2b)", () => {
    expect(got).toContain("APS-2b");
  });
});

describe("calls — bridge, trust, external, transitive", () => {
  const src = `
    interface IBridge { function bridgeToPublic(address token, uint256 amount) external; }
    contract Calls {
      mapping(bytes32 => uint256) private deal;
      IBridge constant APS = IBridge(address(0x801));
      address private auditor;
      /// @aps:Restricted
      function settle(bytes32 id) external {
        uint256 amt = deal[id];
        APS.bridgeToPublic(address(0xA0b8), uint256(amt));
      }
      /// @aps:Restricted
      function trustBad(address x) external { addTrustee(x); }
      /// @aps:Restricted
      function trustOk() external { addTrustee(auditor); }
      /// @aps:Restricted
      function trustNoArg() external { addTrustee(); }
      /// @aps:Restricted
      function trustExpr() external { addTrustee(address(0)); }
      function addTrustee(address a) internal {}
      function addTrustee() internal {}
    }`;
  const got = ids(src);

  it("flags a value bridged to the public EVM, tracked through a local (APS-3)", () => {
    const r = analyzeContractAst(src);
    const aps3 = r.findings.find((f) => f.id === "APS-3");
    expect(aps3?.severity).toBe("high");
    expect(aps3?.refVars).toContain("amt");
  });
  it("flags an over-broad trust grant (APS-4) and accepts a compliance party (APS-4ok)", () => {
    expect(got).toContain("APS-4");
    expect(got).toContain("APS-4ok");
    expect(got.filter((x) => x === "APS-4").length).toBe(3);
  });

  it("flags a confidential value passed to an external contract (APS-10)", () => {
    const src2 = `
      contract Ext {
        mapping(uint256 => uint256) private v;
        /// @aps:Restricted
        function leak(address sink, uint256 id) external { ISink(sink).store(v[id]); }
        /// @aps:Restricted
        function leak2(uint256 id) external { Helper(address(0)).consume(v[id]); }
        /// @aps:Restricted
        function leak3(uint256 id) external { obj.doThing(v[id]); }
        /// @aps:Restricted
        function leak4(UnknownC u, uint256 id) external { u.sink(v[id]); }
      }
      contract Helper { function consume(uint256 z) external {} }`;
    expect(ids(src2).filter((x) => x === "APS-10").length).toBe(4);
  });

  it("flags transitive exposure through an Open forwarder (APS-T)", () => {
    const src3 = `
      contract Vault2 {
        mapping(uint256 => uint256) private amt;
        /// @aps:Restricted
        function amountOf(uint256 id) external view returns (uint256) { return amt[id]; }
      }
      contract Router {
        /// @aps:Open
        function peek(address v, uint256 id) external view returns (uint256) {
          return Vault2(v).amountOf(id);
        }
        /// @aps:Open
        function peek2(Vault2 vv, uint256 id) external view returns (uint256) {
          return vv.amountOf(id);
        }
      }`;
    const r = analyzeContractAst(src3);
    expect(r.findings.filter((f) => f.id === "APS-T").length).toBe(2);
  });
});

describe("variables and assignments", () => {
  const src = `
    struct S { uint256 x; }
    contract Vars {
      uint256 public totalSupply;
      bool public flag;
      uint256 immutable fee;
      uint256 private secret;
      uint256 public exposed;
      address public admin; // @aps:clear
      mapping(uint256 => uint256) public pubMap;
      S private st;
      constructor() { admin = msg.sender; fee = 1; }
      /// @aps:Restricted
      function copy() external { exposed = secret; }
      /// @aps:Restricted
      function idxAssign() external { pubMap[0] = secret; }
      /// @aps:Restricted
      function memberAssign() external { st.x = secret; }
      function noPolicy() external {}
      fallback() external {}
      receive() external payable {}
    }`;
  const got = ids(src);

  it("flags a public confidential variable, Medium for amounts and Low otherwise (APS-5)", () => {
    const r = analyzeContractAst(src);
    const supply = r.findings.find(
      (f) => f.id === "APS-5" && f.fnName === "totalSupply",
    );
    const flag = r.findings.find(
      (f) => f.id === "APS-5" && f.fnName === "flag",
    );
    expect(supply?.severity).toBe("medium");
    expect(flag?.severity).toBe("low");
  });
  it("does not flag a variable acknowledged with @aps:clear", () => {
    const r = analyzeContractAst(src);
    expect(
      r.findings.some((f) => f.id === "APS-5" && f.fnName === "admin"),
    ).toBe(false);
  });
  it("flags a confidential immutable (APS-7)", () => {
    expect(got).toContain("APS-7");
  });
  it("flags an external function with no access policy (APS-6)", () => {
    expect(got).toContain("APS-6");
  });
  it("flags copies of confidential state into a public variable or mapping (APS-14)", () => {
    const r = analyzeContractAst(src);
    const targets = r.findings
      .filter((f) => f.id === "APS-14")
      .map((f) => f.refVars?.[0]);
    expect(targets).toContain("exposed");
    expect(targets).toContain("pubMap");
    expect(
      r.findings.some((f) => f.id === "APS-14" && f.fnName === "memberAssign"),
    ).toBe(false);
  });
});

describe("inheritance resolution", () => {
  it("resolves inherited state and events through the base chain", () => {
    const src = `
      contract Base { mapping(address => uint256) internal bal; event Ev(uint256 amount); }
      contract Mid is Base { uint256 internal nav; }
      contract Derived is Mid {
        /// @aps:Open
        function getBal(address who) external view returns (uint256) { return bal[who]; }
        /// @aps:Restricted
        function emitInherited(uint256 amount) external { emit Ev(amount); }
      }`;
    const got = ids(src);
    expect(got).toContain("APS-1");
    expect(got).toContain("APS-2");
  });

  it("tolerates an unresolved base and an inheritance cycle", () => {
    const src = `
      contract Missing is Unknownbase {}
      contract A is B {}
      contract B is A {}`;
    const r = analyzeContractAst(src);
    expect(r.ok).toBe(true);
  });
});

describe("taint edges and clean contracts", () => {
  it("handles bare, binary, unary, tuple, and assignment expressions and ordinary calls", () => {
    const src = `
      contract Edges {
        uint256 private nav;
        /// @aps:Restricted
        function ownerRead() external view returns (uint256) { return nav; }
        /// @aps:Restricted
        function edges(uint256 p) external view returns (uint256) {
          require();
          uint256 x;
          uint256 y = nav + p;
          uint256 z = -y;
          uint256 w = helper(nav);
          (uint256 a, ) = pair();
          x = y;
          return z + w + a;
        }
        /// @aps:Restricted
        function twoRet() external view returns (uint256, uint256) { return (nav, 1); }
        /// @aps:Restricted
        function assignExpr() external returns (uint256) { uint256 t; return (t = nav); }
        function helper(uint256 q) internal pure returns (uint256) { return q; }
        function pair() internal pure returns (uint256, uint256) { return (1, 2); }
      }`;
    const r = analyzeContractAst(src);
    expect(r.ok).toBe(true);
    expect(r.summary.high).toBe(0);
    expect(r.summary.medium).toBe(0);
    expect(r.findings.some((f) => f.id === "APS-CLEAN")).toBe(true);
  });

  it("reports a clean summary with counts for a benign contract", () => {
    const src = `
      contract Clean {
        mapping(address => uint256) private bal;
        /// @aps:Restricted
        function ownerRead() external view returns (uint256) { return bal[msg.sender]; }
        /// @aps:Open
        function pub() external pure returns (uint256) { return 42; }
      }`;
    const r = analyzeContractAst(src);
    expect(r.findings.some((f) => f.id === "APS-CLEAN")).toBe(true);
    expect(r.summary.functions).toBe(2);
    expect(r.summary.exposedFns).toBe(2);
    expect(r.summary.stateVars).toBe(1);
    expect(r.summary.contracts).toBe(1);
  });
});

describe("browser-facing model, focus, and observers", () => {
  it("exposes a per-contract function view with policy and reachability", () => {
    const src = `
      contract M {
        uint256 private nav;
        /// @aps:Open
        function a(address who) external view returns (uint256) { return nav; }
        /// @aps:Restricted
        function b() external {}
        /// @aps:Locked
        function c() external {}
        function d() external {}
        function e() internal {}
        constructor() {}
      }`;
    const r = analyzeContractAst(src);
    const cm = r.model?.contracts[0];
    expect(cm?.name).toBe("M");
    const byName = new Map((cm?.fns ?? []).map((f) => [f.name, f]));
    expect(byName.get("a")?.policy).toBe("open");
    expect(byName.get("a")?.reach).toBe("anyone");
    expect(byName.get("b")?.policy).toBe("restricted");
    expect(byName.get("b")?.reach).toBe("grantees");
    expect(byName.get("c")?.policy).toBe("locked");
    expect(byName.get("c")?.reach).toBe("nobody");
    expect(byName.get("d")?.policy).toBe(null);
    expect(byName.get("d")?.reach).toBe("unset");
    expect(byName.get("e")?.reach).toBe("unset");
    expect(cm?.fns.find((f) => f.kind === "constructor")).toBeTruthy();
  });

  it("renders user-defined and array parameter types, and blanks the exotic", () => {
    const src = `
      contract Sink { uint256 x; }
      contract P {
        /// @aps:Restricted
        function f(Sink s, uint256[] xs, uint256 n) external {}
      }`;
    const r = analyzeContractAst(src);
    const f = r.model?.contracts
      .find((c) => c.name === "P")
      ?.fns.find((x) => x.name === "f");
    expect(f?.params.map((p) => p.type)).toEqual(["Sink", "", "uint256"]);
  });

  it("picks an Open state-returning function as the focus and names its params", () => {
    const src = `
      contract Unnamed {
        uint256 private nav;
        /// @aps:Open
        function get(uint256) external view returns (uint256) { return nav; }
      }`;
    const r = analyzeContractAst(src);
    expect(r.focus?.name).toBe("get");
    // The unnamed parameter falls back to its type in the observer line.
    expect(r.observers?.authorized[0]).toBe("call Unnamed.get(uint256)");
  });

  it("falls back to any externally visible function when no policy is set", () => {
    const src =
      "contract OnlyUnset { function ping() external {} function hidden() internal {} }";
    const r = analyzeContractAst(src);
    expect(r.focus?.name).toBe("ping");
    expect(r.observers?.authorized).toContain("no confidential state touched");
  });

  it("has no focus and a generic authorized view when there is no callable function", () => {
    const src = "contract Empty { uint256 private x; }";
    const r = analyzeContractAst(src);
    expect(r.focus).toBe(null);
    expect(r.observers?.authorized[0]).toMatch(/decrypted call/);
  });
});
