/**
 * Functional and structural unit tests for the APS confidentiality analyzer.
 *
 * The functional tests load a set of representative contracts — four with a
 * distinct, realistic confidentiality defect, one written correctly, and one
 * per rule introduced beyond the original set — and assert the findings each
 * produces. The structural tests confirm invariants that hold of every
 * analysis: that findings are ordered by descending severity, that the summary
 * counts agree with the findings, that the observer view reports exactly the
 * high- and medium-severity findings as leaks, and that an Open function which
 * moves value without disclosing it is not reported.
 */

import { describe, expect, test } from "vitest";
import * as concentric from "#/lib";

/** Assert that an analysis succeeded and narrow it to the success case. */
function analyze(source: string): concentric.AnalysisOk {
  const result = concentric.analyzeContract(source);
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error("analysis failed unexpectedly");
  }
  return result;
}

const has = (r: concentric.AnalysisOk, id: string): boolean =>
  r.findings.some((f) => f.id === id);
const sevOf = (r: concentric.AnalysisOk, id: string): string | undefined =>
  r.findings.find((f) => f.id === id)?.severity;

/** A confidential salary token with an Open balance getter (APS-1). */
function payroll(): string {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfidentialPayroll {
    mapping(address => uint256) private balances;
    uint256 private totalPayroll;
    address public admin; // @aps:clear

    event Paid(address indexed employee);

    constructor() { admin = msg.sender; }

    /// @aps:Restricted
    function pay(address employee, uint256 amount) external {
        require(msg.sender == admin, "not admin");
        balances[employee] += amount;
        totalPayroll += amount;
        emit Paid(employee);
    }

    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    /// @aps:Restricted
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}`;
}

/** A vault that emits the withdrawal amount in an event (APS-2). */
function vault(): string {
  return `pragma solidity ^0.8.24;
contract TreasuryVault {
    mapping(address => uint256) private shares;
    uint256 private nav;

    event Withdrawal(address indexed to, uint256 amount);

    /// @aps:Restricted
    function withdraw(address to, uint256 amount) external {
        shares[msg.sender] -= amount;
        emit Withdrawal(to, amount);
    }

    /// @aps:Restricted
    function navPerShare() external view returns (uint256) {
        return nav;
    }
}`;
}

/** A settlement contract that bridges a confidential price (APS-3). */
function bridge(): string {
  return `pragma solidity ^0.8.24;
interface IArcPrecompiles { function bridgeToPublic(address token, uint256 amount) external; }
contract Settlement {
    mapping(bytes32 => uint256) private dealAmount;
    IArcPrecompiles constant APS = IArcPrecompiles(address(0x801));

    /// @aps:Restricted
    function settle(bytes32 dealId) external {
        uint256 amt = dealAmount[dealId];
        APS.bridgeToPublic(address(0xA0b8), amt);
    }
}`;
}

/** Invoices that over-share via trust, re-exposed by an Open forwarder (APS-4/APS-T). */
function trust(): string {
  return `pragma solidity ^0.8.24;
contract ConfidentialInvoices {
    mapping(uint256 => uint256) private invoiceAmount;
    address public admin; // @aps:clear

    /// @aps:Restricted
    function amountOf(uint256 id) external view returns (uint256) {
        return invoiceAmount[id];
    }

    /// @aps:Restricted
    function onboard(address auditor, address marketplaceRouter) external {
        require(msg.sender == admin);
        addTrustee(auditor);
        addTrustee(marketplaceRouter);
    }
    function addTrustee(address a) internal {}
}
contract MarketplaceRouter {
    /// @aps:Open
    function peek(address invoices, uint256 id) external view returns (uint256) {
        return ConfidentialInvoices(invoices).amountOf(id);
    }
}`;
}

/** A confidential token written correctly: owner-gated reads, no amount leak. */
function clean(): string {
  return `pragma solidity ^0.8.24;
contract ConfidentialUSD {
    mapping(address => uint256) private balances;
    uint256 private _totalSupply;

    /// @aps:Restricted
    function balanceOf(address who) external view returns (uint256) {
        require(msg.sender == who, "self only");
        return balances[who];
    }

    /// @aps:Open
    function transfer(address to, uint256 amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    /// @aps:Locked
    function _mint(address to, uint256 amount) external {
        balances[to] += amount;
        _totalSupply += amount;
    }
}`;
}

/** An Open function that discloses a confidential value only as a hash (APS-H). */
function commitment(): string {
  return `pragma solidity ^0.8.24;
contract Sealed {
    uint256 private secret;

    /// @aps:Open
    function proof() external view returns (bytes32) {
        return keccak256(abi.encodePacked(secret));
    }
}`;
}

/** An event that indexes a confidential amount into a topic (APS-12). */
function indexedEvent(): string {
  return `pragma solidity ^0.8.24;
contract Book {
    mapping(bytes32 => uint256) private amountOf;

    event Trade(bytes32 indexed dealId, uint256 indexed amount);

    /// @aps:Restricted
    function record(bytes32 dealId, uint256 amount) external {
        amountOf[dealId] = amount;
        emit Trade(dealId, amount);
    }
}`;
}

/** A function that hands confidential state to an external contract (APS-10). */
function externalArg(): string {
  return `pragma solidity ^0.8.24;
contract Reporter {
    mapping(address => uint256) private balances;

    /// @aps:Restricted
    function report(address who, address oracle) external {
        Oracle(oracle).push(balances[who]);
    }
}`;
}

/** A function that copies a confidential value into a public variable (APS-14). */
function aliasLeak(): string {
  return `pragma solidity ^0.8.24;
contract Mirror {
    mapping(address => uint256) private balances;
    uint256 public lastAmount;

    /// @aps:Open
    function snapshot() external {
        lastAmount = balances[msg.sender];
    }
}`;
}

describe("canonical scenarios", () => {
  test("payroll: an Open getter over confidential balances is HIGH", () => {
    const r = analyze(payroll());
    expect(r.summary.high).toBe(1);
    expect(has(r, "APS-1")).toBe(true);
    expect(sevOf(r, "APS-1")).toBe("high");
    expect(has(r, "APS-5")).toBe(false); // admin is @aps:clear
    expect(r.focus?.name).toBe("balanceOf");
  });

  test("vault: an emitted amount is MEDIUM and is not misread as an indexed leak", () => {
    const r = analyze(vault());
    expect(sevOf(r, "APS-2")).toBe("medium");
    expect(has(r, "APS-9")).toBe(true);
    expect(r.summary.high).toBe(0);
    expect(has(r, "APS-12")).toBe(false); // amount is not indexed here
  });

  test("bridge: a bridged confidential amount is HIGH", () => {
    const r = analyze(bridge());
    expect(sevOf(r, "APS-3")).toBe("high");
  });

  test("trust: an over-broad grant is HIGH and its transitive path is MEDIUM", () => {
    const r = analyze(trust());
    expect(
      r.findings.some((f) => f.id === "APS-4" && f.severity === "high"),
    ).toBe(true);
    expect(has(r, "APS-4ok")).toBe(true);
    expect(sevOf(r, "APS-T")).toBe("medium");
    expect(has(r, "APS-10")).toBe(false); // the forwarded argument is an id, not state
  });

  test("clean: a correct contract yields a clean bill and no false positives", () => {
    const r = analyze(clean());
    expect(r.summary.high).toBe(0);
    expect(r.summary.medium).toBe(0);
    expect(has(r, "APS-CLEAN")).toBe(true);
    expect(has(r, "APS-OK")).toBe(true);
    expect(has(r, "APS-1")).toBe(false); // Open transfer discloses nothing
  });
});

describe("rules beyond the original set", () => {
  test("commitment: a hashed disclosure is recognized, not flagged as a leak", () => {
    const r = analyze(commitment());
    expect(has(r, "APS-H")).toBe(true);
    expect(sevOf(r, "APS-H")).toBe("info");
    expect(has(r, "APS-1")).toBe(false);
    expect(r.summary.high).toBe(0);
  });

  test("indexed event: a confidential amount in a topic is MEDIUM", () => {
    const r = analyze(indexedEvent());
    expect(sevOf(r, "APS-12")).toBe("medium");
    expect(r.findings.find((f) => f.id === "APS-12")?.refVars).toContain(
      "amount",
    );
  });

  test("external argument: confidential state passed to another contract is HIGH", () => {
    const r = analyze(externalArg());
    expect(sevOf(r, "APS-10")).toBe("high");
    expect(r.findings.find((f) => f.id === "APS-10")?.refVars).toContain(
      "balances",
    );
  });

  test("alias: a confidential value copied into a public variable is HIGH", () => {
    const r = analyze(aliasLeak());
    expect(sevOf(r, "APS-14")).toBe("high");
    expect(has(r, "APS-5")).toBe(true); // lastAmount is public and amount-like
  });
});

describe("structural invariants", () => {
  test("findings are ordered by descending severity", () => {
    const rank: Record<string, number> = {
      high: 3,
      medium: 2,
      low: 1,
      info: 0,
      ok: -1,
    };
    for (const source of [payroll(), vault(), trust(), clean()]) {
      const r = analyze(source);
      for (let i = 1; i < r.findings.length; i++) {
        expect(
          rank[r.findings[i - 1].severity] >= rank[r.findings[i].severity],
        ).toBe(true);
      }
    }
  });

  test("the summary counts agree with the findings", () => {
    const r = analyze(trust());
    const count = (s: string): number =>
      r.findings.filter((f) => f.severity === s).length;
    expect(r.summary.high).toBe(count("high"));
    expect(r.summary.medium).toBe(count("medium"));
    expect(r.summary.low).toBe(count("low"));
    expect(r.summary.info).toBe(count("info"));
    expect(r.summary.ok).toBe(count("ok"));
  });

  test("the observer view reports exactly the high and medium findings as leaks", () => {
    const r = analyze(trust());
    const leakCount = r.findings.filter(
      (f) => f.severity === "high" || f.severity === "medium",
    ).length;
    expect(r.observers.leaked.length).toBe(leakCount);
    expect(r.observers.public.length).toBe(4);
  });

  test("a clean contract leaks nothing in the observer view", () => {
    const r = analyze(clean());
    expect(r.observers.leaked.length).toBe(0);
  });
});

describe("errors and empty input", () => {
  test("source with no contract returns an error result", () => {
    const r = concentric.analyzeContract("pragma solidity ^0.8.24;");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.error).toMatch(/no contract/i);
    }
  });
});
