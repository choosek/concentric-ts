/**
 * Tests for project-level analysis, the reporting layer, and the rule catalog.
 *
 * The project tests link small multi-file projects — flat, inherited across
 * files, diamond-shaped, cyclic, and with unresolved or duplicate names — and
 * assert both the findings (reported at their true file and line) and the
 * linking metadata. They also exercise the continuous-integration controls:
 * inline suppressions, disabled rules, and the minimum-severity filter. The
 * reporting tests confirm the severity helpers and both exporters, and the
 * catalog tests confirm the rule lookup.
 */

import { describe, expect, test } from "vitest";
import * as concentric from "#/lib";

const file = (path: string, content: string): concentric.SourceFile => ({
  path,
  content,
});
const ids = (r: concentric.ProjectResult): string[] =>
  r.findings.map((f) => f.id);
const find = (r: concentric.ProjectResult, id: string) =>
  r.findings.find((f) => f.id === id);

/* ======================================================================== */
/* Project linking                                                          */
/* ======================================================================== */

describe("single-file project", () => {
  test("analyzes one file and reports the finding at its file and line", () => {
    const src = `pragma solidity ^0.8.24;
contract Payroll {
    mapping(address => uint256) private balances;
    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}`;
    const r = concentric.analyzeProject([file("Payroll.sol", src)]);
    expect(r.ok).toBe(true);
    expect(r.summary.high).toBe(1);
    const f = find(r, "APS-1");
    expect(f?.file).toBe("Payroll.sol");
    expect(f?.line).toBe(5); // the `function balanceOf` declaration line
    expect(r.project.contracts).toHaveLength(1);
    expect(r.project.edges).toEqual([]);
  });
});

describe("cross-file inheritance", () => {
  test("a derived contract sees confidential state declared in a base file", () => {
    const base = `pragma solidity ^0.8.24;
contract TokenBase {
    mapping(address => uint256) internal balances;
}`;
    const token = `pragma solidity ^0.8.24;
import "./base.sol";
contract Token is TokenBase {
    /// @aps:Open
    function balanceOf(address a) external view returns (uint256) {
        return balances[a];
    }
}`;
    const r = concentric.analyzeProject([
      file("base.sol", base),
      file("token.sol", token),
    ]);
    const f = find(r, "APS-1");
    expect(f?.severity).toBe("high");
    expect(f?.file).toBe("token.sol"); // the getter lives in token.sol
    expect(f?.refVars).toContain("balances");
    expect(r.project.edges).toContainEqual(["Token", "TokenBase"]);
  });

  test("an inherited Open getter is reported once, not once per inheritor", () => {
    const base = `pragma solidity ^0.8.24;
contract Base2 {
    mapping(address => uint256) internal bal;
    /// @aps:Open
    function getBal(address a) external view returns (uint256) {
        return bal[a];
    }
}`;
    const child = `pragma solidity ^0.8.24;
contract Child2 is Base2 {}`;
    const r = concentric.analyzeProject([
      file("base2.sol", base),
      file("child2.sol", child),
    ]);
    // The getter is declared in Base2 and folded into Child2; de-duplication
    // collapses the two identical findings to one, at the base's location.
    expect(r.findings.filter((f) => f.id === "APS-1")).toHaveLength(1);
    expect(find(r, "APS-1")?.file).toBe("base2.sol");
  });

  test("a diamond resolves each shared base once", () => {
    const src = `pragma solidity ^0.8.24;
contract A { uint256 internal x; }
contract B is A {}
contract C is A {}
contract D is B, C {}`;
    const r = concentric.analyzeProject([file("diamond.sol", src)]);
    expect(r.ok).toBe(true);
    expect(r.project.edges).toContainEqual(["D", "B"]);
    expect(r.project.edges).toContainEqual(["D", "C"]);
    expect(r.project.edges).toContainEqual(["B", "A"]);
    expect(r.project.edges).toContainEqual(["C", "A"]);
    expect(r.project.errors).toEqual([]);
  });
});

describe("linking edge cases", () => {
  test("an inheritance cycle is recorded and does not hang", () => {
    const src = `pragma solidity ^0.8.24;
contract X is Y {}
contract Y is X {}`;
    const r = concentric.analyzeProject([file("cycle.sol", src)]);
    expect(r.ok).toBe(true);
    expect(r.project.errors.some((e) => /cycle/i.test(e))).toBe(true);
  });

  test("an unresolved base is recorded", () => {
    const src = `pragma solidity ^0.8.24;
contract Solo is Missing { uint256 private s; }`;
    const r = concentric.analyzeProject([file("solo.sol", src)]);
    expect(r.project.errors.some((e) => /Unresolved base/i.test(e))).toBe(true);
    expect(r.project.edges).toContainEqual(["Solo", "Missing"]);
  });

  test("a duplicated contract name keeps the first definition for linking", () => {
    const a = `pragma solidity ^0.8.24;
contract Dup { uint256 private a; }`;
    const b = `pragma solidity ^0.8.24;
contract Dup { uint256 private b; }`;
    const r = concentric.analyzeProject([file("a.sol", a), file("b.sol", b)]);
    expect(r.ok).toBe(true);
    expect(r.project.contracts).toHaveLength(2);
  });

  test("linkProject exposes the combined source and a line map", () => {
    const src = `pragma solidity ^0.8.24;
contract One { uint256 private a; }`;
    const linked = concentric.linkProject([file("one.sol", src)]);
    expect(linked.source).toContain("contract One {");
    expect(linked.origin.length).toBe(linked.source.split("\n").length);
    expect(linked.headers).toHaveLength(1);
  });

  test("no contract in any file returns an error result", () => {
    const r = concentric.analyzeProject([
      file("empty.sol", "pragma solidity ^0.8.24;"),
    ]);
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/no contract/i);
    expect(r.findings).toEqual([]);
  });
});

/* ======================================================================== */
/* CI controls                                                              */
/* ======================================================================== */

describe("inline suppressions", () => {
  test("disable-next-line by id suppresses only that rule, disable-line suppresses all", () => {
    const src = `pragma solidity ^0.8.24;
contract Sup {
    mapping(address => uint256) private m;
    // @aps:Open
    // concentric-disable-next-line APS-1
    function a(address k) external view returns (uint256) { return m[k]; }
    uint256 public flag; // concentric-disable-line
    uint256 public open2;
}`;
    const r = concentric.analyzeProject([file("sup.sol", src)]);
    // APS-1 on `a` is suppressed by id; the `flag` getter is suppressed by a
    // bare disable-line; `open2`'s getter is not suppressed.
    expect(ids(r)).not.toContain("APS-1");
    const fives = r.findings.filter((f) => f.id === "APS-5");
    expect(fives).toHaveLength(1);
    expect(fives[0].fnName).toBe("open2");
  });
});

describe("disabled rules and severity filter", () => {
  test("disabledRules removes the named rule", () => {
    const src = `pragma solidity ^0.8.24;
contract P {
    mapping(address => uint256) private b;
    /// @aps:Open
    function g(address a) external view returns (uint256) { return b[a]; }
}`;
    const r = concentric.analyzeProject([file("p.sol", src)], {
      disabledRules: ["APS-1"],
    });
    expect(ids(r)).not.toContain("APS-1");
  });

  test("minSeverity drops everything below the threshold", () => {
    const src = `pragma solidity ^0.8.24;
contract Invoices {
    mapping(uint256 => uint256) private amt;
    /// @aps:Restricted
    function onboard(address marketplaceRouter) external { addTrustee(marketplaceRouter); }
    function addTrustee(address x) internal {}
    /// @aps:Restricted
    function amountOf(uint256 id) external view returns (uint256) { return amt[id]; }
}`;
    const r = concentric.analyzeProject([file("inv.sol", src)], {
      minSeverity: "high" as concentric.Severity,
    });
    expect(r.findings.length).toBeGreaterThan(0);
    for (const f of r.findings) expect(f.severity).toBe("high");
  });
});

/* ======================================================================== */
/* Reporting                                                                */
/* ======================================================================== */

describe("severity helpers", () => {
  test("worstSeverity picks the most severe, or ok when empty", () => {
    expect(concentric.worstSeverity([])).toBe("ok");
    expect(
      concentric.worstSeverity([
        { severity: "low" as concentric.Severity },
        { severity: "high" as concentric.Severity },
        { severity: "info" as concentric.Severity },
      ]),
    ).toBe("high");
  });

  test("exceedsThreshold is true only at or above the bar", () => {
    const high = [{ severity: "high" as concentric.Severity }];
    const medium = [{ severity: "medium" as concentric.Severity }];
    expect(
      concentric.exceedsThreshold(high, "high" as concentric.Severity),
    ).toBe(true);
    expect(
      concentric.exceedsThreshold(medium, "high" as concentric.Severity),
    ).toBe(false);
  });
});

describe("SARIF export", () => {
  const src = `pragma solidity ^0.8.24;
contract Payroll {
    mapping(address => uint256) private balances;
    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}`;

  test("publishes the rule catalog and a located error result", () => {
    const r = concentric.analyzeProject([file("Payroll.sol", src)]);
    const sarif = concentric.toSarif(r.findings, { version: "0.1.0" }) as {
      version: string;
      runs: {
        tool: { driver: { name: string; version: string; rules: unknown[] } };
        results: {
          ruleId: string;
          level: string;
          locations?: unknown[];
        }[];
      }[];
    };
    expect(sarif.version).toBe("2.1.0");
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("Concentric");
    expect(run.tool.driver.version).toBe("0.1.0");
    expect(run.tool.driver.rules).toHaveLength(concentric.RULES.length);
    const one = run.results.find((x) => x.ruleId === "APS-1");
    expect(one?.level).toBe("error");
    expect(one?.locations).toBeTruthy();
  });

  test("omits ok-level results and a finding with no location", () => {
    const clean = `pragma solidity ^0.8.24;
contract CleanToken {
    mapping(address => uint256) private balances;
    /// @aps:Restricted
    function balanceOf(address who) external view returns (uint256) {
        require(msg.sender == who);
        return balances[who];
    }
}`;
    const r = concentric.analyzeProject([file("clean.sol", clean)]);
    const sarif = concentric.toSarif(r.findings, { version: "0.1.0" }) as {
      runs: { results: { ruleId: string }[] }[];
    };
    // APS-OK / APS-CLEAN are ok-level and are not emitted as SARIF results.
    expect(sarif.runs[0].results.some((x) => x.ruleId === "APS-CLEAN")).toBe(
      false,
    );

    // A non-ok finding with no location still emits a result, without a region.
    const synthetic: concentric.LocatedFinding = {
      id: "APS-1",
      severity: "high" as concentric.Severity,
      contract: "C",
      fnName: "f",
      line: 0,
      title: "t",
      detail: "d",
      sink: "s",
      fix: "",
      rule: "",
      file: null,
    };
    const s2 = concentric.toSarif([synthetic], { version: "0.1.0" }) as {
      runs: { results: { locations?: unknown[] }[] }[];
    };
    expect(s2.runs[0].results[0].locations).toBeUndefined();
  });
});

describe("JSON export", () => {
  test("flattens findings and passes through summary and assumptions", () => {
    const src = `pragma solidity ^0.8.24;
contract CleanToken {
    mapping(address => uint256) private balances;
    /// @aps:Restricted
    function balanceOf(address who) external view returns (uint256) {
        require(msg.sender == who);
        return balances[who];
    }
}`;
    const r = concentric.analyzeProject([file("clean.sol", src)]);
    const report = concentric.toJsonReport({
      summary: r.summary,
      findings: r.findings,
      assumptions: r.assumptions,
    });
    expect(Array.isArray(report.findings)).toBe(true);
    expect(report.assumptions.length).toBeGreaterThan(0);
    // The clean bill (APS-CLEAN) has no file, exercising the null branch.
    const clean = report.findings.find((f) => f.id === "APS-CLEAN");
    expect(clean?.file).toBeNull();

    // A located finding keeps its file.
    const payroll = `pragma solidity ^0.8.24;
contract P { mapping(address=>uint256) private b; /// @aps:Open
function g(address a) external view returns(uint256){ return b[a]; } }`;
    const r2 = concentric.analyzeProject([file("p.sol", payroll)]);
    const rep2 = concentric.toJsonReport({
      summary: r2.summary,
      findings: r2.findings,
      assumptions: r2.assumptions,
    });
    expect(rep2.findings.find((f) => f.id === "APS-1")?.file).toBe("p.sol");
  });
});

describe("rule catalog", () => {
  test("looks a rule up by id and reports a miss", () => {
    expect(concentric.ruleById("APS-1")?.defaultSeverity).toBe("high");
    expect(concentric.ruleById("APS-NONEXISTENT")).toBeUndefined();
    expect(concentric.ruleHelpUri("APS-1")).toContain("aps-1");
  });
});

describe("analyzeProject front-end selection", () => {
  const payroll = file(
    "Payroll.sol",
    `pragma solidity ^0.8.24;
contract Payroll {
    mapping(address => uint256) private balances;
    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}`,
  );

  test("the AST front-end is the default and finds the Open leak", () => {
    const r = concentric.analyzeProject([payroll]);
    expect(r.ok).toBe(true);
    expect(ids(r)).toContain("APS-1");
  });

  test("the lexical front-end can be selected explicitly", () => {
    const r = concentric.analyzeProject([payroll], { frontend: "lexical" });
    expect(r.ok).toBe(true);
    expect(ids(r)).toContain("APS-1");
  });

  test("the AST front-end falls back to the lexical engine when a source will not parse", () => {
    // The lexical reader sees a contract, so linking proceeds, but the real
    // grammar rejects the body; analysis must still complete via the fallback.
    const broken = file(
      "Broken.sol",
      "pragma solidity ^0.8.24;\ncontract Broken { function f() external { 0x } }",
    );
    const r = concentric.analyzeProject([broken]);
    expect(r.ok).toBe(true);
  });
});
