import { describe, expect, it } from "vitest";
import {
  analyzeBuildInfo,
  isDependencyPath,
  readBuildInfo,
} from "#/ingest/buildinfo";

/** Build a build-info blob from a path→content map, with optional version keys. */
function blob(
  sources: Record<string, string>,
  extra: Record<string, unknown> = {},
): string {
  const src: Record<string, { content: string }> = {};
  for (const [p, c] of Object.entries(sources)) src[p] = { content: c };
  return JSON.stringify({
    input: { language: "Solidity", sources: src, settings: {} },
    output: {},
    ...extra,
  });
}

const DEP = `pragma solidity ^0.8.24;
contract ERC20Confidential {
  mapping(address => uint256) internal _balances;
  /// @aps:Open
  function peek(address a) external view returns (uint256) { return _balances[a]; }
}`;
const MINE = `pragma solidity ^0.8.24;
import "oz/ERC20Confidential.sol";
contract PayrollToken is ERC20Confidential {
  /// @aps:Open
  function balanceOf(address who) external view returns (uint256) { return _balances[who]; }
}`;
const CLEAN = `pragma solidity ^0.8.24;
contract Vault {
  mapping(address => uint256) private bal;
  /// @aps:Restricted
  function mine() external view returns (uint256) { return bal[msg.sender]; }
}`;

describe("isDependencyPath", () => {
  it("recognises the conventional dependency roots", () => {
    expect(isDependencyPath("lib/openzeppelin/ERC20.sol")).toBe(true);
    expect(isDependencyPath("node_modules/@oz/ERC20.sol")).toBe(true);
    expect(isDependencyPath("@openzeppelin/contracts/token/ERC20.sol")).toBe(
      true,
    );
    expect(isDependencyPath("src/PayrollToken.sol")).toBe(false);
    expect(isDependencyPath("contracts/Foo.sol")).toBe(false);
  });
});

describe("readBuildInfo", () => {
  it("recovers sources and the solc version from a single blob", () => {
    const r = readBuildInfo(
      blob({ "src/A.sol": "contract A {}" }, { solcVersion: "0.8.24" }),
    );
    expect(r.sources).toEqual([
      { path: "src/A.sol", content: "contract A {}" },
    ]);
    expect(r.solcVersion).toBe("0.8.24");
    expect(r.errors).toEqual([]);
  });

  it("prefers the long version and keeps the first version across blobs", () => {
    const r = readBuildInfo([
      blob(
        { "src/A.sol": "contract A {}" },
        {
          solcVersion: "0.8.24",
          solcLongVersion: "0.8.24+commit.aaaa",
        },
      ),
      blob({ "src/B.sol": "contract B {}" }, { solcVersion: "0.8.99" }),
    ]);
    expect(r.solcVersion).toBe("0.8.24+commit.aaaa");
    expect(r.sources.map((s) => s.path)).toEqual(["src/A.sol", "src/B.sol"]);
  });

  it("reports no version when none is present", () => {
    const r = readBuildInfo(blob({ "src/A.sol": "contract A {}" }));
    expect(r.solcVersion).toBe(null);
  });

  it("de-duplicates a path shared across blobs, keeping the first", () => {
    const r = readBuildInfo([
      blob({ "src/A.sol": "contract A { uint256 first; }" }),
      blob({ "src/A.sol": "contract A { uint256 second; }" }),
    ]);
    expect(r.sources).toHaveLength(1);
    expect(r.sources[0].content).toContain("first");
  });

  it("skips entries without string content", () => {
    const raw = JSON.stringify({
      input: {
        sources: {
          "src/A.sol": { content: "contract A {}" },
          "src/B.sol": { content: 123 },
          "src/C.sol": null,
          "src/D.sol": "not-an-object",
        },
      },
    });
    const r = readBuildInfo(raw);
    expect(r.sources.map((s) => s.path)).toEqual(["src/A.sol"]);
  });

  it("records an error for invalid JSON", () => {
    const r = readBuildInfo("{ not json");
    expect(r.sources).toEqual([]);
    expect(r.errors[0]).toMatch(/not valid JSON/);
  });

  it("records an error when a blob has no input.sources", () => {
    const noInput = JSON.stringify({ output: {} });
    const nullSources = JSON.stringify({ input: { sources: null } });
    const badSources = JSON.stringify({ input: { sources: "nope" } });
    expect(readBuildInfo(noInput).errors[0]).toMatch(/no input\.sources/);
    expect(readBuildInfo(nullSources).errors[0]).toMatch(/no input\.sources/);
    expect(readBuildInfo(badSources).errors[0]).toMatch(/no input\.sources/);
  });
});

describe("analyzeBuildInfo", () => {
  it("links dependencies but reports only the project's sources by default", () => {
    const r = analyzeBuildInfo(
      blob(
        { "src/PayrollToken.sol": MINE, "lib/oz/ERC20Confidential.sol": DEP },
        { solcLongVersion: "0.8.24+commit.e11b9ed9" },
      ),
    );
    expect(r.ok).toBe(true);
    expect(r.solcVersion).toBe("0.8.24+commit.e11b9ed9");
    // The inherited base resolves, so the project's getter is flagged...
    const ids = r.findings.map((f) => `${f.id}@${f.file}`);
    expect(ids).toContain("APS-1@src/PayrollToken.sol");
    // ...but the dependency's own leak is not surfaced.
    expect(
      r.findings.some((f) => f.file === "lib/oz/ERC20Confidential.sol"),
    ).toBe(false);
    expect(r.project.edges).toContainEqual([
      "PayrollToken",
      "ERC20Confidential",
    ]);
    expect(r.summary.high).toBe(1);
  });

  it("reports dependency findings when asked", () => {
    const r = analyzeBuildInfo(
      blob({
        "src/PayrollToken.sol": MINE,
        "lib/oz/ERC20Confidential.sol": DEP,
      }),
      { includeDependencies: true },
    );
    expect(r.summary.high).toBe(2);
    expect(
      r.findings.some((f) => f.file === "lib/oz/ERC20Confidential.sol"),
    ).toBe(true);
  });

  it("honors an explicit include predicate over the default", () => {
    const r = analyzeBuildInfo(
      blob({
        "src/PayrollToken.sol": MINE,
        "lib/oz/ERC20Confidential.sol": DEP,
      }),
      { include: (f) => f.startsWith("lib/") },
    );
    // Only the dependency file is reported now.
    expect(
      r.findings.every((f) => f.file === "lib/oz/ERC20Confidential.sol"),
    ).toBe(true);
    expect(r.summary.high).toBe(1);
  });

  it("keeps an unmapped finding (APS-CLEAN) under a dependency gate", () => {
    // A clean project yields APS-CLEAN at line 0, which maps to no file; the
    // include gate must keep such findings.
    const r = analyzeBuildInfo(blob({ "src/Vault.sol": CLEAN }));
    expect(r.ok).toBe(true);
    expect(
      r.findings.some((f) => f.id === "APS-CLEAN" && f.file === null),
    ).toBe(true);
  });

  it("errors with detail when a blob yields no sources", () => {
    const r = analyzeBuildInfo("{ broken");
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/No sources recovered.*not valid JSON/);
    expect(r.project.errors[0]).toMatch(/not valid JSON/);
    expect(r.solcVersion).toBe(null);
  });

  it("errors without detail when sources are simply empty", () => {
    const r = analyzeBuildInfo(blob({}));
    expect(r.ok).toBe(false);
    expect(r.error).toBe("No sources recovered from build-info.");
  });

  it("passes project options through to the analyzer", () => {
    const r = analyzeBuildInfo(
      blob({
        "src/PayrollToken.sol": MINE,
        "lib/oz/ERC20Confidential.sol": DEP,
      }),
      { minSeverity: "high" as never, disabledRules: ["APS-9"] },
    );
    expect(r.findings.every((f) => f.severity === "high")).toBe(true);
  });
});
