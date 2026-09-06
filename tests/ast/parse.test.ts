import { describe, expect, it } from "vitest";
import { apsAnnotations, parseSolidity } from "#/ast/parse";

describe("parseSolidity", () => {
  it("parses valid source into a syntax tree", () => {
    const { unit, errors } = parseSolidity(
      "pragma solidity ^0.8.0; contract C {}",
    );
    expect(unit).not.toBeNull();
    expect(unit?.type).toBe("SourceUnit");
    expect(errors).toEqual([]);
  });

  it("reports a recoverable parse error without throwing", () => {
    const { unit, errors } = parseSolidity("contract C { 3 = ; }");
    expect(unit).not.toBeNull();
    expect(errors.length).toBeGreaterThan(0);
  });

  it("returns a null tree with a diagnostic when the parser fails outright", () => {
    const { unit, errors } = parseSolidity(
      "contract C { function f() external { 0x } }",
    );
    expect(unit).toBeNull();
    expect(errors.length).toBe(1);
  });
});

describe("apsAnnotations", () => {
  const src = [
    "contract C {", // 1
    "    // @aps:Open", // 2
    "    function a() external {}", // 3
    "", // 4
    "    /// leading natspec", // 5
    "    // @aps:Restricted", // 6
    "    function b() external {}", // 7
    "    function c() external {} // @aps:Locked", // 8
    "    // @aps:clear", // 9
    "    uint256 x;", // 10
    "    uint256 y;", // 11
    "}", // 12
  ].join("\n");
  const at = apsAnnotations(src);

  it("resolves a policy on the line above a declaration", () => {
    expect(at(3)).toBe("Open");
  });

  it("scans upward over comment and blank lines", () => {
    expect(at(7)).toBe("Restricted");
  });

  it("reads a trailing annotation on the declaration's own line", () => {
    expect(at(8)).toBe("Locked");
  });

  it("normalizes the clear policy", () => {
    expect(at(10)).toBe("clear");
  });

  it("returns null when the nearest thing above is code", () => {
    expect(at(11)).toBeNull();
  });

  it("returns null past the top of the file", () => {
    expect(at(1)).toBeNull();
  });
});
