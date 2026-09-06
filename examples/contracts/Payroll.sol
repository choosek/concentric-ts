// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// A confidential payroll with one mistake: the balance getter is Open, so any
// caller can read any account's confidential balance. Run:
//   npx @choosek/concentric check examples/contracts
contract ConfidentialPayroll {
    mapping(address => uint256) private balances;
    address private admin;

    /// @aps:Open
    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }
}
