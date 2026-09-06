// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// The same idea done right: the getter is Restricted and gated so each caller
// can read only their own entry. Concentric reports no leak.
contract CleanToken {
    mapping(address => uint256) private balances;

    /// @aps:Restricted
    function balanceOf(address who) external view returns (uint256) {
        require(msg.sender == who, "not authorized");
        return balances[who];
    }
}
