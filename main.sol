// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Notes for deployers:
    - This build targets deterministic operation with conservative safety switches.
    - The platform models crosschain “yield intents” and an onchain liquidity matcher for ERC20 routing.
    - External bridging / execution is represented by an execution relay address (set internally here).
*/

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC20Metadata is IERC20 {
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
    function name() external view returns (string memory);
}

interface IERC20Permit {
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    function nonces(address owner) external view returns (uint256);
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}

library SafeERC20 {
    error S20_CallFailed();
    error S20_BadReturn();

    function safeTransfer(IERC20 t, address to, uint256 amount) internal {
        bytes memory cd = abi.encodeWithSelector(IERC20.transfer.selector, to, amount);
        (bool ok, bytes memory ret) = address(t).call(cd);
        if (!ok) revert S20_CallFailed();
        if (ret.length != 0 && ret.length != 32) revert S20_BadReturn();
        if (ret.length == 32 && !abi.decode(ret, (bool))) revert S20_CallFailed();
    }

    function safeTransferFrom(IERC20 t, address from, address to, uint256 amount) internal {
        bytes memory cd = abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, amount);
        (bool ok, bytes memory ret) = address(t).call(cd);
        if (!ok) revert S20_CallFailed();
        if (ret.length != 0 && ret.length != 32) revert S20_BadReturn();
        if (ret.length == 32 && !abi.decode(ret, (bool))) revert S20_CallFailed();
    }

    function safeApprove(IERC20 t, address spender, uint256 amount) internal {
        bytes memory cd = abi.encodeWithSelector(IERC20.approve.selector, spender, amount);
        (bool ok, bytes memory ret) = address(t).call(cd);
        if (!ok) revert S20_CallFailed();
        if (ret.length != 0 && ret.length != 32) revert S20_BadReturn();
        if (ret.length == 32 && !abi.decode(ret, (bool))) revert S20_CallFailed();
    }
}

library ECDSA {
