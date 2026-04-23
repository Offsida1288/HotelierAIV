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
    error ECDSA_InvalidSig();
    error ECDSA_InvalidS();
    error ECDSA_InvalidV();

    function recover(bytes32 digest, bytes memory signature) internal pure returns (address signer) {
        if (signature.length != 65) revert ECDSA_InvalidSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert ECDSA_InvalidS();
        if (v != 27 && v != 28) revert ECDSA_InvalidV();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert ECDSA_InvalidSig();
    }
}

library MiniStrings {
    error Str_BadHex();

    function _fromHexChar(uint8 c) internal pure returns (uint8) {
        if (c >= 48 && c <= 57) return c - 48;
        if (c >= 65 && c <= 70) return c - 55;
        if (c >= 97 && c <= 102) return c - 87;
        revert Str_BadHex();
    }

    function parseHexAddress(string memory s) internal pure returns (address a) {
        bytes memory b = bytes(s);
        if (b.length != 42) revert Str_BadHex();
        if (b[0] != "0" || (b[1] != "x" && b[1] != "X")) revert Str_BadHex();

        uint160 out = 0;
        for (uint256 i = 2; i < 42; i += 2) {
            uint8 hi = _fromHexChar(uint8(b[i]));
            uint8 lo = _fromHexChar(uint8(b[i + 1]));
            out = (out << 8) | uint160((hi << 4) | lo);
        }
        a = address(out);
    }
}

abstract contract ReentrancyGuard {
    uint256 private _gate;
    modifier nonReentrant() {
        if (_gate == 2) revert();
        _gate = 2;
        _;
        _gate = 1;
    }

    constructor() {
        _gate = 1;
    }
}

abstract contract Pausable {
    event PauseFlip(address indexed operator, bool isPaused, uint256 at);
    bool private _paused;

    modifier whenNotPaused() {
        if (_paused) revert();
        _;
    }
