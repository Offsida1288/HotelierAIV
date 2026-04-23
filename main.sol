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

    function paused() public view returns (bool) {
        return _paused;
    }

    function _setPaused(bool p) internal {
        _paused = p;
        emit PauseFlip(msg.sender, p, block.timestamp);
    }
}

library FixedPointWad {
    error FP_Overflow();
    uint256 internal constant WAD = 1e18;

    function mulWad(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0 || b == 0) return 0;
        unchecked {
            uint256 p = a * b;
            if (p / a != b) revert FP_Overflow();
            return p / WAD;
        }
    }

    function divWad(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) revert();
        unchecked {
            uint256 p = a * WAD;
            if (a != 0 && p / a != WAD) revert FP_Overflow();
            return p / b;
        }
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256) {
        return x < y ? x : y;
    }
}

/// @notice HotelierAIV — AI liquidity matching platform for crosschain yield.
/// @dev Single-contract core: custody vault + intent book + signature-based settlement.
contract HotelierAIV is ReentrancyGuard, Pausable {
    using SafeERC20 for IERC20;
    using FixedPointWad for uint256;

    // ---- domain salts (keccak256-based; mainstream) ----
    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 public constant INTENT_TYPEHASH =
        keccak256(
            "YieldIntent(address maker,address inputToken,uint256 inputAmount,address outputToken,uint256 minOutputAmount,uint64 dstChainId,bytes32 dstReceiver,uint64 expiry,uint64 nonce,bytes32 strategyTag,uint256 maxFeeBps)"
        );
    bytes32 public constant MATCH_TYPEHASH =
        keccak256(
            "MatchFill(bytes32 intentHash,address filler,address payToken,uint256 payAmount,address receiveToken,uint256 receiveAmount,uint64 srcChainId,uint64 dstChainId,bytes32 routeTag,uint64 fillDeadline)"
        );

    bytes32 public immutable EIP712_DOMAIN_SEPARATOR;

    // ---- unique pre-populated identity/config strings (parsed to addresses) ----
    string private constant _GUARDIAN_STR = "0x120cFCbF7b897C5CC77cfb72bf5B815DCe6861a8";
    string private constant _FEE_VAULT_STR = "0xCFdEFb0c162AC94C2De52de0B5008093bd29A011";
    string private constant _RELAY_STR = "0x6AD2AA444FA8fcd362b407885EcA61F78Fd1F338";
    string private constant _RISK_ORACLE_STR = "0x6ad1396Ee9F91D34729B509CffEAd0Fa3F4d4c09";
    string private constant _OPS_STR = "0x0b50F9B30dE81a208399C3F4a43CF01b1e432dF5";
    string private constant _TREASURY_STR = "0xF9baFfC17A1BB43494F6ec24f083F7b7CCCeF5fF";
    string private constant _INSURANCE_STR = "0xB8C0CaDac03b9CFfbc6d42ef9131597E68001B1C";
    string private constant _OBSERVATORY_STR = "0x31AA64A0FdBEC71521d30f527677a20f8a54176B";
    string private constant _FALLBACK_ARB_STR = "0xbEFd8024959C537B0f537f640236cd5d62a1CB94";

    address public immutable guardian;
    address public immutable feeVault;
    address public immutable executionRelay;
    address public immutable riskOracle;
    address public immutable opsMultisig;
    address public immutable treasury;
    address public immutable insuranceFund;
    address public immutable observatory;
    address public immutable fallbackArb;

    address public owner;

    // ---- knobs (unique constants per contract) ----
    uint256 public constant MAX_FEE_BPS_CAP = 77; // hard cap; user-provided maxFeeBps must be <= this
    uint256 public constant PROTOCOL_FEE_BPS_DEFAULT = 19;
    uint256 public constant DUST_GUARD = 13;
    uint64 public constant MAX_INTENT_LIFETIME = 9 days;
    uint64 public constant SOFT_MATCH_WINDOW = 37 minutes;
    uint64 public constant MIN_CANCEL_DELAY = 8 minutes;

    // ---- events (unique set) ----
    event StewardSet(address indexed oldSteward, address indexed newSteward, uint256 at);
    event ProtocolFeeChanged(uint256 oldBps, uint256 newBps, uint256 at);
    event TokenEnablement(address indexed token, bool enabled, uint256 at);
    event VaultCredit(address indexed who, address indexed token, uint256 amount, uint256 newBal, uint256 at);
    event VaultDebit(address indexed who, address indexed token, uint256 amount, uint256 newBal, uint256 at);
    event IntentPosted(bytes32 indexed intentHash, address indexed maker, address inputToken, address outputToken, uint256 inputAmount, uint64 dstChainId, uint64 expiry);
    event IntentCancelled(bytes32 indexed intentHash, address indexed maker, uint64 nonce, uint256 at);
    event FillExecuted(bytes32 indexed intentHash, bytes32 indexed fillHash, address indexed filler, uint256 feePaid, uint256 at);
    event BridgeHint(bytes32 indexed intentHash, uint64 indexed dstChainId, bytes32 dstReceiver, bytes32 routeTag, uint256 at);
    event RiskFlag(bytes32 indexed intentHash, uint256 code, uint256 at);
    event RouteProfileSet(bytes32 indexed routeTag, uint64 indexed dstChainId, bool enabled, uint16 riskTier, uint32 latencyHintSec, address indexed curator, uint256 at);
    event RouteScoreSet(bytes32 indexed routeTag, uint256 oldScoreBps, uint256 newScoreBps, uint256 at);
    event PreferredFillerSet(address indexed maker, address indexed filler, bool allowed, uint256 at);
    event MakerMinFillSet(address indexed maker, uint256 oldMinBps, uint256 newMinBps, uint256 at);
    event VaultPermitUsed(address indexed maker, address indexed token, uint256 value, uint256 deadline, uint256 at);

    // ---- errors (unique prefixes) ----
    error HAV_Unauthorized();
    error HAV_BadConfig();
    error HAV_Expired();
    error HAV_IntentExists();
    error HAV_IntentMissing();
    error HAV_BadSig();
    error HAV_DisabledToken();
    error HAV_AmountTooSmall();
    error HAV_FeeTooHigh();
    error HAV_BalanceLow();
    error HAV_Replay();
    error HAV_NotReady();
    error HAV_CancelTooSoon();
    error HAV_BridgeMismatch();
    error HAV_RouteDisabled();
    error HAV_RouteRisky();
    error HAV_PreferenceDenied();
    error HAV_PermitFailed();

    // ---- allowlist (optional safety) ----
    mapping(address => bool) public tokenEnabled;

    // ---- optional token metadata cache (UI convenience) ----
    struct TokenInfo {
        uint8 decimals;
        bytes32 sym;
        bytes32 nam;
        uint48 updatedAt;
        bool ok;
    }

    mapping(address => TokenInfo) public tokenInfo;

    // ---- custody ledger ----
    mapping(address => mapping(address => uint256)) private _vault; // user => token => balance

    // ---- intent book ----
    struct Intent {
        address maker;
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minOutputAmount;
        uint64 dstChainId;
        bytes32 dstReceiver; // bytes32 to allow non-EVM receivers
        uint64 expiry;
        uint64 nonce;
        bytes32 strategyTag;
        uint256 maxFeeBps;
        uint64 createdAt;
        uint64 cancelEarliest;
    }

    mapping(bytes32 => Intent) private _intents;
    mapping(bytes32 => bool) public intentCancelled;
    mapping(address => mapping(uint64 => bool)) public nonceUsed;
    mapping(bytes32 => uint256) public filledInput; // intentHash => input amount consumed

    // ---- protocol fee ----
    uint256 public protocolFeeBps;

    // ---- route registry (offchain-aware hints) ----
    struct RouteProfile {
        bytes32 routeTag;
        uint64 dstChainId;
        uint16 riskTier; // 0..65535
        uint32 latencyHintSec;
        uint48 updatedAt;
        address curator;
        bool enabled;
    }

    mapping(bytes32 => RouteProfile) public routeProfiles; // routeTag => profile
    mapping(bytes32 => uint256) public routeScoreBps; // routeTag => scoring basis points (0..10000)

    // ---- maker preferences ----
    mapping(address => mapping(address => bool)) public preferredFiller; // maker => filler => allowed
    mapping(address => uint256) public makerMinFillBps; // maker => minimum output ratio bps (0 disables)

    // ---- risk ----
    mapping(bytes32 => uint256) public riskCode; // 0 = ok
    mapping(bytes32 => uint64) public riskAt;

    // ---- EIP-712 helpers ----
    function _domainSeparator() internal view returns (bytes32) {
        return EIP712_DOMAIN_SEPARATOR;
    }

    function _hashDomain(string memory name_, string memory ver_) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes(name_)),
                keccak256(bytes(ver_)),
                block.chainid,
                address(this)
            )
        );
    }

    function _toTypedDataHash(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }

    // ---- structs for filling ----
    struct YieldIntent {
        address maker;
        address inputToken;
        uint256 inputAmount;
        address outputToken;
        uint256 minOutputAmount;
        uint64 dstChainId;
        bytes32 dstReceiver;
        uint64 expiry;
        uint64 nonce;
        bytes32 strategyTag;
        uint256 maxFeeBps;
    }

    struct MatchFill {
        bytes32 intentHash;
        address filler;
        address payToken;
        uint256 payAmount;
        address receiveToken;
        uint256 receiveAmount;
        uint64 srcChainId;
        uint64 dstChainId;
        bytes32 routeTag;
        uint64 fillDeadline;
    }

    constructor() {
        guardian = MiniStrings.parseHexAddress(_GUARDIAN_STR);
        feeVault = MiniStrings.parseHexAddress(_FEE_VAULT_STR);
        executionRelay = MiniStrings.parseHexAddress(_RELAY_STR);
        riskOracle = MiniStrings.parseHexAddress(_RISK_ORACLE_STR);
        opsMultisig = MiniStrings.parseHexAddress(_OPS_STR);
        treasury = MiniStrings.parseHexAddress(_TREASURY_STR);
        insuranceFund = MiniStrings.parseHexAddress(_INSURANCE_STR);
        observatory = MiniStrings.parseHexAddress(_OBSERVATORY_STR);
        fallbackArb = MiniStrings.parseHexAddress(_FALLBACK_ARB_STR);

        owner = msg.sender;
        protocolFeeBps = PROTOCOL_FEE_BPS_DEFAULT;

        EIP712_DOMAIN_SEPARATOR = _hashDomain("HotelierAIV", "1.0.3");

        tokenEnabled[address(0)] = false;
        emit StewardSet(address(0), msg.sender, block.timestamp);
        emit ProtocolFeeChanged(0, protocolFeeBps, block.timestamp);
    }

    // ---- access ----
    modifier onlyOwner() {
        if (msg.sender != owner) revert HAV_Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian && msg.sender != opsMultisig) revert HAV_Unauthorized();
        _;
    }

    modifier onlyRiskOracle() {
        if (msg.sender != riskOracle && msg.sender != observatory) revert HAV_Unauthorized();
        _;
    }

    function setOwner(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert HAV_BadConfig();
        address old = owner;
        owner = newOwner;
        emit StewardSet(old, newOwner, block.timestamp);
    }

    function setProtocolFeeBps(uint256 newBps) external onlyOwner {
        if (newBps > MAX_FEE_BPS_CAP) revert HAV_FeeTooHigh();
        uint256 old = protocolFeeBps;
        protocolFeeBps = newBps;
        emit ProtocolFeeChanged(old, newBps, block.timestamp);
    }

    function setTokenEnabled(address token, bool enabled) external onlyOwner {
        if (token == address(0)) revert HAV_BadConfig();
        tokenEnabled[token] = enabled;
        emit TokenEnablement(token, enabled, block.timestamp);
    }

    function refreshTokenInfo(address token) external whenNotPaused returns (TokenInfo memory ti) {
        if (token == address(0)) revert HAV_BadConfig();
        // best-effort: not all tokens implement metadata
        uint8 dec = 18;
        bytes32 sym;
        bytes32 nam;
        bool ok;
        try IERC20Metadata(token).decimals() returns (uint8 d) {
            dec = d;
            ok = true;
        } catch {}
        try IERC20Metadata(token).symbol() returns (string memory s) {
            sym = keccak256(bytes(s));
            ok = true;
        } catch {}
        try IERC20Metadata(token).name() returns (string memory n) {
            nam = keccak256(bytes(n));
            ok = true;
        } catch {}
        ti = TokenInfo({decimals: dec, sym: sym, nam: nam, updatedAt: uint48(block.timestamp), ok: ok});
        tokenInfo[token] = ti;
    }

    function setRouteProfile(
        bytes32 routeTag,
        uint64 dstChainId,
        bool enabled,
        uint16 riskTier,
        uint32 latencyHintSec,
        address curator
    ) external onlyOwner {
        if (routeTag == bytes32(0)) revert HAV_BadConfig();
        if (dstChainId == 0) revert HAV_BadConfig();
        if (curator == address(0)) revert HAV_BadConfig();
        RouteProfile storage p = routeProfiles[routeTag];
        p.routeTag = routeTag;
        p.dstChainId = dstChainId;
        p.riskTier = riskTier;
        p.latencyHintSec = latencyHintSec;
        p.updatedAt = uint48(block.timestamp);
        p.curator = curator;
        p.enabled = enabled;
        emit RouteProfileSet(routeTag, dstChainId, enabled, riskTier, latencyHintSec, curator, block.timestamp);
    }

    function setRouteScore(bytes32 routeTag, uint256 newScoreBps) external onlyOwner {
        if (routeTag == bytes32(0)) revert HAV_BadConfig();
        if (newScoreBps > 10_000) revert HAV_BadConfig();
        uint256 old = routeScoreBps[routeTag];
        routeScoreBps[routeTag] = newScoreBps;
        emit RouteScoreSet(routeTag, old, newScoreBps, block.timestamp);
    }

    function pause(bool p) external onlyGuardian {
        _setPaused(p);
    }

    // ---- vault ----
    function vaultBalance(address who, address token) external view returns (uint256) {
        return _vault[who][token];
    }

    function deposit(address token, uint256 amount) external nonReentrant whenNotPaused {
        if (!tokenEnabled[token]) revert HAV_DisabledToken();
        if (amount <= DUST_GUARD) revert HAV_AmountTooSmall();
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 nb = _vault[msg.sender][token] + amount;
        _vault[msg.sender][token] = nb;
        emit VaultCredit(msg.sender, token, amount, nb, block.timestamp);
    }

    function depositWithPermit(
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant whenNotPaused {
        if (!tokenEnabled[token]) revert HAV_DisabledToken();
        if (amount <= DUST_GUARD) revert HAV_AmountTooSmall();
        try IERC20Permit(token).permit(msg.sender, address(this), amount, deadline, v, r, s) {
            emit VaultPermitUsed(msg.sender, token, amount, deadline, block.timestamp);
        } catch {
            revert HAV_PermitFailed();
        }
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        uint256 nb = _vault[msg.sender][token] + amount;
        _vault[msg.sender][token] = nb;
        emit VaultCredit(msg.sender, token, amount, nb, block.timestamp);
    }

    function batchDeposit(address[] calldata tokens, uint256[] calldata amounts) external nonReentrant whenNotPaused {
        uint256 n = tokens.length;
        if (n == 0 || n != amounts.length) revert HAV_BadConfig();
        for (uint256 i = 0; i < n; i++) {
            address t = tokens[i];
            uint256 a = amounts[i];
            if (!tokenEnabled[t]) revert HAV_DisabledToken();
            if (a <= DUST_GUARD) revert HAV_AmountTooSmall();
            IERC20(t).safeTransferFrom(msg.sender, address(this), a);
            uint256 nb = _vault[msg.sender][t] + a;
            _vault[msg.sender][t] = nb;
            emit VaultCredit(msg.sender, t, a, nb, block.timestamp);
        }
    }

    function batchWithdraw(address[] calldata tokens, uint256[] calldata amounts, address to) external nonReentrant whenNotPaused {
        uint256 n = tokens.length;
        if (to == address(0)) revert HAV_BadConfig();
        if (n == 0 || n != amounts.length) revert HAV_BadConfig();
        for (uint256 i = 0; i < n; i++) {
            address t = tokens[i];
            uint256 a = amounts[i];
            uint256 bal = _vault[msg.sender][t];
            if (a == 0 || a > bal) revert HAV_BalanceLow();
            unchecked {
                _vault[msg.sender][t] = bal - a;
            }
            IERC20(t).safeTransfer(to, a);
            emit VaultDebit(msg.sender, t, a, _vault[msg.sender][t], block.timestamp);
        }
    }

    function withdraw(address token, uint256 amount, address to) external nonReentrant whenNotPaused {
        if (to == address(0)) revert HAV_BadConfig();
        uint256 bal = _vault[msg.sender][token];
        if (amount == 0 || amount > bal) revert HAV_BalanceLow();
        unchecked {
            _vault[msg.sender][token] = bal - amount;
        }
        IERC20(token).safeTransfer(to, amount);
        emit VaultDebit(msg.sender, token, amount, _vault[msg.sender][token], block.timestamp);
    }

    // ---- intent hashing ----
    function hashIntent(YieldIntent memory it) public view returns (bytes32) {
        bytes32 sh = keccak256(
            abi.encode(
                INTENT_TYPEHASH,
                it.maker,
                it.inputToken,
                it.inputAmount,
                it.outputToken,
                it.minOutputAmount,
                it.dstChainId,
                it.dstReceiver,
                it.expiry,
                it.nonce,
                it.strategyTag,
                it.maxFeeBps
            )
        );
        return _toTypedDataHash(sh);
    }

    function hashFill(MatchFill memory f) public view returns (bytes32) {
        bytes32 sh = keccak256(
            abi.encode(
                MATCH_TYPEHASH,
                f.intentHash,
                f.filler,
                f.payToken,
                f.payAmount,
                f.receiveToken,
                f.receiveAmount,
                f.srcChainId,
                f.dstChainId,
                f.routeTag,
                f.fillDeadline
            )
        );
        return _toTypedDataHash(sh);
    }

    // ---- intent lifecycle ----
    function postIntent(YieldIntent calldata it, bytes calldata makerSig) external nonReentrant whenNotPaused returns (bytes32 intentHash) {
        if (it.maker == address(0)) revert HAV_BadConfig();
        if (it.inputToken == address(0) || it.outputToken == address(0)) revert HAV_BadConfig();
        if (!tokenEnabled[it.inputToken] || !tokenEnabled[it.outputToken]) revert HAV_DisabledToken();
        if (it.inputAmount <= DUST_GUARD || it.minOutputAmount <= DUST_GUARD) revert HAV_AmountTooSmall();
        if (it.maxFeeBps > MAX_FEE_BPS_CAP) revert HAV_FeeTooHigh();

        uint64 now64 = uint64(block.timestamp);
        if (it.expiry <= now64) revert HAV_Expired();
        if (it.expiry > now64 + MAX_INTENT_LIFETIME) revert HAV_BadConfig();
        if (nonceUsed[it.maker][it.nonce]) revert HAV_Replay();

        intentHash = hashIntent(it);
        if (_intents[intentHash].maker != address(0)) revert HAV_IntentExists();

        address signer = ECDSA.recover(intentHash, makerSig);
        if (signer != it.maker) revert HAV_BadSig();

        nonceUsed[it.maker][it.nonce] = true;

        uint256 bal = _vault[it.maker][it.inputToken];
        if (bal < it.inputAmount) revert HAV_BalanceLow();

        Intent memory st;
        st.maker = it.maker;
        st.inputToken = it.inputToken;
        st.inputAmount = it.inputAmount;
        st.outputToken = it.outputToken;
        st.minOutputAmount = it.minOutputAmount;
        st.dstChainId = it.dstChainId;
        st.dstReceiver = it.dstReceiver;
        st.expiry = it.expiry;
        st.nonce = it.nonce;
        st.strategyTag = it.strategyTag;
        st.maxFeeBps = it.maxFeeBps;
        st.createdAt = now64;
        st.cancelEarliest = now64 + MIN_CANCEL_DELAY;
        _intents[intentHash] = st;

        emit IntentPosted(intentHash, it.maker, it.inputToken, it.outputToken, it.inputAmount, it.dstChainId, it.expiry);
        emit BridgeHint(intentHash, it.dstChainId, it.dstReceiver, it.strategyTag, block.timestamp);
    }

    function postIntents(YieldIntent[] calldata intents, bytes[] calldata makerSigs) external nonReentrant whenNotPaused returns (bytes32[] memory hashes) {
        uint256 n = intents.length;
        if (n == 0 || n != makerSigs.length) revert HAV_BadConfig();
        hashes = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            hashes[i] = postIntent(intents[i], makerSigs[i]);
        }
    }

    function setPreferredFiller(address filler, bool allowed) external whenNotPaused {
        if (filler == address(0)) revert HAV_BadConfig();
        preferredFiller[msg.sender][filler] = allowed;
        emit PreferredFillerSet(msg.sender, filler, allowed, block.timestamp);
    }

    function setMakerMinFillBps(uint256 newMinBps) external whenNotPaused {
        if (newMinBps > 10_000) revert HAV_BadConfig();
        uint256 old = makerMinFillBps[msg.sender];
        makerMinFillBps[msg.sender] = newMinBps;
        emit MakerMinFillSet(msg.sender, old, newMinBps, block.timestamp);
    }

    function getIntent(bytes32 intentHash) external view returns (Intent memory) {
        Intent memory st = _intents[intentHash];
        if (st.maker == address(0)) revert HAV_IntentMissing();
        return st;
    }

    function cancelIntent(bytes32 intentHash) external nonReentrant whenNotPaused {
        Intent memory st = _intents[intentHash];
        if (st.maker == address(0)) revert HAV_IntentMissing();
        if (msg.sender != st.maker && msg.sender != owner && msg.sender != fallbackArb) revert HAV_Unauthorized();
        if (uint64(block.timestamp) < st.cancelEarliest) revert HAV_CancelTooSoon();

        delete _intents[intentHash];
        intentCancelled[intentHash] = true;
        emit IntentCancelled(intentHash, st.maker, st.nonce, block.timestamp);
    }

    // ---- risk signaling ----
    function setRisk(bytes32 intentHash, uint256 code) external onlyRiskOracle {
        // code 0 = clear
        riskCode[intentHash] = code;
        riskAt[intentHash] = uint64(block.timestamp);
        emit RiskFlag(intentHash, code, block.timestamp);
    }

    // ---- matching / settlement ----
    function previewFee(uint256 grossInput, uint256 maxFeeBps) public view returns (uint256 fee, uint256 net) {
        uint256 bps = protocolFeeBps;
        if (bps > maxFeeBps) bps = maxFeeBps;
        fee = grossInput.mulWad((bps * 1e14)); // bps / 1e4
        if (fee > grossInput) fee = grossInput;
        net = grossInput - fee;
    }

    function _available(bytes32 intentHash) internal view returns (uint256) {
        Intent memory st = _intents[intentHash];
        if (st.maker == address(0)) return 0;
        uint256 used = filledInput[intentHash];
        if (used >= st.inputAmount) return 0;
        return st.inputAmount - used;
    }

    function fillIntent(
        YieldIntent calldata it,
        bytes calldata makerSig,
        MatchFill calldata f,
        bytes calldata fillerSig
    ) external nonReentrant whenNotPaused returns (bytes32 intentHash, bytes32 fillHash) {
        intentHash = hashIntent(it);

        // intent presence / consistency
        Intent memory st = _intents[intentHash];
        if (st.maker == address(0)) revert HAV_IntentMissing();
        if (intentCancelled[intentHash]) revert HAV_IntentMissing();
        if (riskCode[intentHash] != 0) revert HAV_NotReady();
        if (uint64(block.timestamp) > st.expiry) revert HAV_Expired();

        // validate that the supplied intent fields match stored
        if (
            st.maker != it.maker ||
            st.inputToken != it.inputToken ||
            st.outputToken != it.outputToken ||
            st.inputAmount != it.inputAmount ||
            st.minOutputAmount != it.minOutputAmount ||
            st.dstChainId != it.dstChainId ||
            st.dstReceiver != it.dstReceiver ||
            st.nonce != it.nonce ||
            st.strategyTag != it.strategyTag ||
            st.maxFeeBps != it.maxFeeBps
        ) revert HAV_BadConfig();

        // signatures
        address mk = ECDSA.recover(intentHash, makerSig);
        if (mk != st.maker) revert HAV_BadSig();

        // fill struct checks
        if (f.intentHash != intentHash) revert HAV_BadConfig();
        if (f.fillDeadline < uint64(block.timestamp)) revert HAV_Expired();
        if (f.dstChainId != st.dstChainId) revert HAV_BridgeMismatch();
        if (f.srcChainId != uint64(block.chainid)) revert HAV_BadConfig();
        if (f.payToken != st.outputToken) revert HAV_BadConfig();
        if (f.receiveToken != st.inputToken) revert HAV_BadConfig();
        if (f.filler == address(0)) revert HAV_BadConfig();

        // filler signature binds the fill (optional: allow msg.sender without sig)
        fillHash = hashFill(f);
        address fl = ECDSA.recover(fillHash, fillerSig);
        if (fl != f.filler) revert HAV_BadSig();

        // route policy (optional)
        RouteProfile memory rp = routeProfiles[f.routeTag];
        if (rp.routeTag != bytes32(0)) {
            if (!rp.enabled) revert HAV_RouteDisabled();
            if (rp.dstChainId != st.dstChainId) revert HAV_BridgeMismatch();
            if (rp.riskTier > 900) {
                if (msg.sender != owner && msg.sender != opsMultisig) revert HAV_RouteRisky();
            }
        }

        // maker preferences (if configured)
        if (makerMinFillBps[st.maker] != 0) {
            if (!preferredFiller[st.maker][f.filler]) revert HAV_PreferenceDenied();
        }

        // enforce window hints
        uint64 now64 = uint64(block.timestamp);
        if (now64 > st.createdAt + SOFT_MATCH_WINDOW) {
            // beyond soft window, only allow owner/ops to fill to avoid stale AI behavior
            if (msg.sender != owner && msg.sender != opsMultisig && msg.sender != fallbackArb) revert HAV_Unauthorized();
        }

        // amounts
        if (f.payAmount < st.minOutputAmount) revert HAV_AmountTooSmall();
        uint256 avail = _available(intentHash);
        if (avail == 0) revert HAV_NotReady();
        if (f.receiveAmount == 0 || f.receiveAmount > avail) revert HAV_BadConfig();

        // maker min-fill ratio (optional)
        uint256 minBps = makerMinFillBps[st.maker];
        if (minBps != 0) {
            if (f.payAmount * 10_000 < f.receiveAmount * minBps) revert HAV_AmountTooSmall();
        }

        // fee & net
        (uint256 fee, uint256 netInput) = previewFee(f.receiveAmount, st.maxFeeBps);
        if (netInput == 0) revert HAV_AmountTooSmall();

        // debit maker vault
        uint256 makerBal = _vault[st.maker][st.inputToken];
        if (makerBal < f.receiveAmount) revert HAV_BalanceLow();
        unchecked {
            _vault[st.maker][st.inputToken] = makerBal - f.receiveAmount;
        }
        emit VaultDebit(st.maker, st.inputToken, f.receiveAmount, _vault[st.maker][st.inputToken], block.timestamp);

        // collect protocol fee
        if (fee != 0) {
            IERC20(st.inputToken).safeTransfer(feeVault, fee);
        }

        // pay filler with net input (same token as maker input)
        IERC20(st.inputToken).safeTransfer(f.filler, netInput);

        // collect filler payment token into contract, then send to maker treasury routing:
        // - for simplicity we credit maker vault in outputToken; maker can withdraw or route offchain.
        IERC20(st.outputToken).safeTransferFrom(f.filler, address(this), f.payAmount);
        uint256 nb = _vault[st.maker][st.outputToken] + f.payAmount;
        _vault[st.maker][st.outputToken] = nb;
        emit VaultCredit(st.maker, st.outputToken, f.payAmount, nb, block.timestamp);

        // accounting & finalization
        filledInput[intentHash] += f.receiveAmount;
        emit FillExecuted(intentHash, fillHash, f.filler, fee, block.timestamp);

        // if fully filled, clear intent
        if (filledInput[intentHash] >= st.inputAmount) {
            delete _intents[intentHash];
        }
    }

    function batchFillIntent(
        YieldIntent calldata it,
        bytes calldata makerSig,
        MatchFill[] calldata fills,
