// SPDX-License-Identifier: UNLICENSED
// Source: 0x61083249e50cf247ab83a8a207fbab4b8fabc23f
// Contract Name: VirtualRollup
// Generated on: 2026-05-14 11:58:35


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable2Step.sol)

pragma solidity ^0.8.0;

import "./OwnableUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership} and {acceptOwnership}.
 *
 * This module is used through inheritance. It will make available all functions
 * from parent (Ownable).
 */
abstract contract Ownable2StepUpgradeable is Initializable, OwnableUpgradeable {
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    function __Ownable2Step_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable2Step_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev Returns the address of the pending owner.
     */
    function pendingOwner() public view virtual returns (address) {
        return _pendingOwner;
    }

    /**
     * @dev Starts the ownership transfer of the contract to a new account. Replaces the pending transfer if there is one.
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual override onlyOwner {
        _pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner(), newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`) and deletes any pending owner.
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual override {
        delete _pendingOwner;
        super._transferOwnership(newOwner);
    }

    /**
     * @dev The new owner accepts the ownership transfer.
     */
    function acceptOwnership() public virtual {
        address sender = _msgSender();
        require(pendingOwner() == sender, "Ownable2Step: caller is not the new owner");
        _transferOwnership(sender);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/ContextUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function __Ownable_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable_init_unchained() internal onlyInitializing {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        _checkOwner();
        _;
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby disabling any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/interfaces/IERC5267Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC5267.sol)

pragma solidity ^0.8.0;

interface IERC5267Upgradeable {
    /**
     * @dev MAY be emitted to signal that the domain could have changed.
     */
    event EIP712DomainChanged();

    /**
     * @dev returns the fields and values that describe the domain separator used by this contract for EIP-712
     * signature.
     */
    function eip712Domain()
        external
        view
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        );
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.2;

import "../../utils/AddressUpgradeable.sol";

/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since proxied contracts do not make use of a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * The initialization functions use a version number. Once a version number is used, it is consumed and cannot be
 * reused. This mechanism prevents re-execution of each "step" but allows the creation of new initialization steps in
 * case an upgrade adds a module that needs to be initialized.
 *
 * For example:
 *
 * [.hljs-theme-light.nopadding]
 * ```solidity
 * contract MyToken is ERC20Upgradeable {
 *     function initialize() initializer public {
 *         __ERC20_init("MyToken", "MTK");
 *     }
 * }
 *
 * contract MyTokenV2 is MyToken, ERC20PermitUpgradeable {
 *     function initializeV2() reinitializer(2) public {
 *         __ERC20Permit_init("MyToken");
 *     }
 * }
 * ```
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {ERC1967Proxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 *
 * [CAUTION]
 * ====
 * Avoid leaving a contract uninitialized.
 *
 * An uninitialized contract can be taken over by an attacker. This applies to both a proxy and its implementation
 * contract, which may impact the proxy. To prevent the implementation contract from being used, you should invoke
 * the {_disableInitializers} function in the constructor to automatically lock it when it is deployed:
 *
 * [.hljs-theme-light.nopadding]
 * ```
 * /// @custom:oz-upgrades-unsafe-allow constructor
 * constructor() {
 *     _disableInitializers();
 * }
 * ```
 * ====
 */
abstract contract Initializable {
    /**
     * @dev Indicates that the contract has been initialized.
     * @custom:oz-retyped-from bool
     */
    uint8 private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint8 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that functions marked with `initializer` can be nested in the context of a
     * constructor.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        bool isTopLevelCall = !_initializing;
        require(
            (isTopLevelCall && _initialized < 1) || (!AddressUpgradeable.isContract(address(this)) && _initialized == 1),
            "Initializable: contract is already initialized"
        );
        _initialized = 1;
        if (isTopLevelCall) {
            _initializing = true;
        }
        _;
        if (isTopLevelCall) {
            _initializing = false;
            emit Initialized(1);
        }
    }

    /**
     * @dev A modifier that defines a protected reinitializer function that can be invoked at most once, and only if the
     * contract hasn't been initialized to a greater version before. In its scope, `onlyInitializing` functions can be
     * used to initialize parent contracts.
     *
     * A reinitializer may be used after the original initialization step. This is essential to configure modules that
     * are added through upgrades and that require initialization.
     *
     * When `version` is 1, this modifier is similar to `initializer`, except that functions marked with `reinitializer`
     * cannot be nested. If one is invoked in the context of another, execution will revert.
     *
     * Note that versions can jump in increments greater than 1; this implies that if multiple reinitializers coexist in
     * a contract, executing them in the right order is up to the developer or operator.
     *
     * WARNING: setting the version to 255 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint8 version) {
        require(!_initializing && _initialized < version, "Initializable: contract is already initialized");
        _initialized = version;
        _initializing = true;
        _;
        _initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        require(_initializing, "Initializable: contract is not initializing");
        _;
    }

    /**
     * @dev Locks the contract, preventing any future reinitialization. This cannot be part of an initializer call.
     * Calling this in the constructor of a contract will prevent that contract from being initialized or reinitialized
     * to any version. It is recommended to use this to lock implementation contracts that are designed to be called
     * through proxies.
     *
     * Emits an {Initialized} event the first time it is successfully executed.
     */
    function _disableInitializers() internal virtual {
        require(!_initializing, "Initializable: contract is initializing");
        if (_initialized != type(uint8).max) {
            _initialized = type(uint8).max;
            emit Initialized(type(uint8).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint8) {
        return _initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _initializing;
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)

pragma solidity ^0.8.0;

import "../utils/ContextUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract PausableUpgradeable is Initializable, ContextUpgradeable {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    function __Pausable_init() internal onlyInitializing {
        __Pausable_init_unchained();
    }

    function __Pausable_init_unchained() internal onlyInitializing {
        _paused = false;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        _requireNotPaused();
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        _requirePaused();
        _;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (security/ReentrancyGuard.sol)

pragma solidity ^0.8.0;
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuardUpgradeable is Initializable {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    function __ReentrancyGuard_init() internal onlyInitializing {
        __ReentrancyGuard_init_unchained();
    }

    function __ReentrancyGuard_init_unchained() internal onlyInitializing {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be _NOT_ENTERED
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == _ENTERED;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20PermitUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.4) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * ==== Security Considerations
 *
 * There are two important considerations concerning the use of `permit`. The first is that a valid permit signature
 * expresses an allowance, and it should not be assumed to convey additional meaning. In particular, it should not be
 * considered as an intention to spend the allowance in any specific way. The second is that because permits have
 * built-in replay protection and can be submitted by anyone, they can be frontrun. A protocol that uses permits should
 * take this into consideration and allow a `permit` call to fail. Combining these two aspects, a pattern that may be
 * generally recommended is:
 *
 * ```solidity
 * function doThingWithPermit(..., uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public {
 *     try token.permit(msg.sender, address(this), value, deadline, v, r, s) {} catch {}
 *     doThing(..., value);
 * }
 *
 * function doThing(..., uint256 value) public {
 *     token.safeTransferFrom(msg.sender, address(this), value);
 *     ...
 * }
 * ```
 *
 * Observe that: 1) `msg.sender` is used as the owner, leaving no ambiguity as to the signer intent, and 2) the use of
 * `try/catch` allows the permit to fail and makes the code tolerant to frontrunning. (See also
 * {SafeERC20-safeTransferFrom}).
 *
 * Additionally, note that smart contract wallets (such as Argent or Safe) are not able to produce permit signatures, so
 * contracts should have entry points that don't rely on permit.
 */
interface IERC20PermitUpgradeable {
    /**
     * @dev Sets `value` as the allowance of `spender` over ``owner``'s tokens,
     * given ``owner``'s signed approval.
     *
     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
     * ordering also apply here.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     *
     * For more information on the signature format, see the
     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
     * section].
     *
     * CAUTION: See Security Considerations above.
     */
    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for {permit}, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20Upgradeable {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.3) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.0;

import "../IERC20Upgradeable.sol";
import "../extensions/IERC20PermitUpgradeable.sol";
import "../../../utils/AddressUpgradeable.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20Upgradeable {
    using AddressUpgradeable for address;

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20Upgradeable token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20Upgradeable token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20Upgradeable token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        require(
            (value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeIncreaseAllowance(IERC20Upgradeable token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance + value));
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeDecreaseAllowance(IERC20Upgradeable token, address spender, uint256 value) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance - value));
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function forceApprove(IERC20Upgradeable token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeWithSelector(token.approve.selector, spender, value);

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, 0));
            _callOptionalReturn(token, approvalCall);
        }
    }

    /**
     * @dev Use a ERC-2612 signature to set the `owner` approval toward `spender` on `token`.
     * Revert on invalid signature.
     */
    function safePermit(
        IERC20PermitUpgradeable token,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        uint256 nonceBefore = token.nonces(owner);
        token.permit(owner, spender, value, deadline, v, r, s);
        uint256 nonceAfter = token.nonces(owner);
        require(nonceAfter == nonceBefore + 1, "SafeERC20: permit did not succeed");
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20Upgradeable token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address-functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        require(returndata.length == 0 || abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     *
     * This is a variant of {_callOptionalReturn} that silents catches all reverts and returns a bool instead.
     */
    function _callOptionalReturnBool(IERC20Upgradeable token, bytes memory data) private returns (bool) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return
            success && (returndata.length == 0 || abi.decode(returndata, (bool))) && AddressUpgradeable.isContract(address(token));
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)

pragma solidity ^0.8.1;

/**
 * @dev Collection of functions related to the address type
 */
library AddressUpgradeable {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     *
     * Furthermore, `isContract` will also return true if the target contract within
     * the same transaction is already scheduled for destruction by `SELFDESTRUCT`,
     * which only has an effect at the end of a transaction.
     * ====
     *
     * [IMPORTANT]
     * ====
     * You shouldn't rely on `isContract` to protect against flash loan attacks!
     *
     * Preventing calls from contracts is highly discouraged. It breaks composability, breaks support for smart wallets
     * like Gnosis Safe, and does not provide security since it can be circumvented by calling from a contract
     * constructor.
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize/address.code.length, which returns 0
        // for contracts in construction, since the code is only stored at the end
        // of the constructor execution.

        return account.code.length > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://consensys.net/diligence/blog/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.8.0/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(
        address target,
        bytes memory data,
        uint256 value,
        string memory errorMessage
    ) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(
        address target,
        bytes memory data,
        string memory errorMessage
    ) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata, errorMessage);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and revert (either by bubbling
     * the revert reason or using the provided one) in case of unsuccessful call or if target was not a contract.
     *
     * _Available since v4.8._
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal view returns (bytes memory) {
        if (success) {
            if (returndata.length == 0) {
                // only check isContract if the call was successful and the return data is empty
                // otherwise we already know that it was a contract
                require(isContract(target), "Address: call to non-contract");
            }
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and revert if it wasn't, either by bubbling the
     * revert reason or using the provided one.
     *
     * _Available since v4.3._
     */
    function verifyCallResult(
        bool success,
        bytes memory returndata,
        string memory errorMessage
    ) internal pure returns (bytes memory) {
        if (success) {
            return returndata;
        } else {
            _revert(returndata, errorMessage);
        }
    }

    function _revert(bytes memory returndata, string memory errorMessage) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert(errorMessage);
        }
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/ContextUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.4) (utils/Context.sol)

pragma solidity ^0.8.0;
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract ContextUpgradeable is Initializable {
    function __Context_init() internal onlyInitializing {
    }

    function __Context_init_unchained() internal onlyInitializing {
    }
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.0;

import "../StringsUpgradeable.sol";

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSAUpgradeable {
    enum RecoverError {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV // Deprecated in v4.8
    }

    function _throwError(RecoverError error) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert("ECDSA: invalid signature");
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert("ECDSA: invalid signature length");
        } else if (error == RecoverError.InvalidSignatureS) {
            revert("ECDSA: invalid signature 's' value");
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature` or error string. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError) {
        if (signature.length == 65) {
            bytes32 r;
            bytes32 s;
            uint8 v;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                s := mload(add(signature, 0x40))
                v := byte(0, mload(add(signature, 0x60)))
            }
            return tryRecover(hash, v, r, s);
        } else {
            return (address(0), RecoverError.InvalidSignatureLength);
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, signature);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError) {
        bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
        uint8 v = uint8((uint256(vs) >> 255) + 27);
        return tryRecover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     *
     * _Available since v4.2._
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, r, vs);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     *
     * _Available since v4.3._
     */
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, RecoverError) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return (address(0), RecoverError.InvalidSignatureS);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature);
        }

        return (signer, RecoverError.NoError);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error) = tryRecover(hash, v, r, s);
        _throwError(error);
        return recovered;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 message) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32")
            mstore(0x1c, hash)
            message := keccak256(0x00, 0x3c)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from `s`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", StringsUpgradeable.toString(s.length), s));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 data) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, "\x19\x01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            data := keccak256(ptr, 0x42)
        }
    }

    /**
     * @dev Returns an Ethereum Signed Data with intended validator, created from a
     * `validator` and `data` according to the version 0 of EIP-191.
     *
     * See {recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x00", validator, data));
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/EIP712.sol)

pragma solidity ^0.8.8;

import "./ECDSAUpgradeable.sol";
import "../../interfaces/IERC5267Upgradeable.sol";
import {Initializable} from "../../proxy/utils/Initializable.sol";

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
 * they need in their contracts using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 *
 * NOTE: In the upgradeable version of this contract, the cached values will correspond to the address, and the domain
 * separator of the implementation contract. This will cause the `_domainSeparatorV4` function to always rebuild the
 * separator from the immutable values, which is cheaper than accessing a cached version in cold storage.
 *
 * _Available since v3.4._
 *
 * @custom:storage-size 52
 */
abstract contract EIP712Upgradeable is Initializable, IERC5267Upgradeable {
    bytes32 private constant _TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @custom:oz-renamed-from _HASHED_NAME
    bytes32 private _hashedName;
    /// @custom:oz-renamed-from _HASHED_VERSION
    bytes32 private _hashedVersion;

    string private _name;
    string private _version;

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    function __EIP712_init(string memory name, string memory version) internal onlyInitializing {
        __EIP712_init_unchained(name, version);
    }

    function __EIP712_init_unchained(string memory name, string memory version) internal onlyInitializing {
        _name = name;
        _version = version;

        // Reset prior values in storage if upgrading
        _hashedName = 0;
        _hashedVersion = 0;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        return _buildDomainSeparator();
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(_TYPE_HASH, _EIP712NameHash(), _EIP712VersionHash(), block.chainid, address(this)));
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSAUpgradeable.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    /**
     * @dev See {EIP-5267}.
     *
     * _Available since v4.9._
     */
    function eip712Domain()
        public
        view
        virtual
        override
        returns (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        )
    {
        // If the hashed name and version in storage are non-zero, the contract hasn't been properly initialized
        // and the EIP712 domain is not reliable, as it will be missing name and version.
        require(_hashedName == 0 && _hashedVersion == 0, "EIP712: Uninitialized");

        return (
            hex"0f", // 01111
            _EIP712Name(),
            _EIP712Version(),
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    /**
     * @dev The name parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712Name() internal virtual view returns (string memory) {
        return _name;
    }

    /**
     * @dev The version parameter for the EIP712 domain.
     *
     * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
     * are a concern.
     */
    function _EIP712Version() internal virtual view returns (string memory) {
        return _version;
    }

    /**
     * @dev The hash of the name parameter for the EIP712 domain.
     *
     * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Name` instead.
     */
    function _EIP712NameHash() internal view returns (bytes32) {
        string memory name = _EIP712Name();
        if (bytes(name).length > 0) {
            return keccak256(bytes(name));
        } else {
            // If the name is empty, the contract may have been upgraded without initializing the new storage.
            // We return the name hash in storage if non-zero, otherwise we assume the name is empty by design.
            bytes32 hashedName = _hashedName;
            if (hashedName != 0) {
                return hashedName;
            } else {
                return keccak256("");
            }
        }
    }

    /**
     * @dev The hash of the version parameter for the EIP712 domain.
     *
     * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Version` instead.
     */
    function _EIP712VersionHash() internal view returns (bytes32) {
        string memory version = _EIP712Version();
        if (bytes(version).length > 0) {
            return keccak256(bytes(version));
        } else {
            // If the version is empty, the contract may have been upgraded without initializing the new storage.
            // We return the version hash in storage if non-zero, otherwise we assume the version is empty by design.
            bytes32 hashedVersion = _hashedVersion;
            if (hashedVersion != 0) {
                return hashedVersion;
            } else {
                return keccak256("");
            }
        }
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[48] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/math/MathUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library MathUpgradeable {
    enum Rounding {
        Down, // Toward negative infinity
        Up, // Toward infinity
        Zero // Toward zero
    }

    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow.
        return (a & b) + (a ^ b) / 2;
    }

    /**
     * @dev Returns the ceiling of the division of two numbers.
     *
     * This differs from standard division with `/` in that it rounds up instead
     * of rounding down.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or denominator == 0
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv)
     * with further edits by Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }

            // Handle non-overflow cases, 256 by 256 division.
            if (prod1 == 0) {
                // Solidity will revert if denominator == 0, unlike the div opcode on its own.
                // The surrounding unchecked block does not change this fact.
                // See https://docs.soliditylang.org/en/latest/control-structures.html#checked-or-unchecked-arithmetic.
                return prod0 / denominator;
            }

            // Make sure the result is less than 2^256. Also prevents denominator == 0.
            require(denominator > prod1, "Math: mulDiv overflow");

            ///////////////////////////////////////////////
            // 512 by 256 division.
            ///////////////////////////////////////////////

            // Make division exact by subtracting the remainder from [prod1 prod0].
            uint256 remainder;
            assembly {
                // Compute remainder using mulmod.
                remainder := mulmod(x, y, denominator)

                // Subtract 256 bit number from 512 bit number.
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator. Always >= 1.
            // See https://cs.stackexchange.com/q/138556/92363.

            // Does not overflow because the denominator cannot be zero at this stage in the function.
            uint256 twos = denominator & (~denominator + 1);
            assembly {
                // Divide denominator by twos.
                denominator := div(denominator, twos)

                // Divide [prod1 prod0] by twos.
                prod0 := div(prod0, twos)

                // Flip twos such that it is 2^256 / twos. If twos is zero, then it becomes one.
                twos := add(div(sub(0, twos), twos), 1)
            }

            // Shift in bits from prod1 into prod0.
            prod0 |= prod1 * twos;

            // Invert denominator mod 2^256. Now that denominator is an odd number, it has an inverse modulo 2^256 such
            // that denominator * inv = 1 mod 2^256. Compute the inverse by starting with a seed that is correct for
            // four bits. That is, denominator * inv = 1 mod 2^4.
            uint256 inverse = (3 * denominator) ^ 2;

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also works
            // in modular arithmetic, doubling the correct bits in each step.
            inverse *= 2 - denominator * inverse; // inverse mod 2^8
            inverse *= 2 - denominator * inverse; // inverse mod 2^16
            inverse *= 2 - denominator * inverse; // inverse mod 2^32
            inverse *= 2 - denominator * inverse; // inverse mod 2^64
            inverse *= 2 - denominator * inverse; // inverse mod 2^128
            inverse *= 2 - denominator * inverse; // inverse mod 2^256

            // Because the division is now exact we can divide by multiplying with the modular inverse of denominator.
            // This will give us the correct result modulo 2^256. Since the preconditions guarantee that the outcome is
            // less than 2^256, this is the final result. We don't need to compute the high bits of the result and prod1
            // is no longer required.
            result = prod0 * inverse;
            return result;
        }
    }

    /**
     * @notice Calculates x * y / denominator with full precision, following the selected rounding direction.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator, Rounding rounding) internal pure returns (uint256) {
        uint256 result = mulDiv(x, y, denominator);
        if (rounding == Rounding.Up && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded down.
     *
     * Inspired by Henry S. Warren, Jr.'s "Hacker's Delight" (Chapter 11).
     */
    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        // For our first guess, we get the biggest power of 2 which is smaller than the square root of the target.
        //
        // We know that the "msb" (most significant bit) of our target number `a` is a power of 2 such that we have
        // `msb(a) <= a < 2*msb(a)`. This value can be written `msb(a)=2**k` with `k=log2(a)`.
        //
        // This can be rewritten `2**log2(a) <= a < 2**(log2(a) + 1)`
        // → `sqrt(2**k) <= sqrt(a) < sqrt(2**(k+1))`
        // → `2**(k/2) <= sqrt(a) < 2**((k+1)/2) <= 2**(k/2 + 1)`
        //
        // Consequently, `2**(log2(a) / 2)` is a good first approximation of `sqrt(a)` with at least 1 correct bit.
        uint256 result = 1 << (log2(a) >> 1);

        // At this point `result` is an estimation with one bit of precision. We know the true value is a uint128,
        // since it is the square root of a uint256. Newton's method converges quadratically (precision doubles at
        // every iteration). We thus need at most 7 iteration to turn our partial result with one bit of precision
        // into the expected uint128 result.
        unchecked {
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            result = (result + a / result) >> 1;
            return min(result, a / result);
        }
    }

    /**
     * @notice Calculates sqrt(a), following the selected rounding direction.
     */
    function sqrt(uint256 a, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = sqrt(a);
            return result + (rounding == Rounding.Up && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 128;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 64;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 32;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 16;
            }
            if (value >> 8 > 0) {
                value >>= 8;
                result += 8;
            }
            if (value >> 4 > 0) {
                value >>= 4;
                result += 4;
            }
            if (value >> 2 > 0) {
                value >>= 2;
                result += 2;
            }
            if (value >> 1 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 2, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log2(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log2(value);
            return result + (rounding == Rounding.Up && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10, rounded down, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >= 10 ** 64) {
                value /= 10 ** 64;
                result += 64;
            }
            if (value >= 10 ** 32) {
                value /= 10 ** 32;
                result += 32;
            }
            if (value >= 10 ** 16) {
                value /= 10 ** 16;
                result += 16;
            }
            if (value >= 10 ** 8) {
                value /= 10 ** 8;
                result += 8;
            }
            if (value >= 10 ** 4) {
                value /= 10 ** 4;
                result += 4;
            }
            if (value >= 10 ** 2) {
                value /= 10 ** 2;
                result += 2;
            }
            if (value >= 10 ** 1) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 10, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log10(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log10(value);
            return result + (rounding == Rounding.Up && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256, rounded down, of a positive value.
     * Returns 0 if given 0.
     *
     * Adding one to the result gives the number of pairs of hex symbols needed to represent `value` as a hex string.
     */
    function log256(uint256 value) internal pure returns (uint256) {
        uint256 result = 0;
        unchecked {
            if (value >> 128 > 0) {
                value >>= 128;
                result += 16;
            }
            if (value >> 64 > 0) {
                value >>= 64;
                result += 8;
            }
            if (value >> 32 > 0) {
                value >>= 32;
                result += 4;
            }
            if (value >> 16 > 0) {
                value >>= 16;
                result += 2;
            }
            if (value >> 8 > 0) {
                result += 1;
            }
        }
        return result;
    }

    /**
     * @dev Return the log in base 256, following the selected rounding direction, of a positive value.
     * Returns 0 if given 0.
     */
    function log256(uint256 value, Rounding rounding) internal pure returns (uint256) {
        unchecked {
            uint256 result = log256(value);
            return result + (rounding == Rounding.Up && 1 << (result << 3) < value ? 1 : 0);
        }
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/math/SignedMathUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMathUpgradeable {
    /**
     * @dev Returns the largest of two signed numbers.
     */
    function max(int256 a, int256 b) internal pure returns (int256) {
        return a > b ? a : b;
    }

    /**
     * @dev Returns the smallest of two signed numbers.
     */
    function min(int256 a, int256 b) internal pure returns (int256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two signed numbers without overflow.
     * The result is rounded towards zero.
     */
    function average(int256 a, int256 b) internal pure returns (int256) {
        // Formula from the book "Hacker's Delight"
        int256 x = (a & b) + ((a ^ b) >> 1);
        return x + (int256(uint256(x) >> 255) & (a ^ b));
    }

    /**
     * @dev Returns the absolute unsigned value of a signed value.
     */
    function abs(int256 n) internal pure returns (uint256) {
        unchecked {
            // must be unchecked in order to support `n = type(int256).min`
            return uint256(n >= 0 ? n : -n);
        }
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)

pragma solidity ^0.8.0;

import "./math/MathUpgradeable.sol";
import "./math/SignedMathUpgradeable.sol";

/**
 * @dev String operations.
 */
library StringsUpgradeable {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = MathUpgradeable.log10(value) + 1;
            string memory buffer = new string(length);
            uint256 ptr;
            /// @solidity memory-safe-assembly
            assembly {
                ptr := add(buffer, add(32, length))
            }
            while (true) {
                ptr--;
                /// @solidity memory-safe-assembly
                assembly {
                    mstore8(ptr, byte(mod(value, 10), _SYMBOLS))
                }
                value /= 10;
                if (value == 0) break;
            }
            return buffer;
        }
    }

    /**
     * @dev Converts a `int256` to its ASCII `string` decimal representation.
     */
    function toString(int256 value) internal pure returns (string memory) {
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMathUpgradeable.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, MathUpgradeable.log256(value) + 1);
        }
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _SYMBOLS[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), _ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}


// ============================================================================
// FILE: contracts/rollups/VirtualRollup.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Openzeppelin Contracts
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/IERC20Upgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {SafeERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import {StringsUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/StringsUpgradeable.sol";

// Custom Errors
error AccessDenied();
error DisputeChallengeFailed();
error DisputeWindowClosed();
error DisputeWindowNotClosed();
error ECRecoverFailed();
error NotRollupToken();
error InsufficientFunds();
error InvalidAddress();
error InvalidBuyIn();
error InvalidConversion();
error InvalidNumberOfParticipants();
error InvalidParticipant();
error InvalidRange();
error InvalidSchnorrSignature();
error InvalidSessionStatus();
error InvalidSignature();
error InvalidSP();
error RequestFinishSessionRequired();
error SessionNotExist();
error SettleDisputeFailed();
error SessionInDispute();
error SessionInRequestReview();

/**
 * @title VirtualRollup
 * @author Virtual Labs
 * @dev A smart contract representing a virtual rollup for off-chain gaming interactions.
 * This contract allows users to create and join sessions, deposit funds to active sessions,
 * and finish sessions with verified balances.
 */
contract VirtualRollup is
    Initializable,
    Ownable2StepUpgradeable,
    PausableUpgradeable,
    ReentrancyGuardUpgradeable,
    EIP712Upgradeable
{
    using SafeERC20Upgradeable for IERC20Upgradeable;
    using StringsUpgradeable for uint16;

    // Enums
    enum SessionStatus {
        None,
        Created,
        Finished,
        InDispute
    }

    enum DisputeStatus {
        None,
        Opened,
        Challenged,
        Settled
    }

    enum SchnorrSignatureProofType {
        Round,
        Join,
        Leave,
        Remove,
        Final
    }

    // Structs
    struct RollupToken {
        uint96 minBuyIn;
        uint96 maxBuyIn;
        uint8 supported;
    }

    struct Session {
        address token;
        address combinedPublicKey;
        uint8 status;
    }

    struct SchnorrSignature {
        bytes data;
        bytes signature;
        address combinedPublicKey;
    }

    struct SchnorrData {
        uint32 schnorrSignatureId;
        address signatureFor;
        address[] participants;
        uint96[] balances;
        uint8 proofType;
    }

    struct Dispute {
        address user;
        address challenger;
        uint64 timestamp;
        uint8 status;
    }

    // State Variables
    uint256 private constant SECP256K1_CURVE_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    bytes32 private constant FINISH_SESSION_TYPEHASH =
        keccak256(
            "FinishSession(uint32 sessionId,uint96 balance,address participant,uint32 rn)"
        );
    bytes32 private constant JOIN_SESSION_TYPEHASH =
        keccak256(
            "JoinSession(address participant,uint96 buyIn,address combinedPublicKey)"
        );
    bytes32 private constant LEAVE_SESSION_TYPEHASH =
        keccak256(
            "LeaveSession(address participant,uint96 amount,address combinedPublicKey)"
        );
    bytes32 private constant REMOVE_PARTICIPANT_TYPEHASH =
        keccak256(
            "RemoveParticipant(address participant,uint96 amount,address combinedPublicKey)"
        );

    uint16 public ROLLUP_ID;
    bytes32 public DOMAIN_SEPARATOR;

    mapping(uint96 => Session) public sessions;
    mapping(address => RollupToken) public rollupTokens;
    mapping(address => mapping(address => uint96)) public userDeposits;
    
    uint32 private _sessionIdCounter;
    uint32 private _requestIdCounter;
    address private _trustedSigner;
    address private _rollupAdmin;

    mapping(bytes => bool) private _schnorrSignatureUsed;
    mapping(uint32 => uint32) private _latestSessionSchnorrSignatureId;
    mapping(uint32 => Dispute) private _disputes;
    mapping(bytes => bool) private _signatureUsed;
    mapping(address => uint96) public lockedFunds;

    // Events
    event RollupTokenAdded(
        address indexed token,
        uint96 minBuyIn,
        uint96 maxBuyIn
    );
    event RollupTokenRemoved(address indexed token);
    event TrustedSignerChanged(
        address indexed prevSigner,
        address indexed newSigner
    );
    event SessionCreated(
        uint32 indexed sessionId,
        address indexed creator,
        uint96 buyIn
    );
    event SessionFinished(uint32 indexed sessionId);
    event JoinedSession(
        uint32 indexed sessionId,
        address indexed user,
        uint96 buyIn
    );
    event LeftSession(
        uint32 indexed sessionId,
        address indexed user,
        uint96 amount
    );
    event FinishSessionRequested(uint32 requestId, uint32 indexed sessionId);
    event RemoveParticipantRequested(
        uint32 requestId,
        uint32 indexed sessionId,
        address indexed participant,
        uint96 amount
    );
    event Deposit(address indexed user, address indexed token, uint96 amount);
    event Withdraw(address indexed user, address indexed token, uint96 amount);
    event DisputeOpened(
        uint32 requestId,
        uint32 indexed sessionId,
        uint32 schnorrSignatureId,
        address indexed user
    );
    event DisputeChallenged(
        uint32 requestId,
        uint32 indexed sessionId,
        uint32 schnorrSignatureId
    );
    event DisputeSettled(
        uint32 requestId,
        uint32 indexed sessionId,
        uint32 schnorrSignatureId
    );
    event SchnorrSignatureUpdated(
        uint32 indexed sessionId,
        address indexed combinedPublicKey
    );

    modifier onlyAdmins() {
        if (msg.sender != owner() && msg.sender != _rollupAdmin) {
            revert AccessDenied();
        }

        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /**
     * @dev Initializes the VirtualRollup contract with the provided rollup ID and signer address.
     *
     * Requirements:
     * - This function should only be called once during contract deployment.
     *
     * @param _rollupId (uint16) The ID of the rollup.
     * @param _signer (address) The address of the trusted signer.
     */
    function initialize(
        uint16 _rollupId,
        address _signer
    ) external initializer {
        __Ownable2Step_init();
        __Pausable_init();
        __EIP712_init("VirtualRollup", _rollupId.toString());

        setTrustedSigner(_signer);

        ROLLUP_ID = _rollupId;
        DOMAIN_SEPARATOR = _domainSeparatorV4();
    }

    /**
     * @dev Pauses contract functionality.
     *
     * Emits a {Paused} event.
     *
     * Requirements:
     * - The caller must be the contract owner.
     */
    function pause() external onlyAdmins {
        _pause();
    }

    /**
     * @dev Unpauses contract functionality.
     *
     * Emits an {Unpaused} event.
     *
     * Requirements:
     * - The caller must be the contract owner.
     */
    function unpause() external onlyAdmins {
        _unpause();
    }

    /**
     * @dev Adds a new rollup token with the specified details.
     *
     * Emits a {RollupTokenAdded} event.
     *
     * Requirements:
     * - The caller must be the contract owner.
     * - The provided `_minBuyIn` must be less than or equal to `_maxBuyIn`.
     * - `_minBuyIn` and `_maxBuyIn` must not be zero.
     *
     * @param _token (address) The address of the added token.
     * @param _minBuyIn (uint96) The minimum buy-in amount for the token.
     * @param _maxBuyIn (uint96) The maximum buy-in amount for the token.
     */
    function addRollupToken(
        address _token,
        uint96 _minBuyIn,
        uint96 _maxBuyIn
    ) external onlyAdmins {
        if (_minBuyIn > _maxBuyIn || _minBuyIn == 0 || _maxBuyIn == 0) {
            revert InvalidRange();
        }

        rollupTokens[_token] = RollupToken(_minBuyIn, _maxBuyIn, uint8(1));

        emit RollupTokenAdded(_token, _minBuyIn, _maxBuyIn);
    }

    /**
     * @dev Removes a rollup token.
     *
     * Emits a {RollupTokenRemoved} event.
     *
     * Requirements:
     * - The caller must be the contract owner.
     *
     * @param _token (address) The address of the removed token.
     */
    function removeRollupToken(address _token) external onlyAdmins {
        delete rollupTokens[_token];

        emit RollupTokenRemoved(_token);
    }

    function setRollupAdmin(address _admin) external onlyOwner {
        _rollupAdmin = _admin;
    }

    /**
     * @dev Deposits specified amount of tokens into the contract as reserves.
     *
     * Emits a {Deposit} event.
     *
     * Requirements:
     * - The caller must be the contract owner.
     *
     * @param _token (address) The address of the deposited token.
     * @param _amount (uint96) The amount of tokens deposited.
     */
    function depositRollupReserves(
        address _token,
        uint96 _amount
    ) external whenNotPaused onlyAdmins {
        IERC20Upgradeable(_token).safeTransferFrom(
            msg.sender,
            address(this),
            _amount
        );
        lockedFunds[_token] += _amount;

        emit Deposit(msg.sender, _token, _amount);
    }

    function withdrawRollupReserves(
        address _token,
        uint96 _amount
    ) external whenNotPaused onlyAdmins {
        if (lockedFunds[_token] < _amount) {
            revert InsufficientFunds();
        }

        IERC20Upgradeable(_token).transfer(msg.sender, _amount);
        lockedFunds[_token] -= _amount;

        emit Withdraw(msg.sender, _token, _amount);
    }

    /**
     * @dev Creates a new session.
     *
     * Emits a {SessionCreated} event and a {JoinedSession} event for the session creator.
     *
     * Requirements:
     * - The provided `_token` must be a valid rollup token.
     * - The `_buyIn` amount must be in the contract's buy-in range of the token.
     *
     * @param _token (address) The address of the token for the session.
     * @param _buyIn (uint96) The buy-in amount for the session.
     * @param _combinedPublicKey (address) The combined public key for the session.
     */
    function createSession(
        address _token,
        uint96 _buyIn,
        address _combinedPublicKey
    ) external payable whenNotPaused nonReentrant {
        _checkRollupToken(_token, _buyIn);

        _deposit(msg.sender, _token, _buyIn);

        _sessionIdCounter = _sessionIdCounter + 1;

        uint32 newSessionId = _sessionIdCounter;

        sessions[newSessionId] = Session(
            _token,
            _combinedPublicKey,
            uint8(SessionStatus.Created)
        );

        emit SessionCreated(newSessionId, msg.sender, _buyIn);

        emit JoinedSession(newSessionId, msg.sender, _buyIn);
    }

    /**
     * @dev Request to finish a session.
     *
     * Emits a {FinishSessionRequested} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The input parameters `_participants` and `_balances` must be same as the one signed by trusted signer.
     *
     * @param _sessionId (uint32) The ID of the session to finish.
     * @param _participant (address[] calldata) The array of participant addresses for the session.
     * @param _balance (uint96[] calldata) The array of final balances of each participant for the session.
     * @param _signature (bytes calldata) The signature signed by trusted signer to verify the input data.
     */
    function requestFinishSession(
        uint32 _sessionId,
        address _participant,
        uint96 _balance,
        bytes calldata _signature,
        uint32 _rn
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            FINISH_SESSION_TYPEHASH,
                            _sessionId,
                            _balance,
                            _participant,
                            _rn
                        )
                    )
                )
            ),
            _signature
        );

        _requestIdCounter = _requestIdCounter + 1;

        uint32 newRequestId = _requestIdCounter;

        _disputes[newRequestId].timestamp = uint64(block.timestamp);

        emit FinishSessionRequested(newRequestId, _sessionId);
    }

    function finishSession(
        uint32 _sessionId,
        uint32 _requestId,
        address _participant,
        uint96 _balance,
        bytes calldata _signature,
        uint32 _rn
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        // if (_requestId == 0) {
        //     revert RequestFinishSessionRequired();
        // }

        // Dispute memory dispute = _disputes[_requestId];

        // if (
        //     dispute.status != uint8(DisputeStatus.None) &&
        //     dispute.status != uint8(DisputeStatus.Settled)
        // ) {
        //     revert SessionInDispute();
        // }

        // if (block.timestamp - dispute.timestamp < 2 minutes) {
        //     revert SessionInRequestReview();
        // }

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            FINISH_SESSION_TYPEHASH,
                            _sessionId,
                            _balance,
                            _participant,
                            _rn
                        )
                    )
                )
            ),
            _signature
        );

        session.status = uint8(SessionStatus.Finished);

        if (_balance != 0) {
            _unlock(_participant, session.token, _balance);
        }

        emit SessionFinished(_sessionId);
    }

    /**
     * @dev Join an existing session.
     *
     * Emits a {JoinedSession} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The input parameters `_buyIn` and `_combinedPublicKey` must be same as the one signed by trusted signer.
     *
     * @param _sessionId (uint32) The ID of the session to join.
     * @param _buyIn (uint96) The buy-in amount for joining the session.
     * @param _combinedPublicKey (address) The combined public key for the session.
     * @param _signature (bytes calldata) The signature signed by trusted signer to verify the input data.
     */
    function joinSession(
        uint32 _sessionId,
        uint96 _buyIn,
        address _combinedPublicKey,
        bytes calldata _signature
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        _checkBuyInRange(session.token, _buyIn);

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            JOIN_SESSION_TYPEHASH,
                            msg.sender,
                            _buyIn,
                            _combinedPublicKey
                        )
                    )
                )
            ),
            _signature
        );

        session.combinedPublicKey = _combinedPublicKey;

        _deposit(msg.sender, session.token, _buyIn);

        emit JoinedSession(_sessionId, msg.sender, _buyIn);
    }

    /**
     * @dev Joins an existing session in trustless way.
     *
     * Emits a {JoinedSession} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The `_buyIn` amount must be within the valid range.
     * - The schnorr signature `_schnorr` must be valid.
     *
     * @param _sessionId (uint32) The ID of the session to join.
     * @param _buyIn (uint96) The buy-in amount for joining the session.
     * @param _combinedPublicKey (address) The combined public key for the session.
     * @param _schnorr (SchnorrSignature) The Schnorr signature created by all members of the session.
     */
    function joinSessionTrustlessly(
        uint32 _sessionId,
        uint96 _buyIn,
        address _combinedPublicKey,
        SchnorrSignature calldata _schnorr
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        _checkBuyInRange(session.token, _buyIn);

        if (!_verifySchnorrSignature(_schnorr, session.combinedPublicKey)) {
            revert InvalidSchnorrSignature();
        }

        SchnorrData memory schnorrData = decodeSchnorrData(_schnorr.data);

        if (schnorrData.proofType != uint8(SchnorrSignatureProofType.Join)) {
            revert InvalidSchnorrSignature();
        }

        if (schnorrData.signatureFor != msg.sender) {
            revert InvalidSchnorrSignature();
        }

        session.combinedPublicKey = _combinedPublicKey;

        _deposit(msg.sender, session.token, _buyIn);

        emit JoinedSession(_sessionId, msg.sender, _buyIn);
    }

    /**
     * @dev Leaving an ongoing session.
     *
     * Emits a {LeftSession} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The input parameters `_balance` and `_combinedPublicKey` must be same as the one signed by trusted signer.
     *
     * @param _sessionId (uint32) The ID of the session to leave.
     * @param _balance (uint96) The array of final balances of each participant for the session.
     * @param _combinedPublicKey (address) The combined public key for the session.
     * @param _signature (bytes calldata) The signature signed by trusted signer to verify the input data.
     */
    function leaveSession(
        uint32 _sessionId,
        uint96 _balance,
        address _combinedPublicKey,
        bytes calldata _signature
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            LEAVE_SESSION_TYPEHASH,
                            msg.sender,
                            _balance,
                            _combinedPublicKey
                        )
                    )
                )
            ),
            _signature
        );

        session.combinedPublicKey = _combinedPublicKey;

        if (_balance != 0) {
            _unlock(msg.sender, session.token, _balance);
        }

        emit LeftSession(_sessionId, msg.sender, _balance);
    }

    /**
     * @dev Leaves an ongoing session in trustless way.
     *
     * Emits a {LeftSession} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The schnorr signature `_schnorr` must be valid.
     *
     * @param _sessionId (uint32) The ID of the session to leave.
     * @param _combinedPublicKey (address) The combined public key for the session.
     * @param _schnorr (SchnorrSignature) The Schnorr signature created by all members of the session.
     */
    function leaveSessionTrustlessly(
        uint32 _sessionId,
        address _combinedPublicKey,
        SchnorrSignature calldata _schnorr
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        if (!_verifySchnorrSignature(_schnorr, session.combinedPublicKey)) {
            revert InvalidSchnorrSignature();
        }

        SchnorrData memory schnorrData = decodeSchnorrData(_schnorr.data);

        if (schnorrData.proofType != uint8(SchnorrSignatureProofType.Leave)) {
            revert InvalidSchnorrSignature();
        }

        if (schnorrData.signatureFor != msg.sender) {
            revert InvalidSchnorrSignature();
        }

        uint256 participantsLength = schnorrData.participants.length;
        uint256 participantIndex = participantsLength;
        for (uint256 i; i < participantsLength; ) {
            if (schnorrData.participants[i] == msg.sender) {
                participantIndex = i;
                break;
            }

            unchecked {
                ++i;
            }
        }

        if (participantIndex == participantsLength) {
            revert InvalidParticipant();
        }

        session.combinedPublicKey = _combinedPublicKey;

        uint96 balance = schnorrData.balances[participantIndex];

        if (balance != 0) {
            _unlock(msg.sender, session.token, balance);
        }

        emit LeftSession(_sessionId, msg.sender, balance);
    }

    /**
     * @dev Deposits funds into an existing session.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The `_buyIn` amount must be within the valid range.
     *
     * @param _sessionId (uint32) The ID of the session to deposit into.
     * @param _buyIn (uint96) The new buy-in amount for the session.
     */
    function depositIntoSession(
        uint32 _sessionId,
        uint96 _buyIn
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        address token = session.token;

        _checkBuyInRange(token, _buyIn);

        _deposit(msg.sender, token, _buyIn);
    }

    /**
     * @dev Withdraws unlocked funds.
     * @param _amount (uint96) The withdrawal amount from the session.
     */
    function withdraw(
        address _token,
        uint96 _amount
    ) external whenNotPaused nonReentrant {
        _withdraw(msg.sender, _token, _amount);
    }

    /**
     * @dev Removes a participant from the session, called by any user, updating the combined public key and submitting a
     * signature signed by a trusted signer.
     *
     * Emits a {RemoveParticipantRequested} event.
     *
     * Requirements:
     * - The session must be {Created} status.
     * - The input parameters `_participant`, `_balance`, and `_combinedPublicKey` must be same as the one signed by trusted signer.
     *
     * @param _sessionId (uint32) The ID of the session to remove the participant.
     * @param _participant (address) The address of the participant to be removed.
     * @param _balance (uint96) The balance of the participant to be removed.
     * @param _combinedPublicKey (address) The combined public key for the session.
     * @param _signature (bytes calldata) The signature signed by trusted signer to verify the input data.
     */
    function requestRemoveParticipant(
        uint32 _sessionId,
        address _participant,
        uint96 _balance,
        address _combinedPublicKey,
        bytes calldata _signature
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        if (msg.sender == _participant) {
            revert InvalidParticipant();
        }

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            REMOVE_PARTICIPANT_TYPEHASH,
                            _participant,
                            _balance,
                            _combinedPublicKey
                        )
                    )
                )
            ),
            _signature
        );

        session.combinedPublicKey = _combinedPublicKey;

        _requestIdCounter = _requestIdCounter + 1;

        uint32 newRequestId = _requestIdCounter;

        _disputes[newRequestId].timestamp = uint64(block.timestamp);

        emit RemoveParticipantRequested(
            newRequestId,
            _sessionId,
            _participant,
            _balance
        );
    }

    function removeParticipant(
        uint32 _sessionId,
        uint32 _requestId,
        address _participant,
        uint96 _balance,
        address _combinedPublicKey,
        bytes calldata _signature
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        if (msg.sender == _participant) {
            revert InvalidParticipant();
        }

        Dispute memory dispute = _disputes[_requestId];

        if (
            dispute.status != uint8(DisputeStatus.None) &&
            dispute.status != uint8(DisputeStatus.Settled)
        ) {
            revert SessionInDispute();
        }

        if (block.timestamp - dispute.timestamp < 2 minutes) {
            revert SessionInRequestReview();
        }

        _verifySignature(
            keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR,
                    keccak256(
                        abi.encode(
                            REMOVE_PARTICIPANT_TYPEHASH,
                            _participant,
                            _balance,
                            _combinedPublicKey
                        )
                    )
                )
            ),
            _signature
        );

        session.combinedPublicKey = _combinedPublicKey;

        if (_balance != 0) {
            _unlock(_participant, session.token, _balance);
        }

        emit LeftSession(_sessionId, _participant, _balance);
    }

    /**
     * @dev Allows any user to open a dispute if they find any discrepancy in the session, especially in the participants' array and their balances.
     *
     * The session will be in dispute status until the dispute is resolved.
     * `openDispute` can only be called after 2 minutes of a specific Schnorr signature, identified by the Schnorr signature ID.
     * Users should submit the most recent `_schnorr` signature, and it must be verified before opening the dispute.
     *
     * Requirements:
     * - The session must exist.
     * - The most recent Schnorr signature provided must be verified.
     * - The dispute can only be opened after 2 minutes of a specific Schnorr signature. The Schnorr signature ID and signature are specified to indicate the issue.
     *
     * @param _sessionId (uint32) The ID of the session in dispute.
     * @param _requestId (uint32) The ID of the request.
     * @param _schnorr (SchnorrSignature) The most recent Schnorr signature to be verified.
     */
    function openDispute(
        uint32 _sessionId,
        uint32 _requestId,
        SchnorrSignature calldata _schnorr
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.Created)) {
            revert InvalidSessionStatus();
        }

        Dispute storage dispute = _disputes[_requestId];

        if (block.timestamp - dispute.timestamp >= 2 minutes) {
            revert DisputeWindowClosed();
        }

        if (!_verifySchnorrSignature(_schnorr, session.combinedPublicKey)) {
            revert InvalidSchnorrSignature();
        }

        SchnorrData memory schnorrData = decodeSchnorrData(_schnorr.data);

        if (schnorrData.proofType != uint8(SchnorrSignatureProofType.Round)) {
            revert InvalidSchnorrSignature();
        }

        session.status = uint8(SessionStatus.InDispute);

        uint32 schnorrSignatureId = schnorrData.schnorrSignatureId;
        _latestSessionSchnorrSignatureId[_sessionId] = schnorrSignatureId;

        dispute.status = uint8(DisputeStatus.Opened);
        dispute.timestamp = uint64(block.timestamp);
        dispute.user = msg.sender;

        emit DisputeOpened(
            _requestId,
            _sessionId,
            schnorrSignatureId,
            msg.sender
        );
    }

    function challengeDispute(
        uint32 _sessionId,
        uint32 _requestId,
        SchnorrSignature calldata _schnorr
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.InDispute)) {
            revert InvalidSessionStatus();
        }

        Dispute storage dispute = _disputes[_requestId];

        if (block.timestamp - dispute.timestamp >= 10 minutes) {
            revert DisputeWindowClosed();
        }

        if (!_verifySchnorrSignature(_schnorr, session.combinedPublicKey)) {
            revert InvalidSchnorrSignature();
        }

        SchnorrData memory schnorrData = decodeSchnorrData(_schnorr.data);

        if (schnorrData.proofType != uint8(SchnorrSignatureProofType.Round)) {
            revert InvalidSchnorrSignature();
        }

        uint32 schnorrSignatureId = schnorrData.schnorrSignatureId;

        if (
            _latestSessionSchnorrSignatureId[_sessionId] <
            schnorrData.schnorrSignatureId
        ) {
            _latestSessionSchnorrSignatureId[_sessionId] = schnorrSignatureId;

            dispute.challenger = msg.sender;
            dispute.status = uint8(DisputeStatus.Challenged);

            emit DisputeChallenged(_requestId, _sessionId, schnorrSignatureId);
        } else {
            revert DisputeChallengeFailed();
        }
    }

    function settleDispute(
        uint32 _sessionId,
        uint32 _requestId,
        SchnorrSignature calldata _schnorr
    ) external whenNotPaused nonReentrant {
        Session storage session = sessions[_sessionId];

        if (session.status != uint8(SessionStatus.InDispute)) {
            revert InvalidSessionStatus();
        }

        Dispute storage dispute = _disputes[_requestId];

        if (block.timestamp - dispute.timestamp < 10 minutes) {
            revert DisputeWindowNotClosed();
        }

        if (!_verifySchnorrSignature(_schnorr, session.combinedPublicKey)) {
            revert InvalidSchnorrSignature();
        }

        SchnorrData memory schnorrData = decodeSchnorrData(_schnorr.data);

        if (schnorrData.proofType != uint8(SchnorrSignatureProofType.Round)) {
            revert InvalidSchnorrSignature();
        }

        uint32 schnorrSignatureId = _latestSessionSchnorrSignatureId[
            _sessionId
        ];
        if (schnorrSignatureId != schnorrData.schnorrSignatureId) {
            revert SettleDisputeFailed();
        }

        session.status = uint8(SessionStatus.Finished);

        uint96 openerBalance;
        uint96 challengerBalance;
        bool foundOpener;
        bool foundChallenger;
        uint256 participantsLength = schnorrData.participants.length;

        if (dispute.status == uint8(DisputeStatus.Challenged)) {
            for (uint256 i; i < participantsLength; ) {
                if (dispute.status == uint8(DisputeStatus.Challenged)) {
                    if (schnorrData.participants[i] == dispute.user) {
                        openerBalance = schnorrData.balances[i];
                        foundOpener = true;
                    } else if (
                        schnorrData.participants[i] == dispute.challenger
                    ) {
                        challengerBalance = schnorrData.balances[i];
                        foundChallenger = true;
                    }

                    if (foundOpener && foundChallenger) {
                        break;
                    }

                    unchecked {
                        ++i;
                    }
                }
            }
        }

        for (uint256 i; i < participantsLength; ) {
            uint96 balance;

            if (
                schnorrData.participants[i] == dispute.user &&
                dispute.status == uint8(DisputeStatus.Challenged)
            ) {
                balance = 0;
            } else if (
                schnorrData.participants[i] == dispute.challenger &&
                dispute.status == uint8(DisputeStatus.Challenged)
            ) {
                balance = challengerBalance + openerBalance;
            } else {
                balance = schnorrData.balances[i];
            }

            if (balance != 0) {
                _unlock(schnorrData.participants[i], session.token, balance);
            }

            unchecked {
                ++i;
            }
        }

        emit SessionFinished(_sessionId);

        dispute.status = uint8(DisputeStatus.Settled);

        emit DisputeSettled(_requestId, _sessionId, schnorrSignatureId);
    }

    /**
     * @dev Internal function to deposit funds into the contract for a specific user and token.
     *
     * @param _user (address) The address of the user making the deposit.
     * @param _token (address) The address of the token for the deposit.
     * @param _amount (uint96) The amount to deposit.
     */
    function _deposit(address _user, address _token, uint96 _amount) internal {
        uint96 userDeposit = userDeposits[_user][_token];
        if (userDeposit < _amount) {
            uint96 amountToDeposit = _amount - userDeposit;

            IERC20Upgradeable(_token).safeTransferFrom(
                _user,
                address(this),
                amountToDeposit
            );

            userDeposits[_user][_token] += amountToDeposit;

            emit Deposit(_user, _token, amountToDeposit);
        }

        userDeposits[_user][_token] -= _amount;
        lockedFunds[_token] += _amount;
    }

    /**
     * @dev Internal function to withdraw funds from the contract for a specific user and token.
     *
     * @param _user (address) The address of the user making the withdrawal.
     * @param _token (address) The address of the token for the withdrawal.
     * @param _amount (uint96) The amount to withdraw.
     */
    function _withdraw(address _user, address _token, uint96 _amount) internal {
        if (IERC20Upgradeable(_token).balanceOf(address(this)) < _amount) {
            revert InsufficientFunds();
        }

        uint256 userDeposit = userDeposits[_user][_token];
        if (userDeposit < _amount) {
            revert InsufficientFunds();
        }

        userDeposits[_user][_token] -= _amount;

        IERC20Upgradeable(_token).safeTransfer(_user, _amount);

        emit Withdraw(_user, _token, _amount);
    }

    /**
     * @dev Internal function to unlock funds for a specific user and token.
     *
     * @param _user (address) The address of the user for whom funds will be unlocked.
     * @param _token (address) The address of the token for the unlocked funds.
     * @param _amount (uint96) The amount to unlock.
     */
    function _unlock(address _user, address _token, uint96 _amount) internal {
        if (lockedFunds[_token] < _amount) {
            revert InsufficientFunds();
        }

        lockedFunds[_token] -= _amount;
        userDeposits[_user][_token] += _amount;
    }

    /**
     * @dev Extracts a slice from the provided bytes array.
     *
     * @param bytes_ (bytes memory) The bytes array from which to extract the slice.
     * @param start_ (uint256) The starting position of the slice.
     * @param length_ (uint256)The length of the slice.
     * @return (bytes memory) Returns the slice from the bytes array.
     */
    function _sliceBytes(
        bytes memory bytes_,
        uint256 start_,
        uint256 length_
    ) internal pure returns (bytes memory) {
        bytes memory data = new bytes(length_);
        for (uint256 i; i < length_; ) {
            data[i] = bytes_[start_ + i];

            unchecked {
                ++i;
            }
        }

        return data;
    }

    /**
     * @dev Converts a bytes memory array to a bytes32 variable.
     *
     * Requirements:
     * - The provided bytes array must be at least 32 bytes long.
     *
     * @param bytes_ (bytes memory) The bytes array to be converted.
     * @return data (bytes32) Returns the bytes32 representation of the provided bytes array.
     */
    function _bytesToBytes32(
        bytes memory bytes_
    ) internal pure returns (bytes32 data) {
        if (bytes_.length < 32) {
            revert InvalidConversion();
        }
        assembly {
            data := mload(add(bytes_, 32))
        }
    }

    /**
     * @dev Internal function to check if the provided token is a valid rollup token and if the buy-in is within the specified range.
     *
     * @param _token (address) The address of the token to be checked.
     * @param _buyIn (uint96) The buy-in amount to be checked.
     */
    function _checkRollupToken(address _token, uint96 _buyIn) internal view {
        RollupToken memory rollupToken = rollupTokens[_token];

        if (rollupToken.supported != uint8(1)) {
            revert NotRollupToken();
        }

        if (_buyIn < rollupToken.minBuyIn || _buyIn > rollupToken.maxBuyIn) {
            revert InvalidBuyIn();
        }
    }

    /**
     * @dev Internal function to check if the provided buy-in is within the specified range for a given token.
     *
     * @param _token (address) The address of the token for which the buy-in range is checked.
     * @param _buyIn (uint96) The buy-in amount to be checked.
     */
    function _checkBuyInRange(address _token, uint96 _buyIn) internal view {
        RollupToken memory rollupToken = rollupTokens[_token];

        if (_buyIn < rollupToken.minBuyIn || _buyIn > rollupToken.maxBuyIn) {
            revert InvalidBuyIn();
        }
    }

    /**
     * @dev Internal function to check the validity of a signature against a digest and mark the Schnorr signature as used.
     *
     * @param _digest (bytes32) The digest to be signed.
     * @param _signature (bytes) The signature to be verified.
     */
    function _verifySignature(
        bytes32 _digest,
        bytes calldata _signature
    ) internal {
        if (_signatureUsed[_signature]) {
            revert InvalidSignature();
        }

        if (
            ecrecover(
                _digest,
                uint8(_signature[64]),
                _bytesToBytes32(_sliceBytes(_signature, 0, 32)),
                _bytesToBytes32(_sliceBytes(_signature, 32, 32))
            ) != _trustedSigner
        ) {
            revert InvalidSignature();
        }

        _signatureUsed[_signature] = true;
    }

    /**
     * @dev Internal function to verify a Schnorr signature.
     *
     * @param _schnorr (SchnorrSignature) The Schnorr signature to be verified.
     *
     * @return (bool) True if the Schnorr signature is valid, otherwise false.
     */
    function _verifySchnorrSignature(
        SchnorrSignature memory _schnorr,
        address _sessionCombinedPublicKey
    ) internal returns (bool) {
        if (_schnorrSignatureUsed[_schnorr.signature]) {
            revert InvalidSchnorrSignature();
        }

        if (_schnorr.combinedPublicKey != _sessionCombinedPublicKey) {
            revert InvalidSchnorrSignature();
        }

        if (_schnorr.signature.length != 128) {
            revert InvalidSchnorrSignature();
        }

        (bytes32 px, bytes32 e, bytes32 s, uint8 parity) = abi.decode(
            _schnorr.signature,
            (bytes32, bytes32, bytes32, uint8)
        );
        bytes32 sp = bytes32(
            SECP256K1_CURVE_N -
                mulmod(uint256(s), uint256(px), SECP256K1_CURVE_N)
        );
        bytes32 ep = bytes32(
            SECP256K1_CURVE_N -
                mulmod(uint256(e), uint256(px), SECP256K1_CURVE_N)
        );

        if (sp == 0) {
            revert InvalidSP();
        }

        address R = ecrecover(sp, parity, px, ep);
        if (R == address(0)) {
            revert ECRecoverFailed();
        }

        if (
            e ==
            keccak256(
                abi.encodePacked(
                    R,
                    uint8(parity),
                    px,
                    solidityPackedKeccak256(_schnorr.data)
                )
            ) &&
            address(uint160(uint256(px))) == _schnorr.combinedPublicKey
        ) {
            _schnorrSignatureUsed[_schnorr.signature] = true;

            return true;
        }

        return false;
    }

    /**
     * @dev Sets the trusted signer's address for validating Session and Participants information.
     *
     * Emits a {TrustedSignerChanged} event indicating the previous signer and the newly set signer.
     *
     * Requirements:
     * - The provided address must not be the zero address.
     *
     * @param _newSigner (address) The address of the trusted signer.
     */
    function setTrustedSigner(address _newSigner) public onlyAdmins {
        if (_newSigner == address(0)) {
            revert InvalidAddress();
        }
        address prevSigner = _trustedSigner;
        _trustedSigner = _newSigner;

        emit TrustedSignerChanged(prevSigner, _newSigner);
    }

    /**
     * @dev Decodes bytes into Schnorr data.
     *
     * @param _data (bytes) The encoded Schnorr data.
     * @return (SchnorrData) The decoded Schnorr data.
     */
    function decodeSchnorrData(
        bytes memory _data
    ) public pure returns (SchnorrData memory) {
        return abi.decode(_data, (SchnorrData));
    }

    /**
     * @dev Computes the solidity-packed keccak256 hash of Schnorr data in bytes.
     *
     * @param _data (bytes calldata) The Schnorr data to be hashed in bytes.
     * @return (bytes32) The keccak256 hash of the packed Schnorr data.
     */
    function solidityPackedKeccak256(
        bytes memory _data
    ) public pure returns (bytes32) {
        SchnorrData memory schnorrData = decodeSchnorrData(_data);

        return
            keccak256(
                abi.encodePacked(
                    schnorrData.schnorrSignatureId,
                    schnorrData.signatureFor,
                    abi.encodePacked(schnorrData.participants),
                    abi.encodePacked(schnorrData.balances),
                    schnorrData.proofType
                )
            );
    }
}
