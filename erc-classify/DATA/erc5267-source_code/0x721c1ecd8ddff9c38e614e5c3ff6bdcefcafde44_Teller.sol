// SPDX-License-Identifier: UNLICENSED
// Source: 0x721c1ecd8ddff9c38e614e5c3ff6bdcefcafde44
// Contract Name: Teller
// Generated on: 2026-05-14 12:07:13


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable2Step.sol)

pragma solidity ^0.8.0;

import "./OwnableUpgradeable.sol";
import "../proxy/utils/Initializable.sol";

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
    function __Ownable2Step_init() internal onlyInitializing {
        __Ownable_init_unchained();
    }

    function __Ownable2Step_init_unchained() internal onlyInitializing {
    }
    address private _pendingOwner;

    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

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
import "../proxy/utils/Initializable.sol";

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
import "../proxy/utils/Initializable.sol";

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
import "../proxy/utils/Initializable.sol";

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
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;
import "../proxy/utils/Initializable.sol";

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
import "../../proxy/utils/Initializable.sol";

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
// FILE: @openzeppelin/contracts/token/ERC1155/IERC1155.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC1155/IERC1155.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256[] ids,
        uint256[] values
    );

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(
        address[] calldata accounts,
        uint256[] calldata ids
    ) external view returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] calldata ids,
        uint256[] calldata amounts,
        bytes calldata data
    ) external;
}


// ============================================================================
// FILE: @openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
interface IERC20Permit {
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
// FILE: @openzeppelin/contracts/token/ERC20/IERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
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
// FILE: @openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.0;

import "../IERC20.sol";
import "../extensions/IERC20Permit.sol";
import "../../../utils/Address.sol";

/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
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
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance + value));
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, oldAllowance - value));
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Compatible with tokens that require the approval to be set to
     * 0 before setting it to a non-zero value.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
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
        IERC20Permit token,
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
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
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
    function _callOptionalReturnBool(IERC20 token, bytes memory data) private returns (bool) {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We cannot use {Address-functionCall} here since this should return false
        // and not revert is the subcall reverts.

        (bool success, bytes memory returndata) = address(token).call(data);
        return
            success && (returndata.length == 0 || abi.decode(returndata, (bool))) && Address.isContract(address(token));
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/token/ERC721/IERC721.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC721/IERC721.sol)

pragma solidity ^0.8.0;

import "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721
     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must
     * understand this adds an external call which potentially creates a reentrancy vulnerability.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/Address.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Address.sol)

pragma solidity ^0.8.1;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
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
// FILE: @openzeppelin/contracts/utils/introspection/IERC165.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/IERC165.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}


// ============================================================================
// FILE: contracts/interfaces/IHandler.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

import "../libs/Types.sol";

interface IHandler {
    function handleOperation(
        Operation calldata op,
        uint256 perJoinSplitVerifyGas,
        address bundler
    ) external returns (OperationResult memory);

    function handleDeposit(
        Deposit calldata deposit
    ) external returns (uint128 merkleIndex);
}


// ============================================================================
// FILE: contracts/interfaces/IJoinSplitVerifier.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

import {IVerifier} from "./IVerifier.sol";

/// @title Verifier interface.
/// @dev Interface of Verifier contract.
interface IJoinSplitVerifier is IVerifier {

}


// ============================================================================
// FILE: contracts/interfaces/IPoseidonExt.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

interface IPoseidonExtT3 {
    function poseidonExt(
        uint256,
        uint256[2] memory
    ) external pure returns (uint256);
}

interface IPoseidonExtT4 {
    function poseidonExt(
        uint256,
        uint256[3] memory
    ) external pure returns (uint256);
}

interface IPoseidonExtT7 {
    function poseidonExt(
        uint256,
        uint256[6] memory
    ) external pure returns (uint256);
}


// ============================================================================
// FILE: contracts/interfaces/ITeller.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

import "../libs/Types.sol";

interface ITeller {
    function processBundle(
        Bundle calldata bundle
    )
        external
        returns (
            uint256[] memory opDigests,
            OperationResult[] memory opResults
        );

    function depositFunds(
        Deposit calldata deposit
    ) external returns (uint128 merkleIndex);

    function requestAsset(
        EncodedAsset calldata encodedAsset,
        uint256 value
    ) external;
}


// ============================================================================
// FILE: contracts/interfaces/IVerifier.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;
import {Groth16} from "../libs/Groth16.sol";

/// @title interface for verifiers that support batch verification.
/// @dev Interface for verifiers that support batch verification.
interface IVerifier {
    /// @param proof: the proof to verify
    /// @param pis: an array of containing the public inputs for the proof
    function verifyProof(
        uint256[8] memory proof,
        uint256[] memory pis
    ) external view returns (bool);

    /// @param proofs: an array containing the proofs to verify
    /// @param pis: an array of length `NUM_PIS * numProofs` containing the PIs for each proof concatenated together
    function batchVerifyProofs(
        uint256[8][] memory proofs,
        uint256[][] memory pis
    ) external view returns (bool);
}


// ============================================================================
// FILE: contracts/libs/AssetUtils.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC1155/IERC1155.sol";

import {Utils} from "../libs/Utils.sol";
import "../libs/Types.sol";

library AssetUtils {
    using SafeERC20 for IERC20;

    uint256 constant MASK_111 = 7;
    uint256 constant MASK_11 = 3;
    uint256 constant BITS_250_TO_252_MASK = (MASK_111 << 250);
    uint256 constant BOTTOM_253_MASK = (1 << 253) - 1;
    uint256 constant BOTTOM_160_MASK = (1 << 160) - 1;

    function encodeAsset(
        AssetType assetType,
        address assetAddr,
        uint256 id
    ) internal pure returns (EncodedAsset memory encodedAsset) {
        uint256 encodedAssetId = id & BOTTOM_253_MASK;
        uint256 assetTypeBits;
        if (assetType == AssetType.ERC20) {
            assetTypeBits = uint256(0);
        } else if (assetType == AssetType.ERC721) {
            assetTypeBits = uint256(1);
        } else if (assetType == AssetType.ERC1155) {
            assetTypeBits = uint256(2);
        } else {
            revert("Invalid assetType");
        }

        uint256 encodedAssetAddr = ((id >> 3) & BITS_250_TO_252_MASK) |
            (assetTypeBits << 160) |
            (uint256(uint160(assetAddr)));

        return
            EncodedAsset({
                encodedAssetAddr: encodedAssetAddr,
                encodedAssetId: encodedAssetId
            });
    }

    function decodeAsset(
        EncodedAsset memory encodedAsset
    )
        internal
        pure
        returns (AssetType assetType, address assetAddr, uint256 id)
    {
        id =
            ((encodedAsset.encodedAssetAddr & BITS_250_TO_252_MASK) << 3) |
            encodedAsset.encodedAssetId;
        assetAddr = address(
            uint160(encodedAsset.encodedAssetAddr & BOTTOM_160_MASK)
        );
        uint256 assetTypeBits = (encodedAsset.encodedAssetAddr >> 160) &
            MASK_11;
        if (assetTypeBits == 0) {
            assetType = AssetType.ERC20;
        } else if (assetTypeBits == 1) {
            assetType = AssetType.ERC721;
        } else if (assetTypeBits == 2) {
            assetType = AssetType.ERC1155;
        } else {
            revert("Invalid encodedAssetAddr");
        }
        return (assetType, assetAddr, id);
    }

    function hashEncodedAsset(
        EncodedAsset memory encodedAsset
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked(
                    encodedAsset.encodedAssetAddr,
                    encodedAsset.encodedAssetId
                )
            );
    }

    function balanceOfAsset(
        EncodedAsset memory encodedAsset
    ) internal view returns (uint256) {
        (AssetType assetType, address assetAddr, uint256 id) = AssetUtils
            .decodeAsset(encodedAsset);
        uint256 value = 0;
        if (assetType == AssetType.ERC20) {
            value = IERC20(assetAddr).balanceOf(address(this));
        } else if (assetType == AssetType.ERC721) {
            // If erc721 not minted, return balance = 0
            try IERC721(assetAddr).ownerOf(id) returns (address owner) {
                if (owner == address(this)) {
                    value = 1;
                }
            } catch {}
        } else if (assetType == AssetType.ERC1155) {
            value = IERC1155(assetAddr).balanceOf(address(this), id);
        } else {
            revert("Invalid asset");
        }

        return value;
    }

    /**
      @dev Transfer asset to receiver. Throws if unsuccssful.
    */
    function transferAssetTo(
        EncodedAsset memory encodedAsset,
        address receiver,
        uint256 value
    ) internal {
        (AssetType assetType, address assetAddr, ) = decodeAsset(encodedAsset);
        if (assetType == AssetType.ERC20) {
            IERC20(assetAddr).safeTransfer(receiver, value);
        } else if (assetType == AssetType.ERC721) {
            revert("!supported");
        } else if (assetType == AssetType.ERC1155) {
            revert("!supported");
        } else {
            revert("Invalid asset");
        }
    }

    /**
      @dev Transfer asset from spender. Throws if unsuccssful.
    */
    function transferAssetFrom(
        EncodedAsset memory encodedAsset,
        address spender,
        uint256 value
    ) internal {
        (AssetType assetType, address assetAddr, ) = decodeAsset(encodedAsset);
        if (assetType == AssetType.ERC20) {
            IERC20(assetAddr).safeTransferFrom(spender, address(this), value);
        } else if (assetType == AssetType.ERC721) {
            revert("!supported");
        } else if (assetType == AssetType.ERC1155) {
            revert("!supported");
        } else {
            revert("Invalid asset");
        }
    }

    /**
      @dev Approve asset to spender for value. Throws if unsuccssful.
    */
    function approveAsset(
        EncodedAsset memory encodedAsset,
        address spender,
        uint256 value
    ) internal {
        (AssetType assetType, address assetAddr, ) = decodeAsset(encodedAsset);

        if (assetType == AssetType.ERC20) {
            // TODO: next OZ release will add SafeERC20.forceApprove
            IERC20(assetAddr).approve(spender, 0);
            IERC20(assetAddr).approve(spender, value);
        } else if (assetType == AssetType.ERC721) {
            revert("!supported");
        } else if (assetType == AssetType.ERC1155) {
            revert("!supported");
        } else {
            revert("Invalid asset");
        }
    }

    function eq(
        EncodedAsset calldata assetA,
        EncodedAsset calldata assetB
    ) internal pure returns (bool) {
        return
            (assetA.encodedAssetAddr == assetB.encodedAssetAddr) &&
            (assetA.encodedAssetId == assetB.encodedAssetId);
    }
}


// ============================================================================
// FILE: contracts/libs/Groth16.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;
import {Pairing} from "./Pairing.sol";
import {Utils} from "./Utils.sol";

library Groth16 {
    struct VerifyingKey {
        Pairing.G1Point alpha1;
        Pairing.G2Point beta2;
        Pairing.G2Point gamma2;
        Pairing.G2Point delta2;
        Pairing.G1Point[] IC;
    }

    struct Proof {
        Pairing.G1Point A;
        Pairing.G2Point B;
        Pairing.G1Point C;
    }

    // Verifying a single Groth16 proof
    function verifyProof(
        VerifyingKey memory vk,
        uint256[8] memory proof8,
        uint256[] memory pi
    ) internal view returns (bool) {
        require(vk.IC.length == pi.length + 1, "Public input length mismatch.");
        Pairing.G1Point memory vk_x = vk.IC[0];
        for (uint i = 0; i < pi.length; i++) {
            require(
                pi[i] < Utils.BN254_SCALAR_FIELD_MODULUS,
                "Malformed public input."
            );
            vk_x = Pairing.addition(
                vk_x,
                Pairing.scalar_mul(vk.IC[i + 1], pi[i])
            );
        }

        Proof memory proof = _proof8ToStruct(proof8);

        return
            Pairing.pairingProd4(
                Pairing.negate(proof.A),
                proof.B,
                vk.alpha1,
                vk.beta2,
                vk_x,
                vk.gamma2,
                proof.C,
                vk.delta2
            );
    }

    function accumulate(
        Proof[] memory proofs,
        uint256[][] memory allPis
    )
        internal
        view
        returns (
            Pairing.G1Point[] memory proofAsandAggegateC,
            uint256[] memory publicInputAccumulators
        )
    {
        uint256 allPisLength = allPis.length;
        uint256 numProofs = proofs.length;

        uint256 numPublicInputs = allPis[0].length;
        for (uint256 i = 1; i < allPisLength; i++) {
            require(
                numPublicInputs == allPis[i].length,
                "Public input mismatch during batch verification."
            );
        }
        uint256[] memory entropy = new uint256[](numProofs);
        publicInputAccumulators = new uint256[](numPublicInputs + 1);

        // Generate entropy for each proof and accumulate each PI
        // seed a challenger by hashing all of the proofs and the current blockhash togethre
        uint256 challengerState = uint256(
            keccak256(abi.encode(proofs, blockhash(block.number - 1)))
        );
        for (uint256 proofIndex = 0; proofIndex < numProofs; proofIndex++) {
            if (proofIndex == 0) {
                entropy[proofIndex] = 1;
            } else {
                challengerState = uint256(
                    keccak256(abi.encodePacked(challengerState))
                );
                entropy[proofIndex] = challengerState;
            }
            require(entropy[proofIndex] != 0, "Entropy should not be zero");
            // here multiplication by 1 is implied
            publicInputAccumulators[0] = addmod(
                publicInputAccumulators[0],
                entropy[proofIndex],
                Utils.BN254_SCALAR_FIELD_MODULUS
            );
            for (uint256 i = 0; i < numPublicInputs; i++) {
                require(
                    allPis[proofIndex][i] < Utils.BN254_SCALAR_FIELD_MODULUS,
                    "Malformed public input"
                );
                // accumulate the exponent with extra entropy mod Utils.BN254_SCALAR_FIELD_MODULUS
                publicInputAccumulators[i + 1] = addmod(
                    publicInputAccumulators[i + 1],
                    mulmod(
                        entropy[proofIndex],
                        allPis[proofIndex][i],
                        Utils.BN254_SCALAR_FIELD_MODULUS
                    ),
                    Utils.BN254_SCALAR_FIELD_MODULUS
                );
            }
        }

        proofAsandAggegateC = new Pairing.G1Point[](numProofs + 1);
        proofAsandAggegateC[0] = proofs[0].A;

        // raise As from each proof to entropy[i]
        for (uint256 proofIndex = 1; proofIndex < numProofs; proofIndex++) {
            uint256 s = entropy[proofIndex];
            proofAsandAggegateC[proofIndex] = Pairing.scalar_mul(
                proofs[proofIndex].A,
                s
            );
        }

        // MSM(proofCs, entropy)
        Pairing.G1Point memory msmProduct = proofs[0].C;
        for (uint256 proofIndex = 1; proofIndex < numProofs; proofIndex++) {
            uint256 s = entropy[proofIndex];
            Pairing.G1Point memory term = Pairing.scalar_mul(
                proofs[proofIndex].C,
                s
            );
            msmProduct = Pairing.addition(msmProduct, term);
        }

        proofAsandAggegateC[numProofs] = msmProduct;

        return (proofAsandAggegateC, publicInputAccumulators);
    }

    function batchVerifyProofs(
        VerifyingKey memory vk,
        uint256[8][] memory proof8s,
        uint256[][] memory allPis
    ) internal view returns (bool success) {
        uint256 proof8sLength = proof8s.length;
        require(
            allPis.length == proof8sLength,
            "Invalid inputs length for a batch"
        );

        Proof[] memory proofs = new Proof[](proof8sLength);
        for (uint256 i = 0; i < proof8sLength; i++) {
            proofs[i] = _proof8ToStruct(proof8s[i]);
        }

        // strategy is to accumulate entropy separately for some proof elements
        // (accumulate only for G1, can't in G2) of the pairing equation, as well as input verification key,
        // postpone scalar multiplication as much as possible and check only one equation
        // by using 3 + proofs.length pairings only plus 2*proofs.length + (num_inputs+1) + 1 scalar multiplications compared to naive
        // 4*proofs.length pairings and proofs.length*(num_inputs+1) scalar multiplications

        (
            Pairing.G1Point[] memory proofAsandAggegateC,
            uint256[] memory publicInputAccumulators
        ) = accumulate(proofs, allPis);

        Pairing.G1Point[2] memory finalVKAlphaAndX = _prepareBatch(
            vk,
            publicInputAccumulators
        );

        Pairing.G1Point[] memory p1s = new Pairing.G1Point[](proofs.length + 3);
        Pairing.G2Point[] memory p2s = new Pairing.G2Point[](proofs.length + 3);

        // first proofs.length pairings e(ProofA, ProofB)
        for (
            uint256 proofNumber = 0;
            proofNumber < proofs.length;
            proofNumber++
        ) {
            p1s[proofNumber] = proofAsandAggegateC[proofNumber];
            p2s[proofNumber] = proofs[proofNumber].B;
        }

        // second pairing e(-finalVKaplha, vk.beta)
        p1s[proofs.length] = Pairing.negate(finalVKAlphaAndX[0]);
        p2s[proofs.length] = vk.beta2;

        // third pairing e(-finalVKx, vk.gamma)
        p1s[proofs.length + 1] = Pairing.negate(finalVKAlphaAndX[1]);
        p2s[proofs.length + 1] = vk.gamma2;

        // fourth pairing e(-proof.C, vk.delta)
        p1s[proofs.length + 2] = Pairing.negate(
            proofAsandAggegateC[proofs.length]
        );
        p2s[proofs.length + 2] = vk.delta2;

        return Pairing.pairing(p1s, p2s);
    }

    function _prepareBatch(
        VerifyingKey memory vk,
        uint256[] memory publicInputAccumulators
    ) internal view returns (Pairing.G1Point[2] memory finalVKAlphaAndX) {
        // Compute the linear combination vk_x using accumulator

        // Performs an MSM(vkIC, publicInputAccumulators)
        Pairing.G1Point memory msmProduct = Pairing.scalar_mul(
            vk.IC[0],
            publicInputAccumulators[0]
        );

        uint256 piAccumulatorsLength = publicInputAccumulators.length;
        for (uint256 i = 1; i < piAccumulatorsLength; i++) {
            Pairing.G1Point memory product = Pairing.scalar_mul(
                vk.IC[i],
                publicInputAccumulators[i]
            );
            msmProduct = Pairing.addition(msmProduct, product);
        }

        finalVKAlphaAndX[1] = msmProduct;

        // add one extra memory slot for scalar for multiplication usage
        Pairing.G1Point memory finalVKalpha = vk.alpha1;
        finalVKalpha = Pairing.scalar_mul(
            finalVKalpha,
            publicInputAccumulators[0]
        );
        finalVKAlphaAndX[0] = finalVKalpha;

        return finalVKAlphaAndX;
    }

    function _proof8ToStruct(
        uint256[8] memory proof
    ) internal pure returns (Proof memory) {
        return
            Groth16.Proof(
                Pairing.G1Point(proof[0], proof[1]),
                Pairing.G2Point([proof[2], proof[3]], [proof[4], proof[5]]),
                Pairing.G1Point(proof[6], proof[7])
            );
    }
}


// ============================================================================
// FILE: contracts/libs/OperationUtils.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;
import {Groth16} from "../libs/Groth16.sol";
import {Utils} from "../libs/Utils.sol";
import "../libs/Types.sol";

// Helpers for extracting data / formatting operations
library OperationUtils {
    function extractJoinSplitProofsAndPis(
        Operation[] calldata ops,
        uint256[] memory digests
    )
        internal
        pure
        returns (uint256[8][] memory proofs, uint256[][] memory allPis)
    {
        // compute number of joinsplits in the bundle
        uint256 totalNumJoinSplits = 0;
        uint256 numOps = ops.length;
        for (uint256 i = 0; i < numOps; i++) {
            totalNumJoinSplits += (ops[i].pubJoinSplits.length +
                ops[i].confJoinSplits.length);
        }

        proofs = new uint256[8][](totalNumJoinSplits);
        allPis = new uint256[][](totalNumJoinSplits);

        // current index into proofs and pis
        uint256 totalIndex = 0;

        // Batch verify all the joinsplit proofs
        for (uint256 j = 0; j < numOps; j++) {
            (
                uint256[8][] memory proofsForOp,
                uint256[][] memory pisForOp
            ) = extractProofsAndPisFromOperation(ops[j], digests[j]);

            for (uint256 i = 0; i < proofsForOp.length; i++) {
                proofs[totalIndex] = proofsForOp[i];
                allPis[totalIndex] = pisForOp[i];
                totalIndex++;
            }
        }

        return (proofs, allPis);
    }

    function extractProofsAndPisFromOperation(
        Operation calldata op,
        uint256 opDigest
    )
        internal
        pure
        returns (uint256[8][] memory proofs, uint256[][] memory allPis)
    {
        uint256 numJoinSplitsForOp = OperationLib.totalNumJoinSplits(op);
        proofs = new uint256[8][](numJoinSplitsForOp);
        allPis = new uint256[][](numJoinSplitsForOp);

        (uint256 refundAddrH1SignBit, uint256 refundAddrH1YCoordinate) = Utils
            .decomposeCompressedPoint(op.refundAddr.h1);
        (uint256 refundAddrH2SignBit, uint256 refundAddrH2YCoordinate) = Utils
            .decomposeCompressedPoint(op.refundAddr.h2);

        for (uint256 i = 0; i < numJoinSplitsForOp; i++) {
            bool isPublicJoinSplit = i < op.pubJoinSplits.length;
            JoinSplit calldata joinSplit = isPublicJoinSplit
                ? op.pubJoinSplits[i].joinSplit
                : op.confJoinSplits[i - op.pubJoinSplits.length];
            EncodedAsset memory encodedAsset = isPublicJoinSplit
                ? op.trackedAssets[op.pubJoinSplits[i].assetIndex].encodedAsset
                : EncodedAsset(0, 0);
            uint256 publicSpend = isPublicJoinSplit
                ? op.pubJoinSplits[i].publicSpend
                : 0;

            uint256 encodedAssetAddrWithSignBits = encodeEncodedAssetAddrWithSignBitsPI(
                    encodedAsset.encodedAssetAddr,
                    refundAddrH1SignBit,
                    refundAddrH2SignBit
                );

            proofs[i] = joinSplit.proof;
            allPis[i] = new uint256[](13);
            allPis[i][0] = joinSplit.newNoteACommitment;
            allPis[i][1] = joinSplit.newNoteBCommitment;
            allPis[i][2] = joinSplit.commitmentTreeRoot;
            allPis[i][3] = publicSpend;
            allPis[i][4] = joinSplit.nullifierA;
            allPis[i][5] = joinSplit.nullifierB;
            allPis[i][6] = joinSplit.senderCommitment;
            allPis[i][7] = joinSplit.joinSplitInfoCommitment;
            allPis[i][8] = opDigest;
            allPis[i][9] = encodedAsset.encodedAssetId;
            allPis[i][10] = encodedAssetAddrWithSignBits;
            allPis[i][11] = refundAddrH1YCoordinate;
            allPis[i][12] = refundAddrH2YCoordinate;
        }
    }

    function encodeEncodedAssetAddrWithSignBitsPI(
        uint256 encodedAssetAddr,
        uint256 h1SignBit,
        uint256 h2SignBit
    ) internal pure returns (uint256) {
        return encodedAssetAddr | (h1SignBit << 248) | (h2SignBit << 249);
    }

    function calculateBundlerGasAssetPayout(
        Operation calldata op,
        OperationResult memory opResult
    ) internal pure returns (uint256) {
        uint256 handleJoinSplitGas = OperationLib.totalNumJoinSplits(op) *
            GAS_PER_JOINSPLIT_HANDLE;
        uint256 refundGas = opResult.numRefunds *
            (GAS_PER_INSERTION_ENQUEUE + GAS_PER_INSERTION_SUBTREE_UPDATE);

        return
            op.gasPrice *
            (opResult.verificationGas +
                handleJoinSplitGas +
                opResult.executionGas +
                refundGas +
                GAS_PER_OPERATION_MISC);
    }

    // From https://ethereum.stackexchange.com/questions/83528
    // returns empty string if no revert message
    function getRevertMsg(
        bytes memory reason
    ) internal pure returns (string memory) {
        // If the _res length is less than 68, then the transaction failed silently (without a revert message)
        if (reason.length < 68) {
            return "";
        }

        assembly {
            // Slice the sighash.
            reason := add(reason, 0x04)
        }
        return abi.decode(reason, (string)); // All that remains is the revert string
    }
}


// ============================================================================
// FILE: contracts/libs/Pairing.sol
// ============================================================================

// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// 2019 OKIMS
//      ported to solidity 0.6
//      fixed linter warnings
//      added requiere error messages
//
//
// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.2;

library Pairing {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /// @return the generator of G1
    function P1() internal pure returns (G1Point memory) {
        return G1Point(1, 2);
    }

    /// @return the generator of G2
    function P2() internal pure returns (G2Point memory) {
        // Original code point
        return
            G2Point(
                [
                    11559732032986387107991004021392285783925812861821192530917403151452391805634,
                    10857046999023057135944570762232829481370756359578518086990519993285655852781
                ],
                [
                    4082367875863433681332203403145435568316851327593401208105741076214120093531,
                    8495653923123431417604973247489272438418190587263600148770280649306958101930
                ]
            );

        /*
        // Changed by Jordi point
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
*/
    }

    /// @return r the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) internal pure returns (G1Point memory r) {
        // The prime q in the base field F_q for G1
        uint256 q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    /// @return r the sum of two points of G1
    function addition(
        G1Point memory p1,
        G1Point memory p2
    ) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success, "pairing-add-failed");
    }

    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(
        G1Point memory p,
        uint256 s
    ) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success, "pairing-mul-failed");
    }

    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(
        G1Point[] memory p1,
        G2Point[] memory p2
    ) internal view returns (bool) {
        require(p1.length == p2.length, "pairing-lengths-failed");
        uint256 elements = p1.length;
        uint256 inputSize = elements * 6;
        uint256[] memory input = new uint256[](inputSize);
        for (uint256 i = 0; i < elements; i++) {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }
        uint256[1] memory out;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(
                sub(gas(), 2000),
                8,
                add(input, 0x20),
                mul(inputSize, 0x20),
                out,
                0x20
            )
            // Use "invalid" to make gas estimation work
            switch success
            case 0 {
                invalid()
            }
        }
        require(success, "pairing-opcode-failed");
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }

    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2,
        G1Point memory d1,
        G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}


// ============================================================================
// FILE: contracts/libs/Types.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

uint256 constant GAS_PER_JOINSPLIT_HANDLE = 110_000; // two 20k SSTOREs from NF insertions, ~70k for merkle tree checks + NF mapping checks + processing joinsplits not including tree insertions
uint256 constant GAS_PER_INSERTION_SUBTREE_UPDATE = 25_000; // Full 16 leaf non-zero subtree update = 320k / 16 = 20k per insertion (+5k buffer)
uint256 constant GAS_PER_INSERTION_ENQUEUE = 25_000; // 20k for enqueueing note commitment not including subtree update cost (+5k buffer)
uint256 constant GAS_PER_OPERATION_MISC = 100_000; // remaining gas cost for operation including  miscellaneous costs such as sending gas tokens to bundler, requesting assets from teller, sending tokens back for refunds, calldata, event, etc.

uint256 constant ERC20_ID = 0;

enum AssetType {
    ERC20,
    ERC721,
    ERC1155
}

struct EncodedAsset {
    uint256 encodedAssetAddr;
    uint256 encodedAssetId;
}

struct CompressedStealthAddress {
    uint256 h1;
    uint256 h2;
}

struct EncryptedNote {
    bytes ciphertextBytes;
    bytes encapsulatedSecretBytes;
}

struct PublicJoinSplit {
    JoinSplit joinSplit;
    uint8 assetIndex; // Index in op.joinSplitAssets
    uint256 publicSpend;
}

struct JoinSplit {
    uint256 commitmentTreeRoot;
    uint256 nullifierA;
    uint256 nullifierB;
    uint256 newNoteACommitment;
    uint256 newNoteBCommitment;
    uint256 senderCommitment;
    uint256 joinSplitInfoCommitment;
    uint256[8] proof;
    EncryptedNote newNoteAEncrypted;
    EncryptedNote newNoteBEncrypted;
}

struct JoinSplitInfo {
    uint256 compressedSenderCanonAddr;
    uint256 compressedReceiverCanonAddr;
    uint256 oldMerkleIndicesWithSignBits;
    uint256 newNoteValueA;
    uint256 newNoteValueB;
    uint256 nonce;
}

struct EncodedNote {
    uint256 ownerH1;
    uint256 ownerH2;
    uint256 nonce;
    uint256 encodedAssetAddr;
    uint256 encodedAssetId;
    uint256 value;
}

struct DepositRequest {
    address spender;
    EncodedAsset encodedAsset;
    uint256 value;
    CompressedStealthAddress depositAddr;
    uint256 nonce;
    uint256 gasCompensation;
}

struct Deposit {
    address spender;
    EncodedAsset encodedAsset;
    uint256 value;
    CompressedStealthAddress depositAddr;
}

struct Action {
    address contractAddress;
    bytes encodedFunction;
}

struct TrackedAsset {
    EncodedAsset encodedAsset;
    uint256 minRefundValue;
}

struct Operation {
    PublicJoinSplit[] pubJoinSplits;
    JoinSplit[] confJoinSplits;
    CompressedStealthAddress refundAddr;
    TrackedAsset[] trackedAssets;
    Action[] actions;
    EncodedAsset encodedGasAsset;
    uint256 gasAssetRefundThreshold;
    uint256 executionGasLimit;
    uint256 gasPrice;
    uint256 deadline;
    bool atomicActions;
}

// An operation is processed if its joinsplitTxs are processed.
// If an operation is processed, the following is guaranteeed to happen:
// 1. Encoded calls are attempted (not necessarily successfully)
// 2. The bundler is compensated verification and execution gas
// Bundlers should only be submitting operations that can be processed.
struct OperationResult {
    bool opProcessed;
    bool assetsUnwrapped;
    string failureReason;
    bool[] callSuccesses;
    bytes[] callResults;
    uint256 verificationGas;
    uint256 executionGas;
    uint256 numRefunds;
    uint128 preOpMerkleCount;
    uint128 postOpMerkleCount;
}

struct Bundle {
    Operation[] operations;
}

struct CanonAddrRegistryEntry {
    address ethAddress;
    uint256 compressedCanonAddr;
    uint256 perCanonAddrNonce;
}

library OperationLib {
    function maxGasLimit(
        Operation calldata self,
        uint256 perJoinSplitVerifyGas
    ) internal pure returns (uint256) {
        uint256 numJoinSplits = totalNumJoinSplits(self);
        return
            self.executionGasLimit +
            ((perJoinSplitVerifyGas + GAS_PER_JOINSPLIT_HANDLE) *
                numJoinSplits) +
            ((GAS_PER_INSERTION_SUBTREE_UPDATE + GAS_PER_INSERTION_ENQUEUE) *
                (self.trackedAssets.length + (numJoinSplits * 2))) + // NOTE: assume refund for every asset
            GAS_PER_OPERATION_MISC;
    }

    function maxGasAssetCost(
        Operation calldata self,
        uint256 perJoinSplitVerifyGas
    ) internal pure returns (uint256) {
        return self.gasPrice * maxGasLimit(self, perJoinSplitVerifyGas);
    }

    function totalNumJoinSplits(
        Operation calldata self
    ) internal pure returns (uint256) {
        return self.pubJoinSplits.length + self.confJoinSplits.length;
    }
}


// ============================================================================
// FILE: contracts/libs/Utils.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;
import {ITeller} from "../interfaces/ITeller.sol";
import {Groth16} from "../libs/Groth16.sol";
import {Pairing} from "../libs/Pairing.sol";
import "../libs/Types.sol";

// helpers for converting to/from field elems, uint256s, and/or bytes, and hashing them
library Utils {
    uint256 public constant BN254_SCALAR_FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    uint256 constant COMPRESSED_POINT_SIGN_MASK = 1 << 254;

    // takes a compressed point and extracts the sign bit and y coordinate
    // returns (sign, y)
    function decomposeCompressedPoint(
        uint256 compressedPoint
    ) internal pure returns (uint256 sign, uint256 y) {
        sign = (compressedPoint & COMPRESSED_POINT_SIGN_MASK) >> 254;
        y = compressedPoint & (COMPRESSED_POINT_SIGN_MASK - 1);
        return (sign, y);
    }

    // return the minimum of the two values
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return (a >= b) ? b : a;
    }

    function sum(uint256[] calldata arr) internal pure returns (uint256) {
        uint256 total = 0;
        uint256 arrLength = arr.length;
        for (uint256 i = 0; i < arrLength; i++) {
            total += arr[i];
        }
        return total;
    }
}


// ============================================================================
// FILE: contracts/libs/Validation.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

import "./Types.sol";
import "./Utils.sol";
import {AssetUtils} from "./AssetUtils.sol";

library Validation {
    uint256 constant MAX_NOTE_VALUE = (1 << 252) - 1; // value must fit in 252 bits
    uint256 constant ENCODED_ASSET_ADDR_MASK = ((1 << 163) - 1) | (7 << 249);
    uint256 constant MAX_ASSET_ID = (1 << 253) - 1;

    uint256 constant CURVE_A = 168700;
    uint256 constant CURVE_D = 168696;
    uint256 constant COMPRESSED_POINT_Y_MASK = ~uint256(1 << 254);

    function validateOperation(Operation calldata op) internal view {
        uint256 numPubJoinSplits = op.pubJoinSplits.length;
        require(numPubJoinSplits + op.confJoinSplits.length > 0, "!JoinSplits");

        // Ensure public spend > 0 for public joinsplit. Ensures handler only deals
        // with assets that are actually unwrappable. If asset has > 0 public spend, then
        // circuit guarantees that note with the _revealed_ asset is included in the tree is
        // unwrappable. If asset has public spend = 0, circuit guarantees that the note with the
        // _masked_ asset is included in the tree and unwrappable, but the revealed asset for public
        // spend = 0 is (0,0) and is not unwrappable.
        for (uint256 i = 0; i < numPubJoinSplits; i++) {
            require(op.pubJoinSplits[i].publicSpend > 0, "0 public spend");
        }

        // Ensure timestamp for op has not already expired
        require(block.timestamp <= op.deadline, "expired deadline");

        // Ensure gas asset is erc20 to ensure transfers to bundler retain control flow (no
        // callbacks/receiver hooks)
        (AssetType assetType, , ) = AssetUtils.decodeAsset(op.encodedGasAsset);
        require(assetType == AssetType.ERC20, "!gas erc20");
    }

    // Ensure note fields are also valid as circuit inputs
    function validateNote(EncodedNote memory note) internal pure {
        require(
            // nonce is a valid field element
            note.nonce < Utils.BN254_SCALAR_FIELD_MODULUS &&
                // encodedAssetAddr is a valid field element
                note.encodedAssetAddr < Utils.BN254_SCALAR_FIELD_MODULUS &&
                // encodedAssetAddr doesn't have any bits set outside bits 0-162 and 250-252
                note.encodedAssetAddr & (~ENCODED_ASSET_ADDR_MASK) == 0 &&
                // encodedAssetId is a 253 bit number (and therefore a valid field element)
                note.encodedAssetId <= MAX_ASSET_ID &&
                // value is < the 2^252 limit (and therefore a valid field element)
                note.value <= MAX_NOTE_VALUE,
            "invalid note"
        );

        validateCompressedBJJPoint(note.ownerH1);
        validateCompressedBJJPoint(note.ownerH2);
    }

    function validateCompressedBJJPoint(uint256 p) internal pure {
        // Clear X-sign bit. Leaves MSB untouched for the next check.
        uint256 y = p & COMPRESSED_POINT_Y_MASK;
        // Simultaneously check that the high-bit is unset and Y is a canonical field element
        // this works because y >= Utils.BN254_SCALAR_FIELD_MODULUS if high bit is set or y is not a valid field element
        require(y < Utils.BN254_SCALAR_FIELD_MODULUS, "invalid point");
    }
}


// ============================================================================
// FILE: contracts/OperationEIP712.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

// External
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
// Internal
import {Utils} from "./libs/Utils.sol";
import "./libs/Types.sol";

/// @title OperationEIP712
/// @author Nocturne Labs
/// @notice Base contract for Teller containing EIP712 signing logic for operation
contract OperationEIP712 is EIP712Upgradeable {
    bytes32 public constant OPERATION_TYPEHASH =
        keccak256(
            bytes(
                // solhint-disable-next-line max-line-length
                "OperationWithoutProofs(PublicJoinSplitWithoutProof[] pubJoinSplits,JoinSplitWithoutProof[] confJoinSplits,CompressedStealthAddress refundAddr,TrackedAsset[] trackedAssets,Action[] actions,EncodedAsset encodedGasAsset,uint256 gasAssetRefundThreshold,uint256 executionGasLimit,uint256 gasPrice,uint256 deadline,bool atomicActions)Action(address contractAddress,bytes encodedFunction)CompressedStealthAddress(uint256 h1,uint256 h2)EncodedAsset(uint256 encodedAssetAddr,uint256 encodedAssetId)EncryptedNote(bytes ciphertextBytes,bytes encapsulatedSecretBytes)JoinSplitWithoutProof(uint256 commitmentTreeRoot,uint256 nullifierA,uint256 nullifierB,uint256 newNoteACommitment,uint256 newNoteBCommitment,uint256 senderCommitment,uint256 joinSplitInfoCommitment,EncryptedNote newNoteAEncrypted,EncryptedNote newNoteBEncrypted)PublicJoinSplitWithoutProof(JoinSplitWithoutProof joinSplit,uint8 assetIndex,uint256 publicSpend)TrackedAsset(EncodedAsset encodedAsset,uint256 minRefundValue)"
            )
        );

    bytes32 public constant ACTION_TYPEHASH =
        keccak256(
            bytes(
                // solhint-disable-next-line max-line-length
                "Action(address contractAddress,bytes encodedFunction)"
            )
        );

    bytes32 public constant COMPRESSED_STEALTH_ADDRESS_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "CompressedStealthAddress(uint256 h1,uint256 h2)"
        );

    bytes32 public constant PUBLIC_JOINSPLIT_WITHOUT_PROOF_TYPEHASH =
        keccak256(
            bytes(
                // solhint-disable-next-line max-line-length
                "PublicJoinSplitWithoutProof(JoinSplitWithoutProof joinSplit,uint8 assetIndex,uint256 publicSpend)EncryptedNote(bytes ciphertextBytes,bytes encapsulatedSecretBytes)JoinSplitWithoutProof(uint256 commitmentTreeRoot,uint256 nullifierA,uint256 nullifierB,uint256 newNoteACommitment,uint256 newNoteBCommitment,uint256 senderCommitment,uint256 joinSplitInfoCommitment,EncryptedNote newNoteAEncrypted,EncryptedNote newNoteBEncrypted)"
            )
        );

    bytes32 public constant JOINSPLIT_WITHOUT_PROOF_TYPEHASH =
        keccak256(
            bytes(
                // solhint-disable-next-line max-line-length
                "JoinSplitWithoutProof(uint256 commitmentTreeRoot,uint256 nullifierA,uint256 nullifierB,uint256 newNoteACommitment,uint256 newNoteBCommitment,uint256 senderCommitment,uint256 joinSplitInfoCommitment,EncryptedNote newNoteAEncrypted,EncryptedNote newNoteBEncrypted)EncryptedNote(bytes ciphertextBytes,bytes encapsulatedSecretBytes)"
            )
        );

    bytes32 public constant ENCODED_ASSET_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "EncodedAsset(uint256 encodedAssetAddr,uint256 encodedAssetId)"
        );

    bytes32 public constant ENCRYPTED_NOTE_TYPEHASH =
        keccak256(
            bytes(
                // solhint-disable-next-line max-line-length
                "EncryptedNote(bytes ciphertextBytes,bytes encapsulatedSecretBytes)"
            )
        );

    bytes32 public constant TRACKED_ASSET_TYPEHASH =
        keccak256(
            // solhint-disable-next-line max-line-length
            "TrackedAsset(EncodedAsset encodedAsset,uint256 minRefundValue)EncodedAsset(uint256 encodedAssetAddr,uint256 encodedAssetId)"
        );

    /// @notice Internal initializer
    /// @param contractName Name of the contract
    /// @param contractVersion Version of the contract
    function __OperationEIP712_init(
        string memory contractName,
        string memory contractVersion
    ) internal onlyInitializing {
        __EIP712_init(contractName, contractVersion);
    }

    /// @notice Computes EIP712 digest of operation
    /// @dev The inherited EIP712 domain separator includes block.chainid for replay protection.
    /// @param op OperationWithoutProof
    function _computeDigest(
        Operation calldata op
    ) public view returns (uint256) {
        bytes32 domainSeparator = _domainSeparatorV4();
        bytes32 structHash = _hashOperation(op);

        bytes32 digest = ECDSAUpgradeable.toTypedDataHash(
            domainSeparator,
            structHash
        );

        // mod digest by BN254 since this is PI to joinsplit circuit
        return uint256(digest) % Utils.BN254_SCALAR_FIELD_MODULUS;
    }

    /// @notice Hashes operation
    /// @param op Operation
    /// @dev We hash every field of operation except for the joinsplit proofs
    function _hashOperation(
        Operation calldata op
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    OPERATION_TYPEHASH,
                    _hashPublicJoinSplits(op.pubJoinSplits),
                    _hashJoinSplits(op.confJoinSplits),
                    _hashCompressedStealthAddress(op.refundAddr),
                    _hashTrackedAssets(op.trackedAssets),
                    _hashActions(op.actions),
                    _hashEncodedAsset(op.encodedGasAsset),
                    op.gasAssetRefundThreshold,
                    op.executionGasLimit,
                    op.gasPrice,
                    op.deadline,
                    uint256(op.atomicActions ? 1 : 0)
                )
            );
    }

    function _hashPublicJoinSplits(
        PublicJoinSplit[] calldata publicJoinSplits
    ) internal pure returns (bytes32) {
        uint256 numPublicJoinSplits = publicJoinSplits.length;
        bytes32[] memory publicJoinSplitHashes = new bytes32[](
            numPublicJoinSplits
        );
        for (uint256 i = 0; i < numPublicJoinSplits; i++) {
            publicJoinSplitHashes[i] = _hashPublicJoinSplit(
                publicJoinSplits[i]
            );
        }

        return keccak256(abi.encodePacked(publicJoinSplitHashes));
    }

    function _hashPublicJoinSplit(
        PublicJoinSplit calldata publicJoinSplit
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    PUBLIC_JOINSPLIT_WITHOUT_PROOF_TYPEHASH,
                    _hashJoinSplit(publicJoinSplit.joinSplit),
                    uint256(publicJoinSplit.assetIndex),
                    publicJoinSplit.publicSpend
                )
            );
    }

    /// @notice Hashes array of joinsplits
    /// @param joinSplits JoinSplits
    /// @dev We hash every field except for the joinSplit proofs
    function _hashJoinSplits(
        JoinSplit[] calldata joinSplits
    ) internal pure returns (bytes32) {
        uint256 numJoinSplits = joinSplits.length;
        bytes32[] memory joinSplitHashes = new bytes32[](numJoinSplits);
        for (uint256 i = 0; i < numJoinSplits; i++) {
            joinSplitHashes[i] = _hashJoinSplit(joinSplits[i]);
        }

        return keccak256(abi.encodePacked(joinSplitHashes));
    }

    /// @notice Hashes single joinsplit
    /// @param joinSplit JoinSplit
    /// @dev We hash every field except for the proof
    function _hashJoinSplit(
        JoinSplit calldata joinSplit
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    JOINSPLIT_WITHOUT_PROOF_TYPEHASH,
                    joinSplit.commitmentTreeRoot,
                    joinSplit.nullifierA,
                    joinSplit.nullifierB,
                    joinSplit.newNoteACommitment,
                    joinSplit.newNoteBCommitment,
                    joinSplit.senderCommitment,
                    joinSplit.joinSplitInfoCommitment,
                    _hashEncryptedNote(joinSplit.newNoteAEncrypted),
                    _hashEncryptedNote(joinSplit.newNoteBEncrypted)
                )
            );
    }

    /// @notice Hashes array of actions
    /// @param actions Actions
    function _hashActions(
        Action[] calldata actions
    ) internal pure returns (bytes32) {
        uint256 numActions = actions.length;
        bytes32[] memory actionHashes = new bytes32[](numActions);
        for (uint256 i = 0; i < numActions; i++) {
            actionHashes[i] = _hashAction(actions[i]);
        }

        return keccak256(abi.encodePacked(actionHashes));
    }

    /// @notice Hashes single action
    /// @param action Action
    function _hashAction(
        Action calldata action
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ACTION_TYPEHASH,
                    action.contractAddress,
                    keccak256(action.encodedFunction)
                )
            );
    }

    /// @notice Hashes encrypted note
    /// @param encryptedNote Encrypted note
    function _hashEncryptedNote(
        EncryptedNote calldata encryptedNote
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ENCRYPTED_NOTE_TYPEHASH,
                    keccak256(encryptedNote.ciphertextBytes),
                    keccak256(encryptedNote.encapsulatedSecretBytes)
                )
            );
    }

    /// @notice Hashes stealth address
    /// @param stealthAddress Compressed stealth address
    function _hashCompressedStealthAddress(
        CompressedStealthAddress calldata stealthAddress
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    COMPRESSED_STEALTH_ADDRESS_TYPEHASH,
                    stealthAddress.h1,
                    stealthAddress.h2
                )
            );
    }

    /// @notice Hashes tracked assets
    /// @param trackedAssets Encoded refund assets
    function _hashTrackedAssets(
        TrackedAsset[] calldata trackedAssets
    ) internal pure returns (bytes32) {
        uint256 numTrackedAssets = trackedAssets.length;
        bytes32[] memory trackedAssetHashes = new bytes32[](numTrackedAssets);
        for (uint256 i = 0; i < numTrackedAssets; i++) {
            trackedAssetHashes[i] = _hashTrackedAsset(trackedAssets[i]);
        }

        return keccak256(abi.encodePacked(trackedAssetHashes));
    }

    /// @notice Hashes tracked asset
    /// @param trackedAsset Tracked asset
    function _hashTrackedAsset(
        TrackedAsset calldata trackedAsset
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    TRACKED_ASSET_TYPEHASH,
                    _hashEncodedAsset(trackedAsset.encodedAsset),
                    trackedAsset.minRefundValue
                )
            );
    }

    /// @notice Hashes encoded asset
    /// @param encodedAsset Encoded asset
    function _hashEncodedAsset(
        EncodedAsset calldata encodedAsset
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ENCODED_ASSET_TYPEHASH,
                    encodedAsset.encodedAssetAddr,
                    encodedAsset.encodedAssetId
                )
            );
    }
}


// ============================================================================
// FILE: contracts/Teller.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

// External
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {Versioned} from "./upgrade/Versioned.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {PausableUpgradeable} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
// Internal
import {ITeller} from "./interfaces/ITeller.sol";
import {IHandler} from "./interfaces/IHandler.sol";
import {IJoinSplitVerifier} from "./interfaces/IJoinSplitVerifier.sol";
import {IPoseidonExtT7} from "./interfaces/IPoseidonExt.sol";
import {OperationEIP712} from "./OperationEIP712.sol";
import {Utils} from "./libs/Utils.sol";
import {Validation} from "./libs/Validation.sol";
import {AssetUtils} from "./libs/AssetUtils.sol";
import {OperationUtils} from "./libs/OperationUtils.sol";
import {Groth16} from "./libs/OperationUtils.sol";
import "./libs/Types.sol";

/// @title Teller
/// @author Nocturne Labs
/// @notice Teller stores deposited funds and serves as the entry point contract for operations.
contract Teller is
    ITeller,
    OperationEIP712,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    Ownable2StepUpgradeable,
    Versioned
{
    using OperationLib for Operation;

    // Domain separator hashed with joinsplit info for joinsplit info commitment
    uint256 public constant JOINSPLIT_INFO_COMMITMENT_DOMAIN_SEPARATOR =
        uint256(keccak256(bytes("JOINSPLIT_INFO_COMMITMENT")));

    // Handler contract
    IHandler public _handler;

    // JoinSplit verifier contract
    IJoinSplitVerifier public _joinSplitVerifier;

    // Set of contracts which can deposit funds into Teller
    mapping(address => bool) public _depositSources;

    // 6 elem poseidon hasher
    IPoseidonExtT7 public _poseidonExtT7;

    // Gap for upgrade safety
    uint256[50] private __GAP;

    /// @notice Event emitted when a deposit source is given/revoked permission
    event DepositSourcePermissionSet(address source, bool permission);

    /// @notice Event emitted when an operation is processed/executed (one per operation)
    event OperationProcessed(
        uint256 indexed operationDigest,
        bool opProcessed,
        bool assetsUnwrapped,
        string failureReason,
        bool[] callSuccesses,
        bytes[] callResults,
        uint128 preOpMerkleCount,
        uint128 postOpMerkleCount
    );

    /// @notice Initializer function
    /// @param handler Address of the handler contract
    /// @param joinSplitVerifier Address of the joinsplit verifier contract
    function initialize(
        string calldata contractName,
        string calldata contractVersion,
        address handler,
        address joinSplitVerifier,
        address poseidonExtT7
    ) external initializer {
        __Pausable_init();
        __Ownable2Step_init();
        __ReentrancyGuard_init();
        __OperationEIP712_init(contractName, contractVersion);
        _handler = IHandler(handler);
        _joinSplitVerifier = IJoinSplitVerifier(joinSplitVerifier);
        _poseidonExtT7 = IPoseidonExtT7(poseidonExtT7);
    }

    /// @notice Only callable by the Handler, so Handler can request assets
    modifier onlyHandler() {
        require(msg.sender == address(_handler), "Only handler");
        _;
    }

    /// @notice Only callable by allowed deposit source
    modifier onlyDepositSource() {
        require(_depositSources[msg.sender], "Only deposit source");
        _;
    }

    /// @notice Only callable by EOA
    modifier onlyEoa() {
        require(tx.origin == msg.sender, "Only eoa");
        _;
    }

    /// @notice Pauses contract, only callable by owner
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses contract, only callable by owner
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Sets permission for a deposit source
    /// @param source Address of the contract or EOA
    /// @param permission Whether or not the source is allowed to deposit funds
    function setDepositSourcePermission(
        address source,
        bool permission
    ) external onlyOwner {
        _depositSources[source] = permission;
        emit DepositSourcePermissionSet(source, permission);
    }

    /// @notice Deposits funds into the Teller contract and calls on handler to add new notes
    /// @dev Only callable by allowed deposit source when not paused
    /// @param deposit Deposit
    function depositFunds(
        Deposit calldata deposit
    )
        external
        override
        whenNotPaused
        onlyDepositSource
        returns (uint128 merkleIndex)
    {
        merkleIndex = _handler.handleDeposit(deposit);
        AssetUtils.transferAssetFrom(
            deposit.encodedAsset,
            msg.sender,
            deposit.value
        );
    }

    /// @notice Sends assets to the Handler to fund operation, only callable by Handler contract
    /// @param encodedAsset Encoded asset being requested
    /// @param value Amount of asset to send
    function requestAsset(
        EncodedAsset calldata encodedAsset,
        uint256 value
    ) external override whenNotPaused onlyHandler {
        AssetUtils.transferAssetTo(encodedAsset, address(_handler), value);
    }

    /// @notice Processes a bundle of operations. Verifies all proofs, then loops through each op
    ///         and passes to Handler for processing/execution. Emits one OperationProcessed event
    ///         per op.
    /// @dev Restricts caller of entrypoint to EOA to ensure processBundle cannot be atomically
    ///      called with another transaction.
    /// @param bundle Bundle of operations to process
    function processBundle(
        Bundle calldata bundle
    )
        external
        override
        whenNotPaused
        nonReentrant
        onlyEoa
        returns (uint256[] memory opDigests, OperationResult[] memory opResults)
    {
        Operation[] calldata ops = bundle.operations;
        require(ops.length > 0, "empty bundle");

        opDigests = new uint256[](ops.length);
        for (uint256 i = 0; i < ops.length; i++) {
            Validation.validateOperation(ops[i]);
            opDigests[i] = _computeDigest(ops[i]);
        }

        (bool success, uint256 perJoinSplitVerifyGas) = _verifyAllProofsMetered(
            ops,
            opDigests
        );
        require(success, "Batch JoinSplit verify failed");

        uint256 numOps = ops.length;
        opResults = new OperationResult[](numOps);
        for (uint256 i = 0; i < numOps; i++) {
            try
                _handler.handleOperation(
                    ops[i],
                    perJoinSplitVerifyGas,
                    msg.sender
                )
            returns (OperationResult memory result) {
                opResults[i] = result;
            } catch (bytes memory reason) {
                // Indicates revert because of expired deadline or error processing joinsplits.
                // Bundler is not compensated and we do not bubble up further OperationResult
                // info other than failureReason.
                string memory revertMsg = OperationUtils.getRevertMsg(reason);
                if (bytes(revertMsg).length == 0) {
                    opResults[i]
                        .failureReason = "handleOperation failed silently";
                } else {
                    opResults[i].failureReason = revertMsg;
                }
            }
            emit OperationProcessed(
                opDigests[i],
                opResults[i].opProcessed,
                opResults[i].assetsUnwrapped,
                opResults[i].failureReason,
                opResults[i].callSuccesses,
                opResults[i].callResults,
                opResults[i].preOpMerkleCount,
                opResults[i].postOpMerkleCount
            );
        }
        return (opDigests, opResults);
    }

    /// @notice Verifies or batch verifies joinSplit proofs for an array of operations.
    /// @dev If there is a single proof, it is cheaper to single verify. If multiple proofs,
    ///      we batch verify.
    /// @param ops Array of operations
    /// @param opDigests Array of operation digests in same order as the ops
    /// @return success Whether or not all proofs were successfully verified
    /// @return perJoinSplitVerifyGas Gas cost of verifying a single joinSplit proof (total batch
    ///         verification cost divided by number of proofs)
    function _verifyAllProofsMetered(
        Operation[] calldata ops,
        uint256[] memory opDigests
    ) internal view returns (bool success, uint256 perJoinSplitVerifyGas) {
        uint256 preVerificationGasLeft = gasleft();

        (uint256[8][] memory proofs, uint256[][] memory allPis) = OperationUtils
            .extractJoinSplitProofsAndPis(ops, opDigests);

        if (proofs.length == 1) {
            success = _joinSplitVerifier.verifyProof(proofs[0], allPis[0]);
        } else {
            success = _joinSplitVerifier.batchVerifyProofs(proofs, allPis);
        }

        perJoinSplitVerifyGas =
            (preVerificationGasLeft - gasleft()) /
            proofs.length;
        return (success, perJoinSplitVerifyGas);
    }
}


// ============================================================================
// FILE: contracts/upgrade/Versioned.sol
// ============================================================================

// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.17;

/**
 * @title Versioned
 * @notice Version getter for contracts
 **/
contract Versioned {
    uint8 public constant VERSION = 0;
}
