// SPDX-License-Identifier: UNLICENSED
// Source: 0x2d68676c40bf820eb84e3b7d8d77a1c473b08b61
// Contract Name: CrossChainSwaps
// Generated on: 2026-05-14 12:05:59


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
// FILE: @openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/cryptography/draft-EIP712.sol)

pragma solidity ^0.8.0;

// EIP-712 is Final as of 2022-08-11. This file is deprecated.

import "./EIP712Upgradeable.sol";


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
// FILE: @openzeppelin/contracts/utils/cryptography/ECDSA.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.0;

import "../Strings.sol";

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
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
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n", Strings.toString(s.length), s));
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
// FILE: @openzeppelin/contracts/utils/math/Math.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/math/Math.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
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
// FILE: @openzeppelin/contracts/utils/math/SignedMath.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.8.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.0;

/**
 * @dev Standard signed math utilities missing in the Solidity language.
 */
library SignedMath {
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
// FILE: @openzeppelin/contracts/utils/Strings.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/Strings.sol)

pragma solidity ^0.8.0;

import "./math/Math.sol";
import "./math/SignedMath.sol";

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant _SYMBOLS = "0123456789abcdef";
    uint8 private constant _ADDRESS_LENGTH = 20;

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        unchecked {
            uint256 length = Math.log10(value) + 1;
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
        return string(abi.encodePacked(value < 0 ? "-" : "", toString(SignedMath.abs(value))));
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        unchecked {
            return toHexString(value, Math.log256(value) + 1);
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
// FILE: @openzeppelin/contracts/utils/structs/BitMaps.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/structs/BitMaps.sol)
pragma solidity ^0.8.0;

/**
 * @dev Library for managing uint256 to bool mapping in a compact and efficient way, providing the keys are sequential.
 * Largely inspired by Uniswap's https://github.com/Uniswap/merkle-distributor/blob/master/contracts/MerkleDistributor.sol[merkle-distributor].
 */
library BitMaps {
    struct BitMap {
        mapping(uint256 => uint256) _data;
    }

    /**
     * @dev Returns whether the bit at `index` is set.
     */
    function get(BitMap storage bitmap, uint256 index) internal view returns (bool) {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        return bitmap._data[bucket] & mask != 0;
    }

    /**
     * @dev Sets the bit at `index` to the boolean `value`.
     */
    function setTo(BitMap storage bitmap, uint256 index, bool value) internal {
        if (value) {
            set(bitmap, index);
        } else {
            unset(bitmap, index);
        }
    }

    /**
     * @dev Sets the bit at `index`.
     */
    function set(BitMap storage bitmap, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        bitmap._data[bucket] |= mask;
    }

    /**
     * @dev Unsets the bit at `index`.
     */
    function unset(BitMap storage bitmap, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        bitmap._data[bucket] &= ~mask;
    }
}


// ============================================================================
// FILE: contracts/crossChainSwaps/CrossChainSwaps.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {
    CrossChainSwapsSignatureUtil
} from "./CrossChainSwapsSignatureUtil.sol";
import {
    OwnableUpgradeable,
    Initializable
} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {
    ReentrancyGuardUpgradeable
} from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import {
    PausableUpgradeable
} from "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import {
    AssetType,
    TradeOffer,
    TradeDetailed,
    Status,
    TradeAcceptMessage,
    PayloadType,
    Fees,
    TradeResultMessage,
    Result,
    Trade,
    TradeConstants,
    SELLER_BITMASK,
    BUYER_BITMASK,
    ForwardingGas
} from "../utils/DataTypes.sol";
import { CrossChainSwapsStorage } from "./CrossChainSwapsStorage.sol";
import { IWormholeReceiver } from "../interfaces/IWormholeReceiver.sol";
import { WormholeInteraction } from "./WormholeInteraction.sol";
import { Encoder, Decoder } from "../libraries/Formatters.sol";
import { IVault } from "../interfaces/IVault.sol";

/// @title CrossChainSwaps
/// @author NF3 Exchange
/// @notice This contract inherits from WormholeInteractions, CrossChainSwapsSignatureUtil
///         contracts and implements IWormholeReceiver interface.
/// @dev This contract acts as the public facing functions that the users as well as relayers
///      directly interact with

contract CrossChainSwaps is
    Initializable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    CrossChainSwapsSignatureUtil,
    WormholeInteraction,
    IWormholeReceiver
{
    /* ===== INIT ===== */

    function initialize(
        address wormholeRelayer_,
        uint16 wormholeChainId_,
        uint8 consistencyLevel_
    ) public initializer {
        _setWormholeRelayer(wormholeRelayer_);
        _setConsistencyLevel(consistencyLevel_);
        _setWormholeChainId(wormholeChainId_);

        __Ownable_init();
        __Pausable_init();
        __ReentrancyGuard_init();
        __EIP712_init("NF3 Crosschain Swaps", "0.2.0");
    }

    /// -----------------------------------------------------------------------
    /// Modifiers
    /// -----------------------------------------------------------------------

    modifier onlyRelayer() {
        _onlyRelayer();
        _;
    }

    /// -----------------------------------------------------------------------
    /// Trade actions
    /// -----------------------------------------------------------------------

    /// @notice Inherit from ICrossChainSwaps
    function cancelTrade(
        TradeOffer calldata _offer,
        bytes memory _signature
    ) external override whenNotPaused {
        // verify signature
        _verifyTradeOfferSignature(_offer, _signature);

        // should be called by the owner
        if (_offer.owner != _msgSender()) {
            revert SwapError(SwapErrorCode.OFFER_OWNER_ONLY);
        }

        // check nonce
        if (getNonce(_offer.owner, _offer.nonce)) {
            revert SwapError(SwapErrorCode.INVALID_OFFER_NONCE);
        }

        // set nonce
        _setNonce(_offer.owner, _offer.nonce);

        emit TradeOfferCancelled(_offer);
    }

    /// @notice Inherit from ICrossChainSwaps
    function initializeTrade(
        TradeOffer calldata _offer,
        bytes memory offerSignature,
        ForwardingGas calldata _forwardingGas,
        bytes memory gasSignature
    )
        external
        payable
        override
        whenNotPaused
        nonReentrant
        returns (uint64 sequence)
    {
        // perform sanity check
        _initTradeSanityChecks(
            _offer,
            offerSignature,
            _forwardingGas,
            gasSignature
        );

        // get hash of the trade offer
        bytes32 tradeOfferHash = Encoder.hashTradeOffer(_offer);

        // build trade struct
        TradeDetailed memory trade = TradeDetailed({
            tradeOfferHash: tradeOfferHash,
            offeringAssets: _offer.offeringAssets.primaryChainAssets,
            considerationAssets: _offer.considerationAssets.primaryChainAssets,
            seller: _offer.owner,
            buyer: _msgSender(),
            status: Status.PENDING,
            withdrawBitmap: 0,
            recoveryRequested: false
        });

        // make external calls to pull funds etc
        IVault(_state.vaultAddress).receiveAssets(
            trade,
            _offer.buyerFees,
            _offer.sellerFees
        );

        // invalidate nonce
        _setNonce(_offer.owner, _offer.nonce);
        _setGasNonce(_forwardingGas.nonce);

        // store trade data to storage corrsoponding to it's hash
        _setTradeData(trade);

        bytes memory payload = Encoder.encodeTradeAcceptMessage(
            TradeAcceptMessage({
                payloadType: PayloadType.PROCESS_TRADE,
                tradeOfferHash: tradeOfferHash,
                offeringAssets: _offer.offeringAssets.secondaryChainAssets,
                considerationAssets: _offer
                    .considerationAssets
                    .secondaryChainAssets,
                seller: trade.seller,
                buyer: trade.buyer,
                primaryChainId: uint16(_offer.primaryChainId),
                secondaryChainId: uint16(_offer.secondaryChainId)
            })
        );

        // emit message and request delivery
        sequence = _sendWormholeMessage(
            payload,
            _offer.offeringAssets.secondaryChainAssets,
            _offer.considerationAssets.secondaryChainAssets,
            _state.targetChainIdToContract[uint16(_offer.secondaryChainId)],
            uint16(_offer.secondaryChainId),
            uint16(_offer.primaryChainId),
            _forwardingGas.forwardingValue
        );

        // emit custom event
        emit TradeInitialized(
            _offer,
            tradeOfferHash,
            trade,
            _msgSender(),
            _offer.owner,
            sequence
        );
    }

    /// @notice Inherit from ICrossChainSwaps
    function requestRecovery(
        bytes32 tradeOfferHash,
        TradeConstants calldata tradeConstants
    ) external override {
        Trade storage trade = _state.trades[tradeOfferHash];

        // check if trade exist and is in correct state
        if (trade.status != Status.PENDING) {
            revert SwapError(SwapErrorCode.INVALID_TRADE_STATUS);
        }

        // check if correct trade constants are passed
        _checkTradeConstants(trade, tradeConstants);

        if (
            _msgSender() != tradeConstants.seller &&
            _msgSender() != tradeConstants.buyer
        ) // check if called by buyer or seller, get their bit
        {
            revert SwapError(SwapErrorCode.TRADE_OWNERS_ONLY);
        }

        if (!trade.recoveryRequested) {
            // mark trade as requsted recovery
            trade.recoveryRequested = true;

            // emit event
            emit RecoveryRequested(tradeOfferHash);
        }
    }

    /// @notice Inherit from ICrossChainSwaps
    function recoverTrade(
        bytes32 tradeOfferHash,
        Result result
    ) external override onlyOwner {
        Trade storage trade = _state.trades[tradeOfferHash];

        // check if trade exist, is in correct state
        if (trade.status != Status.PENDING) {
            revert SwapError(SwapErrorCode.INVALID_TRADE_STATUS);
        }

        //check if recovery is requested
        if (!trade.recoveryRequested) {
            revert SwapError(SwapErrorCode.RECOVERY_NOT_REQUESTED);
        }

        // set the status of the trade
        trade.status = result == Result.SUCCESS
            ? Status.SUCCESS
            : Status.FAILED;

        // emit event
        emit TradeRecovered(tradeOfferHash, trade.status);
    }

    /// @notice Inherit from ICrossChainSwaps
    function withdrawTradeAssets(
        bytes32 tradeOfferHash,
        TradeConstants calldata tradeConstants
    ) external override whenNotPaused nonReentrant {
        // check trade with given offer hash has currect status
        Trade memory trade = _state.trades[tradeOfferHash];
        if (trade.status != Status.SUCCESS && trade.status != Status.FAILED) {
            revert SwapError(SwapErrorCode.INVALID_TRADE_STATUS);
        }

        // check if correct trade constants are passed
        _checkTradeConstants(trade, tradeConstants);

        // send assets to buyer and seller if not already withdrawn
        if (_msgSender() == tradeConstants.buyer) {
            if ((trade.withdrawBitmap & BUYER_BITMASK) > 0) {
                revert SwapError(SwapErrorCode.BUYER_ALREADY_CLAIMED);
            }
            IVault(_state.vaultAddress).sendAssets(
                trade.status == Status.SUCCESS
                    ? tradeConstants.offeringAssets
                    : tradeConstants.considerationAssets,
                tradeConstants.buyer
            );
            _state.trades[tradeOfferHash].withdrawBitmap |= BUYER_BITMASK;
        } else if (_msgSender() == tradeConstants.seller) {
            if ((trade.withdrawBitmap & SELLER_BITMASK) > 0) {
                revert SwapError(SwapErrorCode.SELLER_ALREADY_CLAIMED);
            }
            IVault(_state.vaultAddress).sendAssets(
                trade.status == Status.SUCCESS
                    ? tradeConstants.considerationAssets
                    : tradeConstants.offeringAssets,
                tradeConstants.seller
            );
            _state.trades[tradeOfferHash].withdrawBitmap |= SELLER_BITMASK;
        }

        emit AssetsWithdrew(tradeOfferHash, _msgSender());
    }

    /// @notice Inherit from IWormholeReceiver
    function receiveWormholeMessages(
        bytes memory payload,
        bytes[] memory,
        bytes32 sourceAddress,
        uint16 sourceChain,
        bytes32 deliveryHash
    ) external payable override onlyRelayer {
        // perform sanity checks
        _wormholeMessageValidation(
            address(uint160(uint256(sourceAddress))),
            sourceChain,
            deliveryHash
        );
        // get action type
        PayloadType payloadType = Decoder.getPayloadType(payload);

        if (payloadType == PayloadType.PROCESS_TRADE) {
            // decode trade message
            TradeAcceptMessage memory trade = Decoder.decodeTradeAcceptMessage(
                payload
            );
            (
                bytes memory _payload,
                TradeDetailed memory _finalTrade,
                Status _status,
                bool success
            ) = _processTrade(trade);

            // forward message with successs status
            uint64 sequence = _forwardWormholeMessage(
                _payload,
                sourceChain,
                trade.buyer
            );

            if (success)
                emit TradeProcessed(
                    trade.tradeOfferHash,
                    _finalTrade,
                    _status,
                    sequence
                );
        } else {
            TradeResultMessage memory message = Decoder
                .decodeTradeResultMessage(payload);

            _completeTrade(message);
        }
    }

    /// -----------------------------------------------------------------------
    /// Owner actions
    /// -----------------------------------------------------------------------

    /// @notice Inherit from ICrossChainSwaps
    function setWormholeRelayer(
        address wormholeRelayer_
    ) external override onlyOwner {
        _setWormholeRelayer(wormholeRelayer_);
    }

    /// @notice Inherit from ICrossChainSwaps
    function setConsistencyLevel(
        uint8 consistencyLevel_
    ) external override onlyOwner {
        _setConsistencyLevel(consistencyLevel_);
    }

    /// @notice Inherit from ICrossChainSwaps
    function setWormholeChainId(
        uint16 wormholeChainId_
    ) external override onlyOwner {
        _setWormholeChainId(wormholeChainId_);
    }

    /// @notice Inherit from ICrossChainSwaps
    function addTargetContractAddress(
        address targetContractAddress_,
        uint16 targetChainId_
    ) external override onlyOwner {
        _addTargetContractAddress(targetContractAddress_, targetChainId_);

        emit TargetContractAdded(targetContractAddress_, targetChainId_);
    }

    /// @notice Inherit from ICrossChainSwaps
    function setVault(address vaultAddress_) external override onlyOwner {
        _setVault(vaultAddress_);
    }

    /// @notice Intherit from ICrossChainSwaps
    function setGasSignatureAdmin(
        address gasSignatureAdmin_
    ) external override onlyOwner {
        _setGasSignatureAdmin(gasSignatureAdmin_);
    }

    /// @notice Inherit from ICrossChainSwaps
    function setTokenTypes(
        address[] calldata _tokens,
        AssetType[] calldata _types
    ) external override onlyOwner {
        _setTokenTypes(_tokens, _types);

        emit TokensTypeSet(_tokens, _types);
    }

    /// -----------------------------------------------------------------------
    /// Internal functions
    /// -----------------------------------------------------------------------

    /// @dev helper function to perform sanity checks while initiating a
    ///      cross chain trade
    /// @param _offer Trade offer params
    /// @param _signature signature of the offer parameters
    /// @param _forwardingGas Gas forwarding details struct
    /// @param _gasSignature Signaute of the gas forwarding params
    function _initTradeSanityChecks(
        TradeOffer calldata _offer,
        bytes memory _signature,
        ForwardingGas calldata _forwardingGas,
        bytes memory _gasSignature
    ) private view {
        // verify typed signature
        _verifyTradeOfferSignature(_offer, _signature);
        _verifyForwardingGasSignature(_forwardingGas, _gasSignature);

        // check gas signature owner
        if (_forwardingGas.owner != _state.gasSignatureAdmin) {
            revert SwapError(SwapErrorCode.INVALID_SIGNATURE_ADMIN);
        }

        // nonce validation
        if (getNonce(_offer.owner, _offer.nonce)) {
            revert SwapError(SwapErrorCode.INVALID_OFFER_NONCE);
        }

        if (getGasNonce(_forwardingGas.nonce)) {
            revert SwapError(SwapErrorCode.INVALID_FORWARDER_NONCE);
        }

        // check expiration
        if (_offer.timePeriod < block.timestamp) {
            revert SwapError(SwapErrorCode.OFFER_EXPIRED);
        }

        // check accepted by correct user address
        address intendedFor = _offer.tradeIntendedFor;
        if (!(intendedFor == address(0) || intendedFor == _msgSender())) {
            revert SwapError(SwapErrorCode.INTENDED_FOR_P2P_TRADE);
        }

        // check emitter chainId in signature
        // check if receiver chainId is registred
        if (
            _offer.primaryChainId != _state.wormholeChainId ||
            _state.targetChainIdToContract[uint16(_offer.secondaryChainId)] ==
            address(0)
        ) {
            revert SwapError(SwapErrorCode.INVALID_CHAIN_IDS);
        }

        // get assets type
        bool isOfferValid = verifyAssetWhitelist(
            _offer.offeringAssets.primaryChainAssets
        );

        bool isConsiderationValid = verifyAssetWhitelist(
            _offer.offeringAssets.primaryChainAssets
        );

        if (!(isOfferValid && isConsiderationValid)) {
            revert SwapError(SwapErrorCode.ASSETS_NOT_WHITELISTED);
        }
    }

    /// @dev helper function to perform wormhole specific validation on the
    ///      received message
    /// @param sourceAddress Address of the contract at source chain
    /// @param sourceChain wormhole chainId of the source chain
    /// @param deliveryHash message hash of the wormhole delivery
    function _wormholeMessageValidation(
        address sourceAddress,
        uint16 sourceChain,
        bytes32 deliveryHash
    ) private {
        // check if correct emitter
        uint16 _sourceChainId = _state.targetContractToChainId[sourceAddress];
        address _sourceAddress = _state.targetChainIdToContract[sourceChain];

        if (
            _sourceChainId == 0 ||
            _sourceAddress == address(0) ||
            _sourceAddress != sourceAddress
        ) {
            revert SwapError(SwapErrorCode.INVALID_CHAIN_IDS);
        }

        // completed (replay protection), also serves as reentrancy protection
        if (messageHashConsumed(deliveryHash)) {
            revert SwapError(SwapErrorCode.MESSAGE_ALREADY_CONSUMED);
        }
        _consumeMessageHash(deliveryHash);
    }

    /// @dev helper function to process trade after receving payload as a
    ///      wormhole delivery. Performs sanity checks and pulls assets on this chain
    ///      Emits a new message for wormhole to deliver back to initial chain
    /// @param trade Trade accepting message sent by wormhole
    function _processTrade(
        TradeAcceptMessage memory trade
    ) private returns (bytes memory, TradeDetailed memory, Status, bool) {
        TradeDetailed memory finalTrade;
        // check if correct chain ids are in place
        if (trade.secondaryChainId != _state.wormholeChainId) {
            // return with failure message payload
            return (
                _getForwardingMessagePayload(
                    trade.tradeOfferHash,
                    Result.FAILED,
                    trade.primaryChainId,
                    trade.secondaryChainId
                ),
                finalTrade,
                Status.FAILED,
                false
            );
        }

        // get validate asset types
        bool isOfferValid = verifyAssetWhitelist(trade.offeringAssets);
        bool isConsiderationValid = verifyAssetWhitelist(
            trade.considerationAssets
        );

        if (!(isOfferValid && isConsiderationValid)) {
            return (
                _getForwardingMessagePayload(
                    trade.tradeOfferHash,
                    Result.FAILED,
                    trade.primaryChainId,
                    trade.secondaryChainId
                ),
                finalTrade,
                Status.FAILED,
                false
            );
        }

        finalTrade = TradeDetailed({
            tradeOfferHash: trade.tradeOfferHash,
            offeringAssets: trade.offeringAssets,
            considerationAssets: trade.considerationAssets,
            seller: trade.seller,
            buyer: trade.buyer,
            status: Status.SUCCESS,
            withdrawBitmap: 0,
            recoveryRequested: false
        });

        // pull assets with external call along with a try catch
        try
            IVault(_state.vaultAddress).receiveAssets(
                finalTrade,
                Fees({ to: address(0), token: address(0), amount: 0 }),
                Fees({ to: address(0), token: address(0), amount: 0 })
            )
        {
            _setTradeData(finalTrade);

            return (
                _getForwardingMessagePayload(
                    trade.tradeOfferHash,
                    Result.SUCCESS,
                    trade.primaryChainId,
                    trade.secondaryChainId
                ),
                finalTrade,
                Status.SUCCESS,
                true
            );
        } catch {
            return (
                _getForwardingMessagePayload(
                    trade.tradeOfferHash,
                    Result.FAILED,
                    trade.primaryChainId,
                    trade.secondaryChainId
                ),
                finalTrade,
                Status.FAILED,
                true
            );
        }
    }

    /// @dev helper function to finalize a trade once it has done processing on
    ///      secondary chain
    ///      Updates the trade status based on the incomming wormhole message
    /// @param message Incomming trade message from wormhole
    function _completeTrade(TradeResultMessage memory message) private {
        // check if correct chain ids are in place
        if (message.primaryChainId != _state.wormholeChainId) {
            revert SwapError(SwapErrorCode.INVALID_CHAIN_IDS);
        }
        // if success => allow to withdraw swapped else => allow to withdraw original
        _state.trades[message.tradeOfferHash].status = message.result ==
            Result.SUCCESS
            ? Status.SUCCESS
            : Status.FAILED;

        emit TradeCompleted(
            message.tradeOfferHash,
            message.result == Result.SUCCESS ? Status.SUCCESS : Status.FAILED
        );
    }

    /// @dev internal helper function to verify trade constants with stored values
    /// @param trade Trade stored onchain
    /// @param tradeConstants Trade constants passed in the call
    function _checkTradeConstants(
        Trade memory trade,
        TradeConstants calldata tradeConstants
    ) internal pure {
        if (
            trade.tradeContantsHash !=
            Encoder.hashTradeConstants(
                tradeConstants.offeringAssets,
                tradeConstants.considerationAssets,
                tradeConstants.buyer,
                tradeConstants.seller
            )
        ) {
            revert SwapError(SwapErrorCode.INVALID_TRADE_CONSTANTS);
        }
    }

    /// @dev internal helper function for modifier onlyRelayer
    function _onlyRelayer() internal view {
        if (_msgSender() != _state.wormholeRelayer) {
            revert SwapError(SwapErrorCode.ONLY_RELAYER);
        }
    }

    /// @dev helper function to get encoded bytes of payload to forward
    /// @param _tradeOfferHash hash of the trade offer
    /// @param _result Final result of the trade
    /// @param _primaryChainId wormhole chain id of the primary chain
    /// @param _secondaryChainId wormhole chain id of the secondary chain
    function _getForwardingMessagePayload(
        bytes32 _tradeOfferHash,
        Result _result,
        uint16 _primaryChainId,
        uint16 _secondaryChainId
    ) private pure returns (bytes memory) {
        return
            Encoder.encodeTradeResultMessage(
                TradeResultMessage({
                    payloadType: PayloadType.COMPLETE_TRADE,
                    tradeOfferHash: _tradeOfferHash,
                    result: _result,
                    primaryChainId: _primaryChainId,
                    secondaryChainId: _secondaryChainId
                })
            );
    }

    /// @dev storage gap
    // solhint-disable-next-line
    uint[50] __gap;
}


// ============================================================================
// FILE: contracts/crossChainSwaps/CrossChainSwapsSignatureUtil.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {
    EIP712Upgradeable
} from "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import {
    TradeOffer,
    ForwardingGas,
    Fees,
    AssetsSet,
    Assets,
    AssetData
} from "../utils/DataTypes.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title Cross Chain Swaps Signing Utils
/// @author NF3 Exchange
/// @dev  Helper contract for Protocol. This contract manages verifying signatures
///       from off-chain Protocol orders.

abstract contract CrossChainSwapsSignatureUtil is EIP712Upgradeable {
    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------

    enum SigningUtilsErrorCodes {
        INVALID_TRADE_OFFER_SIGNATURE,
        INVALID_GAS_FORWARDING_SIGNATURE
    }

    error SigningUtilsError(SigningUtilsErrorCodes code);

    /// -----------------------------------------------------------------------
    /// Library usage
    /// -----------------------------------------------------------------------
    using ECDSA for bytes32;

    /// -----------------------------------------------------------------------
    /// Storage variables
    /// -----------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable TRADE_OFFER_TYPE_HASH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable FORWARDING_GAS_TYPE_HASH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable FEES_TYPE_HASH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable ASSETS_SET_TYPE_HASH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable ASSETS_TYPE_HASH;

    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    bytes32 private immutable ASSET_DATA_TYPE_HASH;

    /* ===== INIT ===== */

    /// @dev Constructor
    /// @dev Calculate and set type hashes for all the structs and nested structs types
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        bytes memory assetDataTypeString = abi.encodePacked(
            "AssetData(",
            "address token,",
            "uint8 assetType,",
            "uint256 tokenId,",
            "uint256 amount",
            ")"
        );

        bytes memory assetsTypeString = abi.encodePacked(
            "Assets(",
            "AssetData[] assets"
            ")"
        );

        bytes memory assetsSetTypeString = abi.encodePacked(
            "AssetsSet(",
            "Assets primaryChainAssets,",
            "Assets secondaryChainAssets",
            ")"
        );

        bytes memory feesTypeString = abi.encodePacked(
            "Fees(",
            "address to,",
            "address token,",
            "uint256 amount",
            ")"
        );

        bytes memory tradeOfferTypeString = abi.encodePacked(
            "TradeOffer(",
            "AssetsSet offeringAssets,",
            "AssetsSet considerationAssets,",
            "Fees buyerFees,",
            "Fees sellerFees,",
            "address owner,",
            "uint256 timePeriod,",
            "uint256 nonce,",
            "address tradeIntendedFor,",
            "uint256 primaryChainId,",
            "uint256 secondaryChainId"
            ")"
        );

        bytes memory forwardingGasTypeString = abi.encodePacked(
            "ForwardingGas(",
            "uint256 forwardingValue,",
            "uint256 nonce,",
            "address owner",
            ")"
        );

        TRADE_OFFER_TYPE_HASH = keccak256(
            abi.encodePacked(
                tradeOfferTypeString,
                assetDataTypeString,
                assetsTypeString,
                assetsSetTypeString,
                feesTypeString
            )
        );
        FORWARDING_GAS_TYPE_HASH = keccak256(forwardingGasTypeString);
        FEES_TYPE_HASH = keccak256(feesTypeString);
        ASSETS_SET_TYPE_HASH = keccak256(
            abi.encodePacked(
                assetsSetTypeString,
                assetDataTypeString,
                assetsTypeString
            )
        );
        ASSETS_TYPE_HASH = keccak256(
            abi.encodePacked(assetsTypeString, assetDataTypeString)
        );
        ASSET_DATA_TYPE_HASH = keccak256(assetDataTypeString);
    }

    /// -----------------------------------------------------------------------
    /// Signature Verification Functions
    /// -----------------------------------------------------------------------

    /// @dev Check the signature if the trade offer info is valid or not.
    /// @param _offer trade offer info
    /// @param signature offer signature
    function _verifyTradeOfferSignature(
        TradeOffer calldata _offer,
        bytes memory signature
    ) internal view {
        bytes32 tradeOfferHash = keccak256(
            abi.encode(
                TRADE_OFFER_TYPE_HASH,
                _hashAssetsSet(_offer.offeringAssets),
                _hashAssetsSet(_offer.considerationAssets),
                _hashFees(_offer.buyerFees),
                _hashFees(_offer.sellerFees),
                _offer.owner,
                _offer.timePeriod,
                _offer.nonce,
                _offer.tradeIntendedFor,
                _offer.primaryChainId,
                _offer.secondaryChainId
            )
        );

        address signer = _hashTypedDataV4(tradeOfferHash).recover(signature);
        if (_offer.owner != signer) {
            revert SigningUtilsError(
                SigningUtilsErrorCodes.INVALID_TRADE_OFFER_SIGNATURE
            );
        }
    }

    /// @dev Check the signature if the gas forwarding info is valid or not.
    /// @param _forwardingGas forwarding gas info
    /// @param signature forwardingGas signature
    function _verifyForwardingGasSignature(
        ForwardingGas calldata _forwardingGas,
        bytes memory signature
    ) internal view {
        bytes32 forwardingGasHash = keccak256(
            abi.encode(
                FORWARDING_GAS_TYPE_HASH,
                _forwardingGas.forwardingValue,
                _forwardingGas.nonce,
                _forwardingGas.owner
            )
        );

        address signer = _hashTypedDataV4(forwardingGasHash).recover(signature);
        if (_forwardingGas.owner != signer) {
            revert SigningUtilsError(
                SigningUtilsErrorCodes.INVALID_GAS_FORWARDING_SIGNATURE
            );
        }
    }

    /// -----------------------------------------------------------------------
    /// Private functions
    /// -----------------------------------------------------------------------

    /// @dev Get eip 712 compliant hash for Fees struct type
    /// @param _fees Fees struct to be hashed
    function _hashFees(Fees calldata _fees) private view returns (bytes32) {
        bytes32 feesTypeHash = keccak256(
            abi.encode(FEES_TYPE_HASH, _fees.to, _fees.token, _fees.amount)
        );
        return feesTypeHash;
    }

    /// @dev Get eip 712 compliant hash for AssetsSet struct type
    /// @param _assets AssetsSet struct to be hashed
    function _hashAssetsSet(
        AssetsSet calldata _assets
    ) private view returns (bytes32) {
        bytes32 assetsSetTypeHash = keccak256(
            abi.encode(
                ASSETS_SET_TYPE_HASH,
                _hashAssets(_assets.primaryChainAssets),
                _hashAssets(_assets.secondaryChainAssets)
            )
        );

        return assetsSetTypeHash;
    }

    /// @dev Get eip 712 compliant hash for Assets struct type
    /// @param _assets Assetes struct to be hashed
    function _hashAssets(
        Assets calldata _assets
    ) private view returns (bytes32) {
        uint256 assetsCount = _assets.assets.length;
        bytes32[] memory assetsHashes = new bytes32[](assetsCount);

        for (uint i; i < assetsCount; ) {
            assetsHashes[i] = _hashAssetData(_assets.assets[i]);
            unchecked {
                ++i;
            }
        }

        bytes32 assetsTypeHash = keccak256(
            abi.encode(
                ASSETS_TYPE_HASH,
                keccak256(abi.encodePacked(assetsHashes))
            )
        );

        return assetsTypeHash;
    }

    /// @dev Get eip 712 compliant hash for AssetData struct type
    /// @param _asset AssetData struct to be hashed
    function _hashAssetData(
        AssetData calldata _asset
    ) private view returns (bytes32) {
        bytes32 assetDataTypeHash = keccak256(
            abi.encode(
                ASSET_DATA_TYPE_HASH,
                _asset.token,
                _asset.assetType,
                _asset.tokenId,
                _asset.amount
            )
        );

        return assetDataTypeHash;
    }
}


// ============================================================================
// FILE: contracts/crossChainSwaps/CrossChainSwapsStorage.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { BitMaps } from "@openzeppelin/contracts/utils/structs/BitMaps.sol";
import {
    TradeDetailed,
    AssetType,
    Assets,
    Trade,
    State
} from "../utils/DataTypes.sol";
import { ICrossChainSwaps } from "../interfaces/ICrossChainSwaps.sol";
import { Encoder } from "../libraries/Formatters.sol";

/// @title Cross Chain Swaps Storage
/// @author NF3 Exchange
/// @notice This is an abstract contract that inherits from ICrossChainSwaps interface.
/// @dev This contract acts as a storage provider for other contracts in the inheritance tree

abstract contract CrossChainSwapsStorage is ICrossChainSwaps {
    /// -----------------------------------------------------------------------
    /// Library usage
    /// -----------------------------------------------------------------------

    using BitMaps for BitMaps.BitMap;

    /// -----------------------------------------------------------------------
    /// Storage variables
    /// -----------------------------------------------------------------------

    /// @notice Tightly packed storage values required for the system
    State internal _state;

    /// -----------------------------------------------------------------------
    /// Setter functions
    /// -----------------------------------------------------------------------

    /// @dev Set wormhole relayer's address
    /// @param wormholeRelayer_ Address of the new relayer contract
    function _setWormholeRelayer(address wormholeRelayer_) internal {
        if (wormholeRelayer_ == address(0))
            revert SwapError(SwapErrorCode.INVALID_ADDRESS);
        _state.wormholeRelayer = payable(wormholeRelayer_);
    }

    /// @dev Set consistency level on the current chainId.
    /// See https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consist#consistency-levels
    /// @param consistencyLevel_ value of new consistency level
    function _setConsistencyLevel(uint8 consistencyLevel_) internal {
        _state.consistencyLevel = consistencyLevel_;
    }

    /// @dev Set wormhole chain id of the current evm chain
    /// @param wormholeChainId_ new wormhole chain id for the current evm chain
    function _setWormholeChainId(uint16 wormholeChainId_) internal {
        _state.wormholeChainId = wormholeChainId_;
    }

    /// @dev Register new evm chain for cross chain swaps
    /// @param targetContractAddress_ EVM address of the new chain
    /// @param targetChainId_ wormhole chain id of the new chain
    function _addTargetContractAddress(
        address targetContractAddress_,
        uint16 targetChainId_
    ) internal {
        if (targetContractAddress_ == address(0))
            revert SwapError(SwapErrorCode.INVALID_ADDRESS);
        _state.targetContractToChainId[targetContractAddress_] = targetChainId_;
        _state.targetChainIdToContract[targetChainId_] = targetContractAddress_;
    }

    /// @dev Update nonce of a user address
    /// @param owner User's address
    /// @param _nonce Nonce to be updated
    function _setNonce(address owner, uint _nonce) internal {
        _state.nonce[owner].set(_nonce);
    }

    /// @dev Update nonce of gas forwarding message
    /// @param _nonce Nonce to be updated
    function _setGasNonce(uint _nonce) internal {
        _state.gasForwardingNonce.set(_nonce);
    }

    /// @dev Update the incomming trade message as consumed
    /// @param vmHash Hash of the trade offer
    function _consumeMessageHash(bytes32 vmHash) internal {
        _state.consumedMessages[vmHash] = true;
    }

    /// @dev Whitelist new token, allowing trade on the platform
    /// @param _tokens Addresses of new tokens
    /// @param _types Types of asset corrosponding to each token address
    function _setTokenTypes(
        address[] calldata _tokens,
        AssetType[] calldata _types
    ) internal {
        for (uint256 i = 0; i < _tokens.length; i++) {
            _state.types[_tokens[i]] = _types[i];
        }
    }

    /// @dev Update address of vault contract. Restricted function, can only be called by owner
    /// @param vaultAddress_ address of new vault
    function _setVault(address vaultAddress_) internal {
        if (vaultAddress_ == address(0))
            revert SwapError(SwapErrorCode.INVALID_ADDRESS);
        _state.vaultAddress = vaultAddress_;
    }

    /// @dev Update address of the admin who will sign the gas forwarding message
    /// @param gasSignatureAdmin_ address of new gas admin
    function _setGasSignatureAdmin(address gasSignatureAdmin_) internal {
        if (gasSignatureAdmin_ == address(0))
            revert SwapError(SwapErrorCode.INVALID_ADDRESS);
        _state.gasSignatureAdmin = gasSignatureAdmin_;
    }

    /// @dev Set data a trade corrosponding to it's trade offer hash
    /// @param _trade Trade data to be stored
    function _setTradeData(TradeDetailed memory _trade) internal {
        Trade storage trade = _state.trades[_trade.tradeOfferHash];
        trade.tradeContantsHash = Encoder.hashTradeConstants(
            _trade.offeringAssets,
            _trade.considerationAssets,
            _trade.buyer,
            _trade.seller
        );
        trade.status = _trade.status;
        trade.withdrawBitmap = _trade.withdrawBitmap;
    }

    /// -----------------------------------------------------------------------
    /// Getter functions
    /// -----------------------------------------------------------------------

    /// @dev wormhole core contract address
    function wormholeRelayer() public view returns (address) {
        return _state.wormholeRelayer;
    }

    /// @dev number of confirmations for wormhole messages
    function consistencyLevel() public view returns (uint8) {
        return _state.consistencyLevel;
    }

    /// @dev wormhole chain id of current network
    function wormholeChainId() public view returns (uint16) {
        return _state.wormholeChainId;
    }

    /// @dev assets vault for the system
    function vaultAddress() public view returns (address) {
        return _state.vaultAddress;
    }

    /// @dev admin's address who will sign the gas signatures
    function gasSignatureAdmin() public view returns (address) {
        return _state.gasSignatureAdmin;
    }

    /// @dev mapping from target contract on other chain to their wormhole chain id
    /// @param _contract Target contract address
    function targetContractToChainId(
        address _contract
    ) public view returns (uint16) {
        return _state.targetContractToChainId[_contract];
    }

    /// @dev mapping from wormhole chain id to target contract on other chain
    /// @param _chainId Target chainId
    function targetChainIdToContract(
        uint16 _chainId
    ) public view returns (address) {
        return _state.targetChainIdToContract[_chainId];
    }

    /// @dev trade data mapped to it's hash
    /// @param _hash Trade offer hash for the given trade
    function trades(bytes32 _hash) public view returns (Trade memory) {
        return _state.trades[_hash];
    }

    /// @dev Get nonce status of a user and nonce value
    /// @param owner User's address
    /// @param _nonce Nonce value to check
    function getNonce(address owner, uint _nonce) public view returns (bool) {
        return _state.nonce[owner].get(_nonce);
    }

    /// @dev Get nonce status of the gas forwarding admin
    /// @param _nonce Nonce value to check
    function getGasNonce(uint _nonce) public view returns (bool) {
        return _state.gasForwardingNonce.get(_nonce);
    }

    /// @dev Check if message hash is already consumed or not
    /// @param hash Message hash to check
    function messageHashConsumed(bytes32 hash) public view returns (bool) {
        return _state.consumedMessages[hash];
    }

    /// @dev Check if a give set of assets are whitelisted and their token
    ///      types are set correctly or not
    /// @param _assets Assets struct to be checked for whitelist
    function verifyAssetWhitelist(
        Assets memory _assets
    ) public view returns (bool) {
        uint i;
        uint len = _assets.assets.length;

        // loop through assets and check their types
        for (i; i < len; ) {
            if (
                _state.types[_assets.assets[i].token] !=
                _assets.assets[i].assetType
            ) {
                return false;
            }
            unchecked {
                ++i;
            }
        }

        return true;
    }
}


// ============================================================================
// FILE: contracts/crossChainSwaps/WormholeInteraction.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { IWormholeRelayer, VaaKey } from "../interfaces/IWormholeRelayer.sol";
import { CrossChainSwapsStorage } from "./CrossChainSwapsStorage.sol";
import {
    Assets,
    AssetType,
    GAS_REQUIRED_FOR_ERC20,
    GAS_REQUIRED_FOR_ERC721,
    GAS_REQUIRED_FOR_ERC1155,
    BASE_GAS_REQUIRED,
    BASE_GAS_FOR_FORWARDING
} from "../utils/DataTypes.sol";

/// @title Wormhole Interactions
/// @author NF3 Exchange
/// @notice This is an abstract contract that inherits from CrossChainSwapsStorage.
/// @dev This contract acts as a layer responsible for sending and forwarding wormhole messages

abstract contract WormholeInteraction is CrossChainSwapsStorage {
    /// -----------------------------------------------------------------------
    /// Wormhole actions
    /// -----------------------------------------------------------------------

    /// @dev Send a wormhole message to the specifed chain id and contract
    ///      address along with the give payload
    /// @param payload Encoded payload bytes to be sent
    /// @param offeringAssets Assets offered on the secondary chain
    /// @param considerationAssets Assets required as consideration on secondary chain
    /// @param _targetAddress Address of cross chain contract on secondary chain
    /// @param _targetChainId ChainId to which message needs to be delivered
    /// @param _refundChainId ChainId on which the remainig gas will be refunded to
    /// @param _receiverValue Amount to be sent to second chain to fund forwarding
    function _sendWormholeMessage(
        bytes memory payload,
        Assets calldata offeringAssets,
        Assets calldata considerationAssets,
        address _targetAddress,
        uint16 _targetChainId,
        uint16 _refundChainId,
        uint256 _receiverValue
    ) internal returns (uint64 sequence) {
        // get estimated gas requried
        uint256 amountOfGasRequried = calculateGasForRelay(
            offeringAssets,
            considerationAssets
        );

        // get quote on deliver cost
        (uint256 cost, ) = IWormholeRelayer(_state.wormholeRelayer)
            .quoteEVMDeliveryPrice(
                _targetChainId,
                _receiverValue,
                amountOfGasRequried
            );

        if (cost > msg.value) {
            revert SwapError(SwapErrorCode.INSUFFICIENT_GAS_FEES_PROVIDED);
        }

        // emit message and request delivery
        sequence = IWormholeRelayer(_state.wormholeRelayer).sendPayloadToEvm{
            value: msg.value
        }(
            _targetChainId,
            _targetAddress,
            payload,
            _receiverValue,
            amountOfGasRequried,
            _refundChainId,
            msg.sender
        );
    }

    /// @dev Forward a wormhole message to the specifed chain id and contract
    ///      address along with the give payload
    /// @param _payload Encoded payload bytes to be sent
    /// @param _targetChainId ChainId to which message needs to be delivered
    /// @param _refundAddress Address to which gas refund should be sent
    function _forwardWormholeMessage(
        bytes memory _payload,
        uint16 _targetChainId,
        address _refundAddress
    ) internal returns (uint64 sequence) {
        uint256 receiverValue = 0;

        sequence = IWormholeRelayer(_state.wormholeRelayer).sendPayloadToEvm{
            value: msg.value
        }(
            _targetChainId,
            _state.targetChainIdToContract[_targetChainId],
            _payload,
            receiverValue,
            BASE_GAS_FOR_FORWARDING,
            _targetChainId,
            _refundAddress
        );
    }

    /// -----------------------------------------------------------------------
    /// internal actions
    /// -----------------------------------------------------------------------

    /// @dev Helper function to calculate gas required for relaying the message
    /// @param offeringAssets Assets offered on the secondary chain
    /// @param considerationAssets Assets required as consideration on secondary chain
    function calculateGasForRelay(
        Assets calldata offeringAssets,
        Assets calldata considerationAssets
    ) public pure returns (uint256) {
        // base amount for relaying
        uint amountOfGasRequired = BASE_GAS_REQUIRED;

        // amount of gas required for pulling assets on the other chain
        amountOfGasRequired +=
            _calculateGasRequriedForPullingAssets(offeringAssets) +
            _calculateGasRequriedForPullingAssets(considerationAssets);

        // adding a buffer of base gas
        amountOfGasRequired += BASE_GAS_FOR_FORWARDING;

        return amountOfGasRequired;
    }

    /// @dev Helper function to calculate gas required for pulling assets
    /// @param _assets Assets to be pulled on the other chain
    function _calculateGasRequriedForPullingAssets(
        Assets calldata _assets
    ) private pure returns (uint256) {
        uint gasRequired = 0;

        uint len = _assets.assets.length;
        uint i;
        for (i; i < len; ) {
            if (_assets.assets[i].assetType == AssetType.ERC_721)
                gasRequired += GAS_REQUIRED_FOR_ERC721;
            else if (_assets.assets[i].assetType == AssetType.ERC_20)
                gasRequired += GAS_REQUIRED_FOR_ERC20;
            else gasRequired += GAS_REQUIRED_FOR_ERC1155;
            unchecked {
                ++i;
            }
        }

        return gasRequired;
    }
}


// ============================================================================
// FILE: contracts/interfaces/ICrossChainSwaps.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import {
    TradeOffer,
    AssetType,
    Result,
    Status,
    ForwardingGas,
    TradeConstants,
    TradeDetailed
} from "../utils/DataTypes.sol";

/// @title Cross chain swaps interface
/// @author NF3 Exchange
/// @dev This interface defines all the functions related initiating and finalizing cross chain trades.

interface ICrossChainSwaps {
    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------

    enum SwapErrorCode {
        INVALID_ADDRESS,
        INVALID_OFFER_NONCE,
        INVALID_FORWARDER_NONCE,
        OFFER_EXPIRED,
        INTENDED_FOR_P2P_TRADE,
        INVALID_CHAIN_IDS,
        ASSETS_NOT_WHITELISTED,
        MESSAGE_ALREADY_CONSUMED,
        ONLY_RELAYER,
        INVALID_TRADE_STATUS,
        BUYER_ALREADY_CLAIMED,
        SELLER_ALREADY_CLAIMED,
        TRADE_OWNERS_ONLY,
        INVALID_INPUT,
        RECOVERY_NOT_REQUESTED,
        INSUFFICIENT_GAS_FEES_PROVIDED,
        INVALID_SIGNATURE_ADMIN,
        INVALID_TRADE_CONSTANTS,
        OFFER_OWNER_ONLY
    }

    error SwapError(SwapErrorCode code);

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    /// @dev Emits when a new trade is initialzied
    /// @param offer Trade offer struct
    /// @param tradeOfferHash Hash of the trade from which assetes are withdrawn
    /// @param trade Details of the trade data on the current chain
    /// @param buyer Buyer's address
    /// @param seller Seller's address
    /// @param wormholeSequence Wormhole's message sequence number
    event TradeInitialized(
        TradeOffer offer,
        bytes32 indexed tradeOfferHash,
        TradeDetailed trade,
        address indexed buyer,
        address indexed seller,
        uint256 wormholeSequence
    );

    /// @dev Emits when a trade offer is cancelled
    /// @param offer Trade offer struct
    event TradeOfferCancelled(TradeOffer offer);

    /// @dev Emits when trade assets are withdrawn by the users
    /// @param tradeOfferHash Hash of the trade from which assetes are withdrawn
    /// @param user User address which has withdrawn the assets
    event AssetsWithdrew(bytes32 indexed tradeOfferHash, address indexed user);

    /// @dev Emits when trade is processed on being the secondary chain
    /// @param tradeOfferHash Hash of the trade offer which has been processed
    /// @param trade Details of the trade data on the current chain
    /// @param status Status to which the trade has moved
    /// @param wormholeSequence Wormhole's message sequence number
    event TradeProcessed(
        bytes32 indexed tradeOfferHash,
        TradeDetailed trade,
        Status status,
        uint64 wormholeSequence
    );

    /// @dev Emits when trade is completed
    /// @param tradeOfferHash Hash of the trade offer which has completed
    /// @param status Status to which the trade has moved
    event TradeCompleted(bytes32 indexed tradeOfferHash, Status status);

    /// @dev Emits when trade recovery is requested by either seler or buyer
    /// @param tradeOfferHash Hash of the stored trade offer who's recovery
    ///        is requested
    event RecoveryRequested(bytes32 indexed tradeOfferHash);

    /// @dev Emits when trade recovery is completed
    /// @param tradeOfferHash Hash of the stored trade offer which has
    ///        been recovered
    /// @param status Status to which trade has moved to (SUCCESS/FAILED)
    event TradeRecovered(bytes32 indexed tradeOfferHash, Status status);

    /// @dev Emits when tokens types are whitelisted by setting tokenType
    /// @param tokens Tokens that are being whitelisted
    /// @param types Token types
    event TokensTypeSet(address[] tokens, AssetType[] types);

    /// @dev Emits when new target chains are added for cross chain activity
    /// @param targetContract EVM address of the new chain
    /// @param targetChainId wormhole chain id of the new chain
    event TargetContractAdded(address targetContract, uint16 targetChainId);

    /// -----------------------------------------------------------------------
    /// Trade actions
    /// -----------------------------------------------------------------------

    /// @dev Cancel an existing trade offer by setting the nonce of that offer
    ///      Can only be called by the owner of the offer
    /// @param offer Trade offer to cancel
    /// @param signature Signature of the trade offer
    function cancelTrade(
        TradeOffer calldata offer,
        bytes memory signature
    ) external;

    /// @dev Initialize trade by lockings assets on chain A and sending a wormhole
    ///      message to chain B
    /// @param offer Details of the trade offer
    /// @param signature seller's signature of the offer parameters
    /// @param forwardingGas Amount to be sent to second chain to fund forwarding
    /// @param gasSignature Admin's signature of forwarding gas message
    /// @return sequence Wormhole sequence number
    function initializeTrade(
        TradeOffer calldata offer,
        bytes memory signature,
        ForwardingGas calldata forwardingGas,
        bytes memory gasSignature
    ) external payable returns (uint64 sequence);

    /// @dev An emergency fallback function in case of wormhole message is not
    ///      able to be delivered, the user assets don't get stuck.
    ///      Either the seller or buyer can request the recovery of a trade and
    ///      furhter processing will be done by the NF3 Admin
    /// @param tradeOfferHash Hash of the trade offer who's recovery is requested
    /// @param tradeConstants Constants involved in this trade requried for matching stored hash
    function requestRecovery(
        bytes32 tradeOfferHash,
        TradeConstants calldata tradeConstants
    ) external;

    /// @dev The trade can be set to FAILED or SUCCESS state based
    ///      on the activity on other chain To update the trade status
    ///      Restricted function, can only be called by the owner when a
    ///      recovery is requested by the seller of buyer
    /// @param tradeOfferHash Hash of the trade offer who's recovery is set
    /// @param result Result to which trade will be updated to
    function recoverTrade(bytes32 tradeOfferHash, Result result) external;

    /// @dev Withdraw assets after trade is completed. If trade was SUCCESS then
    ///      users withdraw swapped assets else withdraw their original assets
    /// @param tradeOfferHash Hash of the original trade offer
    /// @param tradeConstants Constants involved in this trade requried for matching stored hash
    function withdrawTradeAssets(
        bytes32 tradeOfferHash,
        TradeConstants calldata tradeConstants
    ) external;

    /// -----------------------------------------------------------------------
    /// Owner actions
    /// -----------------------------------------------------------------------

    /// @dev Set wormhole relayer's address. Restricted function, can only be called by owner
    /// @param wormholeRelayer Address of the new relayer contract
    function setWormholeRelayer(address wormholeRelayer) external;

    /// @dev Set consistency level on the current chainId. Restricted function, can only be called by owner
    /// See https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consist#consistency-levels
    /// @param consistencyLevel value of new consistency level
    function setConsistencyLevel(uint8 consistencyLevel) external;

    /// @dev Set wormhole chain id of the current evm chain. Restricted function, can only be called by owner
    /// @param wormholeChainId new wormhole chain id for the current evm chain
    function setWormholeChainId(uint16 wormholeChainId) external;

    /// @dev Register new evm chain for cross chain swaps. Restricted function, can only be called by owner
    /// @param targetContractAddress EVM address of the new chain
    /// @param targetChainId wormhole chain id of the new chain
    function addTargetContractAddress(
        address targetContractAddress,
        uint16 targetChainId
    ) external;

    /// @dev Update address of vault contract. Restricted function, can only be called by owner
    /// @param vaultAddress address of new vault
    function setVault(address vaultAddress) external;

    /// @dev Update address of the admin who will sign the gas forwarding
    ///      message. Restricted function, can only be called by owner
    /// @param gasSignatureAdmin address of new gas admin
    function setGasSignatureAdmin(address gasSignatureAdmin) external;

    /// @dev Whitelist new token, allowing trade on the platform.  Restricted function, can only be called by owner
    /// @param tokens Addresses of new tokens
    /// @param types Types of asset corrosponding to each token address
    function setTokenTypes(
        address[] calldata tokens,
        AssetType[] calldata types
    ) external;
}


// ============================================================================
// FILE: contracts/interfaces/IVault.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { Assets, Fees, TradeDetailed } from "../utils/DataTypes.sol";

/// @title NF3 Vault Interface
/// @author NF3 Exchange
/// @dev This interface defines all the functions related to assets transfer and assets escrow.

interface IVault {
    /// -----------------------------------------------------------------------
    /// Errors
    /// -----------------------------------------------------------------------

    enum VaultErrorCodes {
        CALLER_NOT_ALLOWED,
        INVALID_ADDRESS
    }

    error VaultError(VaultErrorCodes code);

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    /// @dev Emits when assets are transffered from a user to the vault
    /// @param assets Assets struct that is transfered
    /// @param from Address from which assets are transfered
    event AssetsReceived(Assets assets, address indexed from);

    /// @dev Emits when assets are transffered to a user from the vault
    /// @param assets Assets struct that is transfered
    /// @param to Address to which assets are transfered
    event AssetsSent(Assets assets, address indexed to);

    /// @dev Emits when fees is transferred from buyer and seller
    /// @param fees Fees details that are taken from buyer and seller
    /// @param user Address of the user who paid the fee
    event FeeTransferred(Fees fees, address indexed user);

    /// @dev Emits when new core contract address has set.
    /// @param oldCoreAddress Previous core contract address
    /// @param newCoreAddress New core contract address
    event CoreSet(address oldCoreAddress, address newCoreAddress);

    /// -----------------------------------------------------------------------
    /// Transfer actions
    /// -----------------------------------------------------------------------

    /// @dev Receive assets from seller and buyer, also deducts fees while receiving assets
    ///      Restricted function can only be called by the core contract
    /// @param trade Trade details from which assets need to be received
    /// @param buyerFees Fees details for buyer
    /// @param sellerFees Fees details for seller
    function receiveAssets(
        TradeDetailed calldata trade,
        Fees calldata buyerFees,
        Fees calldata sellerFees
    ) external returns (bool);

    /// @dev Sends locked assets to the mentioned address. Restricted function, can only be called
    ///      by the core contract
    /// @param assets Assets details that need to be sent
    /// @param to Address to which assets need to be sent
    function sendAssets(
        Assets memory assets,
        address to
    ) external returns (bool);

    /// -----------------------------------------------------------------------
    /// Owner actions
    /// -----------------------------------------------------------------------

    /// @dev Set core contract's address. Restricted function, can only be called by owner
    /// @param coreAddress Address of the new core contract
    function setCoreAddress(address coreAddress) external;
}


// ============================================================================
// FILE: contracts/interfaces/IWormholeReceiver.sol
// ============================================================================

// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

/**
 * @notice Interface for a contract which can receive Wormhole messages.
 */
interface IWormholeReceiver {
    /**
     * @notice When a `send` is performed with this contract as the target, this function will be
     *     invoked by the WormholeRelayer contract
     *
     * NOTE: This function should be restricted such that only the Wormhole Relayer contract can call it.
     *
     * We also recommend that this function:
     *   - Stores all received `deliveryHash`s in a mapping `(bytes32 => bool)`, and
     *       on every call, checks that deliveryHash has not already been stored in the
     *       map (This is to prevent other users maliciously trying to relay the same message)
     *   - Checks that `sourceChain` and `sourceAddress` are indeed who
     *       you expect to have requested the calling of `send` or `forward` on the source chain
     *
     * The invocation of this function corresponding to the `send` request will have msg.value equal
     *   to the receiverValue specified in the send request.
     *
     * If the invocation of this function reverts or exceeds the gas limit
     *   specified by the send requester, this delivery will result in a `ReceiverFailure`.
     *
     * @param payload - an arbitrary message which was included in the delivery by the
     *     requester.
     * @param additionalVaas - Additional VAAs which were requested to be included in this delivery.
     *   They are guaranteed to all be included and in the same order as was specified in the
     *     delivery request.
     * @param sourceAddress - the (wormhole format) address on the sending chain which requested
     *     this delivery.
     * @param sourceChain - the wormhole chain ID where this delivery was requested.
     * @param deliveryHash - the VAA hash of the deliveryVAA.
     *
     * NOTE: These signedVaas are NOT verified by the Wormhole core contract prior to being provided
     *     to this call. Always make sure `parseAndVerify()` is called on the Wormhole core contract
     *     before trusting the content of a raw VAA, otherwise the VAA may be invalid or malicious.
     */
    function receiveWormholeMessages(
        bytes memory payload,
        bytes[] memory additionalVaas,
        bytes32 sourceAddress,
        uint16 sourceChain,
        bytes32 deliveryHash
    ) external payable;
}


// ============================================================================
// FILE: contracts/interfaces/IWormholeRelayer.sol
// ============================================================================

// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

/**
 * @title WormholeRelayer
 * @author
 * @notice This project allows developers to build cross-chain applications powered by Wormhole without needing to
 * write and run their own relaying infrastructure
 *
 * We implement the IWormholeRelayer interface that allows users to request a delivery provider to relay a payload (and/or additional VAAs)
 * to a chain and address of their choice.
 */

/**
 * @notice VaaKey identifies a wormhole message
 *
 * @custom:member chainId Wormhole chain ID of the chain where this VAA was emitted from
 * @custom:member emitterAddress Address of the emitter of the VAA, in Wormhole bytes32 format
 * @custom:member sequence Sequence number of the VAA
 */
struct VaaKey {
    uint16 chainId;
    bytes32 emitterAddress;
    uint64 sequence;
}

interface IWormholeRelayerBase {
    event SendEvent(
        uint64 indexed sequence,
        uint256 deliveryQuote,
        uint256 paymentForExtraReceiverValue
    );

    function getRegisteredWormholeRelayerContract(
        uint16 chainId
    ) external view returns (bytes32);
}

/**
 * @title IWormholeRelayerSend
 * @notice The interface to request deliveries
 */
interface IWormholeRelayerSend is IWormholeRelayerBase {
    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     *
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     *
     * Any refunds (from leftover gas) will be paid to the delivery provider. In order to receive the refunds, use the `sendPayloadToEvm` function
     * with `refundChain` and `refundAddress` as parameters
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver)
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver)
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     *
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     *
     * Any refunds (from leftover gas) will be paid to the delivery provider. In order to receive the refunds, use the `sendVaasToEvm` function
     * with `refundChain` and `refundAddress` as parameters
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver)
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit,
        VaaKey[] memory vaaKeys
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the default delivery provider
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and `msg.value` equal to `receiverValue`
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to `quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit)`
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver)
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit,
        VaaKey[] memory vaaKeys,
        uint16 refundChain,
        address refundAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress`
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and `msg.value` equal to
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to
     * quoteEVMDeliveryPrice(targetChain, receiverValue, gasLimit, deliveryProviderAddress) + paymentForExtraReceiverValue
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver)
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue
     *        (in addition to the `receiverValue` specified)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function sendToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 paymentForExtraReceiverValue,
        uint256 gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Publishes an instruction for the delivery provider at `deliveryProviderAddress`
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with `msg.value` equal to
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * This function must be called with `msg.value` equal to
     * quoteDeliveryPrice(targetChain, receiverValue, encodedExecutionParameters, deliveryProviderAddress) + paymentForExtraReceiverValue
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue
     *        (in addition to the `receiverValue` specified)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to, in Wormhole bytes32 format
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     * @return sequence sequence number of published VAA containing delivery instructions
     */
    function send(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable returns (uint64 sequence);

    /**
     * @notice Performs the same function as a `send`, except:
     * 1)  Can only be used during a delivery (i.e. in execution of `receiveWormholeMessages`)
     * 2)  Is paid for (along with any other calls to forward) by (any msg.value passed in) + (refund leftover from current delivery)
     * 3)  Only executes after `receiveWormholeMessages` is completed (and thus does not return a sequence number)
     *
     * The refund from the delivery currently in progress will not be sent to the user; it will instead
     * be paid to the delivery provider to perform the instruction specified here
     *
     * Publishes an instruction for the same delivery provider (or default, if the same one doesn't support the new target chain)
     * to relay a payload to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and with `msg.value` equal to `receiverValue`
     *
     * The following equation must be satisfied (sum_f indicates summing over all forwards requested in `receiveWormholeMessages`):
     * (refund amount from current execution of receiveWormholeMessages) + sum_f [msg.value_f]
     * >= sum_f [quoteEVMDeliveryPrice(targetChain_f, receiverValue_f, gasLimit_f)]
     *
     * The difference between the two sides of the above inequality will be added to `paymentForExtraReceiverValue` of the first forward requested
     *
     * Any refunds (from leftover gas) from this forward will be paid to the same refundChain and refundAddress specified for the current delivery.
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     */
    function forwardPayloadToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit
    ) external payable;

    /**
     * @notice Performs the same function as a `send`, except:
     * 1)  Can only be used during a delivery (i.e. in execution of `receiveWormholeMessages`)
     * 2)  Is paid for (along with any other calls to forward) by (any msg.value passed in) + (refund leftover from current delivery)
     * 3)  Only executes after `receiveWormholeMessages` is completed (and thus does not return a sequence number)
     *
     * The refund from the delivery currently in progress will not be sent to the user; it will instead
     * be paid to the delivery provider to perform the instruction specified here
     *
     * Publishes an instruction for the same delivery provider (or default, if the same one doesn't support the new target chain)
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and with `msg.value` equal to `receiverValue`
     *
     * The following equation must be satisfied (sum_f indicates summing over all forwards requested in `receiveWormholeMessages`):
     * (refund amount from current execution of receiveWormholeMessages) + sum_f [msg.value_f]
     * >= sum_f [quoteEVMDeliveryPrice(targetChain_f, receiverValue_f, gasLimit_f)]
     *
     * The difference between the two sides of the above inequality will be added to `paymentForExtraReceiverValue` of the first forward requested
     *
     * Any refunds (from leftover gas) from this forward will be paid to the same refundChain and refundAddress specified for the current delivery.
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     */
    function forwardVaasToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 gasLimit,
        VaaKey[] memory vaaKeys
    ) external payable;

    /**
     * @notice Performs the same function as a `send`, except:
     * 1)  Can only be used during a delivery (i.e. in execution of `receiveWormholeMessages`)
     * 2)  Is paid for (along with any other calls to forward) by (any msg.value passed in) + (refund leftover from current delivery)
     * 3)  Only executes after `receiveWormholeMessages` is completed (and thus does not return a sequence number)
     *
     * The refund from the delivery currently in progress will not be sent to the user; it will instead
     * be paid to the delivery provider to perform the instruction specified here
     *
     * Publishes an instruction for the delivery provider at `deliveryProviderAddress`
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with gas limit `gasLimit` and with `msg.value` equal to
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * The following equation must be satisfied (sum_f indicates summing over all forwards requested in `receiveWormholeMessages`):
     * (refund amount from current execution of receiveWormholeMessages) + sum_f [msg.value_f]
     * >= sum_f [quoteEVMDeliveryPrice(targetChain_f, receiverValue_f, gasLimit_f, deliveryProviderAddress_f) + paymentForExtraReceiverValue_f]
     *
     * The difference between the two sides of the above inequality will be added to `paymentForExtraReceiverValue` of the first forward requested
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue
     *        (in addition to the `receiverValue` specified)
     * @param gasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to, in Wormhole bytes32 format
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     */
    function forwardToEvm(
        uint16 targetChain,
        address targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 paymentForExtraReceiverValue,
        uint256 gasLimit,
        uint16 refundChain,
        address refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable;

    /**
     * @notice Performs the same function as a `send`, except:
     * 1)  Can only be used during a delivery (i.e. in execution of `receiveWormholeMessages`)
     * 2)  Is paid for (along with any other calls to forward) by (any msg.value passed in) + (refund leftover from current delivery)
     * 3)  Only executes after `receiveWormholeMessages` is completed (and thus does not return a sequence number)
     *
     * The refund from the delivery currently in progress will not be sent to the user; it will instead
     * be paid to the delivery provider to perform the instruction specified here
     *
     * Publishes an instruction for the delivery provider at `deliveryProviderAddress`
     * to relay a payload and VAAs specified by `vaaKeys` to the address `targetAddress` on chain `targetChain`
     * with `msg.value` equal to
     * receiverValue + (arbitrary amount that is paid for by paymentForExtraReceiverValue of this chain's wei) in targetChain wei.
     *
     * Any refunds (from leftover gas) will be sent to `refundAddress` on chain `refundChain`
     * `targetAddress` must implement the IWormholeReceiver interface
     *
     * The following equation must be satisfied (sum_f indicates summing over all forwards requested in `receiveWormholeMessages`):
     * (refund amount from current execution of receiveWormholeMessages) + sum_f [msg.value_f]
     * >= sum_f [quoteDeliveryPrice(targetChain_f, receiverValue_f, encodedExecutionParameters_f, deliveryProviderAddress_f) + paymentForExtraReceiverValue_f]
     *
     * The difference between the two sides of the above inequality will be added to `paymentForExtraReceiverValue` of the first forward requested
     *
     * @param targetChain in Wormhole Chain ID format
     * @param targetAddress address to call on targetChain (that implements IWormholeReceiver), in Wormhole bytes32 format
     * @param payload arbitrary bytes to pass in as parameter in call to `targetAddress`
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param paymentForExtraReceiverValue amount (in current chain currency units) to spend on extra receiverValue
     *        (in addition to the `receiverValue` specified)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param refundChain The chain to deliver any refund to, in Wormhole Chain ID format
     * @param refundAddress The address on `refundChain` to deliver any refund to, in Wormhole bytes32 format
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @param vaaKeys Additional VAAs to pass in as parameter in call to `targetAddress`
     * @param consistencyLevel Consistency level with which to publish the delivery instructions - see
     *        https://book.wormhole.com/wormhole/3_coreLayerContracts.html?highlight=consistency#consistency-levels
     */
    function forward(
        uint16 targetChain,
        bytes32 targetAddress,
        bytes memory payload,
        uint256 receiverValue,
        uint256 paymentForExtraReceiverValue,
        bytes memory encodedExecutionParameters,
        uint16 refundChain,
        bytes32 refundAddress,
        address deliveryProviderAddress,
        VaaKey[] memory vaaKeys,
        uint8 consistencyLevel
    ) external payable;

    /**
     * @notice Requests a previously published delivery instruction to be redelivered
     * (e.g. with a different delivery provider)
     *
     * This function must be called with `msg.value` equal to
     * quoteEVMDeliveryPrice(targetChain, newReceiverValue, newGasLimit, newDeliveryProviderAddress)
     *
     *  @notice *** This will only be able to succeed if the following is true **
     *         - newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     *         - newDeliveryProvider's `targetChainRefundPerGasUnused` >= old relay provider's `targetChainRefundPerGasUnused`
     *
     * @param deliveryVaaKey VaaKey identifying the wormhole message containing the
     *        previously published delivery instructions
     * @param targetChain The target chain that the original delivery targeted. Must match targetChain from original delivery instructions
     * @param newReceiverValue new msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param newGasLimit gas limit with which to call `targetAddress`. Any units of gas unused will be refunded according to the
     *        `targetChainRefundPerGasUnused` rate quoted by the delivery provider, to the refund chain and address specified in the original request
     * @param newDeliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return sequence sequence number of published VAA containing redelivery instructions
     *
     * @notice *** This will only be able to succeed if the following is true **
     *         - newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     *         - newDeliveryProvider's `targetChainRefundPerGasUnused` >= old relay provider's `targetChainRefundPerGasUnused`
     */
    function resendToEvm(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        uint256 newReceiverValue,
        uint256 newGasLimit,
        address newDeliveryProviderAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Requests a previously published delivery instruction to be redelivered
     *
     *
     * This function must be called with `msg.value` equal to
     * quoteDeliveryPrice(targetChain, newReceiverValue, newEncodedExecutionParameters, newDeliveryProviderAddress)
     *
     * @param deliveryVaaKey VaaKey identifying the wormhole message containing the
     *        previously published delivery instructions
     * @param targetChain The target chain that the original delivery targeted. Must match targetChain from original delivery instructions
     * @param newReceiverValue new msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param newEncodedExecutionParameters new encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param newDeliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return sequence sequence number of published VAA containing redelivery instructions
     *
     *  @notice *** This will only be able to succeed if the following is true **
     *         - (For EVM_V1) newGasLimit >= gas limit of the old instruction
     *         - newReceiverValue >= receiver value of the old instruction
     *         - (For EVM_V1) newDeliveryProvider's `targetChainRefundPerGasUnused` >= old relay provider's `targetChainRefundPerGasUnused`
     */
    function resend(
        VaaKey memory deliveryVaaKey,
        uint16 targetChain,
        uint256 newReceiverValue,
        bytes memory newEncodedExecutionParameters,
        address newDeliveryProviderAddress
    ) external payable returns (uint64 sequence);

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using the default delivery provider
     *
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return targetChainRefundPerGasUnused amount of target chain currency that will be refunded per unit of gas unused,
     *         if a refundAddress is specified
     */
    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        uint256 receiverValue,
        uint256 gasLimit
    )
        external
        view
        returns (
            uint256 nativePriceQuote,
            uint256 targetChainRefundPerGasUnused
        );

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using delivery provider `deliveryProviderAddress`
     *
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param gasLimit gas limit with which to call `targetAddress`.
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return targetChainRefundPerGasUnused amount of target chain currency that will be refunded per unit of gas unused,
     *         if a refundAddress is specified
     */
    function quoteEVMDeliveryPrice(
        uint16 targetChain,
        uint256 receiverValue,
        uint256 gasLimit,
        address deliveryProviderAddress
    )
        external
        view
        returns (
            uint256 nativePriceQuote,
            uint256 targetChainRefundPerGasUnused
        );

    /**
     * @notice Returns the price to request a relay to chain `targetChain`, using delivery provider `deliveryProviderAddress`
     *
     * @param targetChain in Wormhole Chain ID format
     * @param receiverValue msg.value that delivery provider should pass in for call to `targetAddress` (in targetChain currency units)
     * @param encodedExecutionParameters encoded information on how to execute delivery that may impact pricing
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` with which to call `targetAddress`
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return nativePriceQuote Price, in units of current chain currency, that the delivery provider charges to perform the relay
     * @return encodedExecutionInfo encoded information on how the delivery will be executed
     *        e.g. for version EVM_V1, this is a struct that encodes the `gasLimit` and `targetChainRefundPerGasUnused`
     *             (which is the amount of target chain currency that will be refunded per unit of gas unused,
     *              if a refundAddress is specified)
     */
    function quoteDeliveryPrice(
        uint16 targetChain,
        uint256 receiverValue,
        bytes memory encodedExecutionParameters,
        address deliveryProviderAddress
    )
        external
        view
        returns (uint256 nativePriceQuote, bytes memory encodedExecutionInfo);

    /**
     * @notice Returns the (extra) amount of target chain currency that `targetAddress`
     * will be called with, if the `paymentForExtraReceiverValue` field is set to `currentChainAmount`
     *
     * @param targetChain in Wormhole Chain ID format
     * @param currentChainAmount The value that `paymentForExtraReceiverValue` will be set to
     * @param deliveryProviderAddress The address of the desired delivery provider's implementation of IDeliveryProvider
     * @return targetChainAmount The amount such that if `targetAddress` will be called with `msg.value` equal to
     *         receiverValue + targetChainAmount
     */
    function quoteNativeForChain(
        uint16 targetChain,
        uint256 currentChainAmount,
        address deliveryProviderAddress
    ) external view returns (uint256 targetChainAmount);

    /**
     * @notice Returns the address of the current default delivery provider
     * @return deliveryProvider The address of (the default delivery provider)'s contract on this source
     *   chain. This must be a contract that implements IDeliveryProvider.
     */
    function getDefaultDeliveryProvider()
        external
        view
        returns (address deliveryProvider);
}

/**
 * @title IWormholeRelayerDelivery
 * @notice The interface to execute deliveries. Only relevant for Delivery Providers
 */
interface IWormholeRelayerDelivery is IWormholeRelayerBase {
    enum DeliveryStatus {
        SUCCESS,
        RECEIVER_FAILURE,
        FORWARD_REQUEST_FAILURE,
        FORWARD_REQUEST_SUCCESS
    }

    enum RefundStatus {
        REFUND_SENT,
        REFUND_FAIL,
        CROSS_CHAIN_REFUND_SENT,
        CROSS_CHAIN_REFUND_FAIL_PROVIDER_NOT_SUPPORTED,
        CROSS_CHAIN_REFUND_FAIL_NOT_ENOUGH
    }

    /**
     * @custom:member recipientContract - The target contract address
     * @custom:member sourceChain - The chain which this delivery was requested from (in wormhole
     *     ChainID format)
     * @custom:member sequence - The wormhole sequence number of the delivery VAA on the source chain
     *     corresponding to this delivery request
     * @custom:member deliveryVaaHash - The hash of the delivery VAA corresponding to this delivery
     *     request
     * @custom:member gasUsed - The amount of gas that was used to call your target contract
     * @custom:member status:
     *   - RECEIVER_FAILURE, if the target contract reverts
     *   - SUCCESS, if the target contract doesn't revert and no forwards were requested
     *   - FORWARD_REQUEST_FAILURE, if the target contract doesn't revert, forwards were requested,
     *       but provided/leftover funds were not sufficient to cover them all
     *   - FORWARD_REQUEST_SUCCESS, if the target contract doesn't revert and all forwards are covered
     * @custom:member additionalStatusInfo:
     *   - If status is SUCCESS or FORWARD_REQUEST_SUCCESS, then this is empty.
     *   - If status is RECEIVER_FAILURE, this is `RETURNDATA_TRUNCATION_THRESHOLD` bytes of the
     *       return data (i.e. potentially truncated revert reason information).
     *   - If status is FORWARD_REQUEST_FAILURE, this is also the revert data - the reason the forward failed.
     *     This will be either an encoded Cancelled, DeliveryProviderReverted, or DeliveryProviderPaymentFailed error
     * @custom:member refundStatus - Result of the refund. REFUND_SUCCESS or REFUND_FAIL are for
     *     refunds where targetChain=refundChain; the others are for targetChain!=refundChain,
     *     where a cross chain refund is necessary
     * @custom:member overridesInfo:
     *   - If not an override: empty bytes array
     *   - Otherwise: An encoded `DeliveryOverride`
     */
    event Delivery(
        address indexed recipientContract,
        uint16 indexed sourceChain,
        uint64 indexed sequence,
        bytes32 deliveryVaaHash,
        DeliveryStatus status,
        uint256 gasUsed,
        RefundStatus refundStatus,
        bytes additionalStatusInfo,
        bytes overridesInfo
    );

    /**
     * @notice The delivery provider calls `deliver` to relay messages as described by one delivery instruction
     *
     * The delivery provider must pass in the specified (by VaaKeys[]) signed wormhole messages (VAAs) from the source chain
     * as well as the signed wormhole message with the delivery instructions (the delivery VAA)
     *
     * The messages will be relayed to the target address (with the specified gas limit and receiver value) iff the following checks are met:
     * - the delivery VAA has a valid signature
     * - the delivery VAA's emitter is one of these WormholeRelayer contracts
     * - the delivery provider passed in at least enough of this chain's currency as msg.value (enough meaning the maximum possible refund)
     * - the instruction's target chain is this chain
     * - the relayed signed VAAs match the descriptions in container.messages (the VAA hashes match, or the emitter address, sequence number pair matches, depending on the description given)
     *
     * @param encodedVMs - An array of signed wormhole messages (all from the same source chain
     *     transaction)
     * @param encodedDeliveryVAA - Signed wormhole message from the source chain's WormholeRelayer
     *     contract with payload being the encoded delivery instruction container
     * @param relayerRefundAddress - The address to which any refunds to the delivery provider
     *     should be sent
     * @param deliveryOverrides - Optional overrides field which must be either an empty bytes array or
     *     an encoded DeliveryOverride struct
     */
    function deliver(
        bytes[] memory encodedVMs,
        bytes memory encodedDeliveryVAA,
        address payable relayerRefundAddress,
        bytes memory deliveryOverrides
    ) external payable;
}

interface IWormholeRelayer is IWormholeRelayerDelivery, IWormholeRelayerSend {}

/*
 *  Errors thrown by IWormholeRelayer contract
 */

// Bound chosen by the following formula: `memoryWord * 4 + selectorSize`.
// This means that an error identifier plus four fixed size arguments should be available to developers.
// In the case of a `require` revert with error message, this should provide 2 memory word's worth of data.
uint256 constant RETURNDATA_TRUNCATION_THRESHOLD = 132;

//When msg.value was not equal to `delivery provider's quoted delivery price` + `paymentForExtraReceiverValue`
error InvalidMsgValue(uint256 msgValue, uint256 totalFee);

error RequestedGasLimitTooLow();

error DeliveryProviderDoesNotSupportTargetChain(
    address relayer,
    uint16 chainId
);
error DeliveryProviderCannotReceivePayment();

//When calling `forward()` on the WormholeRelayer if no delivery is in progress
error NoDeliveryInProgress();
//When calling `delivery()` a second time even though a delivery is already in progress
error ReentrantDelivery(address msgSender, address lockedBy);
//When any other contract but the delivery target calls `forward()` on the WormholeRelayer while a
//  delivery is in progress
error ForwardRequestFromWrongAddress(address msgSender, address deliveryTarget);

error InvalidPayloadId(uint8 parsed, uint8 expected);
error InvalidPayloadLength(uint256 received, uint256 expected);
error InvalidVaaKeyType(uint8 parsed);

error InvalidDeliveryVaa(string reason);
//When the delivery VAA (signed wormhole message with delivery instructions) was not emitted by the
//  registered WormholeRelayer contract
error InvalidEmitter(bytes32 emitter, bytes32 registered, uint16 chainId);
error VaaKeysLengthDoesNotMatchVaasLength(uint256 keys, uint256 vaas);
error VaaKeysDoNotMatchVaas(uint8 index);
//When someone tries to call an external function of the WormholeRelayer that is only intended to be
//  called by the WormholeRelayer itself (to allow retroactive reverts for atomicity)
error RequesterNotWormholeRelayer();

//When trying to relay a `DeliveryInstruction` to any other chain but the one it was specified for
error TargetChainIsNotThisChain(uint16 targetChain);
error ForwardNotSufficientlyFunded(
    uint256 amountOfFunds,
    uint256 amountOfFundsNeeded
);
//When a `DeliveryOverride` contains a gas limit that's less than the original
error InvalidOverrideGasLimit();
//When a `DeliveryOverride` contains a receiver value that's less than the original
error InvalidOverrideReceiverValue();
//When a `DeliveryOverride` contains a 'refund per unit of gas unused' that's less than the original
error InvalidOverrideRefundPerGasUnused();

//When the delivery provider doesn't pass in sufficient funds (i.e. msg.value does not cover the
// maximum possible refund to the user)
error InsufficientRelayerFunds(uint256 msgValue, uint256 minimum);

//When a bytes32 field can't be converted into a 20 byte EVM address, because the 12 padding bytes
//  are non-zero (duplicated from Utils.sol)
error NotAnEvmAddress(bytes32);


// ============================================================================
// FILE: contracts/libraries/Bytes.sol
// ============================================================================

// SPDX-License-Identifier: Unlicense
/*
 * @title Solidity Bytes Arrays Utils
 * @author Gonçalo Sá <goncalo.sa@consensys.net>
 *
 * @dev Bytes tightly packed arrays utility library for ethereum contracts written in Solidity.
 *      The library lets you concatenate, slice and type cast bytes arrays both in memory and storage.
 */
pragma solidity >=0.8.0 <0.9.0;

library BytesLib {
    function concat(
        bytes memory _preBytes,
        bytes memory _postBytes
    ) internal pure returns (bytes memory) {
        bytes memory tempBytes;

        assembly {
            // Get a location of some free memory and store it in tempBytes as
            // Solidity does for memory variables.
            tempBytes := mload(0x40)

            // Store the length of the first bytes array at the beginning of
            // the memory for tempBytes.
            let length := mload(_preBytes)
            mstore(tempBytes, length)

            // Maintain a memory counter for the current write location in the
            // temp bytes array by adding the 32 bytes for the array length to
            // the starting location.
            let mc := add(tempBytes, 0x20)
            // Stop copying when the memory counter reaches the length of the
            // first bytes array.
            let end := add(mc, length)

            for {
                // Initialize a copy counter to the start of the _preBytes data,
                // 32 bytes into its memory.
                let cc := add(_preBytes, 0x20)
            } lt(mc, end) {
                // Increase both counters by 32 bytes each iteration.
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                // Write the _preBytes data into the tempBytes memory 32 bytes
                // at a time.
                mstore(mc, mload(cc))
            }

            // Add the length of _postBytes to the current length of tempBytes
            // and store it as the new length in the first 32 bytes of the
            // tempBytes memory.
            length := mload(_postBytes)
            mstore(tempBytes, add(length, mload(tempBytes)))

            // Move the memory counter back from a multiple of 0x20 to the
            // actual end of the _preBytes data.
            mc := end
            // Stop copying when the memory counter reaches the new combined
            // length of the arrays.
            end := add(mc, length)

            for {
                let cc := add(_postBytes, 0x20)
            } lt(mc, end) {
                mc := add(mc, 0x20)
                cc := add(cc, 0x20)
            } {
                mstore(mc, mload(cc))
            }

            // Update the free-memory pointer by padding our last write location
            // to 32 bytes: add 31 bytes to the end of tempBytes to move to the
            // next 32 byte block, then round down to the nearest multiple of
            // 32. If the sum of the length of the two arrays is zero then add
            // one before rounding down to leave a blank 32 bytes (the length block with 0).
            mstore(
                0x40,
                and(
                    add(add(end, iszero(add(length, mload(_preBytes)))), 31),
                    not(31) // Round down to the nearest 32 bytes.
                )
            )
        }

        return tempBytes;
    }

    function concatStorage(
        bytes storage _preBytes,
        bytes memory _postBytes
    ) internal {
        assembly {
            // Read the first 32 bytes of _preBytes storage, which is the length
            // of the array. (We don't need to use the offset into the slot
            // because arrays use the entire slot.)
            let fslot := sload(_preBytes.slot)
            // Arrays of 31 bytes or less have an even value in their slot,
            // while longer arrays have an odd value. The actual length is
            // the slot divided by two for odd values, and the lowest order
            // byte divided by two for even values.
            // If the slot is even, bitwise and the slot with 255 and divide by
            // two to get the length. If the slot is odd, bitwise and the slot
            // with -1 and divide by two.
            let slength := div(
                and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)),
                2
            )
            let mlength := mload(_postBytes)
            let newlength := add(slength, mlength)
            // slength can contain both the length and contents of the array
            // if length < 32 bytes so let's prepare for that
            // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
            switch add(lt(slength, 32), lt(newlength, 32))
            case 2 {
                // Since the new array still fits in the slot, we just need to
                // update the contents of the slot.
                // uint256(bytes_storage) = uint256(bytes_storage) + uint256(bytes_memory) + new_length
                sstore(
                    _preBytes.slot,
                    // all the modifications to the slot are inside this
                    // next block
                    add(
                        // we can just add to the slot contents because the
                        // bytes we want to change are the LSBs
                        fslot,
                        add(
                            mul(
                                div(
                                    // load the bytes from memory
                                    mload(add(_postBytes, 0x20)),
                                    // zero all bytes to the right
                                    exp(0x100, sub(32, mlength))
                                ),
                                // and now shift left the number of bytes to
                                // leave space for the length in the slot
                                exp(0x100, sub(32, newlength))
                            ),
                            // increase length by the double of the memory
                            // bytes length
                            mul(mlength, 2)
                        )
                    )
                )
            }
            case 1 {
                // The stored value fits in the slot, but the combined value
                // will exceed it.
                // get the keccak hash to get the contents of the array
                mstore(0x0, _preBytes.slot)
                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                // save new length
                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                // The contents of the _postBytes array start 32 bytes into
                // the structure. Our first read should obtain the `submod`
                // bytes that can fit into the unused space in the last word
                // of the stored array. To get this, we read 32 bytes starting
                // from `submod`, so the data we read overlaps with the array
                // contents by `submod` bytes. Masking the lowest-order
                // `submod` bytes allows us to add that value directly to the
                // stored value.

                let submod := sub(32, slength)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(
                    sc,
                    add(
                        and(
                            fslot,
                            0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
                        ),
                        and(mload(mc), mask)
                    )
                )

                for {
                    mc := add(mc, 0x20)
                    sc := add(sc, 1)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
            default {
                // get the keccak hash to get the contents of the array
                mstore(0x0, _preBytes.slot)
                // Start copying to the last used word of the stored array.
                let sc := add(keccak256(0x0, 0x20), div(slength, 32))

                // save new length
                sstore(_preBytes.slot, add(mul(newlength, 2), 1))

                // Copy over the first `submod` bytes of the new data as in
                // case 1 above.
                let slengthmod := mod(slength, 32)
                // solhint-disable-next-line
                let mlengthmod := mod(mlength, 32)
                let submod := sub(32, slengthmod)
                let mc := add(_postBytes, submod)
                let end := add(_postBytes, mlength)
                let mask := sub(exp(0x100, submod), 1)

                sstore(sc, add(sload(sc), and(mload(mc), mask)))

                for {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } lt(mc, end) {
                    sc := add(sc, 1)
                    mc := add(mc, 0x20)
                } {
                    sstore(sc, mload(mc))
                }

                mask := exp(0x100, sub(mc, end))

                sstore(sc, mul(div(mload(mc), mask), mask))
            }
        }
    }

    function slice(
        bytes memory _bytes,
        uint256 _start,
        uint256 _length
    ) internal pure returns (bytes memory) {
        require(_length + 31 >= _length, "slice_overflow");
        require(_bytes.length >= _start + _length, "slice_outOfBounds");

        bytes memory tempBytes;

        assembly {
            switch iszero(_length)
            case 0 {
                // Get a location of some free memory and store it in tempBytes as
                // Solidity does for memory variables.
                tempBytes := mload(0x40)

                // The first word of the slice result is potentially a partial
                // word read from the original array. To read it, we calculate
                // the length of that partial word and start copying that many
                // bytes into the array. The first word we copy will start with
                // data we don't care about, but the last `lengthmod` bytes will
                // land at the beginning of the contents of the new array. When
                // we're done copying, we overwrite the full first word with
                // the actual length of the slice.
                let lengthmod := and(_length, 31)

                // The multiplication in the next line is necessary
                // because when slicing multiples of 32 bytes (lengthmod == 0)
                // the following copy loop was copying the origin's length
                // and then ending prematurely not copying everything it should.
                let mc := add(
                    add(tempBytes, lengthmod),
                    mul(0x20, iszero(lengthmod))
                )
                let end := add(mc, _length)

                for {
                    // The multiplication in the next line has the same exact purpose
                    // as the one above.
                    let cc := add(
                        add(
                            add(_bytes, lengthmod),
                            mul(0x20, iszero(lengthmod))
                        ),
                        _start
                    )
                } lt(mc, end) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    mstore(mc, mload(cc))
                }

                mstore(tempBytes, _length)

                //update free-memory pointer
                //allocating the array padded to 32 bytes like the compiler does now
                mstore(0x40, and(add(mc, 31), not(31)))
            }
            //if we want a zero-length slice let's just return a zero-length array
            default {
                tempBytes := mload(0x40)
                //zero out the 32 bytes slice we are about to return
                //we need to do it because Solidity does not garbage collect
                mstore(tempBytes, 0)

                mstore(0x40, add(tempBytes, 0x20))
            }
        }

        return tempBytes;
    }

    function toAddress(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (address) {
        require(_bytes.length >= _start + 20, "toAddress_outOfBounds");
        address tempAddress;

        assembly {
            tempAddress := div(
                mload(add(add(_bytes, 0x20), _start)),
                0x1000000000000000000000000
            )
        }

        return tempAddress;
    }

    function toUint8(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint8) {
        require(_bytes.length >= _start + 1, "toUint8_outOfBounds");
        uint8 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x1), _start))
        }

        return tempUint;
    }

    function toUint16(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint16) {
        require(_bytes.length >= _start + 2, "toUint16_outOfBounds");
        uint16 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x2), _start))
        }

        return tempUint;
    }

    function toUint32(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint32) {
        require(_bytes.length >= _start + 4, "toUint32_outOfBounds");
        uint32 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x4), _start))
        }

        return tempUint;
    }

    function toUint64(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint64) {
        require(_bytes.length >= _start + 8, "toUint64_outOfBounds");
        uint64 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x8), _start))
        }

        return tempUint;
    }

    function toUint96(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint96) {
        require(_bytes.length >= _start + 12, "toUint96_outOfBounds");
        uint96 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0xc), _start))
        }

        return tempUint;
    }

    function toUint128(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint128) {
        require(_bytes.length >= _start + 16, "toUint128_outOfBounds");
        uint128 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x10), _start))
        }

        return tempUint;
    }

    function toUint256(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (uint256) {
        require(_bytes.length >= _start + 32, "toUint256_outOfBounds");
        uint256 tempUint;

        assembly {
            tempUint := mload(add(add(_bytes, 0x20), _start))
        }

        return tempUint;
    }

    function toBytes32(
        bytes memory _bytes,
        uint256 _start
    ) internal pure returns (bytes32) {
        require(_bytes.length >= _start + 32, "toBytes32_outOfBounds");
        bytes32 tempBytes32;

        assembly {
            tempBytes32 := mload(add(add(_bytes, 0x20), _start))
        }

        return tempBytes32;
    }

    function equal(
        bytes memory _preBytes,
        bytes memory _postBytes
    ) internal pure returns (bool) {
        bool success = true;

        assembly {
            let length := mload(_preBytes)

            // if lengths don't match the arrays are not equal
            switch eq(length, mload(_postBytes))
            case 1 {
                // cb is a circuit breaker in the for loop since there's
                //  no said feature for inline assembly loops
                // cb = 1 - don't breaker
                // cb = 0 - break
                let cb := 1

                let mc := add(_preBytes, 0x20)
                let end := add(mc, length)

                for {
                    let cc := add(_postBytes, 0x20)
                    // the next line is the loop condition:
                    // while(uint256(mc < end) + cb == 2)
                } eq(add(lt(mc, end), cb), 2) {
                    mc := add(mc, 0x20)
                    cc := add(cc, 0x20)
                } {
                    // if any of these checks fails then arrays are not equal
                    if iszero(eq(mload(mc), mload(cc))) {
                        // unsuccess:
                        success := 0
                        cb := 0
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }

    function equalStorage(
        bytes storage _preBytes,
        bytes memory _postBytes
    ) internal view returns (bool) {
        bool success = true;

        assembly {
            // we know _preBytes_offset is 0
            let fslot := sload(_preBytes.slot)
            // Decode the length of the stored array like in concatStorage().
            let slength := div(
                and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)),
                2
            )
            let mlength := mload(_postBytes)

            // if lengths don't match the arrays are not equal
            switch eq(slength, mlength)
            case 1 {
                // slength can contain both the length and contents of the array
                // if length < 32 bytes so let's prepare for that
                // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
                if iszero(iszero(slength)) {
                    switch lt(slength, 32)
                    case 1 {
                        // blank the last byte which is the length
                        fslot := mul(div(fslot, 0x100), 0x100)

                        if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {
                            // unsuccess:
                            success := 0
                        }
                    }
                    default {
                        // cb is a circuit breaker in the for loop since there's
                        //  no said feature for inline assembly loops
                        // cb = 1 - don't breaker
                        // cb = 0 - break
                        let cb := 1

                        // get the keccak hash to get the contents of the array
                        mstore(0x0, _preBytes.slot)
                        let sc := keccak256(0x0, 0x20)

                        let mc := add(_postBytes, 0x20)
                        let end := add(mc, mlength)

                        // the next line is the loop condition:
                        // while(uint256(mc < end) + cb == 2)
                        for {

                        } eq(add(lt(mc, end), cb), 2) {
                            sc := add(sc, 1)
                            mc := add(mc, 0x20)
                        } {
                            if iszero(eq(sload(sc), mload(mc))) {
                                // unsuccess:
                                success := 0
                                cb := 0
                            }
                        }
                    }
                }
            }
            default {
                // unsuccess:
                success := 0
            }
        }

        return success;
    }
}


// ============================================================================
// FILE: contracts/libraries/Formatters.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { BytesLib } from "./Bytes.sol";
import {
    TradeAcceptMessage,
    TradeResultMessage,
    Assets,
    PayloadType,
    TradeOffer,
    AssetsSet,
    Result,
    AssetType,
    AssetData,
    TradeDetailed
} from "../utils/DataTypes.sol";

/// @title Encoder
/// @author NF3 Exchange
/// @dev This library defines helper functions used to encode structs to
///      array of bytes that can be used a payload in wormhole messages
library Encoder {
    /// -----------------------------------------------------------------------
    /// Library usage
    /// -----------------------------------------------------------------------

    using BytesLib for bytes;

    /// -----------------------------------------------------------------------
    /// Encoding functions
    /// -----------------------------------------------------------------------

    /// @dev Encode trade accept message to bytes array
    /// @param message Trade accept message that needs to be encoded
    function encodeTradeAcceptMessage(
        TradeAcceptMessage memory message
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                message.payloadType,
                message.tradeOfferHash,
                _encodeAssets(message.offeringAssets),
                _encodeAssets(message.considerationAssets),
                message.seller,
                message.buyer,
                message.primaryChainId,
                message.secondaryChainId
            );
    }

    /// @dev Encode trade result message to bytes array
    /// @param message Trade result message that needs to be encoded
    function encodeTradeResultMessage(
        TradeResultMessage memory message
    ) internal pure returns (bytes memory) {
        return
            abi.encodePacked(
                message.payloadType,
                message.tradeOfferHash,
                message.result,
                message.primaryChainId,
                message.secondaryChainId
            );
    }

    /// @dev Convert a trade offer struct to bytes32 hash
    /// @param _offer Trade offer struct that needs to be hashed
    function hashTradeOffer(
        TradeOffer memory _offer
    ) internal pure returns (bytes32) {
        bytes32 _hash;

        _hash = _hashAssetsSet(_offer.offeringAssets, _hash);
        _hash = _hashAssetsSet(_offer.considerationAssets, _hash);
        _hash = keccak256(
            abi.encodePacked(
                _offer.owner,
                _offer.timePeriod,
                _offer.nonce,
                _offer.tradeIntendedFor,
                _offer.primaryChainId,
                _offer.secondaryChainId,
                _hash
            )
        );

        return _hash;
    }

    /// @dev Convert a trade contants data to bytes32 hash
    /// @param offeringAssets Assets that are being offered by the seller
    /// @param considerationAssets Assets that are begin asked by the buyer
    /// @param buyer Address of the buyer
    /// @param seller Address of the seller
    function hashTradeConstants(
        Assets memory offeringAssets,
        Assets memory considerationAssets,
        address buyer,
        address seller
    ) internal pure returns (bytes32) {
        bytes32 _hash;

        _hash = keccak256(
            abi.encodePacked(_encodeAssets(offeringAssets), _hash)
        );
        _hash = keccak256(
            abi.encodePacked(_encodeAssets(considerationAssets), _hash)
        );

        _hash = keccak256(abi.encodePacked(buyer, seller, _hash));

        return _hash;
    }

    /// -----------------------------------------------------------------------
    /// Helper methods
    /// -----------------------------------------------------------------------

    /// @dev Encode Assets data type to bytes array
    /// @param _assets Assets that need to be encoded
    function _encodeAssets(
        Assets memory _assets
    ) private pure returns (bytes memory data) {
        /*
         * Storage Slots Used
         * 1 slot => 32 bytes for lenght of assets
         * 3 slots => 96 bytes for each of AssetData struct
         * total = 32 bytes + assetCount * 96 bytes
         */

        bytes memory packedAssets;

        uint len = _assets.assets.length;
        for (uint i; i < len; ) {
            packedAssets = abi.encodePacked(
                packedAssets,
                _assets.assets[i].token,
                _assets.assets[i].assetType,
                _assets.assets[i].tokenId,
                _assets.assets[i].amount
            );
            unchecked {
                ++i;
            }
        }

        return abi.encodePacked(_assets.assets.length, packedAssets);
    }

    /// @dev convert AssetsSet struct to bytes32 hash
    /// @param assetsSet AssetsSet struct that needs to be hashed
    /// @param _hash previous hash value to be encoded with new hash
    function _hashAssetsSet(
        AssetsSet memory assetsSet,
        bytes32 _hash
    ) private pure returns (bytes32) {
        _hash = keccak256(
            abi.encodePacked(_encodeAssets(assetsSet.primaryChainAssets), _hash)
        );
        _hash = keccak256(
            abi.encodePacked(
                _encodeAssets(assetsSet.secondaryChainAssets),
                _hash
            )
        );

        return _hash;
    }
}

/// @title Decoder
/// @author NF3 Exchange
/// @dev This library defines helper functions used to decode bytes
///      arrays encoded by Encoder library defined above
library Decoder {
    /// -----------------------------------------------------------------------
    /// Library usage
    /// -----------------------------------------------------------------------

    using BytesLib for bytes;

    /// -----------------------------------------------------------------------
    /// Decoding functions
    /// -----------------------------------------------------------------------

    /// @dev Decode trade accept message from bytes array to TradeAcceptMessage struct
    /// @param encoded Recieved bytes array to be decoded
    function decodeTradeAcceptMessage(
        bytes memory encoded
    ) internal pure returns (TradeAcceptMessage memory) {
        uint256 offset = 0;

        uint8 _paylodType = encoded.toUint8(offset);
        PayloadType payloadType = PayloadType(_paylodType);
        offset += 1;

        bytes32 tradeOfferHash = encoded.toBytes32(offset);

        offset += 32;

        (Assets memory offeringAssets, uint256 _offset) = _decodeAssets(
            encoded,
            offset
        );
        offset = _offset;

        (Assets memory considerationAssets, uint256 __offset) = _decodeAssets(
            encoded,
            offset
        );

        offset = __offset;
        address seller = encoded.toAddress(offset);
        offset += 20;
        address buyer = encoded.toAddress(offset);
        offset += 20;

        uint16 primaryChainId = encoded.toUint16(offset);
        offset += 2;
        uint16 secondaryChainId = encoded.toUint16(offset);
        offset += 2;

        return
            TradeAcceptMessage(
                payloadType,
                tradeOfferHash,
                offeringAssets,
                considerationAssets,
                seller,
                buyer,
                primaryChainId,
                secondaryChainId
            );
    }

    /// @dev Decode trade result message from bytes array to TradeResultMessage struct
    /// @param encoded Recieved bytes array to be decoded
    function decodeTradeResultMessage(
        bytes memory encoded
    ) internal pure returns (TradeResultMessage memory) {
        uint256 offset = 0;
        uint8 _paylodType = encoded.toUint8(offset);
        PayloadType payloadType = PayloadType(_paylodType);
        offset += 1;
        bytes32 tradeOfferHash = encoded.toBytes32(offset);
        offset += 32;
        uint8 _type = encoded.toUint8(offset);
        Result result = Result(_type);
        offset += 1;
        uint16 primaryChainId = encoded.toUint16(offset);
        offset += 2;
        uint16 secondaryChainId = encoded.toUint16(offset);

        return
            TradeResultMessage(
                payloadType,
                tradeOfferHash,
                result,
                primaryChainId,
                secondaryChainId
            );
    }

    /// @dev Decode payload type from received encoded bytes array
    /// @param encoded Bytes string of the entire message
    function getPayloadType(
        bytes memory encoded
    ) internal pure returns (PayloadType) {
        uint256 offset = 0;
        uint8 _payloadType = encoded.toUint8(offset);

        return PayloadType(_payloadType);
    }

    /// -----------------------------------------------------------------------
    /// Helper methods
    /// -----------------------------------------------------------------------

    /// @dev Decode Assets data type from bytes array
    /// @param encoded Bytes string of the entire message
    /// @param offset Position of assets struct in the message string
    function _decodeAssets(
        bytes memory encoded,
        uint256 offset
    ) private pure returns (Assets memory, uint256 _offset) {
        // first 32 bytes for assetData array length
        uint256 assetsCount = encoded.toUint256(offset);
        offset += 32;

        // remaining bytes are divided as
        // 1. fist 20 bytes for token address
        // 2. next 1 bytes for assetType enum
        // 3. next 32 bytes for tokenId of the asset
        // 4. next 32 bytes for amount of asset
        AssetData[] memory assets = new AssetData[](assetsCount);
        for (uint i; i < assetsCount; ) {
            address _token = encoded.toAddress(offset);
            offset += 20;
            uint8 _type = encoded.toUint8(offset);
            offset += 1;
            uint256 _tokenId = encoded.toUint256(offset);
            offset += 32;
            uint256 _amount = encoded.toUint256(offset);
            offset += 32;

            assets[i] = AssetData({
                token: _token,
                assetType: AssetType(_type),
                tokenId: _tokenId,
                amount: _amount
            });

            unchecked {
                ++i;
            }
        }

        return (Assets({ assets: assets }), offset);
    }
}


// ============================================================================
// FILE: contracts/utils/DataTypes.sol
// ============================================================================

// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.13;

import { BitMaps } from "@openzeppelin/contracts/utils/structs/BitMaps.sol";

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------

uint8 constant SELLER_BITMASK = 0x1; // 00000001
uint8 constant BUYER_BITMASK = 0x2; // 00000010
uint256 constant GAS_REQUIRED_FOR_ERC20 = 60_000;
uint256 constant GAS_REQUIRED_FOR_ERC721 = 80_000;
uint256 constant GAS_REQUIRED_FOR_ERC1155 = 60_000;
uint256 constant BASE_GAS_REQUIRED = 250_000;
uint256 constant BASE_GAS_FOR_FORWARDING = 150_000;

// -----------------------------------------------------------------------
// Typed structs
// -----------------------------------------------------------------------

/// @dev Common Assets type, packing bundle of NFTs and FTs.
/// @param assets Array of individual tokens along with their details
struct Assets {
    AssetData[] assets;
}

/// @dev Type for individual asset along with it's details
/// @param token token address
/// @param assetType type of asset represented by the address
/// @param tokenId tokenId in case of ERC721 and ERC1155 tokens. Set to 0 in case of ERC20 token
/// @param amount amount of token for ERC20 and ERC1155 tokens. Set to 1 in case of ERC721 token
struct AssetData {
    address token;
    AssetType assetType;
    uint256 tokenId;
    uint256 amount;
}

/// @dev Set of assets on both the chains, representing one side of offering by the user
/// @param primaryChainAssets Assets existing on primary chain of the trade
/// @param secondaryChainAssets Assets exisitng on secondary chain of
struct AssetsSet {
    Assets primaryChainAssets;
    Assets secondaryChainAssets;
}

/// @dev Fees to be sent to admin
/// @param to Address which will receive the fees
/// @param token ERC20 token address used for fees
/// @param amount Amount of token to be transferred
struct Fees {
    address to;
    address token;
    uint256 amount;
}

/// @dev Trade offer proposed by one of the user
/// @param offeringAssets AssetsSet offered by the seller
/// @param considerationAssets AssetsSet requested from the buyer
/// @param buyerFees Fee to be paid by the buyer
/// @param sellerFees Fee to be paid by the seller
/// @param owner Owner of the trade offer. aka seller
/// @param timePeriod Expiration timestamp of the offer
/// @param nonce Nonce of the trade
/// @param tradeIntendedFor Address to which the trade is targetted to. To be used in case of
///        private P2P trades. Can be set to address(0) to allow anyone to accept the trade
/// @param primaryChainId Wormhole chain Id of the primary chain
/// @param secondaryChainId Wormhole chain Id of the secondary chain
struct TradeOffer {
    AssetsSet offeringAssets;
    AssetsSet considerationAssets;
    Fees buyerFees;
    Fees sellerFees;
    address owner;
    uint256 timePeriod;
    uint256 nonce;
    address tradeIntendedFor;
    uint256 primaryChainId; // wormhole chain Id
    uint256 secondaryChainId; // wormhole chain Id
}

/// @dev Compressed trade data that needs to be stored on chain for each trade
///      consumes 2 slots in the storage
/// @param tradeConstantsHash Hash of the constants involved in the trade
/// @param status Current status of the trade
/// @param withdrawBitmap bit 0 represents seller's withdraw status. but 1 represnts
///        buyer's withdraw status. Used to ensure seller and buyer each withdraw only once
/// @param recoveryRequested flag used to mark if recovery of the trade is requested
struct Trade {
    bytes32 tradeContantsHash; // size 32 bytes => slot 1
    Status status; // size 1 byte => slot 2
    uint8 withdrawBitmap; // size 1 byte => slot 2
    bool recoveryRequested; // size 1 byte => slot 2
}

/// @dev Helper struct packing all the constatns involved in a trade
/// @param offeringAssets Assets offered on the current chain by the seller
/// @param considerationAssets Assets requested by the seller on the current chain
/// @param seller Address of the seller
/// @param buyer Address of the buyer
struct TradeConstants {
    Assets offeringAssets;
    Assets considerationAssets;
    address seller;
    address buyer;
}

/// @dev Actual trade data with all the details of the trade
/// @param tradeOfferHash Hash of the acutal trade offer used as uinque id.
///        Using hash because impossible to keep id's on multiple chains in sync
/// @param offeringAssets Assets offered on the current chain by the seller
/// @param considerationAssets Assets requested by the seller on the current chain
/// @param seller Address of the seller
/// @param status Current status of the trade
/// @param buyer Address of the buyer
/// @param withdrawBitmap bit 0 represents seller's withdraw status. but 1 represnts
///        buyer's withdraw status. Used to ensure seller and buyer each withdraw only once
/// @param recoveryRequested flag used to mark if recovery of the trade is requested
struct TradeDetailed {
    bytes32 tradeOfferHash;
    Assets offeringAssets;
    Assets considerationAssets;
    address seller;
    Status status;
    address buyer;
    uint8 withdrawBitmap;
    bool recoveryRequested;
}

/// @dev wormhole to be emmited when a trade has been accepted on one chain and needs
///      to be processed on other chain
/// @param payloadType Type of payload sent in the message. Used for selecting appropriate
///        function while receiving wormhole messages
/// @param tradeOfferHash Hash of the trade offer. Used as id
/// @param offeringAssets Assets offered on current chain
/// @param considerationAssets Assets requested on current chain
/// @param seller Address of the seller
/// @param buyer Address of the buyer
/// @param primaryChainId wormhole chain id of the primary chain
/// @param secondaryChainId wormhole chain id of the secondary chain
struct TradeAcceptMessage {
    PayloadType payloadType;
    bytes32 tradeOfferHash;
    Assets offeringAssets;
    Assets considerationAssets;
    address seller;
    address buyer;
    uint16 primaryChainId; // wormhole chain Id
    uint16 secondaryChainId; // wormhole chain Id
}

/// @dev wormhole message to be emmited when a trade has completed processing on
///      the secondary chain. Used to mark result of the trade
/// @param payloadType Type of payload sent in the message. Used for selecting appropriate
///        function while receiving wormhole messages
/// @param tradeOfferHash Hash of the trade offer. Used as id
/// @param result Final result of the trade
/// @param primaryChainId wormhole chain id of the primary chain
/// @param secondaryChainId wormhole chain id of the secondary chain
struct TradeResultMessage {
    PayloadType payloadType;
    bytes32 tradeOfferHash;
    Result result;
    uint16 primaryChainId; // wormhole chain Id
    uint16 secondaryChainId; // wormhole chain Id
}

/// @dev Struct to pack data regarding the gas forwarding during wormhole
///      message passing
/// @param forwardingValue Value to be passed in the message
/// @param nonce Nonce of the message
/// @param owner Owner of the message
struct ForwardingGas {
    uint256 forwardingValue;
    uint256 nonce;
    address owner;
}

/// @dev Struct to pack storage state for the protcol
/// @param wormholeRelayer wormhole core contract address
/// @param consistencyLevel number of confirmations for wormhole messages
/// @param gasSignatureAdmin admin's address who will sign the gas signatures
/// @param wormholeChainId wormhole chain id of current network
/// @param vaultAddress assets vault for the system
/// @param targetContractToChainId mapping from target contract on other chain to
///        their wormhole chain id
/// @param targetChainIdToContract mapping from wormhole chain id to target contract
///        on other chain
/// @param nonce Mapping of users and their nonce in form of bitmap
/// @param gasForwardingNonce Bitmap for gas forwarding struct of admin signature
/// @param trades trade data mapped to it's hash
/// @param consumedMessages consumed messages, used to prevent reentrancy and
///        replay
/// @param types mapping of token addresses and their Types
struct State {
    address wormholeRelayer;
    uint8 consistencyLevel;
    address gasSignatureAdmin;
    uint16 wormholeChainId;
    address vaultAddress;
    mapping(address => uint16) targetContractToChainId;
    mapping(uint16 => address) targetChainIdToContract;
    mapping(address => BitMaps.BitMap) nonce;
    BitMaps.BitMap gasForwardingNonce;
    mapping(bytes32 => Trade) trades;
    mapping(bytes32 => bool) consumedMessages;
    mapping(address => AssetType) types;
}

// -----------------------------------------------------------------------
// Enums
// -----------------------------------------------------------------------

enum Status {
    IDLE, // default status
    PENDING, // pulled funds on primary chain and sent message to secondary chain
    FAILED, // Could not pull funds on other chain so will revert on primary chain
    SUCCESS // succesfully pulled funds on both the chains and swapped assets can now be withdrawn
}

enum Result {
    SUCCESS, // trade was succesfull on secondary chain
    FAILED // trade failed on secondary chain
}

enum PayloadType {
    PROCESS_TRADE, // function selector for processing trade on secondary chain
    COMPLETE_TRADE // function selector for completing trade on primary chain
}

enum AssetType {
    INVALID,
    ERC_20,
    ERC_721,
    ERC_1155
}
