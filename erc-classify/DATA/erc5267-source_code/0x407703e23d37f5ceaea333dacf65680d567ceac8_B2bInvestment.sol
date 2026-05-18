// SPDX-License-Identifier: UNLICENSED
// Source: 0x407703e23d37f5ceaea333dacf65680d567ceac8
// Contract Name: B2bInvestment
// Generated on: 2026-05-14 11:56:01


// ============================================================================
// FILE: @aave/core-v3/contracts/protocol/libraries/math/WadRayMath.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.0;

/**
 * @title WadRayMath library
 * @author Aave
 * @notice Provides functions to perform calculations with Wad and Ray units
 * @dev Provides mul and div function for wads (decimal numbers with 18 digits of precision) and rays (decimal numbers
 * with 27 digits of precision)
 * @dev Operations are rounded. If a value is >=.5, will be rounded up, otherwise rounded down.
 */
library WadRayMath {
  // HALF_WAD and HALF_RAY expressed with extended notation as constant with operations are not supported in Yul assembly
  uint256 internal constant WAD = 1e18;
  uint256 internal constant HALF_WAD = 0.5e18;

  uint256 internal constant RAY = 1e27;
  uint256 internal constant HALF_RAY = 0.5e27;

  uint256 internal constant WAD_RAY_RATIO = 1e9;

  /**
   * @dev Multiplies two wad, rounding half up to the nearest wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @param b Wad
   * @return c = a*b, in wad
   */
  function wadMul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - HALF_WAD) / b
    assembly {
      if iszero(or(iszero(b), iszero(gt(a, div(sub(not(0), HALF_WAD), b))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, b), HALF_WAD), WAD)
    }
  }

  /**
   * @dev Divides two wad, rounding half up to the nearest wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @param b Wad
   * @return c = a/b, in wad
   */
  function wadDiv(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - halfB) / WAD
    assembly {
      if or(iszero(b), iszero(iszero(gt(a, div(sub(not(0), div(b, 2)), WAD))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, WAD), div(b, 2)), b)
    }
  }

  /**
   * @notice Multiplies two ray, rounding half up to the nearest ray
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Ray
   * @param b Ray
   * @return c = a raymul b
   */
  function rayMul(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - HALF_RAY) / b
    assembly {
      if iszero(or(iszero(b), iszero(gt(a, div(sub(not(0), HALF_RAY), b))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, b), HALF_RAY), RAY)
    }
  }

  /**
   * @notice Divides two ray, rounding half up to the nearest ray
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Ray
   * @param b Ray
   * @return c = a raydiv b
   */
  function rayDiv(uint256 a, uint256 b) internal pure returns (uint256 c) {
    // to avoid overflow, a <= (type(uint256).max - halfB) / RAY
    assembly {
      if or(iszero(b), iszero(iszero(gt(a, div(sub(not(0), div(b, 2)), RAY))))) {
        revert(0, 0)
      }

      c := div(add(mul(a, RAY), div(b, 2)), b)
    }
  }

  /**
   * @dev Casts ray down to wad
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Ray
   * @return b = a converted to wad, rounded half up to the nearest wad
   */
  function rayToWad(uint256 a) internal pure returns (uint256 b) {
    assembly {
      b := div(a, WAD_RAY_RATIO)
      let remainder := mod(a, WAD_RAY_RATIO)
      if iszero(lt(remainder, div(WAD_RAY_RATIO, 2))) {
        b := add(b, 1)
      }
    }
  }

  /**
   * @dev Converts wad up to ray
   * @dev assembly optimized for improved gas savings, see https://twitter.com/transmissions11/status/1451131036377571328
   * @param a Wad
   * @return b = a converted in ray
   */
  function wadToRay(uint256 a) internal pure returns (uint256 b) {
    // to avoid overflow, b/WAD_RAY_RATIO == a
    assembly {
      b := mul(a, WAD_RAY_RATIO)

      if iszero(eq(div(b, WAD_RAY_RATIO), a)) {
        revert(0, 0)
      }
    }
  }
}


// ============================================================================
// FILE: @chainlink/contracts/src/v0.8/interfaces/AggregatorInterface.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface AggregatorInterface {
  function latestAnswer() external view returns (int256);

  function latestTimestamp() external view returns (uint256);

  function latestRound() external view returns (uint256);

  function getAnswer(uint256 roundId) external view returns (int256);

  function getTimestamp(uint256 roundId) external view returns (uint256);

  event AnswerUpdated(int256 indexed current, uint256 indexed roundId, uint256 updatedAt);

  event NewRound(uint256 indexed roundId, address indexed startedBy, uint256 startedAt);
}


// ============================================================================
// FILE: @chainlink/contracts/src/v0.8/interfaces/AggregatorV2V3Interface.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AggregatorInterface.sol";
import "./AggregatorV3Interface.sol";

interface AggregatorV2V3Interface is AggregatorInterface, AggregatorV3Interface {}


// ============================================================================
// FILE: @chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface AggregatorV3Interface {
  function decimals() external view returns (uint8);

  function description() external view returns (string memory);

  function version() external view returns (uint256);

  function getRoundData(uint80 _roundId)
    external
    view
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );

  function latestRoundData()
    external
    view
    returns (
      uint80 roundId,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/AccessControl.sol)

pragma solidity ^0.8.0;

import "./IAccessControlUpgradeable.sol";
import "../utils/ContextUpgradeable.sol";
import "../utils/StringsUpgradeable.sol";
import "../utils/introspection/ERC165Upgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```solidity
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```solidity
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it. We recommend using {AccessControlDefaultAdminRules}
 * to enforce additional security measures for this role.
 */
abstract contract AccessControlUpgradeable is Initializable, ContextUpgradeable, IAccessControlUpgradeable, ERC165Upgradeable {
    struct RoleData {
        mapping(address => bool) members;
        bytes32 adminRole;
    }

    mapping(bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Modifier that checks that an account has a specific role. Reverts
     * with a standardized message including the required role.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     *
     * _Available since v4.1._
     */
    modifier onlyRole(bytes32 role) {
        _checkRole(role);
        _;
    }

    function __AccessControl_init() internal onlyInitializing {
    }

    function __AccessControl_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlUpgradeable).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view virtual override returns (bool) {
        return _roles[role].members[account];
    }

    /**
     * @dev Revert with a standard message if `_msgSender()` is missing `role`.
     * Overriding this function changes the behavior of the {onlyRole} modifier.
     *
     * Format of the revert message is described in {_checkRole}.
     *
     * _Available since v4.6._
     */
    function _checkRole(bytes32 role) internal view virtual {
        _checkRole(role, _msgSender());
    }

    /**
     * @dev Revert with a standard message if `account` is missing `role`.
     *
     * The format of the revert reason is given by the following regular expression:
     *
     *  /^AccessControl: account (0x[0-9a-f]{40}) is missing role (0x[0-9a-f]{64})$/
     */
    function _checkRole(bytes32 role, address account) internal view virtual {
        if (!hasRole(role, account)) {
            revert(
                string(
                    abi.encodePacked(
                        "AccessControl: account ",
                        StringsUpgradeable.toHexString(account),
                        " is missing role ",
                        StringsUpgradeable.toHexString(uint256(role), 32)
                    )
                )
            );
        }
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view virtual override returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleGranted} event.
     */
    function grantRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     *
     * May emit a {RoleRevoked} event.
     */
    function revokeRole(bytes32 role, address account) public virtual override onlyRole(getRoleAdmin(role)) {
        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been revoked `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     *
     * May emit a {RoleRevoked} event.
     */
    function renounceRole(bytes32 role, address account) public virtual override {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event. Note that unlike {grantRole}, this function doesn't perform any
     * checks on the calling account.
     *
     * May emit a {RoleGranted} event.
     *
     * [WARNING]
     * ====
     * This function should only be called from the constructor when setting
     * up the initial roles for the system.
     *
     * Using this function in any other way is effectively circumventing the admin
     * system imposed by {AccessControl}.
     * ====
     *
     * NOTE: This function is deprecated in favor of {_grantRole}.
     */
    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        bytes32 previousAdminRole = getRoleAdmin(role);
        _roles[role].adminRole = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleGranted} event.
     */
    function _grantRole(bytes32 role, address account) internal virtual {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * Internal function without access restriction.
     *
     * May emit a {RoleRevoked} event.
     */
    function _revokeRole(bytes32 role, address account) internal virtual {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[49] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/access/IAccessControlUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/IAccessControl.sol)

pragma solidity ^0.8.0;

/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControlUpgradeable {
    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     *
     * _Available since v3.1._
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call, an admin role
     * bearer except when using {AccessControl-_setupRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) external view returns (bool);

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {AccessControl-_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) external view returns (bytes32);

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) external;

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     */
    function renounceRole(bytes32 role, address account) external;
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
// FILE: @openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

pragma solidity ^0.8.0;

import "./IERC165Upgradeable.sol";
import {Initializable} from "../../proxy/utils/Initializable.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165Upgradeable is Initializable, IERC165Upgradeable {
    function __ERC165_init() internal onlyInitializing {
    }

    function __ERC165_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165Upgradeable).interfaceId;
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/utils/introspection/IERC165Upgradeable.sol
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
interface IERC165Upgradeable {
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
// FILE: @openzeppelin/contracts/interfaces/IERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (interfaces/IERC20.sol)

pragma solidity ^0.8.0;

import "../token/ERC20/IERC20.sol";


// ============================================================================
// FILE: @openzeppelin/contracts/interfaces/IERC20Metadata.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (interfaces/IERC20Metadata.sol)

pragma solidity ^0.8.0;

import "../token/ERC20/extensions/IERC20Metadata.sol";


// ============================================================================
// FILE: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (token/ERC20/extensions/IERC20Metadata.sol)

pragma solidity ^0.8.0;

import "../IERC20.sol";

/**
 * @dev Interface for the optional metadata functions from the ERC20 standard.
 *
 * _Available since v4.1._
 */
interface IERC20Metadata is IERC20 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);
}


// ============================================================================
// FILE: @openzeppelin/contracts/token/ERC20/IERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC20/IERC20.sol)

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
    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) external returns (bool);
}


// ============================================================================
// FILE: @uniswap/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol
// ============================================================================

// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.5.0;

/// @title Callback for IUniswapV3PoolActions#swap
/// @notice Any contract that calls IUniswapV3PoolActions#swap must implement this interface
interface IUniswapV3SwapCallback {
    /// @notice Called to `msg.sender` after executing a swap via IUniswapV3Pool#swap.
    /// @dev In the implementation you must pay the pool tokens owed for the swap.
    /// The caller of this method must be checked to be a UniswapV3Pool deployed by the canonical UniswapV3Factory.
    /// amount0Delta and amount1Delta can both be 0 if no tokens were swapped.
    /// @param amount0Delta The amount of token0 that was sent (negative) or must be received (positive) by the pool by
    /// the end of the swap. If positive, the callback must send that amount of token0 to the pool.
    /// @param amount1Delta The amount of token1 that was sent (negative) or must be received (positive) by the pool by
    /// the end of the swap. If positive, the callback must send that amount of token1 to the pool.
    /// @param data Any data passed through by the caller via the IUniswapV3PoolActions#swap call
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external;
}


// ============================================================================
// FILE: @uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol
// ============================================================================

// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.7.5;
pragma abicoder v2;

import '@uniswap/v3-core/contracts/interfaces/callback/IUniswapV3SwapCallback.sol';

/// @title Router token swapping functionality
/// @notice Functions for swapping tokens via Uniswap V3
interface ISwapRouter is IUniswapV3SwapCallback {
    struct ExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
        uint160 sqrtPriceLimitX96;
    }

    /// @notice Swaps `amountIn` of one token for as much as possible of another token
    /// @param params The parameters necessary for the swap, encoded as `ExactInputSingleParams` in calldata
    /// @return amountOut The amount of the received token
    function exactInputSingle(ExactInputSingleParams calldata params) external payable returns (uint256 amountOut);

    struct ExactInputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountIn;
        uint256 amountOutMinimum;
    }

    /// @notice Swaps `amountIn` of one token for as much as possible of another along the specified path
    /// @param params The parameters necessary for the multi-hop swap, encoded as `ExactInputParams` in calldata
    /// @return amountOut The amount of the received token
    function exactInput(ExactInputParams calldata params) external payable returns (uint256 amountOut);

    struct ExactOutputSingleParams {
        address tokenIn;
        address tokenOut;
        uint24 fee;
        address recipient;
        uint256 deadline;
        uint256 amountOut;
        uint256 amountInMaximum;
        uint160 sqrtPriceLimitX96;
    }

    /// @notice Swaps as little as possible of one token for `amountOut` of another token
    /// @param params The parameters necessary for the swap, encoded as `ExactOutputSingleParams` in calldata
    /// @return amountIn The amount of the input token
    function exactOutputSingle(ExactOutputSingleParams calldata params) external payable returns (uint256 amountIn);

    struct ExactOutputParams {
        bytes path;
        address recipient;
        uint256 deadline;
        uint256 amountOut;
        uint256 amountInMaximum;
    }

    /// @notice Swaps as little as possible of one token for `amountOut` of another along the specified path (reversed)
    /// @param params The parameters necessary for the multi-hop swap, encoded as `ExactOutputParams` in calldata
    /// @return amountIn The amount of the input token
    function exactOutput(ExactOutputParams calldata params) external payable returns (uint256 amountIn);
}


// ============================================================================
// FILE: @uniswap/v3-periphery/contracts/libraries/TransferHelper.sol
// ============================================================================

// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.6.0;

import '@openzeppelin/contracts/token/ERC20/IERC20.sol';

library TransferHelper {
    /// @notice Transfers tokens from the targeted address to the given destination
    /// @notice Errors with 'STF' if transfer fails
    /// @param token The contract address of the token to be transferred
    /// @param from The originating address from which the tokens will be transferred
    /// @param to The destination address of the transfer
    /// @param value The amount to be transferred
    function safeTransferFrom(
        address token,
        address from,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) =
            token.call(abi.encodeWithSelector(IERC20.transferFrom.selector, from, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'STF');
    }

    /// @notice Transfers tokens from msg.sender to a recipient
    /// @dev Errors with ST if transfer fails
    /// @param token The contract address of the token which will be transferred
    /// @param to The recipient of the transfer
    /// @param value The value of the transfer
    function safeTransfer(
        address token,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.transfer.selector, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'ST');
    }

    /// @notice Approves the stipulated contract to spend the given allowance in the given token
    /// @dev Errors with 'SA' if transfer fails
    /// @param token The contract address of the token to be approved
    /// @param to The target of the approval
    /// @param value The amount of the given token the target will be allowed to spend
    function safeApprove(
        address token,
        address to,
        uint256 value
    ) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(IERC20.approve.selector, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'SA');
    }

    /// @notice Transfers ETH to the recipient address
    /// @dev Fails with `STE`
    /// @param to The destination of the transfer
    /// @param value The value to be transferred
    function safeTransferETH(address to, uint256 value) internal {
        (bool success, ) = to.call{value: value}(new bytes(0));
        require(success, 'STE');
    }
}


// ============================================================================
// FILE: contracts/abstracts/NativeMetaTransaction.sol
// ============================================================================

pragma solidity 0.8.12;

/**
 * @notice DISCLAIMER:
 * Do not use NativeMetaTransaction and ContextMixin together with OpenZeppelin's "multicall"
 * nor any other form of self delegatecall!
 * Risk of address spoofing attacks.
 * Read more: https://blog.openzeppelin.com/arbitrary-address-spoofing-vulnerability-erc2771context-multicall-public-disclosure
 */


import {EIP712Upgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";
import {ECDSAUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

contract NativeMetaTransaction is EIP712Upgradeable {

    using ECDSAUpgradeable for bytes32;

    bytes32 private constant META_TRANSACTION_TYPEHASH = keccak256(
        bytes(
            "MetaTransaction(uint256 nonce,address from,bytes functionSignature)"
        )
    );

    event MetaTransactionExecuted(
        address indexed userAddress,
        address payable indexed relayerAddress,
        bytes functionSignature
    );

    mapping(address => uint256) nonces;

    /*
     * Meta transaction structure.
     * No point of including value field here as if user is doing value transfer then he has the funds to pay for gas
     * He should call the desired function directly in that case.
     */
    struct MetaTransaction {
        uint256 nonce;
        address from;
        bytes functionSignature;
    }

    function executeMetaTransaction(
        address userAddress,
        bytes calldata functionSignature,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) external payable returns (bytes memory) {
        MetaTransaction memory metaTx = MetaTransaction({
        nonce : nonces[userAddress],
        from : userAddress,
        functionSignature : functionSignature
        });

        require(
            verify(userAddress, metaTx, sigR, sigS, sigV),
            "Signer and signature do not match"
        );

        // increase nonce for user (to avoid re-use)
        ++nonces[userAddress];

        emit MetaTransactionExecuted(
            userAddress,
            payable(msg.sender),
            functionSignature
        );

        // Append userAddress and relayer address at the end to extract it from calling context
        (bool success, bytes memory returnData) = address(this).call(
            abi.encodePacked(functionSignature, userAddress)
        );
        require(success, "Function call not successful");

        return returnData;
    }

    function getNonce(address user) external view returns (uint256 nonce) {
        nonce = nonces[user];
    }

    function hashMetaTransaction(MetaTransaction memory metaTx)
    internal
    pure
    returns (bytes32)
    {
        return
        keccak256(
            abi.encode(
                META_TRANSACTION_TYPEHASH,
                metaTx.nonce,
                metaTx.from,
                keccak256(metaTx.functionSignature)
            )
        );
    }

    function verify(
        address signer,
        MetaTransaction memory metaTx,
        bytes32 sigR,
        bytes32 sigS,
        uint8 sigV
    ) internal view returns (bool) {
        require(signer != address(0), "NativeMetaTransaction: INVALID_SIGNER");

        return
        signer ==
        _hashTypedDataV4(hashMetaTransaction(metaTx)).recover(
            sigV,
            sigR,
            sigS
        );

    }
}

// ============================================================================
// FILE: contracts/B2bInvestment.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;
pragma experimental ABIEncoderV2;

import {IB2bInvestment} from "./interfaces/IB2bInvestment.sol";
import {SwapTokenLib}  from "./lib/SwapTokenLib.sol";
import {ChainLinkOracleHelper}  from "./lib/ChainLinkOracleHelper.sol";
import {InterestCalculator} from "./lib/InterestCalculator.sol";

import {AccessControlUpgradeable} from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {DaiInvestmentLib} from "./lib/DaiInvestmentLib.sol";
import {NativeMetaTransaction} from "./abstracts/NativeMetaTransaction.sol";

contract B2bInvestment is IB2bInvestment, NativeMetaTransaction, AccessControlUpgradeable {

    using InterestCalculator for uint256;

    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant MAINTAIN_ROLE = keccak256("MAINTAIN_ROLE");


    uint16 constant public PERCENTAGE = 10000;
    uint16 constant public daiSlippage = 50;

    uint256 public etherPriceOnExit;
    uint256 public etherPriceExitTriggerTime;

    uint256 public lastInterestCalculationTime;
    uint256 public lastCalculatedInvestorAssetsInUsdc;

    uint256 public interestPerSecondRay;
    uint256 public interestEndTime;

    //previous interest values
    uint256 public previousInterestPerSecondRay;
    uint256 public previousInterestEndTime;

    address public etherPriceFeed;
    address public daiPriceFeed;
    address public diaAddress;
    IERC20 public usdc;
    IERC20 public dai;
    address public sDaiAddress;
    address public sparkAddress;
    address public sparkDaiATokenAddress;
    address public uniswapRouterAddress;
    uint256 public sDaiMinimumTvl;
    uint256 public sparkMinimumTvl;
    uint256 public sDaiMaxAllocation;
    uint256 public sparkMaxAllocation;
    uint16 public sDaiWeightModifier;
    uint16 public sparkWeightModifier;
    uint16 public sDaiLiquidityMaxPercentage;
    uint16 public sparkLiquidityMaxPercentage;
    uint16 public exitTriggerForEtherPrice;
    uint16 public reenterTriggerForEtherPrice;

    address public investor;

    struct InitParams {
        uint16 exitTriggerForEtherPrice;
        uint16 reenterTriggerForEtherPrice;
        address investor;
        address maintainer;
        address usdcAddress;
        address etherPriceFeed;
        address daiPriceFeed;
        address daiAddress;
        address sDaiAddress;
        address sparkAddress;
        address sparkDaiATokenAddress;
        address uniswapRouterAddress;
        uint256 sDaiMinimumTvl;
        uint256 sparkMinimumTvl;
        uint16 sDaiWeightModifier;
        uint16 sparkWeightModifier;
        uint256 sDaiMaxAllocation;
        uint256 sparkMaxAllocation;
        uint16 sDaiLiquidityMaxPercentage;
        uint16 sparkLiquidityMaxPercentage;
        uint256 interestPerYearWad;
        uint256 interestEndTime;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }


    function initialize(InitParams memory params) external initializer() {
        __AccessControl_init();
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _setupRole(ADMIN_ROLE, msg.sender);
        _setupRole(MAINTAIN_ROLE, params.maintainer);
        _setupRole(MAINTAIN_ROLE, msg.sender);

        investor = params.investor;
        usdc = IERC20(params.usdcAddress);
        daiPriceFeed = params.daiPriceFeed;
        etherPriceFeed = params.etherPriceFeed;
        dai = IERC20(params.daiAddress);
        exitTriggerForEtherPrice = params.exitTriggerForEtherPrice;
        reenterTriggerForEtherPrice = params.reenterTriggerForEtherPrice;
        sDaiAddress = params.sDaiAddress;
        sparkAddress = params.sparkAddress;
        sparkDaiATokenAddress = params.sparkDaiATokenAddress;

        interestPerSecondRay = params.interestPerYearWad.yearlyRateToRay();
        interestEndTime = params.interestEndTime;
        sDaiMinimumTvl = params.sDaiMinimumTvl;
        sparkMinimumTvl = params.sparkMinimumTvl;
        sDaiWeightModifier = params.sDaiWeightModifier;
        sparkWeightModifier = params.sparkWeightModifier;
        sDaiMaxAllocation = params.sDaiMaxAllocation;
        sparkMaxAllocation = params.sparkMaxAllocation;
        sDaiLiquidityMaxPercentage = params.sDaiLiquidityMaxPercentage;
        sparkLiquidityMaxPercentage = params.sparkLiquidityMaxPercentage;
        uniswapRouterAddress = params.uniswapRouterAddress;
    }

    /**
    * @dev Returns if the action is required for the ethereum price. if ethereum price was drop more than the exitTriggerForEtherPrice we need to exit from dai and keep our assets in USDC
    */
    function isEthereumPriceActionRequired() public view returns (uint256 ethPrice, bool actionRequired) {
        (, ethPrice) = ChainLinkOracleHelper.getLatestPrice(etherPriceFeed);

        uint256 etherPrice24hAgo = ChainLinkOracleHelper.getPastPrice(etherPriceFeed, 24 hours, 1 hours);
        actionRequired = ethPrice < etherPrice24hAgo && (etherPrice24hAgo - ethPrice) * PERCENTAGE / etherPrice24hAgo > exitTriggerForEtherPrice;
    }

    /**
    * @dev Returns the desired amount of assets to be deposited in the pools
    */
    function getDesiredAssetsPerPool(uint256 totalAssetsToInvest) public view returns (uint256 desiredSDaiDepositAmount, uint256 desiredSparkDepositAmount) {
        //sDai tvl
        Pool memory sDaiPool = Pool(sDaiMinimumTvl, sDaiWeightModifier, sDaiMaxAllocation, sDaiLiquidityMaxPercentage, DaiInvestmentLib.getSDaiTvl(sDaiAddress), type(uint256).max / PERCENTAGE, 0);
        sDaiPool.weightedTvl = calculateWeightedTvl(sDaiPool, PERCENTAGE);

        Pool memory sparkPool = Pool(sparkMinimumTvl, sparkWeightModifier, sparkMaxAllocation, sparkLiquidityMaxPercentage, IERC20(sparkDaiATokenAddress).totalSupply(), dai.balanceOf(sparkDaiATokenAddress), 0);
        sparkPool.weightedTvl = calculateWeightedTvl(sparkPool, PERCENTAGE);

        desiredSDaiDepositAmount = calculatePoolDepositAmount(sDaiPool, PERCENTAGE, sDaiPool.weightedTvl + sparkPool.weightedTvl, totalAssetsToInvest);
        desiredSparkDepositAmount = calculatePoolDepositAmount(sparkPool, PERCENTAGE, sDaiPool.weightedTvl + sparkPool.weightedTvl, totalAssetsToInvest);

    }

    function maintain(MaintainInput memory maintainInput) external onlyRole(MAINTAIN_ROLE) {
        _maintain(maintainInput);
    }

    function onEtherPriceDrop(uint16 tokenAmountDenominator) external {

        if (etherPriceOnExit > 0 && etherPriceExitTriggerTime + 7 days > block.timestamp) {
            _withdrawAllFromPools();
            SwapTokenLib.swapERC20ToUSDC(uniswapRouterAddress, address(usdc), address(dai), usdc.balanceOf(address(this)) / tokenAmountDenominator, true, address(0), daiSlippage, PERCENTAGE);
            return;
        }

        (uint256 ethPrice,  bool actionRequired) = isEthereumPriceActionRequired();

        if (actionRequired) {
            etherPriceOnExit = ethPrice;
            etherPriceExitTriggerTime = block.timestamp;
            _withdrawAllFromPools();
            SwapTokenLib.swapERC20ToUSDC(uniswapRouterAddress, address(usdc), address(dai), usdc.balanceOf(address(this)) / tokenAmountDenominator, true, address(0), daiSlippage, PERCENTAGE);
            return;
        }

        if (etherPriceOnExit > 0 && etherPriceExitTriggerTime + 7 days < block.timestamp) {
            //Check to reenter dai pools
            if (ethPrice > etherPriceOnExit || (etherPriceOnExit - ethPrice) * PERCENTAGE / etherPriceOnExit < reenterTriggerForEtherPrice) {
                etherPriceOnExit = 0;
                etherPriceExitTriggerTime = 0;
            }
        }
    }

    struct MaintainVars {
        uint256 usdcBalance;
        uint256 daiBalance;
        uint256 desiredUsdcAmount;
        uint256 desiredDaiAmount;
        uint256 desiredAmountInDai;

    }

    /**
    * @dev Maintains the contract, this will be called by the maintainer
    * function will prepare desired amount of assets in the pools and maintain the desired reserve for withdrawal
    */
    function _maintain(MaintainInput memory maintainInput) internal {
        require(maintainInput.slippage <= daiSlippage, "Slippage is higher than allowed");

        if (etherPriceOnExit > 0 && etherPriceExitTriggerTime + 7 days > block.timestamp) {
            return;
        }

        MaintainVars memory maintainVars;
        maintainVars.usdcBalance = usdc.balanceOf(address(this));
        maintainVars.daiBalance = dai.balanceOf(address(this));

        (uint256 sDaiAssetsInDai, uint256 sparkAssetsInDai) = getAssetsInPools();

        if (maintainInput.desiredReserveToken == address(usdc)) {
            maintainVars.desiredUsdcAmount = maintainInput.desiredReserve;
            maintainVars.desiredAmountInDai = usdcToDai(maintainVars.desiredUsdcAmount);
        }
        if (maintainInput.desiredReserveToken == address(dai)) {
            maintainVars.desiredDaiAmount = maintainInput.desiredReserve;
            maintainVars.desiredAmountInDai = maintainVars.desiredDaiAmount;
        }

        uint256 totalAssetsToInvestInDai = sDaiAssetsInDai + sparkAssetsInDai + maintainVars.daiBalance + usdcToDai(maintainVars.usdcBalance) - maintainVars.desiredAmountInDai;

        if (maintainVars.usdcBalance > maintainVars.desiredUsdcAmount) {
            SwapTokenLib.swapUsdcToStableCoin(uniswapRouterAddress, address(usdc), address(dai), (maintainVars.usdcBalance - maintainVars.desiredUsdcAmount) / maintainInput.tokenAmountDenominator, maintainInput.slippage, PERCENTAGE);
        }

        (uint256 desiredSDaiDepositAmount, uint256 desiredSparkDepositAmount) = getDesiredAssetsPerPool(totalAssetsToInvestInDai);

        if (desiredSDaiDepositAmount < sDaiAssetsInDai) {
            DaiInvestmentLib.withdrawFromSDai(sDaiAddress, sDaiAssetsInDai - desiredSDaiDepositAmount);
        }


        if (desiredSparkDepositAmount < sparkAssetsInDai) {
            DaiInvestmentLib.withdrawFromSparkPool(address(dai), sparkAddress, sparkAssetsInDai - desiredSparkDepositAmount);
        }

        if (desiredSDaiDepositAmount > sDaiAssetsInDai) {
            DaiInvestmentLib.approveAndDepositToSDai(address(dai), sDaiAddress, dai.balanceOf(address(this)).min(desiredSDaiDepositAmount - sDaiAssetsInDai));
        }

        if (desiredSparkDepositAmount > sparkAssetsInDai) {
            desiredSparkDepositAmount = dai.balanceOf(address(this)).min(desiredSparkDepositAmount - sparkAssetsInDai);
            DaiInvestmentLib.supplyToSparkPool(address(dai), sparkAddress, desiredSparkDepositAmount);
        }

        if (maintainInput.desiredReserveToken == address(usdc)
        && maintainVars.desiredUsdcAmount > usdc.balanceOf(address(this))
            && dai.balanceOf(address(this)) > 0
        ) {
            SwapTokenLib.swapStableCoinToUSDC(uniswapRouterAddress, address(usdc), address(dai), daiToUsdc(dai.balanceOf(address(this))), maintainInput.slippage, PERCENTAGE);
        }

        if (maintainInput.desiredReserveToken == address(dai)
        && maintainVars.desiredDaiAmount > dai.balanceOf(address(this))
            && usdc.balanceOf(address(this)) > 0
        ) {
            SwapTokenLib.swapUsdcToStableCoin(uniswapRouterAddress, address(usdc), address(dai), usdc.balanceOf(address(this)), maintainInput.slippage, PERCENTAGE);
        }

    }


    /**
    * @dev Updates the interest rate and end time, this will used to extend the contract life
    */
    function updateInterest(uint256 newInterestPerYearWad, uint256 newInterestEndTime) external onlyRole(ADMIN_ROLE) {
        require(newInterestEndTime > interestEndTime, "Interest end time should be greater than current interest end time");
        getAndUpdateLastCalculatedInvestorAssetsInUsdc();
        previousInterestPerSecondRay = interestPerSecondRay;
        previousInterestEndTime = interestEndTime;
        interestPerSecondRay = newInterestPerYearWad.yearlyRateToRay();
        interestEndTime = newInterestEndTime;
    }

    /**
    * @dev Returns the last calculated investor assets in usdc, only for external read only use
    */
    function getLastCalculatedInvestorAssetsInUsdc() external view returns (uint256) {
        if (lastCalculatedInvestorAssetsInUsdc == 0) {
            return 0;
        }

        uint256 localLastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc;
        uint256 localLastInterestCalculationTime = lastInterestCalculationTime;

        if (previousInterestEndTime > 0 && previousInterestEndTime > localLastInterestCalculationTime) {
            if (previousInterestEndTime > block.timestamp) {
                localLastCalculatedInvestorAssetsInUsdc = localLastCalculatedInvestorAssetsInUsdc.accrueInterest(previousInterestPerSecondRay, block.timestamp - lastInterestCalculationTime);
                localLastInterestCalculationTime = block.timestamp;

            } else {
                localLastCalculatedInvestorAssetsInUsdc = localLastCalculatedInvestorAssetsInUsdc.accrueInterest(previousInterestPerSecondRay, previousInterestEndTime - lastInterestCalculationTime);
                localLastInterestCalculationTime = previousInterestEndTime;
            }
        }

        if (localLastInterestCalculationTime < block.timestamp) {
            localLastCalculatedInvestorAssetsInUsdc = localLastCalculatedInvestorAssetsInUsdc.accrueInterest(interestPerSecondRay, block.timestamp - lastInterestCalculationTime);
        }

        return localLastCalculatedInvestorAssetsInUsdc;
    }

    /**
    * @dev Returns the last calculated investor assets in usdc, updated the last calculated value and timestamp
    */
    function getAndUpdateLastCalculatedInvestorAssetsInUsdc() public returns (uint256) {
        if (lastCalculatedInvestorAssetsInUsdc == 0) {
            return 0;
        }

        uint256 previousAssetsTotal = lastCalculatedInvestorAssetsInUsdc;

        //if the interest rate and interestEndTime updated checks if previous values are still valid
        if (previousInterestEndTime > 0 && previousInterestEndTime > lastInterestCalculationTime) {
            if (previousInterestEndTime > block.timestamp) {
                lastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc.accrueInterest(previousInterestPerSecondRay, block.timestamp - lastInterestCalculationTime);
                lastInterestCalculationTime = block.timestamp;

            } else {
                lastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc.accrueInterest(previousInterestPerSecondRay, previousInterestEndTime - lastInterestCalculationTime);
                lastInterestCalculationTime = previousInterestEndTime;
            }
        }

        if (lastInterestCalculationTime < block.timestamp) {
            lastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc.accrueInterest(interestPerSecondRay, block.timestamp - lastInterestCalculationTime);
            lastInterestCalculationTime = block.timestamp;
        }

        emit InterestGained(lastCalculatedInvestorAssetsInUsdc - previousAssetsTotal);
        return lastCalculatedInvestorAssetsInUsdc;
    }


    function reduceLastCalculatedInvestorAssets(uint256 amount) internal {
        lastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc - amount;
        lastInterestCalculationTime = block.timestamp;
    }

    function increaseLastCalculatedInvestorAssets(uint256 amount) internal {
        lastCalculatedInvestorAssetsInUsdc = lastCalculatedInvestorAssetsInUsdc + amount;
        lastInterestCalculationTime = block.timestamp;
    }

    function getAssetsInPools() public view returns (uint256 sdaiAssetsInDai, uint256 sparkAssetsInDai) {
        return (DaiInvestmentLib.getSDaiAssets(sDaiAddress), DaiInvestmentLib.getSparkPoolAssets(sparkAddress, address(dai)));
    }

    function getAssetTotalInPools() public view returns (uint256 assets) {
        return DaiInvestmentLib.getSDaiAssets(sDaiAddress) + DaiInvestmentLib.getSparkPoolAssets(sparkAddress, address(dai));
    }


    function deposit(address from, address tokenAddress, uint256 amount) external {
        _deposit(from, tokenAddress, amount);
    }

    function depositAndMaintain(address from, address tokenAddress, uint256 amount, uint16 tokenAmountDenominator, uint16 slippage) external {
        _deposit(from, tokenAddress, amount);
        _maintain(MaintainInput(tokenAmountDenominator, address(0), 0, slippage));
    }


    function _deposit(address from, address tokenAddress, uint256 amount) internal {

        getAndUpdateLastCalculatedInvestorAssetsInUsdc();
        if (tokenAddress != address(usdc) && tokenAddress != address(dai)) {
            revert TokenIsNotSupported(tokenAddress);
        }

        uint8 slippageMultiplier;
        uint256 usdcAmount;
        if (tokenAddress == address(dai)) {
            usdcAmount = daiToUsdc(amount);
            slippageMultiplier = 1;

        } else {
            usdcAmount = amount;
            slippageMultiplier = 2;
        }

        if (getTotalAssetsOfContact()
            < ((_calculateInterestToInterestPeriodEnd(usdcAmount) * (PERCENTAGE + slippageMultiplier * daiSlippage) / PERCENTAGE)
            + (_calculateInterestToInterestPeriodEnd(lastCalculatedInvestorAssetsInUsdc) * (PERCENTAGE + daiSlippage) / PERCENTAGE)) - usdcAmount) {
            revert MaxAssetLimitExceeded();
        }

        IERC20(tokenAddress).transferFrom(from, address(this), amount);
        increaseLastCalculatedInvestorAssets(usdcAmount);
    }

    function getTotalAssetsOfContact() public view returns (uint256) {
        return daiToUsdc(getAssetTotalInPools()) + daiToUsdc(dai.balanceOf(address(this))) + usdc.balanceOf(address(this));
    }

    function _calculateInterestToInterestPeriodEnd(uint256 usdcAmount) internal view returns (uint256) {
        if (block.timestamp > interestEndTime) {
            return usdcAmount;
        }

        return usdcAmount.accrueInterest(interestPerSecondRay, interestEndTime - block.timestamp);

    }

    function withdraw(address tokenAddress, uint256 amount, address receiver, uint16 slippage) external {
        if (msg.sender != investor) {
            revert OnlyInvestor();
        }
        require(slippage <= daiSlippage, "Slippage is higher than allowed");
        if (tokenAddress != address(usdc) && tokenAddress != address(dai)) {
            revert TokenIsNotSupported(tokenAddress);
        }
        uint256 investorUsdcBalance = getAndUpdateLastCalculatedInvestorAssetsInUsdc();
        uint256 usdcAmount;

        if (tokenAddress == address(dai)) {
            usdcAmount = investorUsdcBalance.min(daiToUsdc(amount));
            amount = usdcToDai(usdcAmount);
        } else {
            usdcAmount = investorUsdcBalance.min(amount);
            amount = usdcAmount;
        }

        if (usdcAmount >= lastCalculatedInvestorAssetsInUsdc) {
            _withdrawAllFromPools();
            if (tokenAddress == address(usdc)) {
                amount = lastCalculatedInvestorAssetsInUsdc;
                SwapTokenLib.swapERC20ToUSDC(uniswapRouterAddress, address(usdc), address(dai), daiToUsdc(dai.balanceOf(address(this))), true, address(0), slippage, PERCENTAGE);
            } else {

                amount = usdcToDai(lastCalculatedInvestorAssetsInUsdc);
                SwapTokenLib.swapUsdcToERC20(uniswapRouterAddress, address(usdc), address(dai), usdc.balanceOf(address(this)), true, address(0), slippage, PERCENTAGE);
            }
        } else if (IERC20(tokenAddress).balanceOf(address(this)) < amount) {
            _maintain(MaintainInput(1, tokenAddress, amount, slippage));
        }


        uint256 tokenBalance = IERC20(tokenAddress).balanceOf(address(this));
        if (tokenBalance < amount) {
            amount = tokenBalance;
        }

        if (tokenAddress == address(dai)) {
            reduceLastCalculatedInvestorAssets(daiToUsdc(amount));
        } else {
            reduceLastCalculatedInvestorAssets(amount);
        }

        IERC20(tokenAddress).transfer(receiver, amount);

    }

    function withdrawAccessFundsAsAdmin(address tokenAddress, uint256 amount, address receiver) external onlyRole(ADMIN_ROLE) {
        if (tokenAddress != address(usdc) && tokenAddress != address(dai)) {
            revert TokenIsNotSupported(tokenAddress);
        }

        uint256 userAsset = getAndUpdateLastCalculatedInvestorAssetsInUsdc();
        if (block.timestamp < interestEndTime) {
            userAsset = userAsset.accrueInterest(interestPerSecondRay, interestEndTime - block.timestamp) * (PERCENTAGE + daiSlippage) / PERCENTAGE;
        }
        if (tokenAddress == address(dai)) {
            amount = amount.min(daiToUsdc(getTotalAssetsOfContact() - userAsset));
        } else {
            amount = amount.min(getTotalAssetsOfContact() - userAsset);
        }

        IERC20(tokenAddress).transfer(receiver, amount);
    }

    function _withdrawAllFromPools() internal returns (bool sDaiWithdrawStatus, bool sparkWithdrawStatus) {
        //withdraw from sdai pool
        (uint256 sDaiAssets, uint256 sparkAssets) = getAssetsInPools();
        if (DaiInvestmentLib.getSDaiBalance(sDaiAddress) > 0) {
            try DaiInvestmentLib.withdrawFromSDai(sDaiAddress, sDaiAssets){
                sDaiWithdrawStatus = DaiInvestmentLib.getSDaiAssets(sDaiAddress) == 0;
            } catch {
                sDaiWithdrawStatus = false;
            }
        } else {
            sDaiWithdrawStatus = true;
        }

        //withdraw from spark pool
        if (DaiInvestmentLib.getSparkPoolAssets(sparkAddress, address(dai)) > 0) {

            try DaiInvestmentLib.withdrawFromSparkPool(address(dai), sparkAddress, sparkAssets) {
                sparkWithdrawStatus = DaiInvestmentLib.getSparkPoolAssets(sparkAddress, address(dai)) == 0;
            } catch {
                sparkWithdrawStatus = false;
            }
        } else {
            sparkWithdrawStatus = true;
        }

        return (sDaiWithdrawStatus, sparkWithdrawStatus);
    }

    function calculateWeightedTvl(Pool memory pool, uint16 percentage) public pure returns (uint256 tvl){
        return pool.tvl > pool.minimumTvl ? pool.tvl * pool.weightModifier / percentage : 0;
    }

    function calculatePoolDepositAmount(Pool memory pool, uint16 percentage, uint256 totalWeightedTvl, uint256 contractDaiBalance) public pure returns (uint256 amount) {
        if (pool.weightedTvl > 0) {
            uint256 desiredDepositAmount = contractDaiBalance * pool.weightedTvl / totalWeightedTvl;
            uint256 minOfCalculatedAmountAndMaxPercentage = min(desiredDepositAmount, pool.maxAllocation);
            return min(minOfCalculatedAmountAndMaxPercentage, pool.liquidity * pool.maxLiquidityPercentage / percentage);
        }

        return 0;
    }

    function min(uint x, uint y) internal pure returns (uint z) {
        return x <= y ? x : y;
    }

    function daiToUsdc(uint256 daiAmount) internal pure returns(uint256) {
        return daiAmount / 10**12;
    }

    function usdcToDai(uint256 usdcAmount) internal pure returns(uint256) {
        return usdcAmount * 10**12;
    }
}

// ============================================================================
// FILE: contracts/interfaces/IB2bInvestment.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;
pragma abicoder v2;

interface IB2bInvestment {

    struct Pool {
        uint256 minimumTvl;
        uint16 weightModifier;
        uint256 maxAllocation;
        uint16 maxLiquidityPercentage;
        uint256 tvl;
        uint256 liquidity;
        uint256 weightedTvl;
    }

    struct MaintainInput {
        uint16 tokenAmountDenominator;
        address desiredReserveToken;
        uint256 desiredReserve;
        uint16 slippage;
    }


    event InterestGained(uint256 amount);

    error MaxAssetLimitExceeded();
    error TokenIsNotSupported(address tokenAddress);
    error OnlyInvestor();
}

// ============================================================================
// FILE: contracts/interfaces/IScaledBalanceToken.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

interface IScaledBalanceToken {
    function scaledBalanceOf(address user) external view returns (uint256);
}

// ============================================================================
// FILE: contracts/interfaces/IsDai.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

interface IsDai {
    function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 asset) external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function pot() external view returns (address);
}

// ============================================================================
// FILE: contracts/interfaces/ISpark.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;

interface ISpark {
    function supply(
        address asset,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode
    ) external;

    function withdraw(
        address asset,
        uint256 amount,
        address to
    ) external returns (uint256);

    function getReserveData(
        address asset
    ) external view returns (ReserveData memory);

    struct ReserveData {
        //stores the reserve configuration
        ReserveConfigurationMap configuration;
        //the liquidity index. Expressed in ray
        uint128 liquidityIndex;
        //the current supply rate. Expressed in ray
        uint128 currentLiquidityRate;
        //variable borrow index. Expressed in ray
        uint128 variableBorrowIndex;
        //the current variable borrow rate. Expressed in ray
        uint128 currentVariableBorrowRate;
        //the current stable borrow rate. Expressed in ray
        uint128 currentStableBorrowRate;
        //timestamp of last update
        uint40 lastUpdateTimestamp;
        //the id of the reserve. Represents the position in the list of the active reserves
        uint16 id;
        //aToken address
        address aTokenAddress;
        //stableDebtToken address
        address stableDebtTokenAddress;
        //variableDebtToken address
        address variableDebtTokenAddress;
        //address of the interest rate strategy
        address interestRateStrategyAddress;
        //the current treasury balance, scaled
        uint128 accruedToTreasury;
        //the outstanding unbacked aTokens minted through the bridging feature
        uint128 unbacked;
        //the outstanding debt borrowed against this asset in isolation mode
        uint128 isolationModeTotalDebt;
    }

    struct ReserveConfigurationMap {
        //bit 0-15: LTV
        //bit 16-31: Liq. threshold
        //bit 32-47: Liq. bonus
        //bit 48-55: Decimals
        //bit 56: reserve is active
        //bit 57: reserve is frozen
        //bit 58: borrowing is enabled
        //bit 59: stable rate borrowing enabled
        //bit 60: asset is paused
        //bit 61: borrowing in isolation mode is enabled
        //bit 62-63: reserved
        //bit 64-79: reserve factor
        //bit 80-115 borrow cap in whole tokens, borrowCap == 0 => no cap
        //bit 116-151 supply cap in whole tokens, supplyCap == 0 => no cap
        //bit 152-167 liquidation protocol fee
        //bit 168-175 eMode category
        //bit 176-211 unbacked mint cap in whole tokens, unbackedMintCap == 0 => minting disabled
        //bit 212-251 debt ceiling for isolation mode with (ReserveConfiguration::DEBT_CEILING_DECIMALS) decimals
        //bit 252-255 unused

        uint256 data;
    }
}

// ============================================================================
// FILE: contracts/interfaces/Pot.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.12;


interface Pot {
    
    function  Pie() external view returns (uint256);
    function chi() external view returns (uint256);

}


// ============================================================================
// FILE: contracts/lib/ChainLinkOracleHelper.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import {AggregatorV2V3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV2V3Interface.sol";
import {AggregatorProxyInterface} from "../priceFeed/interfaces/AggregatorProxyInterface.sol";

library ChainLinkOracleHelper {

    function getLatestPrice(address _oracleAddress) external view returns ( uint80, uint256) {
        AggregatorV2V3Interface oracle = AggregatorV2V3Interface(_oracleAddress);
        ( uint80 roundId, int256 price, , ,) = oracle.latestRoundData();
        return (roundId, uint256(price));
    }


    function getPastPrice(address _oracleAddress, uint256 secondsAgo, uint256 secondWindow) external view returns (uint256) {

        AggregatorProxyInterface oracle = AggregatorProxyInterface(_oracleAddress);

        uint80 startRoundId = uint80(oracle.latestRound());

        int256 price;
        uint256 updatedAt;
        uint80 increment = 100;
        uint80 endRoundId;

        do {
            endRoundId = startRoundId;
            startRoundId = startRoundId - increment;
            (, price, , updatedAt,) = oracle.getRoundData(startRoundId);
            increment = increment * 2;
        }
        while (updatedAt > (block.timestamp - secondsAgo));
        //binary search between startRoundId and endRoundId
        uint80 midRoundId;
        while (startRoundId < endRoundId) {
            midRoundId = (startRoundId + endRoundId) / 2;
            (, price, , updatedAt,) = oracle.getRoundData(midRoundId);

            if ((block.timestamp - (secondsAgo + secondWindow) <= updatedAt)
                && (updatedAt <= block.timestamp - ((secondsAgo - secondWindow)))) {

                return uint256(price);
            }
            if (updatedAt < block.timestamp - secondsAgo) {
                startRoundId = midRoundId + 1;
            } else {
                endRoundId = midRoundId;
            }

        }

        revert("No price found");
    }

    function getRoundId(uint16 phaseId, uint256 aggregatorRoundId) internal pure returns (uint80) {
        return uint80((uint256(phaseId) << 64) | aggregatorRoundId);
    }


}

// ============================================================================
// FILE: contracts/lib/DaiInvestmentLib.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {IsDai} from "../interfaces/IsDai.sol";
import {ISpark} from "../interfaces/ISpark.sol";
import {IScaledBalanceToken} from "../interfaces/IScaledBalanceToken.sol";
import "@aave/core-v3/contracts/protocol/libraries/math/WadRayMath.sol";
import {Pot} from "../interfaces/Pot.sol";

library DaiInvestmentLib {
    using WadRayMath for uint256;

    function approveAndDepositToSDai(
        address daiAddress,
        address sDaiAddress,
        uint256 daiAmount
    ) public returns (uint256 shares) {
        IERC20(daiAddress).approve(sDaiAddress, daiAmount);
        IsDai sDai = IsDai(sDaiAddress);
        return sDai.deposit(daiAmount, address(this));
    }

    function withdrawFromSDai(
        address sDaiAddress,
        uint256 assets
    ) public returns (uint256 daiAmount){
        IsDai sDai = IsDai(sDaiAddress);
        uint256 shares = sDai.convertToShares(assets);
        if (sDai.balanceOf(address(this)) < shares) {
            shares =sDai.balanceOf(address(this));
        }
        return sDai.redeem(shares, address(this), address(this));
    }

    function getSDaiBalance(address sDaiAddress) public view returns (uint256 assets) {
        IsDai sDai = IsDai(sDaiAddress);
        return sDai.balanceOf(address(this));
    }

    function getSDaiShares(address sDaiAddress) public view returns (uint256 shares) {
        IsDai sDai = IsDai(sDaiAddress);
        return sDai.convertToShares(sDai.balanceOf(address(this)));
    }

    function getSDaiAssets(address sDaiAddress) public view returns (uint256 daiAmount) {
        IsDai sDai = IsDai(sDaiAddress);
        return sDai.convertToAssets(sDai.balanceOf(address(this)));
    }

    function getSDaiTvl(address sDaiAddress) public view returns (uint256 daiAmount) {
        IsDai sDai = IsDai(sDaiAddress);
        Pot pot = Pot(sDai.pot());
        return pot.Pie().rayMul(pot.chi());
    }

    function supplyToSparkPool(
        address daiAddress,
        address sparkAddress,
        uint256 daiAmount
    ) public {
        IERC20(daiAddress).approve(sparkAddress, daiAmount);
        ISpark spark = ISpark(sparkAddress);
        spark.supply(daiAddress, daiAmount, address(this), 0);
    }

    function withdrawFromSparkPool(
        address daiAddress,
        address sparkAddress,
        uint256 daiAmount
    ) public returns (uint256 daiAmountWithdrawn) {
        ISpark spark = ISpark(sparkAddress);
        return spark.withdraw(daiAddress, daiAmount, address(this));
    }

    function getSparkPoolAssets(address sparkAddress, address daiAddress) public view returns (uint256 daiAmount) {
        ISpark spark = ISpark(sparkAddress);
        ISpark.ReserveData memory reserveData = spark.getReserveData(daiAddress);
        return IERC20(reserveData.aTokenAddress).balanceOf(address(this));
    }

}

// ============================================================================
// FILE: contracts/lib/InterestCalculator.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

library InterestCalculator {
    //// Fixed point scale factors
    // wei -> the base unit
    // wad -> wei * 10 ** 18. 1 ether = 1 wad, so 0.5 ether can be used
    //      to represent a decimal wad of 0.5
    // ray -> wei * 10 ** 27

    // Go from wad (10**18) to ray (10**27)
    function wadToRay(uint _wad) public pure returns (uint) {
        return mul(_wad, 10 ** 9);
    }

    // Go from wei to ray (10**27)
    function weiToRay(uint _wei) public pure returns (uint) {
        return mul(_wei, 10 ** 27);
    }


    /**
    * @dev Uses an approximation of continuously compounded interest
    * (discretely compounded every second)
    * @param _principal The principal to calculate the interest on.
    *   Accepted in wei.
    * @param _rate The interest rate. Accepted as a ray representing
    *   1 + the effective interest rate per second, compounded every
    *   second. As an example:
    *   I want to accrue interest at a nominal rate (i) of 5.0% per year
    *   compounded continuously. (Effective Annual Rate of 5.127%).
    *   This is approximately equal to 5.0% per year compounded every
    *   second (to 8 decimal places, if max precision is essential,
    *   calculate nominal interest per year compounded every second from
    *   your desired effective annual rate). Effective Rate Per Second =
    *   Nominal Rate Per Second compounded every second = Nominal Rate
    *   Per Year compounded every second * conversion factor from years
    *   to seconds
    *   Effective Rate Per Second = 0.05 / (365 days/yr * 86400 sec/day) = 1.5854895991882 * 10 ** -9
    *   The value we want to send this function is
    *   1 * 10 ** 27 + Effective Rate Per Second * 10 ** 27
    *   = 1000000001585489599188229325
    *   This will return 5.1271096334354555 Dai on a 100 Dai principal
    *   over the course of one year (31536000 seconds)
    * @param _age The time period over which to accrue interest. Accepted
    *   in seconds.
    * @return The new principal as a wad. Equal to original principal +
    *   interest accrued
    */
    function accrueInterest(uint _principal, uint _rate, uint _age) public pure returns (uint) {
        return rmul(_principal, rpow(_rate, _age));
    }


    /**
    * @dev Takes in the desired nominal interest rate per year, compounded
    *   every second (this is approximately equal to nominal interest rate
    *   per year compounded continuously). Returns the ray value expected
    *   by the accrueInterest function
    * @param _rateWad A wad of the desired nominal interest rate per year,
    *   compounded continuously. Converting from ether to wei will effectively
    *   convert from a decimal value to a wad. So 5% rate = 0.05
    *   should be input as yearlyRateToRay( 0.05 ether )
    * @return 1 * 10 ** 27 + Effective Interest Rate Per Second * 10 ** 27
    */
    function yearlyRateToRay(uint _rateWad) public pure returns (uint) {
        return add(wadToRay(1 ether), rdiv(wadToRay(_rateWad), weiToRay(365*86400)));
    }

    function add(uint x, uint y) public pure returns (uint z) {
        require((z = x + y) >= x, "ds-math-add-overflow");
    }
    function sub(uint x, uint y) public pure returns (uint z) {
        require((z = x - y) <= x, "ds-math-sub-underflow");
    }
    function mul(uint x, uint y) public pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x, "ds-math-mul-overflow");
    }

    function min(uint x, uint y) public pure returns (uint z) {
        return x <= y ? x : y;
    }
    function max(uint x, uint y) public pure returns (uint z) {
        return x >= y ? x : y;
    }
    function imin(int x, int y) internal pure returns (int z) {
        return x <= y ? x : y;
    }
    function imax(int x, int y) internal pure returns (int z) {
        return x >= y ? x : y;
    }

    uint constant WAD = 10 ** 18;
    uint constant RAY = 10 ** 27;

    function wmul(uint x, uint y) public pure returns (uint z) {
        z = add(mul(x, y), WAD / 2) / WAD;
    }
    function rmul(uint x, uint y) public pure returns (uint z) {
        z = add(mul(x, y), RAY / 2) / RAY;
    }
    function wdiv(uint x, uint y) public pure returns (uint z) {
        z = add(mul(x, WAD), y / 2) / y;
    }
    function rdiv(uint x, uint y) public pure returns (uint z) {
        z = add(mul(x, RAY), y / 2) / y;
    }

    // This famous algorithm is called "exponentiation by squaring"
    // and calculates x^n with x as fixed-point and n as regular unsigned.
    //
    // It's O(log n), instead of O(n) for naive repeated multiplication.
    //
    // These facts are why it works:
    //
    //  If n is even, then x^n = (x^2)^(n/2).
    //  If n is odd,  then x^n = x * x^(n-1),
    //   and applying the equation for even x gives
    //    x^n = x * (x^2)^((n-1) / 2).
    //
    //  Also, EVM division is flooring and
    //    floor[(n-1) / 2] = floor[n / 2].
    //
    function rpow(uint x, uint n) public pure returns (uint z) {
        z = n % 2 != 0 ? x : RAY;

        for (n /= 2; n != 0; n /= 2) {
            x = rmul(x, x);

            if (n % 2 != 0) {
                z = rmul(z, x);
            }
        }
    }
}

// ============================================================================
// FILE: contracts/lib/SwapTokenLib.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.12;

import {IERC20Metadata} from "@openzeppelin/contracts/interfaces/IERC20Metadata.sol";
import {AggregatorV2V3Interface} from "@chainlink/contracts/src/v0.8/interfaces/AggregatorV2V3Interface.sol";

import '@uniswap/v3-periphery/contracts/interfaces/ISwapRouter.sol';
import '@uniswap/v3-periphery/contracts/libraries/TransferHelper.sol';

library SwapTokenLib {

    uint24 public constant feeTier = 500;

    function swapERC20AllToUSDC(address uniswapRouterAddress, address usdcAddress, address erc20Address) public returns (uint256 amountOut) {
        ISwapRouter swapRouter = ISwapRouter(uniswapRouterAddress);

        uint256 amountIn = IERC20Metadata(erc20Address).balanceOf(address(this));
        TransferHelper.safeApprove(erc20Address, address(swapRouter), amountIn);

        ISwapRouter.ExactInputSingleParams memory params =
        ISwapRouter.ExactInputSingleParams({
        tokenIn : erc20Address,
        tokenOut : usdcAddress,
        fee : feeTier,
        recipient : address(this),
        deadline : block.timestamp,
        amountIn : amountIn,
        amountOutMinimum : 0,
        sqrtPriceLimitX96 : 0
        });
        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);
        return amountOut;

    }

    function swapERC20ToUSDC(address uniswapRouterAddress, address usdcAddress, address erc20Address, uint256 usdcValue, bool isUsdStableCoin, address priceFeedAddress, uint16 slippagePercentage, uint16 PERCENTAGE) public returns (uint256 amountOut) {

        ISwapRouter swapRouter = ISwapRouter(uniswapRouterAddress);
        uint256 tokenValue;
        if (isUsdStableCoin) {
            tokenValue = _convertStableToken(usdcAddress, erc20Address, usdcValue);
        } else {
            tokenValue = _convertToken(usdcAddress, priceFeedAddress, usdcAddress, erc20Address, usdcValue);
        }


        TransferHelper.safeApprove(erc20Address, address(swapRouter), tokenValue);

        ISwapRouter.ExactInputSingleParams memory params =
        ISwapRouter.ExactInputSingleParams({
        tokenIn : erc20Address,
        tokenOut : usdcAddress,
        fee : feeTier,
        recipient : address(this),
        deadline : block.timestamp,
        amountIn : tokenValue,
        amountOutMinimum : usdcValue - (usdcValue * slippagePercentage / PERCENTAGE),
        sqrtPriceLimitX96 : 0
        });
        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);
        return amountOut;

    }

    function swapStableCoinToUSDC(address uniswapRouterAddress, address usdcAddress, address erc20Address, uint256 usdcValue, uint16 slippagePercentage, uint16 PERCENTAGE) public returns (uint256 amountOut) {

        ISwapRouter swapRouter = ISwapRouter(uniswapRouterAddress);
        uint256 tokenValue = _convertStableToken(usdcAddress, erc20Address, usdcValue);

        TransferHelper.safeApprove(erc20Address, address(swapRouter), tokenValue);

        ISwapRouter.ExactInputSingleParams memory params =
        ISwapRouter.ExactInputSingleParams({
        tokenIn : erc20Address,
        tokenOut : usdcAddress,
        fee : feeTier,
        recipient : address(this),
        deadline : block.timestamp,
        amountIn : tokenValue,
        amountOutMinimum : usdcValue - (usdcValue * slippagePercentage / PERCENTAGE),
        sqrtPriceLimitX96 : 0
        });
        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);
        return amountOut;

    }

    function swapUsdcToERC20(address uniswapRouterAddress, address usdcAddress, address erc20Address, uint256 usdcValue, bool isUsdStableCoin, address priceFeedAddress, uint16 slippagePercentage, uint16 PERCENTAGE) public returns (uint256 amountOut) {

        ISwapRouter swapRouter = ISwapRouter(uniswapRouterAddress);
        uint256 tokenValue;
        if (isUsdStableCoin) {
            tokenValue = _convertStableToken(usdcAddress, erc20Address, usdcValue);
        } else {
            tokenValue = _convertToken(usdcAddress, priceFeedAddress, usdcAddress, erc20Address, usdcValue);
        }



        TransferHelper.safeApprove(usdcAddress, uniswapRouterAddress, usdcValue);

        ISwapRouter.ExactInputSingleParams memory params =
        ISwapRouter.ExactInputSingleParams({
        tokenIn : usdcAddress,
        tokenOut : erc20Address,
        fee : feeTier,
        recipient : address(this),
        deadline : block.timestamp,
        amountIn : usdcValue,
        amountOutMinimum : (tokenValue - (tokenValue * slippagePercentage / PERCENTAGE)),
        sqrtPriceLimitX96 : 0
        });
        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);

        return amountOut;

    }

    function swapUsdcToStableCoin(address uniswapRouterAddress, address usdcAddress, address erc20Address, uint256 usdcValue, uint16 slippagePercentage, uint16 PERCENTAGE) public returns (uint256 amountOut) {

        ISwapRouter swapRouter = ISwapRouter(uniswapRouterAddress);
        uint256 tokenValue = _convertStableToken(usdcAddress, erc20Address, usdcValue);

        TransferHelper.safeApprove(usdcAddress, uniswapRouterAddress, usdcValue);

        ISwapRouter.ExactInputSingleParams memory params =
        ISwapRouter.ExactInputSingleParams({
        tokenIn : usdcAddress,
        tokenOut : erc20Address,
        fee : feeTier,
        recipient : address(this),
        deadline : block.timestamp,
        amountIn : usdcValue,
        amountOutMinimum : (tokenValue - (tokenValue * slippagePercentage / PERCENTAGE)),
        sqrtPriceLimitX96 : 0
        });
        // The call to `exactInputSingle` executes the swap.
        amountOut = swapRouter.exactInputSingle(params);

        return amountOut;

    }


    function _convertToken(address usdcAddress, address priceFeed, address token1, address token2, uint256 amount) view public returns (uint256) {
        (uint80 roundId, int256 price,,,uint80 answeredInRound) = AggregatorV2V3Interface(priceFeed).latestRoundData();
        require(answeredInRound >= roundId, "COA: Stale answer");
        if (token1 == usdcAddress) {
            return (amount * (10 ** AggregatorV2V3Interface(priceFeed).decimals()) / uint256(price) * 10 ** IERC20Metadata(token2).decimals() / 10 ** IERC20Metadata(token1).decimals());
        }
        return (amount * uint256(price) / (10 ** AggregatorV2V3Interface(priceFeed).decimals()) * 10 ** IERC20Metadata(token2).decimals() / 10 ** IERC20Metadata(token1).decimals());
    }

    function _convertStableToken(address token1, address token2, uint256 amount) view public returns (uint256) {
        return (amount * (10 ** IERC20Metadata(token2).decimals())) / (10 ** IERC20Metadata(token1).decimals());
    }


}

// ============================================================================
// FILE: contracts/priceFeed/interfaces/AggregatorProxyInterface.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity >=0.8.4;


import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV2V3Interface.sol";

interface AggregatorProxyInterface is AggregatorV2V3Interface {
  function phaseAggregators(uint16 phaseId) external view returns (address);

  function phaseId() external view returns (uint16);

  function proposedAggregator() external view returns (address);

  function proposedGetRoundData(uint80 roundId)
    external
    view
    returns (
      uint80 id,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );

  function proposedLatestRoundData()
    external
    view
    returns (
      uint80 id,
      int256 answer,
      uint256 startedAt,
      uint256 updatedAt,
      uint80 answeredInRound
    );

  function aggregator() external view returns (address);
}
