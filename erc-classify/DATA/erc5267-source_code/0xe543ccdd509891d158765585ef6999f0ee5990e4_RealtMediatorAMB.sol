// SPDX-License-Identifier: UNLICENSED
// Source: 0xe543ccdd509891d158765585ef6999f0ee5990e4
// Contract Name: RealtMediatorAMB
// Generated on: 2026-05-14 12:04:36


// ============================================================================
// FILE: @gnosis.pm/safe-contracts/contracts/common/Enum.sol
// ============================================================================

// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

/// @title Enum - Collection of enums
/// @author Richard Meissner - <richard@gnosis.pm>
contract Enum {
    enum Operation {Call, DelegateCall}
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
import "../proxy/utils/Initializable.sol";

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
    function __AccessControl_init() internal onlyInitializing {
    }

    function __AccessControl_init_unchained() internal onlyInitializing {
    }
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
// FILE: @openzeppelin/contracts-upgradeable/interfaces/draft-IERC1822Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.5.0) (interfaces/draft-IERC1822.sol)

pragma solidity ^0.8.0;

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822ProxiableUpgradeable {
    /**
     * @dev Returns the storage slot that the proxiable contract assumes is being used to store the implementation
     * address.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy.
     */
    function proxiableUUID() external view returns (bytes32);
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/interfaces/IERC1967Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC1967.sol)

pragma solidity ^0.8.0;

/**
 * @dev ERC-1967: Proxy Storage Slots. This interface contains the events defined in the ERC.
 *
 * _Available since v4.8.3._
 */
interface IERC1967Upgradeable {
    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Emitted when the beacon is changed.
     */
    event BeaconUpgraded(address indexed beacon);
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
// FILE: @openzeppelin/contracts-upgradeable/proxy/beacon/IBeaconUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (proxy/beacon/IBeacon.sol)

pragma solidity ^0.8.0;

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeaconUpgradeable {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {BeaconProxy} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}


// ============================================================================
// FILE: @openzeppelin/contracts-upgradeable/proxy/ERC1967/ERC1967UpgradeUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (proxy/ERC1967/ERC1967Upgrade.sol)

pragma solidity ^0.8.2;

import "../beacon/IBeaconUpgradeable.sol";
import "../../interfaces/IERC1967Upgradeable.sol";
import "../../interfaces/draft-IERC1822Upgradeable.sol";
import "../../utils/AddressUpgradeable.sol";
import "../../utils/StorageSlotUpgradeable.sol";
import "../utils/Initializable.sol";

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 *
 * _Available since v4.1._
 */
abstract contract ERC1967UpgradeUpgradeable is Initializable, IERC1967Upgradeable {
    function __ERC1967Upgrade_init() internal onlyInitializing {
    }

    function __ERC1967Upgrade_init_unchained() internal onlyInitializing {
    }
    // This is the keccak-256 hash of "eip1967.proxy.rollback" subtracted by 1
    bytes32 private constant _ROLLBACK_SLOT = 0x4910fdfa16fed3260ed0e7147f7cc6da11a60208b5b9406d12a635614ffd9143;

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Returns the current implementation address.
     */
    function _getImplementation() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(AddressUpgradeable.isContract(newImplementation), "ERC1967: new implementation is not a contract");
        StorageSlotUpgradeable.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Perform implementation upgrade
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Perform implementation upgrade with additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCall(address newImplementation, bytes memory data, bool forceCall) internal {
        _upgradeTo(newImplementation);
        if (data.length > 0 || forceCall) {
            AddressUpgradeable.functionDelegateCall(newImplementation, data);
        }
    }

    /**
     * @dev Perform implementation upgrade with security checks for UUPS proxies, and additional setup call.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data, bool forceCall) internal {
        // Upgrades from old implementations will perform a rollback test. This test requires the new
        // implementation to upgrade back to the old, non-ERC1822 compliant, implementation. Removing
        // this special case will break upgrade paths from old UUPS implementation to new ones.
        if (StorageSlotUpgradeable.getBooleanSlot(_ROLLBACK_SLOT).value) {
            _setImplementation(newImplementation);
        } else {
            try IERC1822ProxiableUpgradeable(newImplementation).proxiableUUID() returns (bytes32 slot) {
                require(slot == _IMPLEMENTATION_SLOT, "ERC1967Upgrade: unsupported proxiableUUID");
            } catch {
                revert("ERC1967Upgrade: new implementation is not UUPS");
            }
            _upgradeToAndCall(newImplementation, data, forceCall);
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     */
    function _getAdmin() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        require(newAdmin != address(0), "ERC1967: new admin is the zero address");
        StorageSlotUpgradeable.getAddressSlot(_ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {AdminChanged} event.
     */
    function _changeAdmin(address newAdmin) internal {
        emit AdminChanged(_getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function _getBeacon() internal view returns (address) {
        return StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        require(AddressUpgradeable.isContract(newBeacon), "ERC1967: new beacon is not a contract");
        require(
            AddressUpgradeable.isContract(IBeaconUpgradeable(newBeacon).implementation()),
            "ERC1967: beacon implementation is not a contract"
        );
        StorageSlotUpgradeable.getAddressSlot(_BEACON_SLOT).value = newBeacon;
    }

    /**
     * @dev Perform beacon upgrade with additional setup call. Note: This upgrades the address of the beacon, it does
     * not upgrade the implementation contained in the beacon (see {UpgradeableBeacon-_setImplementation} for that).
     *
     * Emits a {BeaconUpgraded} event.
     */
    function _upgradeBeaconToAndCall(address newBeacon, bytes memory data, bool forceCall) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);
        if (data.length > 0 || forceCall) {
            AddressUpgradeable.functionDelegateCall(IBeaconUpgradeable(newBeacon).implementation(), data);
        }
    }

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
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
// FILE: @openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (proxy/utils/UUPSUpgradeable.sol)

pragma solidity ^0.8.0;

import "../../interfaces/draft-IERC1822Upgradeable.sol";
import "../ERC1967/ERC1967UpgradeUpgradeable.sol";
import "./Initializable.sol";

/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 *
 * _Available since v4.1._
 */
abstract contract UUPSUpgradeable is Initializable, IERC1822ProxiableUpgradeable, ERC1967UpgradeUpgradeable {
    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
    address private immutable __self = address(this);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        require(address(this) != __self, "Function must be called through delegatecall");
        require(_getImplementation() == __self, "Function must be called through active proxy");
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        require(address(this) == __self, "UUPSUpgradeable: must not be called through delegatecall");
        _;
    }

    /**
     * @dev Implementation of the ERC1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual override notDelegated returns (bytes32) {
        return _IMPLEMENTATION_SLOT;
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeTo(address newImplementation) public virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, new bytes(0), false);
    }

    /**
     * @dev Upgrade the implementation of the proxy to `newImplementation`, and subsequently execute the function call
     * encoded in `data`.
     *
     * Calls {_authorizeUpgrade}.
     *
     * Emits an {Upgraded} event.
     *
     * @custom:oz-upgrades-unsafe-allow-reachable delegatecall
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) public payable virtual onlyProxy {
        _authorizeUpgrade(newImplementation);
        _upgradeToAndCallUUPS(newImplementation, data, true);
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeTo} and {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal override onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /**
     * @dev This empty reserved space is put in place to allow future versions to add new
     * variables without shifting down storage in the inheritance chain.
     * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
     */
    uint256[50] private __gap;
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
// FILE: @openzeppelin/contracts-upgradeable/utils/introspection/ERC165Upgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/introspection/ERC165.sol)

pragma solidity ^0.8.0;

import "./IERC165Upgradeable.sol";
import "../../proxy/utils/Initializable.sol";

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
// FILE: @openzeppelin/contracts-upgradeable/utils/StorageSlotUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

pragma solidity ^0.8.0;

/**
 * @dev Library for reading and writing primitive types to specific storage slots.
 *
 * Storage slots are often used to avoid storage conflict when dealing with upgradeable contracts.
 * This library helps with reading and writing to such slots without the need for inline assembly.
 *
 * The functions in this library return Slot structs that contain a `value` member that can be used to read or write.
 *
 * Example usage to set ERC1967 implementation slot:
 * ```solidity
 * contract ERC1967 {
 *     bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
 *
 *     function _getImplementation() internal view returns (address) {
 *         return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
 *     }
 *
 *     function _setImplementation(address newImplementation) internal {
 *         require(Address.isContract(newImplementation), "ERC1967: new implementation is not a contract");
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 *
 * _Available since v4.1 for `address`, `bool`, `bytes32`, `uint256`._
 * _Available since v4.9 for `string`, `bytes`._
 */
library StorageSlotUpgradeable {
    struct AddressSlot {
        address value;
    }

    struct BooleanSlot {
        bool value;
    }

    struct Bytes32Slot {
        bytes32 value;
    }

    struct Uint256Slot {
        uint256 value;
    }

    struct StringSlot {
        string value;
    }

    struct BytesSlot {
        bytes value;
    }

    /**
     * @dev Returns an `AddressSlot` with member `value` located at `slot`.
     */
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BooleanSlot` with member `value` located at `slot`.
     */
    function getBooleanSlot(bytes32 slot) internal pure returns (BooleanSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Bytes32Slot` with member `value` located at `slot`.
     */
    function getBytes32Slot(bytes32 slot) internal pure returns (Bytes32Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `Uint256Slot` with member `value` located at `slot`.
     */
    function getUint256Slot(bytes32 slot) internal pure returns (Uint256Slot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` with member `value` located at `slot`.
     */
    function getStringSlot(bytes32 slot) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `StringSlot` representation of the string storage pointer `store`.
     */
    function getStringSlot(string storage store) internal pure returns (StringSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` with member `value` located at `slot`.
     */
    function getBytesSlot(bytes32 slot) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := slot
        }
    }

    /**
     * @dev Returns an `BytesSlot` representation of the bytes storage pointer `store`.
     */
    function getBytesSlot(bytes storage store) internal pure returns (BytesSlot storage r) {
        /// @solidity memory-safe-assembly
        assembly {
            r.slot := store.slot
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
// FILE: contracts/AMBMediator.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

import { IAMB } from "./interfaces/IAMB.sol";

/**
* @title AMBMediator
* @dev Basic storage and methods needed by mediators to interact with AMB bridge.
*/
abstract contract AMBMediator {
    IAMB private _bridgeContract;
    uint256 private _requestGasLimit;
    uint256 internal _batchTokenBridgeLimit;

    event BridgeContractSet(IAMB omnibridge);
    // after EIP2929, call to warmed contract address costs 100 instead of 2600
    // https://github.com/omni/tokenbridge-contracts/blob/908a48107919d4ab127f9af07d44d47eac91547e/contracts/upgradeable_contracts/arbitrary_message/MessageDelivery.sol#L13C4-L14
    uint256 private constant MIN_GAS_PER_CALL = 100;

    /**
     * @notice Initializes the mediator contract with the bridge contract address, request gas limit, and batch token bridge limit.
     * @dev The bridge contract address is stored in the _bridgeContract variable, the request gas limit is stored in the _requestGasLimit variable, and the batch token bridge limit is stored in the _batchTokenBridgeLimit variable.
     */
    // solhint-disable-next-line func-name-mixedcase
    function __Mediator_init(
        address bridgeContract_,
        uint256 requestGasLimit_,
        uint256 batchTokenBridgeLimit_
    ) internal {
        _bridgeContract = IAMB(bridgeContract_);
        require(requestGasLimit_ >= MIN_GAS_PER_CALL && requestGasLimit_ <= IAMB(bridgeContract_).maxGasPerTx(), "AM23");
        _requestGasLimit = requestGasLimit_;
        _batchTokenBridgeLimit = batchTokenBridgeLimit_;
        emit BridgeContractSet(IAMB(bridgeContract_));
    }

    /**
    * @dev Throws if caller on the other side is not an associated mediator.
    */
    modifier onlyMediator {
        require(msg.sender == address(_bridgeContract), "AM07");
        require(messageSender() == address(this), "AM08");
        _;
    }

    modifier onlyAuthorized() {
        _authAMB();
        _;
    }

    function _authAMB() internal virtual;

    /**
    * @dev Sets the AMB bridge contract address. Only the owner can call this method.
    * @param bridgeContract_ the address of the bridge contract.
    */
    function setBridgeContract(IAMB bridgeContract_) external onlyAuthorized {
        _bridgeContract = bridgeContract_;
        emit BridgeContractSet(bridgeContract_);
    }
    /**
    * @dev Sets the number of tokens in a single transaction that can be bridged
    * Only the owner can call this method.
    * @param batchTokenBridgeLimit_ the number of tokens allowed per transaction
    */
    function setBatchTokenBridgeLimit(uint256 batchTokenBridgeLimit_) external onlyAuthorized {
        _batchTokenBridgeLimit = batchTokenBridgeLimit_;
    }

    /**
    * @dev Sets the gas limit to be used in the message execution by the AMB bridge on the other network.
    * This value can't exceed the parameter maxGasPerTx defined on the AMB bridge.
    * Only the owner can call this method.
    * @param requestGasLimit_ the gas limit for the message execution.
    */
    function setRequestGasLimit(uint256 requestGasLimit_) external onlyAuthorized {
        require(requestGasLimit_ >= MIN_GAS_PER_CALL && requestGasLimit_ <= maxGasPerTx(), "AM23");
        _requestGasLimit = requestGasLimit_;
    }

    /**
    * @dev Get the AMB interface for the bridge contract address
    * @return AMB interface for the bridge contract address
    */
    function bridgeContract() internal view returns (IAMB) {
        return _bridgeContract;
    }

    /**
    * @dev Get the AMB interface for the bridge contract address
    * @return AMB interface for the bridge contract address
    */
    function getBridgeContract() external view returns (IAMB) {
        return _bridgeContract;
    }

    /** 
    * @dev Tells the number of tokens in a single transaction that can be bridged
    * @return the number of tokens that can possibly be bridged in a single transaction
    */
    function getBatchTokenBridgeLimit() external view returns (uint256) {
        return _batchTokenBridgeLimit;
    }

    /**
    * @dev Tells the gas limit to be used in the message execution by the AMB bridge on the other network.
    * @return the gas limit for the message execution.
    */
    function requestGasLimit() internal view returns (uint256) {
        return _requestGasLimit;
    }

    /**
    * @dev Tells the gas limit to be used in the message execution by the AMB bridge on the other network.
    * @return the gas limit for the message execution.
    */
    function getRequestGasLimit() external view returns (uint256) {
        return _requestGasLimit;
    }

    /**
    * @dev Tells the address that generated the message on the other network that is currently being executed by
    * the AMB bridge.
    * @return the address of the message sender.
    */
    function messageSender() internal view returns (address) {
        return _bridgeContract.messageSender();
    }

    function messageId() internal view returns (bytes32) {
        return _bridgeContract.messageId();
    }

    /**
    * @dev Tells the maximum gas limit that a message can use on its execution by the AMB bridge on the other network.
    * @return the maximum gas limit value.
    */
    function maxGasPerTx() internal view returns (uint256) {
        return _bridgeContract.maxGasPerTx();
    }

    /* Reserved slots for future use: https://docs.openzeppelin.com/sdk/2.5/writing-contracts.html#modifying-your-contracts */
    uint256[47] private ______gap;
}

// ============================================================================
// FILE: contracts/BasicMediator.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import { AMBMediator } from "./AMBMediator.sol";

abstract contract BasicMediator is AMBMediator {
    event FailedMessageRequest(bytes32 messageId);

    mapping(bytes32 => bool) internal _propertyVaultFixed;
    mapping(bytes32 => address) internal _propertyVaultRecipient;
    mapping(bytes32 => uint256[]) internal _propertyVaultAmounts;
    mapping(bytes32 => address[]) internal _propertyVaultTokens;

    mapping(bytes32 => address) private _messageRecipient;
    mapping(bytes32 => address) private _messageSender;
    mapping(bytes32 => address[]) private _messageTokens;
    mapping(bytes32 => uint256[]) private _messageAmounts;
    mapping(bytes32 => bool) private _messageFixed;

    function getBridgeInterfacesVersion() external view returns (uint64, uint64, uint64) {
        return bridgeContract().getBridgeInterfacesVersion();
    }

    function getBridgeMode() external view returns (bytes4) {
        return bridgeContract().getBridgeMode(); // bytes4(keccak256(abi.encodePacked("arbitrary-message-bridge-core")))
    }

    function isPropertyVaultFixed(bytes32 messageId) internal view returns (bool) {
        return _propertyVaultFixed[messageId];
    }

    function propertyVaultIssueFixed(bytes32 messageId) internal {
        _propertyVaultFixed[messageId] = true;
    }

    function saveVaultErrorState(bytes32 messageId, address recipient, address[] calldata tokens, uint256[] calldata amounts) internal {
        _propertyVaultRecipient[messageId] = recipient;
        _propertyVaultTokens[messageId] = tokens;
        _propertyVaultAmounts[messageId] = amounts;
    }

    function setMessageSender(bytes32 _msgId, address _sender) internal {
        _messageSender[_msgId] = _sender;
    }

    function propertyVaultRecipient(bytes32 _msgId) internal view returns (address) {
        return _propertyVaultRecipient[_msgId];
    }

    function propertyVaultTokens(bytes32 _msgId) internal view returns (address[] memory) {
        return _propertyVaultTokens[_msgId];
    }

    function propertyVaultAmounts(bytes32 _msgId) internal view returns (uint256[] memory) {
        return _propertyVaultAmounts[_msgId];
    }

    /**
     * @notice messageSender() function is used to retrieve the address of the sender of a message.
     * @dev messageSender() function takes a bytes32 message ID as an argument and returns the address of the sender of the message. 
     */
    function messageSender(bytes32 _msgId) internal view returns (address) {
        return _messageSender[_msgId];
    }

    /**
     * @notice This function sets the recipient of a message.
     * @dev This function sets the recipient of a message by taking in a message ID and an address.
     */
    function setMessageRecipient(bytes32 _msgId, address _recipient) internal {
        _messageRecipient[_msgId] = _recipient;
    }

    /**
     * @notice messageRecipient() returns the address of the recipient of a message
     * @dev messageRecipient() takes a bytes32 message ID as an argument and returns the address of the recipient of the message. 
     */
    function messageRecipient(bytes32 _msgId) internal view returns (address) {
        return _messageRecipient[_msgId];
    }

    /**
     * @notice setMessageTokens() sets the tokens associated with a message.
     * @dev This function sets the tokens associated with a message. It takes two parameters, a bytes32 message ID and an address array of tokens. It stores the tokens in the _messageTokens mapping.
     */
    function setMessageTokens(bytes32 _msgId, address[] memory _tokens) internal {
        _messageTokens[_msgId] = _tokens;
    }

    /**
     * @notice messageTokens() function
     * 
     * @dev This function returns an array of addresses associated with a given message ID.
     * 
     * @param _msgId bytes32 - The message ID associated with the addresses.
     * 
     * @return address[] memory - An array of addresses associated with the given message ID.
     */
    function messageTokens(bytes32 _msgId) internal view returns (address[] memory) {
        return _messageTokens[_msgId];
    }

    /**
     * @notice setMessageAmounts() sets the amounts associated with a message
     * 
     * @dev This function sets the amounts associated with a message. It takes two parameters:
     * 
     * - _msgId: The message ID
     * - _amounts: An array of uint256 values
     */
    function setMessageAmounts(bytes32 _msgId, uint256[] memory _amounts) internal {
        _messageAmounts[_msgId] = _amounts;
    }

    /**
     * @notice messageAmounts() is a function that returns an array of uint256 values associated with a given message ID.
     * @dev messageAmounts() takes a bytes32 message ID as an argument and returns an array of uint256 values associated with that message ID. 
     */
    function messageAmounts(bytes32 _msgId) internal view returns (uint256[] memory) {
        return _messageAmounts[_msgId];
    }

    /**
     * @notice Sets the message fixed status to true for the given message ID
     * @dev This function is used to set the message fixed status to true for the given message ID
     * @param _msgId The message ID to set the fixed status for
     */
    function setMessageFixed(bytes32 _msgId) internal {
        _messageFixed[_msgId] = true;
    }

    /**
     * @notice messageFixed() is a function that checks if a message has been fixed.
     * @dev messageFixed() takes a bytes32 _msgId as an argument and returns a boolean. It checks if the message has been fixed by looking up the _messageFixed mapping.
     */
    function messageFixed(bytes32 _msgId) internal view returns (bool) {
        return _messageFixed[_msgId];
    }

    /**
     * @notice getMessageFixed() allows a user to check if a message has been fixed.
     * @dev getMessageFixed() takes a bytes32 _msgId as an argument and returns a boolean.
     */
    function getMessageFixed(bytes32 _msgId) external view returns (bool) {
        return _messageFixed[_msgId];
    }

    function getPropertyVaultFailData(bytes32 _msgId) external view returns (bool, address, address[] memory,uint256[] memory) {
        return (_propertyVaultFixed[_msgId], _propertyVaultRecipient[_msgId], _propertyVaultTokens[_msgId], _propertyVaultAmounts[_msgId]);
    }

    /**
     * @notice requestFailedMessageFix
     * 
     * @dev This function is used to fix a failed message request. It takes a bytes32 _msgId as an argument and attempts to fix the failed message request. 
     */
    function requestFailedMessageFix(bytes32 _msgId) external virtual;

    /**
     * @notice This function fixes a failed message.
     * @dev This function is used to fix a failed message. It takes a bytes32 _msgId as an argument.
     */
    function fixFailedMessage(bytes32 _msgId) external virtual;

    /**
     * @notice passMessage is a function that allows a user to send a message to a recipient.
     * @dev The function takes in four parameters: _from, _recipient, _localTokens, _remoteTokens, and _values. 
     * _from is the address of the sender, _recipient is the address of the recipient, _localTokens is an array of addresses of local tokens, 
     * _remoteTokens is an array of addresses of remote tokens, and _values is an array of uint256 values. 
     * The function returns a bytes32 value. 
     */
    function passMessage(address _from, address _recipient, address[] memory _localTokens, address[] memory _remoteTokens, uint256[] memory _values) internal virtual returns (bytes32);

    /* Reserved slots for future use: https://docs.openzeppelin.com/sdk/2.5/writing-contracts.html#modifying-your-contracts */
    uint256[41] private ______gap;
}

// ============================================================================
// FILE: contracts/interfaces/IAMB.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;

interface IAMB {
    /**
     * @notice getBridgeInterfacesVersion() returns the bridge mode of the currently used bridge.
     * @dev getBridgeInterfacesVersion() is a view function that returns the bridge mode of the currently used bridge. It is an external function and does not modify the state of the contract.
     */
    function getBridgeInterfacesVersion() external view returns (uint64, uint64, uint64);
    /**
     * @notice getBridgeMode() returns the bridge mode of the currently used bridge.
     * @dev getBridgeMode() is a view function that returns the bridge mode of the currently used bridge. It is an external function and does not modify the state of the contract.
     */
    function getBridgeMode() external view returns (bytes4);
    /**
     * @notice messageSender() returns the address of the sender of the current message.
     * @dev messageSender() is a view function that returns the address of the sender of the current message. It is an external function and does not modify the state of the contract.
     */
    function messageSender() external view returns (address);

    /**
     * @notice This function returns the maximum gas allowed for a single transaction.
     * @dev This function is used to prevent transactions from consuming too much gas.
     */
    function maxGasPerTx() external view returns (uint256);

    /**
     * @notice This function returns the transaction hash of the current transaction.
     * @dev This function is used to get the transaction hash of the current transaction. It is an external view function and returns a bytes32.
     */
    function transactionHash() external view returns (bytes32);

    /**
     * @notice messageSourceChainId() returns the chain ID of the source chain of the message
     * @dev messageSourceChainId() is a view function that returns the chain ID of the source chain of the message. This is used to verify the origin of the message.
     */
    function messageSourceChainId() external view returns (bytes32);

    /**
     * @notice messageCallStatus() is a function that returns a boolean value based on the messageId passed as an argument.
     * @dev messageCallStatus() takes a bytes32 type argument and returns a boolean value. It is used to check the status of a message call.
     */
    function messageCallStatus(bytes32 _messageId) external view returns (bool);

    /**
     * @dev Returns the data hash of a failed message.
     * @param _messageId The ID of the message.
     * @return The data hash of the failed message.
     */
    function failedMessageDataHash(
        bytes32 _messageId
    ) external view returns (bytes32);

    /**
     * @notice failedMessageReceiver() is a function that returns the address of the failed message receiver.
     * @dev This function takes in a messageId as an argument and returns the address of the failed message receiver.
     */
    function failedMessageReceiver(
        bytes32 _messageId
    ) external view returns (address);

    /**
     * @dev Returns the address of the message sender if the message failed.
     * @param _messageId The message ID.
     * @return The address of the message sender.
     */
    function failedMessageSender(
        bytes32 _messageId
    ) external view returns (address);

    /**
     * @notice This function requires a message to be passed to a contract.
     * @dev This function requires a message to be passed to a contract. It takes in an address of the contract, the data to be passed, and the gas to be used. It returns a bytes32.
     */
    function requireToPassMessage(
        address _contract,
        bytes calldata _data,
        uint256 _gas
    ) external returns (bytes32);

    function requireToConfirmMessage(
        address _contract,
        bytes calldata _data,
        uint256 _gas
    ) external returns (bytes32);

    /**
     * @dev This function requires a bytes32 _requestSelector and a bytes calldata _data to get information.
     * @param _requestSelector The bytes32 request selector.
     * @param _data The bytes calldata.
     * @return The bytes32 of the requested information.
     */
    function requireToGetInformation(
        bytes32 _requestSelector,
        bytes calldata _data
    ) external returns (bytes32);

    /**
     * @notice This function returns the source chain ID.
     * @dev This function is used to get the source chain ID. It is an external view function and returns a uint256.
     */
    function sourceChainId() external view returns (uint256);

    /**
     * destinationChainId()
     *
     * @dev This function returns the ID of the destination chain.
     *
     * @return uint256 - The ID of the destination chain.
     */
    function destinationChainId() external view returns (uint256);

    function messageId() external view returns (bytes32);
}


// ============================================================================
// FILE: contracts/interfaces/IBridgeToken.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

interface IBridgeToken {
  /**
   * @notice This function returns the ruleId and the associated value for a given ruleId.
   * @dev This function is used to retrieve the ruleId and the associated value for a given ruleId. The function takes a uint256 ruleId as an argument and returns a uint256 ruleId and a uint256 value.
   */
  function rule(uint256 ruleId) external view returns (uint256, uint256);
  /**
   * @dev Function to view the balance of an address
   * @param who The address to view the balance of
   * @return uint256 The balance of the address
   */
  function balanceOf(address who) external view returns (uint256);
  /**
   * @notice This function allows a user to transfer tokens from one address to another.
   * @dev The transferFrom function is used to transfer tokens from one address to another. It takes three parameters: 
   * from (the address of the sender), to (the address of the recipient), and value (the amount of tokens to be transferred). 
   * The function returns a boolean value indicating whether the transfer was successful or not. 
   */
  function transferFrom(address from, address to, uint256 value) external returns (bool);
  /**
   * @dev Function to transfer tokens to a specified address
   * @param to The address of the recipient
   * @param value The amount of tokens to be transferred
   * @return A boolean that indicates whether the transfer was successful or not
   */
  function transfer(address to, uint256 value) external returns (bool);
}

// ============================================================================
// FILE: contracts/interfaces/IComplianceRegistry.sol
// ============================================================================

// SPDX-License-Identifier: CNU

/*
    Copyright (c) 2019 Mt Pelerin Group Ltd

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation with the addition of the
    following permission added to Section 15 as permitted in Section 7(a):
    FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
    MT PELERIN GROUP LTD. MT PELERIN GROUP LTD DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
    OF THIRD PARTY RIGHTS

    This program is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with this program; if not, see http://www.gnu.org/licenses or write to
    the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
    Boston, MA, 02110-1301 USA, or download the license from the following URL:
    https://www.gnu.org/licenses/agpl-3.0.fr.html

    The interactive user interfaces in modified source and object code versions
    of this program must display Appropriate Legal Notices, as required under
    Section 5 of the GNU Affero General Public License.

    You can be released from the requirements of the license by purchasing
    a commercial license. Buying such a license is mandatory as soon as you
    develop commercial activities involving Mt Pelerin Group Ltd software without
    disclosing the source code of your own applications.
    These activities include: offering paid services based/using this product to customers,
    using this product in any application, distributing this product with a closed
    source product.

    For more information, please contact Mt Pelerin Group Ltd at this
    address: hello@mtpelerin.com
*/

pragma solidity 0.8.18;

/**
 * @title IComplianceRegistry
 * @dev IComplianceRegistry interface
 **/
interface IComplianceRegistry {
  /**
   * @notice This function returns the userId and the address of the user.
   * @dev This function takes in an array of trusted intermediaries and an address as parameters. It then returns the userId and the address of the user.
   */
  function userId(address[] calldata _trustedIntermediaries, address _address) 
    external view returns (uint256, address);
  /**
   * @notice This function allows a trusted intermediary to set the attributes of a user.
   * @dev The _trustedIntermediary parameter is the address of the trusted intermediary. The _userId parameter is the ID of the user. The _keys parameter is an array of uint256 values that represent the attributes of the user.
   */
  function attributes(address _trustedIntermediary, uint256 _userId, uint256[] calldata _keys) 
    external view returns (uint256[] memory);
  /**
   * @notice This function is used to register a user with the given address and attributes.
   * @dev The function takes in an address and two arrays of uint256 values. The first array contains the keys for the attributes and the second array contains the values for the attributes. The function stores the address and the attributes in the mapping.
   */
  function registerUser(
    address _address, 
    uint256[] calldata _attributeKeys, 
    uint256[] calldata _attributeValues
  ) external;
  /**
   * @notice updateUserAttributes() allows a user to update their attributes.
   * @dev updateUserAttributes() takes in a userId, an array of attribute keys, and an array of attribute values. The function then updates the user's attributes with the given values.
   */
  function updateUserAttributes(
    uint256 _userId, 
    uint256[] calldata _attributeKeys, 
    uint256[] calldata _attributeValues
  ) external;
}


// ============================================================================
// FILE: contracts/interfaces/IERC3009.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

interface IERC3009 {
   /**
    * @notice transferWithAuthorization allows a user to transfer funds from one address to another with authorization.
    * @dev This function requires the sender to provide a valid signature, a valid time window, and a unique nonce.
    * The signature is generated using the ECDSA algorithm and the sender's private key.
    * The valid time window is used to ensure that the transaction is valid only within the specified time frame.
    * The unique nonce is used to prevent replay attacks.
    */
   function transferWithAuthorization(
    address from,
    address to,
    uint256 value,
    uint256 validAfter,
    uint256 validBefore,
    bytes32 nonce,
    uint8 v,
    bytes32 r,
    bytes32 s
  ) external;
}


// ============================================================================
// FILE: contracts/interfaces/IERC677Receiver.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

interface IERC677Receiver {
  function onTokenTransfer(address from, uint256 amount, bytes calldata data) external returns (bool);
}


// ============================================================================
// FILE: contracts/interfaces/IGnosisSafe.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import { Enum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface IGnosisSafe {
  /**
   * @notice Executes a transaction with the given parameters.
   * @dev This function is used to execute a transaction with the given parameters. It takes in the address of the recipient, the value to be sent, the data to be sent, the operation to be performed, the safe transaction gas, the base gas, the gas price, the gas token, the refund receiver, and the signatures. It returns a boolean indicating the success of the transaction.
   */
  function execTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures
  ) external payable returns (bool success);
}

// ============================================================================
// FILE: contracts/libraries/Bytes.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity 0.8.18;
/**
 * @title Bytes
 * @dev Helper methods to transform bytes to other solidity types.
 */
library Bytes {
    /**
    * @dev Truncate bytes array if its size is more than 20 bytes.
    * NOTE: Similar to the bytesToBytes32 function, make sure that _bytes is not shorter than 20 bytes.
    * @param _bytes to be converted to address type
    * @return addr included in the firsts 20 bytes of the bytes array in parameter.
    */
    function bytesToAddress(bytes memory _bytes) internal pure returns (address addr) {
        assembly {
            addr := mload(add(_bytes, 20))
        }
    }
}

// ============================================================================
// FILE: contracts/RealtMediator.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import { ReentrancyGuardUpgradeable } from "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import { UUPSUpgradeable } from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import { AccessControlUpgradeable } from "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import { EIP712Upgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/EIP712Upgradeable.sol";
import { ECDSAUpgradeable } from "@openzeppelin/contracts-upgradeable/utils/cryptography/ECDSAUpgradeable.sol";

import { Safe } from "./Safe.sol";
import { BasicMediator } from "./BasicMediator.sol";
import { WhitelistExecutor } from "./WhitelistExecutor.sol";
import { IBridgeToken } from "./interfaces/IBridgeToken.sol";
import { IERC677Receiver } from "./interfaces/IERC677Receiver.sol";
import { Bytes } from "./libraries/Bytes.sol";
import { IERC3009 } from "./interfaces/IERC3009.sol";
import { IAMB } from "./interfaces/IAMB.sol";

contract RealtMediatorAMB is BasicMediator, WhitelistExecutor, UUPSUpgradeable, AccessControlUpgradeable, IERC677Receiver, EIP712Upgradeable, ReentrancyGuardUpgradeable {
    uint8 public constant VERSION = 2;
    bytes32 public constant OPERATOR_ROLE = 0x97667070c54ef182b0f5858b034beac1b6f3089aa2d3188bb1e8929f4fa9b929; // keccak256("OPERATOR_ROLE");
    bytes32 public constant CREATE2_ROLE = 0x52bb4257e934f54697b64e15b38575f35c49751df7c56535f1ef6073d7102004; // keccak256("CREATE2_ROLE");
    mapping(address => address) private _tokenMapping;
    address private _propertyVault;
    address private _buyBack;
    bytes32 public constant BRIDGE_BATCH_DESTINATION_TYPEHASH = 0xc5aef48f0479b7f9e2039995fb836fd6d6595744dd05bf6818255128a712b1c4; // kecca256(BridgeBatchDestination(address destination,bytes32 hash))
    struct BatchTokenBridge {
        uint256 value;
        uint256 validAfter;
        uint256 validBefore;
        bytes32 nonce;
        IERC3009 token;
        address from;
        address to;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    event ManualFix(bytes32 messageId);
    event BuyBackInitiated(bytes32 messageId);
    event TokenListSet(address[] localTokenList, address[] remoteTokenList);
    event TokenSet(address localToken, address remoteToken);

    constructor() {
        _disableInitializers();
    }

    function initialize() external onlyRole(DEFAULT_ADMIN_ROLE) reinitializer(VERSION) {
        // empty initialize
    }

    // same as keccak256(abi.encode(data));
    function _keccakDataStruct(BatchTokenBridge[] calldata data) private pure returns (bytes32 output) {
        assembly {
            let size := add(0x40, mul(320, data.length))
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, size))
            mstore(ptr, 0x0000000000000000000000000000000000000000000000000000000000000020)
            mstore(add(ptr, 0x20), data.length)
            calldatacopy(add(0x40, ptr), data.offset, size)
            output := keccak256(ptr, size)
        }
    }

    function batchBridgeWithDestination(
        BatchTokenBridge[] calldata data,
        address destination,
        bytes32 r,
        bytes32 vs
    ) external nonReentrant returns (bool) {
        (address from, address[] memory _localTokens, address[] memory _remoteTokens, uint256[] memory _amounts) = _receiveTokens(data);
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            BRIDGE_BATCH_DESTINATION_TYPEHASH,
            destination,
            _keccakDataStruct(data)
        )));
        require(ECDSAUpgradeable.recover(digest, r, vs) == from, "AM21");
        passMessage(from, destination, _localTokens, _remoteTokens, _amounts);
        return true;
    }

    /**
     * @notice batchBridge is a function that allows users to bridge tokens from one chain to another.
     * @dev batchBridge takes in an array of BatchTokenBridge structs, and a destination address. It then calls the _receiveTokens function to get the from address, local tokens, remote tokens, and amounts. Finally, it calls the passMessage function to bridge the tokens from one chain to another. 
     */
    function batchBridge(BatchTokenBridge[] calldata data) external nonReentrant returns (bool) {
        (address from, address[] memory _localTokens, address[] memory _remoteTokens, uint256[] memory _amounts) = _receiveTokens(data);
        passMessage(from, from, _localTokens, _remoteTokens, _amounts);
        return true;
    }

    /**
    * @dev Allow certain functions to be called only by the approved property vault
    * @notice Only Property Vault can pass this modifier
    */
    modifier onlyPropertyVault {
        assembly {
            if xor(sload(_propertyVault.slot), caller()) {
                let ptr := mload(0x40)
                // Revert with `Error("AM18")`
                mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(add(ptr, 0x04), 0x20) // String offset
                mstore(add(ptr, 0x24), 0x04) // Revert reason length
                mstore(add(ptr, 0x44), "AM18")
                revert(ptr, 0x48)
            }
        }
        _;
    }

    /**
     * @notice batchTransferFromVault is a function that allows the PropertyVault to transfer multiple tokens to a single destination address.
     * @dev batchTransferFromVault takes in an array of tokens, an array of amounts, and a destination address. It then iterates through the tokens and amounts and sends the tokens to the destination address.
     */
    function batchTransferFromVault(
        address[] calldata tokens,
        uint256[] calldata amounts,
        address destination
    ) external onlyPropertyVault returns (bool) {
        uint256 tokenBridged = tokens.length;
        for (uint256 i; i < tokenBridged;) {
            _sendTokens(destination, tokens[i], amounts[i]);
            unchecked { ++i; }
        }
        return true;
    }

    /**
    * @dev Transfer tokens from the Vault to a destination address
    * @notice batchBridgeFromVault is a function that allows the PropertyVault to transfer multiple tokens to a single destination address on the destination chain.
    * @param tokens array of BridgeTokens contract addresses
    * @param amounts array of uint256 amounts of respective bridgeTokens contracts
    * @param destination address to transfer tokens to
    * @return true/false if successful
    */
    function batchBridgeFromVault(
        address[] calldata tokens,
        uint256[] calldata amounts,
        address destination
    ) external onlyPropertyVault returns (bool) {
        address[] memory _tokens = _checkTokens(tokens);
        passMessageVault(destination, _tokens, amounts);
        return true;
    }

    /**
    * @dev Sell tokens to the buyback operator on the destination chain.
    * @param data BatchTokenBridge[] array of BatchTokenBridge structs
    * @return true/false if successful
    */
    function batchBuyBackBridge(
        BatchTokenBridge[] calldata data
    ) external nonReentrant returns (bool) {
        address buyBack = _buyBack;
        assembly {
            // Revert if _buyBack = address(0)
            if iszero(buyBack) {
                let ptr := mload(0x40)
                // Revert with `Error("AM22")`
                mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(add(ptr, 0x04), 0x20) // String offset
                mstore(add(ptr, 0x24), 0x04) // Revert reason length
                mstore(add(ptr, 0x44), "AM22")
                revert(ptr, 0x48)
            }
        }
        (address from, address[] memory _localTokens, address[] memory _remoteTokens, uint256[] memory _amounts) = _receiveTokens(data);
        bytes32 _messageId = passMessage(from, buyBack, _localTokens, _remoteTokens, _amounts);
        emit BuyBackInitiated(_messageId);
        return true;
    }

    /**
    * @dev This function is called everytime a transferAndCall is attempted and the to parameter equal to this contract
    * 
    * @param from, address from which tokens are being transferred 
    * @param amount, amount of tokens being sent
    * @param data, calldata which contains the recipient of the transfer on the otherchain
    * @dev AM02, when no corresponding token is found for receiving the tokens
    * @dev AM03, when the input data size is not equal to 20 
    * @dev AM19, when the transferred amount is 0
    * 
    * @return bool if the transaction was successful 
    */
    function onTokenTransfer(
        address from,
        uint256 amount,
        bytes calldata data
    ) external override returns (bool) {
        require(data.length == 20, "AM03");
        require(amount > uint256(0), "AM19");
        address otherSideTokenAddress = _tokenMapping[msg.sender];
        require(otherSideTokenAddress != address(0), "AM02");
        (address[] memory _localTokenAddress, address[] memory _remoteTokenAddress, uint256[] memory _amounts) = (new address[](1), new address[](1), new uint256[](1));
        (_localTokenAddress[0], _remoteTokenAddress[0], _amounts[0]) = (msg.sender, otherSideTokenAddress, amount);
        passMessage(from, Bytes.bytesToAddress(data), _localTokenAddress, _remoteTokenAddress, _amounts);
        return true;
    }

    /**
    * @dev Transfers proper amount of tokens from one side of bridge to another
    * @param data BatchTokenBridge[] calldata Array of TokenBridge structs
    * @dev AM02 When address for the local token is not found
    * @dev AM10 When msg.sender is not the bridge contract
    * @dev AM15 When sender of the tokens to be bridged is different than the one of the first array element
    * @dev AM19 When value of element from batch is 0
    * @return (from, localTokens, remoteTokens, _amounts) 
    *     -from address Address of sender
    *     -localTokens address[] memory An array of addresses of local Tokens
    *     -remoteTokens address[] memory An array of addresses of remote tokens 
    *     -_amounts uint256[] memory Amounts of tokens to be transferred
    */
    function _receiveTokens(BatchTokenBridge[] calldata data) private checkLength(data.length) returns (address, address[] memory, address[] memory, uint256[] memory) {
        uint256 tokenBridged = data.length;
        (address[] memory localTokens, address[] memory remoteTokens, uint256[] memory _amounts) = (new address[](tokenBridged), new address[](tokenBridged), new uint256[](tokenBridged));
        address from = data[0].from;
        BatchTokenBridge calldata c;
        address otherSideAddress;
        address localToken;
        for (uint256 i; i < tokenBridged;) {
            c = data[i];
            require(c.to == address(this), "AM10");
            require(c.from == from, "AM15");
            require(c.value > uint256(0), "AM19");
            localToken = address(c.token);
            otherSideAddress = _tokenMapping[localToken];
            require(otherSideAddress != address(0), "AM02");
            c.token.transferWithAuthorization(c.from, c.to, c.value, c.validAfter, c.validBefore, c.nonce, c.v, c.r, c.s);
            (localTokens[i], remoteTokens[i], _amounts[i]) = (localToken, otherSideAddress, c.value);
            unchecked { ++i; }
        }
        return (from, localTokens, remoteTokens, _amounts);
    }

    /**
    * @dev modifier to check the length of a given array is lesser than a given maximum
    * @param len The length of the array
    *
    * @notice If the given length is greater than the maximum length (or zero) this reverts the transaction and prints AM04
    */
    modifier checkLength(uint256 len) {
        assembly {
            function printError(errorMsg) {
                let ptr := mload(0x40)
                mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(add(ptr, 0x04), 0x20) // string offset
                mstore(add(ptr, 0x24), 0x04) // revert reason length
                mstore(add(ptr, 0x44), errorMsg)
                revert(ptr, 0x48)
            }
            if iszero(len) {
                printError("AM04")
            }
            if gt(len, sload(_batchTokenBridgeLimit.slot)) {
                printError("AM04")
            }
        }
        _;
    }

    /**
    * @dev Checks if `keys` are valid token addresses and stores the valid addresses into `mapped`.
    * @param keys Array of token addresses to check.
    * @return mapped of the valid token values that were mapped from `keys`
    * @dev The array `mapped` is allocated on call and is the responsibility of the caller to free.
    * @dev Preconditions:
    *  1. 0 < `keys.length` <= `_batchTokenBridgeLimit`
    *  2. All `keys` address have a mapping in the `_tokenMapping` state variable.
    *  3.
    * @dev Postconditions:
    *  1. `mapped.length` == `keys.length`
    *  2. All mapped token addresses in `keys` are present and valid in `mapped`.
    * @dev AM02 When called with keys that do not have a mapping in the `_tokenMapping` state variable or if `mapped` is inaccessible.
    * @dev AM04 If the `keys.length` does not satisfy the preconditions.
    */
    function _checkTokens(address[] calldata keys) private view returns (address[] memory mapped) {
        assembly {
            let len := keys.length
            function allocate(length) -> pos {
                pos := mload(0x40)
                mstore(0x40, add(pos, length))
            }
            function printError(errorMsg) {
                let ptr := allocate(0x48)
                mstore(ptr, 0x08c379a000000000000000000000000000000000000000000000000000000000)
                mstore(add(ptr, 0x04), 0x20) // String offset
                mstore(add(ptr, 0x24), 0x04) // Revert reason length
                mstore(add(ptr, 0x44), errorMsg)
                revert(ptr, 0x48)
            }
            if iszero(len) {
                printError("AM04")
            }
            if gt(len, sload(_batchTokenBridgeLimit.slot)) {
                printError("AM04")
            }
            let dataStart := keys.offset
            mapped := allocate(add(0x20, mul(len, 0x20))) // allocate mapped memory
            mstore(mapped, len) // store array length
            let ptr := allocate(0x40)
            for {let i := 0} lt(i, len) {i := add(i, 1)} {
                mstore(ptr, calldataload(add(dataStart, mul(i, 0x20))))
                mstore(add(ptr, 0x20), _tokenMapping.slot)
                mstore(ptr, sload(keccak256(ptr, 0x40)))
                if iszero(mload(ptr)) {
                    printError("AM02")
                }
                // Store the value in the mapped array
                mstore(add(mapped, add(0x20, mul(0x20, i))), mload(ptr))
            }
        }
    }

    /**
    * @notice Passes payment with token denominations to a recipient through the bridge
    * @dev Encodes arguments and calls a function to pass the message to the bridge
    * @param _from Address of tokens sender 
    * @param _recipient Address of tokens recipient
    * @param _localTokens Array of addresses of tokens that are used to send the payment
    * @param _remoteTokens Array of address of tokens that the recipient will receive on the other chain
    * @param _amounts Array of amounts of tokens exchanged 
    * @return msgId bytes32 - The ID of the message sent by the bridge 
    */
    function passMessage(
        address _from,
        address _recipient,
        address[] memory _localTokens,
        address[] memory _remoteTokens,
        uint256[] memory _amounts
    ) override internal returns (bytes32) {
        bytes memory data = abi.encodeWithSelector(
            this.handleBridgedTokens.selector,
            _from,
            _recipient,
            _remoteTokens,
            _amounts
        );
        bytes32 msgId = bridgeContract().requireToPassMessage(
            address(this),
            data,
            requestGasLimit()
        );
        setMessageRecipient(msgId, _recipient);
        setMessageSender(msgId, _from);
        setMessageTokens(msgId, _localTokens);
        setMessageAmounts(msgId, _amounts);
        return msgId;
    }

    /**
    * @notice Passes payment with token denominations to a recipient through the bridge
    * @dev Encodes arguments and calls a function to pass the message to the bridge
    * @param _recipient Address of tokens recipient
    * @param _remoteTokens Array of address of tokens that the recipient will receive on the other chain
    * @param _amounts Array of amounts of tokens exchanged 
    */
    function passMessageVault(
        address _recipient,
        address[] memory _remoteTokens,
        uint256[] memory _amounts
    ) private {
        bytes memory data = abi.encodeWithSelector(
            this.handleBridgedTokensFromVault.selector,
            _recipient,
            _remoteTokens,
            _amounts);
        bridgeContract().requireToPassMessage(
            address(this),
            data,
            requestGasLimit()
        );
    }

    /**
     * @notice This function handles bridged tokens from one address to another.
     * @dev This function requires the `onlyMediator` modifier to be called. It takes in an address `from`, an address `recipient`, an array of addresses `tokens`, and an array of uint256 `amounts` as parameters. If the `from` address is the same as the `recipient` address, the `_whitelist` function is called with the `recipient` and `tokens` as parameters. A for loop is then used to iterate through the `tokens` array and the `_sendTokens` function is called with the `recipient`, `tokens[i]`, and `amounts[i]` as parameters.
     */
    function handleBridgedTokensFromVault(address recipient, address[] calldata tokens, uint256[] calldata amounts) external onlyMediator nonReentrant {
        bytes32 messageId = messageId();
        bool _success = _safeWhitelist(recipient, tokens);
        if (!_success) return saveVaultErrorState(messageId, recipient, tokens, amounts);
        uint256 tokenBridged = tokens.length;
        bytes memory transferData;
        bool transferSuccess;
        bytes memory returndata;
        bool transferDecodeResult;
        for (uint256 i; i < tokenBridged;) {
            transferData = abi.encodeWithSelector(IBridgeToken.transfer.selector, recipient, amounts[i]); 
            (transferSuccess, returndata) = Safe.functionCall(tokens[i], transferData, 0x20);
            if (!transferSuccess) return saveVaultErrorState(messageId, recipient, tokens[i:], amounts[i:]);
            transferDecodeResult = Safe.abiDecodeBoolean(returndata);
            if (!transferDecodeResult) return saveVaultErrorState(messageId, recipient, tokens[i:], amounts[i:]);
            unchecked { ++i; }
        }
    }

    function retryVaultIssue(bytes32 messageId) external nonReentrant {
        require(!isPropertyVaultFixed(messageId), "AM09");
        propertyVaultIssueFixed(messageId);
        (address recipient, address[] memory tokens, uint256[] memory amounts) = (propertyVaultRecipient(messageId), propertyVaultTokens(messageId), propertyVaultAmounts(messageId));
        uint256 tokenBridged = tokens.length;
        require(tokenBridged > 0, "AM00");
        _whitelist(recipient, tokens);
        for (uint256 i; i < tokenBridged;) {
            _sendTokens(recipient, tokens[i], amounts[i]);
            unchecked { ++i; }
        }
    }

    /**
     * @notice This function handles bridged tokens from one address to another.
     * @dev This function requires the `onlyMediator` modifier to be called. It takes in an address `from`, an address `recipient`, an array of addresses `tokens`, and an array of uint256 `amounts` as parameters. If the `from` address is the same as the `recipient` address, the `_whitelist` function is called with the `recipient` and `tokens` as parameters. A for loop is then used to iterate through the `tokens` array and the `_sendTokens` function is called with the `recipient`, `tokens[i]`, and `amounts[i]` as parameters.
     */
    function handleBridgedTokens(address from, address recipient, address[] calldata tokens, uint256[] calldata amounts) external onlyMediator {
        uint256 tokenBridged = tokens.length;
        if (from == recipient) _whitelist(recipient, tokens);
        for (uint256 i; i < tokenBridged;) {
            _sendTokens(recipient, tokens[i], amounts[i]);
            unchecked { ++i; }
        }
    }

    /**
     * @notice This function is used to send tokens from one address to another.
     * @dev This function requires the IBridgeToken contract to be passed in as an argument. It then calls the transfer function of the IBridgeToken contract to transfer the specified amount of tokens to the specified address. 
     */
    function _sendTokens(address to, address token, uint256 amount) private {
        require(IBridgeToken(token).transfer(to, amount), "AM05");
    }

    /**
     * @dev recover lost user funds
     * @param token token to recover
     * @param to address that will receive the tokens
     * @param amount amount to recover
     */
    function withdrawTokenByAdmin(
        IBridgeToken token,
        address to,
        uint256 amount
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(token.transfer(to, amount), "AM14");
    }

    /**
     * @dev recover lost user funds
     * @param messageId messageId to fix/resolve
     */
    function fixFailedMessageByAdmin(
        bytes32 messageId
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _fixFailedMessage(messageId);
        emit ManualFix(messageId);
    }

    /**
     * @dev Method to be called when a bridged message execution failed. It will generate a new message requesting to
     * fix/roll back the transferred assets on the other network.
     * @param _messageId id of the message which execution failed.
     */
    function requestFailedMessageFix(bytes32 _messageId) override external {
        require(!bridgeContract().messageCallStatus(_messageId), "AM11");
        require(
            bridgeContract().failedMessageReceiver(_messageId) == address(this), "AM12"
        );
        require(
            bridgeContract().failedMessageSender(_messageId) ==
                address(this), "AM13"
        );
        bytes memory data = abi.encodeWithSelector(this.fixFailedMessage.selector, _messageId);
        bridgeContract().requireToPassMessage(
            address(this),
            data,
            requestGasLimit()
        );
        emit FailedMessageRequest(_messageId);
    }

    /**
     * @dev Handles the request to fix transferred assets which bridged message execution failed on the other network.
     * It uses the information stored by passMessage method when the assets were initially transferred
     * @param _messageId id of the message which execution failed on the other network.
     */
    function fixFailedMessage(bytes32 _messageId) override external onlyMediator {
        _fixFailedMessage(_messageId);
    }

    function _fixFailedMessage(bytes32 _messageId) private {
        require(!messageFixed(_messageId), "AM09");
        setMessageFixed(_messageId);
        (address[] memory tokens, uint256[] memory amounts, address sender, address recipient) = (messageTokens(_messageId), messageAmounts(_messageId), messageSender(_messageId), messageRecipient(_messageId));
        uint256 len = tokens.length;
        require(len > 0, "AM00");
        if (sender == recipient) _whitelist(sender, tokens);
        for (uint256 i; i < len;) {
            _sendTokens(sender, tokens[i], amounts[i]);
            unchecked { ++i; }
        }
    }

    /**
    * @notice Set the remote token address corresponding to a given local token address.
    * @dev Only operators or create2 contract can call this function 
    * @param localToken {address} The local token address
    * @param remoteToken {address} The remote token address corresponding to the local token
    * @return {bool} Whether the remote token address was set successfully
    **/
    function setToken(
        address localToken,
        address remoteToken
    )
        external returns (bool)
    {
        require(hasRole(CREATE2_ROLE, msg.sender) || hasRole(OPERATOR_ROLE, msg.sender), "AM24");
        _tokenMapping[localToken] = remoteToken;
        emit TokenSet(localToken, remoteToken);
        return true;
    }

    /**
    * @notice Set the set of remote token addresses corresponding to a given set of local token addresses.
    * @dev Only operators can call this function
    * @param _localTokenList {address[]} The list of local token addresses
    * @param _remoteTokenList {address[]} The list of remote token addresses
    **/
    function setTokens(
        address[] calldata _localTokenList,
        address[] calldata _remoteTokenList
    )
        external
        onlyRole(OPERATOR_ROLE)
    {
        uint256 length = _localTokenList.length;
        require(length == _remoteTokenList.length, "AM16");
        for (uint256 i; i < length;) {
            _tokenMapping[_localTokenList[i]] = _remoteTokenList[i];
            unchecked { ++i; }
        }
        emit TokenListSet(_localTokenList, _remoteTokenList);
    }

    /**
    * @notice Set the property vault address.
    * @dev Only operators can call this function
    * @param newPropertyVault
    **/
    function setPropertyVault(
        address newPropertyVault
    )
        external
        onlyRole(OPERATOR_ROLE)
    {
        assembly {
            sstore(_propertyVault.slot, newPropertyVault)
        }
    }

    /**
    * @notice Set the buyback address.
    * @dev Only operators can call this function
    * @param newBuyBack
    **/
    function setBuyBack(
        address newBuyBack
    )
        external
        onlyRole(OPERATOR_ROLE)
    {
        assembly {
            sstore(_buyBack.slot, newBuyBack)
        }
    }

    /**
     * @notice This function returns the address of the token mapping for a given local token list.
     * @dev This function is used to get the address of the token mapping for a given local token list. It takes in an address of the local token list as an argument and returns the address of the token mapping. 
     */
    function getTokenMapping(
        address _localTokenList
    ) external view returns (address) {
        return _tokenMapping[_localTokenList];
    }

    /**
    * @notice Get the address of the PropertyVault
    * @dev This function returns the address of the PropertyVault
    * @return address - The address of the PropertyVault 
    */
    function getPropertyVault() external view returns (address) {
        return _propertyVault;
    }

    /**
    * @notice Get the address of the BuyBack contract 
    * @dev This function returns the address of the BuyBack contract 
    * @return address - The address of the BuyBack contract 
    */
    function getBuyBack() external view returns (address) {
        return _buyBack;
    }

    /* solhint-disable no-empty-blocks */
    /**
     * @notice This function allows the DEFAULT_ADMIN_ROLE to authorize an upgrade to a new implementation.
     * @dev This function should only be called by the DEFAULT_ADMIN_ROLE.
     */
    function _authorizeUpgrade(address /*newImplementation*/) override internal onlyRole(DEFAULT_ADMIN_ROLE) {}

    function _authAMB() override internal onlyRole(DEFAULT_ADMIN_ROLE) {}

    function _authWhitelist() override internal onlyRole(DEFAULT_ADMIN_ROLE) {}
    /* solhint-enable no-empty-blocks */
}

// ============================================================================
// FILE: contracts/Safe.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

// This library enables reentrancy, please protect with a nonReentrant
library Safe {
    uint256 private constant TRUE = 0x0000000000000000000000000000000000000000000000000000000000000001;

    function functionCall(
        address target,
        bytes memory data,
        uint256 expectedLength
    ) internal returns (bool, bytes memory) {
        (bool success, bytes memory returndata) = target.call{value: 0}(data);
        return verifyCallResultFromTarget(success, returndata, expectedLength);
    }

    function functionStaticCall(
        address target,
        bytes memory data,
        uint256 expectedLength
    ) internal view returns (bool, bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(success, returndata, expectedLength);
    }

    function verifyCallResultFromTarget(
        bool success,
        bytes memory returndata,
        uint256 expectedLength
    ) internal pure returns (bool, bytes memory) {
        return (success && returndata.length == expectedLength, returndata);
    }

    function abiDecodeUint256Address(
        bytes memory returndata
    ) internal pure returns (bool b, uint256 u, address a) {
        assembly {
            let _address := mload(add(returndata, 0x40))
            if lt(_address, 0x0000000000000000000000010000000000000000000000000000000000000000) {
                b := TRUE
                u := mload(add(returndata, 0x20))
                a := _address
            }
        }
    }

    function abiDecodeBoolean(
        bytes memory returndata
    ) internal pure returns (bool b) {
        assembly {
            let test := mload(add(returndata, 0x20))
            if lt(test, 0x0000000000000000000000000000000000000000000000000000000000000002) {
                b := test
            }
        }
    }

    function abiDecodeUint256Array(
        bytes memory returndata,
        uint256 expectedLength
    ) internal pure returns (bool b) {
        assembly {
            if and(eq(mload(add(returndata, 0x20)), 0x0000000000000000000000000000000000000000000000000000000000000020), eq(mload(add(returndata, 0x40)), expectedLength)) {
                b := TRUE
            }
        }
    }
}

// ============================================================================
// FILE: contracts/WhitelistExecutor.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity 0.8.18;

import { IGnosisSafe } from "./interfaces/IGnosisSafe.sol";
import { Enum } from "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";
import { IComplianceRegistry } from "./interfaces/IComplianceRegistry.sol";
import { IBridgeToken } from "./interfaces/IBridgeToken.sol";
import { Safe } from "./Safe.sol";

abstract contract WhitelistExecutor {
    bytes4 private constant UPDATE_USER = IComplianceRegistry.updateUserAttributes.selector;
    bytes4 private constant REGISTER_USER = IComplianceRegistry.registerUser.selector;
    address private _trustedIntermediary;
    IComplianceRegistry private _complianceRegistry;

    event TrustedIntermediaryUpdated(address newTrustedIntermediary);
    event ComplianceRegistryUpdated(IComplianceRegistry newComplianceRegistry);

    // solhint-disable-next-line func-name-mixedcase
    function __Whitelist_init(address trustedIntermediary_, address complianceRegistry_) internal {
        _trustedIntermediary = trustedIntermediary_;
        _complianceRegistry = IComplianceRegistry(complianceRegistry_);
        emit TrustedIntermediaryUpdated(trustedIntermediary_);
        emit ComplianceRegistryUpdated(IComplianceRegistry(complianceRegistry_));
    }

    function _contractSignature() private view returns (bytes memory s) {
        assembly {
            s := mload(0x40)
            mstore(0x40, add(s, 0x61))
            mstore(s, 0x41)
            mstore(add(s, 0x20), address())
            mstore(add(s, 0x41), 0x01)
        }
    }

 /// @param account user address
  /// @param tokens tokens addresses to whitelist
  function _whitelist(address account, address[] memory tokens) internal {
    (uint256[] memory tokenIds, uint256[] memory attributeValues, bool shouldRegister) = _getTokenIds(tokens, tokens.length);
    uint256 length = tokenIds.length;
    if (length == 0 && !shouldRegister) return;
    address trusted = _trustedIntermediary;
    address[] memory intermediaries = new address[](1);
    intermediaries[0] = trusted;
    IComplianceRegistry compliance = _complianceRegistry;
    // Check if the user is already registered
    (uint256 userId,) = compliance.userId(intermediaries, account);
    // If the user is not registered, register the user with tokenIds and attributeValues
    if (userId == 0) {
      _staticRegisterUser(account, tokenIds, attributeValues, trusted, address(compliance));
    } else if (length > 0) {
      uint256[] memory isWhitelistedValues = compliance.attributes(trusted, userId, tokenIds);
      for (uint256 i; i < length;) {
        if (isWhitelistedValues[i] == 0) {
          _staticUpdateUserAttributes(userId, tokenIds, attributeValues, trusted, address(compliance));
          return;
        }
        unchecked { ++i; }
      }
    }
  }

    function _registerUpdateUser(address account, uint256[] memory tokenIds, uint256[] memory attributeValues, uint256 userId, address trusted, address compliance) private returns (bool) {
      uint256 length = tokenIds.length;
      if (userId == 0) {
        return _safeRegisterUser(account, tokenIds, attributeValues, trusted, address(compliance));
      } else if (length > 0) {
        (bool successAttributes, bytes memory returndata) = Safe.functionStaticCall(address(compliance), abi.encodeWithSelector(IComplianceRegistry.attributes.selector, trusted, userId, tokenIds), 0x40 + 0x20 * length);
        if (!successAttributes) return false;
        bool canDecodeSafely = Safe.abiDecodeUint256Array(returndata, length);
        if (!canDecodeSafely) return false;
        uint256[] memory isWhitelistedValues = abi.decode(returndata, (uint256[]));
        for (uint256 i; i < length;) {
          if (isWhitelistedValues[i] == 0) {
            return _safeUpdateUserAttributes(userId, tokenIds, attributeValues, trusted, address(compliance));
          }
          unchecked { ++i; }
        }
        return true;
      } else {
        return true;
      }
    }
    /// @param account user address
    /// @param tokens tokens addresses to whitelist
    function _safeWhitelist(address account, address[] memory tokens) internal returns (bool) {
      (bool successTokenIds, uint256[] memory tokenIds, uint256[] memory attributeValues, bool shouldRegister) = _safeGetTokenIds(tokens, tokens.length);
      if (!successTokenIds) return false;
      if (tokenIds.length == 0 && !shouldRegister) return true;
      address trusted = _trustedIntermediary;
      address[] memory intermediaries = new address[](1);
      intermediaries[0] = trusted;
      IComplianceRegistry compliance = _complianceRegistry;
      // Check if the user is already registered
      (bool userIdSuccess, bytes memory result) = Safe.functionStaticCall(address(compliance), abi.encodeWithSelector(IComplianceRegistry.userId.selector, intermediaries, account), 0x40);
      if (!userIdSuccess) return false;
      (bool decodeSafe, uint256 userId,) = Safe.abiDecodeUint256Address(result);
      if (!decodeSafe) return false;
      // If the user is not registered, register the user with tokenIds and attributeValues
      return _registerUpdateUser(account, tokenIds, attributeValues, userId, trusted, address(compliance));
    }

 /**
    * @notice Update a user's attribute keys or values in the contract
    * @dev Submits a transaction to the trustedIntermediary to query for the user's attributes. 
    * @param _userId The user id to be updated
    * @param _attributeKeys The array of attribute keys for the user, indexed by the attribute index
    * @param _attributeValues The array of attribute values for the user, indexed by the attribute index
    * @param trusted The address of the trusted intermediary contract 
    * @param compliance The address of the compliance contract
    */
    function _safeUpdateUserAttributes(
    uint256 _userId, 
    uint256[] memory _attributeKeys, 
    uint256[] memory _attributeValues,
    address trusted,
    address compliance
  ) private returns (bool) {
    bytes memory encodedUpdateUserSelector = abi.encodeWithSelector(UPDATE_USER, _userId, _attributeKeys, _attributeValues);
    bytes memory execTransaction = abi.encodeWithSelector(IGnosisSafe.execTransaction.selector, compliance,0,encodedUpdateUserSelector,Enum.Operation.Call,0,0,0,address(0),payable(address(0)),_contractSignature());
    (bool s,) = Safe.functionCall(trusted, execTransaction, 0x20);
    return s;
  }

  /**
  * @notice Register an address to the contract as a user.
  * @dev Submits a transaction to the trustedIntermediary to registger a user. 
  * @param _address The address of the user to be registered
  * @param _attributeKeys The array of attribute keys for the user, indexed by the attribute index
  * @param _attributeValues The array of attribute values for the user, indexed
  * @param trusted The address of the trusted intermediary contract 
  * @param compliance The address of the compliance contract
  */
  function _safeRegisterUser(
    address _address,
    uint256[] memory _attributeKeys,
    uint256[] memory _attributeValues,
    address trusted,
    address compliance
  ) private returns (bool) {
    bytes memory encodedRegisterSelector = abi.encodeWithSelector(REGISTER_USER, _address, _attributeKeys, _attributeValues);
    bytes memory execTransaction = abi.encodeWithSelector(IGnosisSafe.execTransaction.selector, compliance,0,encodedRegisterSelector,Enum.Operation.Call,0,0,0,address(0),payable(address(0)),_contractSignature());
    (bool success,) = Safe.functionCall(trusted, execTransaction, 0x20);
    return success;
  }

    /**
    * @notice Update a user's attribute keys or values in the contract
    * @dev Submits a transaction to the trustedIntermediary to query for the user's attributes. 
    * @param _userId The user id to be updated
    * @param _attributeKeys The array of attribute keys for the user, indexed by the attribute index
    * @param _attributeValues The array of attribute values for the user, indexed by the attribute index
    * @param trusted The address of the trusted intermediary contract 
    * @param compliance The address of the compliance contract
    */
    function _staticUpdateUserAttributes(
    uint256 _userId, 
    uint256[] memory _attributeKeys, 
    uint256[] memory _attributeValues,
    address trusted,
    address compliance
  ) private {
    bytes memory encodedUpdateUserSelector = abi.encodeWithSelector(UPDATE_USER, _userId, _attributeKeys, _attributeValues);
    _execTransaction(IGnosisSafe(trusted),compliance,0,encodedUpdateUserSelector,Enum.Operation.Call,0,0,0,address(0),payable(address(0)),_contractSignature());
  }

  /**
  * @notice Register an address to the contract as a user.
  * @dev Submits a transaction to the trustedIntermediary to registger a user. 
  * @param _address The address of the user to be registered
  * @param _attributeKeys The array of attribute keys for the user, indexed by the attribute index
  * @param _attributeValues The array of attribute values for the user, indexed
  * @param trusted The address of the trusted intermediary contract 
  * @param compliance The address of the compliance contract
  */
  function _staticRegisterUser(
    address _address,
    uint256[] memory _attributeKeys,
    uint256[] memory _attributeValues,
    address trusted,
    address compliance
  ) private {
    bytes memory encodedRegisterSelector = abi.encodeWithSelector(REGISTER_USER, _address, _attributeKeys, _attributeValues);
    _execTransaction(IGnosisSafe(trusted),compliance,0,encodedRegisterSelector,Enum.Operation.Call,0,0,0,address(0),payable(address(0)),_contractSignature());
  }

  /**
   * @notice Executes a transaction on the Gnosis Safe contract.
   * @dev This function is used to execute a transaction on the Gnosis Safe contract.
   * @param target The Gnosis Safe contract instance.
   * @param to The address to send the transaction to.
   * @param value The amount of Ether to send.
   * @param data The data to send with the transaction.
   * @param operation The type of operation to execute.
   * @param safeTxGas The amount of gas to use for the transaction.
   * @param baseGas The base amount of gas to use for the transaction.
   * @param gasPrice The gas price to use for the transaction.
   * @param gasToken The address of the token to use for the gas.
   * @param refundReceiver The address to receive any refunds.
   * @param signatures The signatures required to execute the transaction.
   */
  function _execTransaction(
    IGnosisSafe target,
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes memory signatures
  ) private {
    require(target.execTransaction(
      to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures
    ), "AM20");
  }

  function _getTokenIds(address[] memory tokens, uint256 length) private view returns (uint256[] memory, uint256[] memory, bool) {
    uint256[] memory tokenIds = new uint256[](length);
    uint256[] memory attributeValues = new uint256[](length);
    uint256 ruleNumber;
    uint256 tokenId;
    bool shouldRegister;
    uint256 y;
    for (uint256 i; i < length;) { 
      (ruleNumber, tokenId) = IBridgeToken(tokens[i]).rule(0); // token address => tokenId (attributeKeys)
      // Rule 11: User Attribute Valid Rule
      // Rule 1: User Freeze Rule
      // https://github.com/MtPelerin/bridge-v2/blob/master/docs/RuleEngine.md#rules-index
      if (ruleNumber == 1) {
        if (tokenId == 0) shouldRegister = true;
      } else {
        require(ruleNumber == 11, "PV17");
        (tokenIds[y], attributeValues[y]) = (tokenId, 1);
        unchecked { ++y; }
      }
      unchecked { ++i; }
    }
    assembly { // resize down array
      mstore(tokenIds, y)
      mstore(attributeValues, y)
    }
    return (tokenIds, attributeValues, shouldRegister);
  }

  function _safeGetTokenIds(address[] memory tokens, uint256 length) private view returns (bool, uint256[] memory, uint256[] memory, bool) {
    uint256[] memory tokenIds = new uint256[](length);
    uint256[] memory attributeValues = new uint256[](length);
    uint256 ruleNumber;
    uint256 tokenId;
    bool success;
    bool shouldRegister;
    uint256 y;
    bytes memory returndata;
    for (uint256 i; i < length;) { 
      (success, returndata) = Safe.functionStaticCall(tokens[i], abi.encodeWithSelector(IBridgeToken.rule.selector, 0), 0x40);
      if (!success) return (false, tokenIds, attributeValues, shouldRegister);
      (ruleNumber, tokenId) = abi.decode(returndata, (uint256, uint256));
      // Rule 11: User Attribute Valid Rule
      // https://github.com/MtPelerin/bridge-v2/blob/master/docs/RuleEngine.md#rules-index
      if (ruleNumber == 1) {
        if (tokenId == 0) shouldRegister = true;
      } else {
        if (ruleNumber != 11) return (false, tokenIds, attributeValues, shouldRegister);
        (tokenIds[y], attributeValues[y]) = (tokenId, 1);
        unchecked { ++y; }
      }
      unchecked { ++i; }
    }
    assembly { // resize down array
      mstore(tokenIds, y)
      mstore(attributeValues, y)
    }
    return (true, tokenIds, attributeValues, shouldRegister);
  }

  /// @param trustedIntermediary_ new address of trustedIntermediary in case of modifying KYC operator
  function setTrustedIntermediary(address trustedIntermediary_) external {
    _authWhitelist();
    _trustedIntermediary = trustedIntermediary_;
    emit TrustedIntermediaryUpdated(trustedIntermediary_);
  }

  /// @return _trustedIntermediary the address of GnosisSafe wallet which is the KYC operator
  function trustedIntermediary() external view returns (address) {
    return _trustedIntermediary;
  }

  /// @param complianceRegistry_ new address of complianceRegistry
  function setComplianceRegistry(IComplianceRegistry complianceRegistry_) external {
    _authWhitelist();
    _complianceRegistry = complianceRegistry_;
    emit ComplianceRegistryUpdated(complianceRegistry_);
  }

  /// @return _complianceRegistry ComplianceRegistry contract 
  function complianceRegistry() external view returns (IComplianceRegistry) {
    return _complianceRegistry;
  }

  /// @return contractSignature which is the signature of the contract to sign execTransaction 
  function contractSignature() external view returns (bytes memory) {
    return _contractSignature();
  }

  /**
   * @notice This function is used to authorize whitelisted addresses to access the contract.
   * @dev This function is used to authorize whitelisted addresses to access the contract. It is called by the owner of the contract to add or remove addresses from the whitelist.
   */
  function _authWhitelist() internal virtual;

  /**
   * @dev This empty reserved space is put in place to allow future versions to add new
   * variables without shifting down storage in the inheritance chain.
   * See https://docs.openzeppelin.com/contracts/4.x/upgradeable#storage_gaps
   */
  uint256[48] private __gap;
}