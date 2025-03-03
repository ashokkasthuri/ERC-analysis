// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.10;

import {ERC20} from "solmate/tokens/ERC20.sol";
import {ERC4626} from "solmate/mixins/ERC4626.sol";
import {AccessControl} from "openzeppelin-contracts/access/AccessControl.sol";
import {Constants as C} from "./lib/Constants.sol";
import {
    CallerNotAdmin,
    CallerNotKeeper,
    ZeroAddress,
    InvalidFlashLoanCaller,
    TreasuryCannotBeZero,
    FeesTooHigh,
    InvalidFloatPercentage,
    InvalidSlippageTolerance
} from "./errors/scErrors.sol";

abstract contract sc4626 is ERC4626, AccessControl {
    constructor(address _admin, address _keeper, ERC20 _asset, string memory _name, string memory _symbol)
        ERC4626(_asset, _name, _symbol)
    {
        if (_admin == address(0)) revert ZeroAddress();
        if (_keeper == address(0)) revert ZeroAddress();

        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(KEEPER_ROLE, _keeper);
    }

    event TreasuryUpdated(address indexed user, address newTreasury);
    event PerformanceFeeUpdated(address indexed user, uint256 newPerformanceFee);
    event FloatPercentageUpdated(address indexed user, uint256 newFloatPercentage);
    event SlippageToleranceUpdated(address indexed admin, uint256 newSlippageTolerance);

    /// Role allowed to harvest/reinvest
    bytes32 public constant KEEPER_ROLE = keccak256("KEEPER_ROLE");

    // flag for checking flash loan caller
    bool public flashLoanInitiated;

    // address of the treasury to send performance fees to
    address public treasury;

    // performance fee percentage
    uint256 public performanceFee = 0.1e18; // 10%

    // percentage of the total assets to be kept in the vault as a withdrawal buffer
    uint256 public floatPercentage = 0.01e18;

    // max slippage tolerance for swaps
    uint256 public slippageTolerance = 0.99e18; // 1% default

    /// @notice set the treasury address
    /// @param _newTreasury the new treasury address
    function setTreasury(address _newTreasury) external {
        _onlyAdmin();

        if (_newTreasury == address(0)) revert TreasuryCannotBeZero();
        treasury = _newTreasury;
        emit TreasuryUpdated(msg.sender, _newTreasury);
    }

    /// @notice set the performance fee percentage
    /// @param _newPerformanceFee the new performance fee percentage
    /// @dev performance fee is a number between 0 and 1e18
    function setPerformanceFee(uint256 _newPerformanceFee) external {
        _onlyAdmin();

        if (_newPerformanceFee > 1e18) revert FeesTooHigh();
        performanceFee = _newPerformanceFee;
        emit PerformanceFeeUpdated(msg.sender, _newPerformanceFee);
    }

    /**
     * @notice Set the percentage of the total assets to be kept in the vault as a withdrawal buffer.
     * @param _newFloatPercentage The new float percentage value.
     */
    function setFloatPercentage(uint256 _newFloatPercentage) external {
        _onlyAdmin();

        if (_newFloatPercentage > C.ONE) revert InvalidFloatPercentage();

        floatPercentage = _newFloatPercentage;
        emit FloatPercentageUpdated(msg.sender, _newFloatPercentage);
    }

    /**
     * @notice Set the default slippage tolerance for swapping tokens.
     * @param _newSlippageTolerance The new slippage tolerance value.
     */
    function setSlippageTolerance(uint256 _newSlippageTolerance) external {
        _onlyAdmin();

        if (_newSlippageTolerance > C.ONE) revert InvalidSlippageTolerance();

        slippageTolerance = _newSlippageTolerance;

        emit SlippageToleranceUpdated(msg.sender, _newSlippageTolerance);
    }

    function _onlyAdmin() internal view {
        if (!hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) revert CallerNotAdmin();
    }

    function _onlyKeeper() internal view {
        if (!hasRole(KEEPER_ROLE, msg.sender)) revert CallerNotKeeper();
    }

    function _onlyKeeperOrFlashLoan() internal view {
        if (!flashLoanInitiated) _onlyKeeper();
    }

    function _initiateFlashLoan() internal {
        flashLoanInitiated = true;
    }

    function _finalizeFlashLoan() internal {
        flashLoanInitiated = false;
    }

    function _isFlashLoanInitiated() internal view {
        if (!flashLoanInitiated) revert InvalidFlashLoanCaller();
    }
}


// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Modern and gas efficient ERC20 + EIP-2612 implementation.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/tokens/ERC20.sol)
/// @author Modified from Uniswap (https://github.com/Uniswap/uniswap-v2-core/blob/master/contracts/UniswapV2ERC20.sol)
/// @dev Do not manually set balances without updating totalSupply, as the sum of all user balances must not exceed it.
abstract contract ERC20 {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Transfer(address indexed from, address indexed to, uint256 amount);

    event Approval(address indexed owner, address indexed spender, uint256 amount);

    /*//////////////////////////////////////////////////////////////
                            METADATA STORAGE
    //////////////////////////////////////////////////////////////*/

    string public name;

    string public symbol;

    uint8 public immutable decimals;

    /*//////////////////////////////////////////////////////////////
                              ERC20 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;

    mapping(address => mapping(address => uint256)) public allowance;

    /*//////////////////////////////////////////////////////////////
                            EIP-2612 STORAGE
    //////////////////////////////////////////////////////////////*/

    uint256 internal immutable INITIAL_CHAIN_ID;

    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    mapping(address => uint256) public nonces;

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(
        string memory _name,
        string memory _symbol,
        uint8 _decimals
    ) {
        name = _name;
        symbol = _symbol;
        decimals = _decimals;

        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = computeDomainSeparator();
    }

    /*//////////////////////////////////////////////////////////////
                               ERC20 LOGIC
    //////////////////////////////////////////////////////////////*/

    function approve(address spender, uint256 amount) public virtual returns (bool) {
        allowance[msg.sender][spender] = amount;

        emit Approval(msg.sender, spender, amount);

        return true;
    }

    function transfer(address to, uint256 amount) public virtual returns (bool) {
        balanceOf[msg.sender] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(msg.sender, to, amount);

        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public virtual returns (bool) {
        uint256 allowed = allowance[from][msg.sender]; // Saves gas for limited approvals.

        if (allowed != type(uint256).max) allowance[from][msg.sender] = allowed - amount;

        balanceOf[from] -= amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(from, to, amount);

        return true;
    }

    /*//////////////////////////////////////////////////////////////
                             EIP-2612 LOGIC
    //////////////////////////////////////////////////////////////*/

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual {
        require(deadline >= block.timestamp, "PERMIT_DEADLINE_EXPIRED");

        // Unchecked because the only math done is incrementing
        // the owner's nonce which cannot realistically overflow.
        unchecked {
            address recoveredAddress = ecrecover(
                keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
                                ),
                                owner,
                                spender,
                                value,
                                nonces[owner]++,
                                deadline
                            )
                        )
                    )
                ),
                v,
                r,
                s
            );

            require(recoveredAddress != address(0) && recoveredAddress == owner, "INVALID_SIGNER");

            allowance[recoveredAddress][spender] = value;
        }

        emit Approval(owner, spender, value);
    }

    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == INITIAL_CHAIN_ID ? INITIAL_DOMAIN_SEPARATOR : computeDomainSeparator();
    }

    function computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                    keccak256(bytes(name)),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL MINT/BURN LOGIC
    //////////////////////////////////////////////////////////////*/

    function _mint(address to, uint256 amount) internal virtual {
        totalSupply += amount;

        // Cannot overflow because the sum of all user
        // balances can't exceed the max uint256 value.
        unchecked {
            balanceOf[to] += amount;
        }

        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal virtual {
        balanceOf[from] -= amount;

        // Cannot underflow because a user's balance
        // will never be larger than the total supply.
        unchecked {
            totalSupply -= amount;
        }

        emit Transfer(from, address(0), amount);
    }
}