// SPDX-License-Identifier: UNLICENSED
// Source: 0xd7298f620b0f752cf41bd818a16c756d9dcaa34f
// Contract Name: DistributionVault
// Generated on: 2026-05-14 12:00:37


// ============================================================================
// FILE: lib/ttg/src/DistributionVault.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC20 } from "../lib/common/src/interfaces/IERC20.sol";

import { StatefulERC712 } from "../lib/common/src/StatefulERC712.sol";

import { ERC20Helper } from "../lib/erc20-helper/src/ERC20Helper.sol";

import { PureEpochs } from "./libs/PureEpochs.sol";

import { IERC6372 } from "./abstract/interfaces/IERC6372.sol";

import { IZeroToken } from "./interfaces/IZeroToken.sol";
import { IDistributionVault } from "./interfaces/IDistributionVault.sol";

/**
 * @title  A contract enabling pro rata distribution of arbitrary tokens to holders of the Zero Token.
 * @author M^0 Labs
 */
contract DistributionVault is IDistributionVault, StatefulERC712 {
    /* ============ Variables ============ */

    /**
     * @dev The scale to apply when accumulating an account's claimable token, per epoch, before dividing.
     *      It is arbitrarily set to `1e9`. The smaller it is, the more dust will accumulate in the contract.
     *      Conversely, the larger it is, the more likely it is to overflow when accumulating.
     *      The more epochs that are claimed at once, the less dust will remain.
     */
    uint256 internal constant _GRANULARITY = 1e9;

    // solhint-disable-next-line max-line-length
    // keccak256("Claim(address account,address token,uint256 startEpoch,uint256 endEpoch,address destination,uint256 nonce,uint256 deadline)")
    /// @inheritdoc IDistributionVault
    bytes32 public constant CLAIM_TYPEHASH = 0x4b4633c3c305de33d5d9cf70f2712f26961648cd68d020c2556a9e43be58051d;

    /// @inheritdoc IDistributionVault
    address public immutable zeroToken;

    /// @dev The last recorded balance per token.
    mapping(address token => uint256 balance) internal _lastTokenBalances;

    /// @inheritdoc IDistributionVault
    mapping(address token => mapping(uint256 epoch => uint256 amount)) public distributionOfAt;

    /// @inheritdoc IDistributionVault
    mapping(address token => mapping(uint256 epoch => mapping(address account => bool claimed))) public hasClaimed;

    /* ============ Constructor ============ */

    /**
     * @notice Constructs a new DistributionVault contract.
     * @param  zeroToken_ The address of the Zero Token contract.
     */
    constructor(address zeroToken_) StatefulERC712("DistributionVault") {
        if ((zeroToken = zeroToken_) == address(0)) revert InvalidZeroTokenAddress();
    }

    /* ============ Interactive Functions ============ */

    /// @inheritdoc IDistributionVault
    function claim(
        address token_,
        uint256 startEpoch_,
        uint256 endEpoch_,
        address destination_
    ) external returns (uint256) {
        return _claim(msg.sender, token_, startEpoch_, endEpoch_, destination_);
    }

    /// @inheritdoc IDistributionVault
    function claimBySig(
        address account_,
        address token_,
        uint256 startEpoch_,
        uint256 endEpoch_,
        address destination_,
        uint256 deadline_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external returns (uint256) {
        unchecked {
            // NOTE: Need to cache to avoid stack too deep error.
            uint256 nonce_ = nonces[account_];

            _revertIfInvalidSignature(
                account_,
                getClaimDigest(account_, token_, startEpoch_, endEpoch_, destination_, nonce_, deadline_),
                v_,
                r_,
                s_
            );

            nonces[account_] = nonce_ + 1; // Nonce realistically cannot overflow.
        }

        _revertIfExpired(deadline_);

        return _claim(account_, token_, startEpoch_, endEpoch_, destination_);
    }

    /// @inheritdoc IDistributionVault
    function claimBySig(
        address account_,
        address token_,
        uint256 startEpoch_,
        uint256 endEpoch_,
        address destination_,
        uint256 deadline_,
        bytes memory signature_
    ) external returns (uint256) {
        unchecked {
            // NOTE: Need to cache to avoid stack too deep error.
            uint256 nonce_ = nonces[account_];

            _revertIfInvalidSignature(
                account_,
                getClaimDigest(account_, token_, startEpoch_, endEpoch_, destination_, nonce_, deadline_),
                signature_
            );

            nonces[account_] = nonce_ + 1; // Nonce realistically cannot overflow.
        }

        _revertIfExpired(deadline_);

        return _claim(account_, token_, startEpoch_, endEpoch_, destination_);
    }

    /// @inheritdoc IDistributionVault
    function distribute(address token_) external returns (uint256 amount_) {
        uint256 currentEpoch_ = clock();
        amount_ = getDistributable(token_);

        emit Distribution(token_, currentEpoch_, amount_);

        unchecked {
            // NOTE: Can be done unchecked because a token's total supply fits in a `uint256`.
            distributionOfAt[token_][currentEpoch_] += amount_; // Add to the distribution for the current epoch.
            _lastTokenBalances[token_] += amount_; // Track this contract's latest balance.
        }
    }

    /* ============ View/Pure Functions ============ */

    /// @inheritdoc IDistributionVault
    function name() external view returns (string memory) {
        return _name;
    }

    /// @inheritdoc IERC6372
    function CLOCK_MODE() external pure returns (string memory) {
        return PureEpochs.clockMode();
    }

    /// @inheritdoc IDistributionVault
    function getClaimDigest(
        address account_,
        address token_,
        uint256 startEpoch_,
        uint256 endEpoch_,
        address destination_,
        uint256 nonce_,
        uint256 deadline_
    ) public view returns (bytes32) {
        return
            _getDigest(
                keccak256(
                    abi.encode(
                        CLAIM_TYPEHASH,
                        account_,
                        token_,
                        startEpoch_,
                        endEpoch_,
                        destination_,
                        nonce_,
                        deadline_
                    )
                )
            );
    }

    /// @inheritdoc IERC6372
    function clock() public view returns (uint48) {
        return uint48(PureEpochs.currentEpoch());
    }

    /// @inheritdoc IDistributionVault
    function getClaimable(
        address token_,
        address account_,
        uint256 startEpoch_,
        uint256 endEpoch_
    ) public view returns (uint256 claimable_) {
        uint256 currentEpoch_ = clock();

        if (endEpoch_ >= currentEpoch_) revert NotPastTimepoint(endEpoch_, currentEpoch_); // Range must be past epochs.

        // Starting must be before or same as end epoch.
        if (startEpoch_ > endEpoch_) revert StartEpochAfterEndEpoch(startEpoch_, endEpoch_);

        uint256[] memory balances_ = IZeroToken(zeroToken).pastBalancesOf(account_, startEpoch_, endEpoch_);
        uint256[] memory totalSupplies_ = IZeroToken(zeroToken).pastTotalSupplies(startEpoch_, endEpoch_);
        uint256 epochCount_ = endEpoch_ - startEpoch_ + 1;

        for (uint256 index_; index_ < epochCount_; ++index_) {
            uint256 balance_ = balances_[index_];

            // Skip epochs with no Zero token balance (i.e. no distribution).
            if (balance_ == 0) continue;

            unchecked {
                if (hasClaimed[token_][startEpoch_ + index_][account_]) continue;
            }

            // Scale the amount by `_GRANULARITY` to avoid some amount of truncation while accumulating.
            claimable_ +=
                (distributionOfAt[token_][startEpoch_ + index_] * balance_ * _GRANULARITY) /
                totalSupplies_[index_];
        }

        unchecked {
            // Divide the accumulated amount by `_GRANULARITY` to get the actual claimable amount.
            return claimable_ / _GRANULARITY;
        }
    }

    /// @inheritdoc IDistributionVault
    function getDistributable(address token_) public view returns (uint256) {
        return IERC20(token_).balanceOf(address(this)) - _lastTokenBalances[token_];
    }

    /* ============ Internal Interactive Functions ============ */

    /**
     * @dev    Allows a caller to claim `token_` distribution between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  account_     The address of the account claiming the token.
     * @param  token_       The address of the token being claimed.
     * @param  startEpoch_  The starting epoch number as a clock value.
     * @param  endEpoch_    The ending epoch number as a clock value.
     * @param  destination_ The address the account where the claimed token will be sent.
     * @return claimed_     The total amount of token claimed by `account_`.
     */
    function _claim(
        address account_,
        address token_,
        uint256 startEpoch_,
        uint256 endEpoch_,
        address destination_
    ) internal returns (uint256 claimed_) {
        if (destination_ == address(0)) revert InvalidDestinationAddress();

        claimed_ = getClaimable(token_, account_, startEpoch_, endEpoch_);

        // NOTE: `getClaimable` skips epochs the account already claimed, so we can safely mark all epochs as claimed.
        // NOTE: This effectively iterates over the range again (is done in `getClaimable`), but the alternative is
        //       a lot of code duplication.
        for (uint256 epoch_ = startEpoch_; epoch_ < endEpoch_ + 1; ++epoch_) {
            hasClaimed[token_][epoch_][account_] = true;
        }

        _lastTokenBalances[token_] -= claimed_; // Track this contract's latest balance of `token_`.

        emit Claim(token_, account_, startEpoch_, endEpoch_, claimed_);

        if (!ERC20Helper.transfer(token_, destination_, claimed_)) revert TransferFailed();
    }
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IERC20.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @title  ERC20 Token Standard.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-20: https://eips.ethereum.org/EIPS/eip-20
 */
interface IERC20 {
    /* ============ Events ============ */

    /**
     * @notice Emitted when `spender` has been approved for `amount` of the token balance of `account`.
     * @param  account The address of the account.
     * @param  spender The address of the spender being approved for the allowance.
     * @param  amount  The amount of the allowance being approved.
     */
    event Approval(address indexed account, address indexed spender, uint256 amount);

    /**
     * @notice Emitted when `amount` tokens is transferred from `sender` to `recipient`.
     * @param  sender    The address of the sender who's token balance is decremented.
     * @param  recipient The address of the recipient who's token balance is incremented.
     * @param  amount    The amount of tokens being transferred.
     */
    event Transfer(address indexed sender, address indexed recipient, uint256 amount);

    /* ============ Interactive Functions ============ */

    /**
     * @notice Allows a calling account to approve `spender` to spend up to `amount` of its token balance.
     * @dev    MUST emit an `Approval` event.
     * @param  spender The address of the account being allowed to spend up to the allowed amount.
     * @param  amount  The amount of the allowance being approved.
     * @return Whether or not the approval was successful.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @notice Allows a calling account to transfer `amount` tokens to `recipient`.
     * @param  recipient The address of the recipient who's token balance will be incremented.
     * @param  amount    The amount of tokens being transferred.
     * @return Whether or not the transfer was successful.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @notice Allows a calling account to transfer `amount` tokens from `sender`, with allowance, to a `recipient`.
     * @param  sender    The address of the sender who's token balance will be decremented.
     * @param  recipient The address of the recipient who's token balance will be incremented.
     * @param  amount    The amount of tokens being transferred.
     * @return Whether or not the transfer was successful.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns the allowance `spender` is allowed to spend on behalf of `account`.
     * @param  account The address of the account who's token balance `spender` is allowed to spend.
     * @param  spender The address of an account allowed to spend on behalf of `account`.
     * @return The amount `spender` can spend on behalf of `account`.
     */
    function allowance(address account, address spender) external view returns (uint256);

    /**
     * @notice Returns the token balance of `account`.
     * @param  account The address of some account.
     * @return The token balance of `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /// @notice Returns the number of decimals UIs should assume all amounts have.
    function decimals() external view returns (uint8);

    /// @notice Returns the name of the contract/token.
    function name() external view returns (string memory);

    /// @notice Returns the symbol of the token.
    function symbol() external view returns (string memory);

    /// @notice Returns the current total supply of the token.
    function totalSupply() external view returns (uint256);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/StatefulERC712.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IStatefulERC712 } from "./interfaces/IStatefulERC712.sol";

import { ERC712Extended } from "./ERC712Extended.sol";

/**
 * @title  Stateful Extension for EIP-712 typed structured data hashing and signing with nonces.
 * @author M^0 Labs
 * @dev    An abstract implementation to satisfy stateful EIP-712 with nonces.
 */
abstract contract StatefulERC712 is IStatefulERC712, ERC712Extended {
    /// @inheritdoc IStatefulERC712
    mapping(address account => uint256 nonce) public nonces; // Nonces for all signatures.

    /**
     * @notice Construct the StatefulERC712 contract.
     * @param  name_ The name of the contract.
     */
    constructor(string memory name_) ERC712Extended(name_) {}
}


// ============================================================================
// FILE: lib/ttg/lib/erc20-helper/src/ERC20Helper.sol
// ============================================================================

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.7;

import { IERC20Like } from "./interfaces/IERC20Like.sol";

/**
 * @title Small Library to standardize erc20 token interactions.
 */
library ERC20Helper {

    /**************************************************************************************************************************************/
    /*** Internal Functions                                                                                                             ***/
    /**************************************************************************************************************************************/

    function transfer(address token_, address to_, uint256 amount_) internal returns (bool success_) {
        return _call(token_, abi.encodeWithSelector(IERC20Like.transfer.selector, to_, amount_));
    }

    function transferFrom(address token_, address from_, address to_, uint256 amount_) internal returns (bool success_) {
        return _call(token_, abi.encodeWithSelector(IERC20Like.transferFrom.selector, from_, to_, amount_));
    }

    function approve(address token_, address spender_, uint256 amount_) internal returns (bool success_) {
        // If setting approval to zero fails, return false.
        if (!_call(token_, abi.encodeWithSelector(IERC20Like.approve.selector, spender_, uint256(0)))) return false;

        // If `amount_` is zero, return true as the previous step already did this.
        if (amount_ == uint256(0)) return true;

        // Return the result of setting the approval to `amount_`.
        return _call(token_, abi.encodeWithSelector(IERC20Like.approve.selector, spender_, amount_));
    }

    function _call(address token_, bytes memory data_) private returns (bool success_) {
        if (token_.code.length == uint256(0)) return false;

        bytes memory returnData;
        ( success_, returnData ) = token_.call(data_);

        return success_ && (returnData.length == uint256(0) || abi.decode(returnData, (bool)));
    }

}


// ============================================================================
// FILE: lib/ttg/src/libs/PureEpochs.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @notice Defines epochs as periods away from STARTING_TIMESTAMP timestamp.
 * @author M^0 Labs
 * @dev    Provides a `uint16` epoch clock value.
 */
library PureEpochs {
    /* ============ Variables ============ */

    /// @notice The timestamp of the start of Epoch 1.
    uint40 internal constant STARTING_TIMESTAMP = 1713099600;

    /// @notice The approximate target of seconds an epoch should endure.
    uint40 internal constant EPOCH_PERIOD = 1296000;

    /* ============ Internal View/Pure Functions ============ */

    /// @dev Returns the current epoch number.
    function currentEpoch() internal view returns (uint16) {
        return uint16(((block.timestamp - STARTING_TIMESTAMP) / EPOCH_PERIOD) + 1);
    }

    /// @dev Returns the remaining time in the current epoch.
    function timeRemainingInCurrentEpoch() internal view returns (uint40) {
        return STARTING_TIMESTAMP + (currentEpoch() * EPOCH_PERIOD) - uint40(block.timestamp);
    }

    function clockMode() internal pure returns (string memory) {
        return "mode=epoch&epochUnderlyingSource=blockTimestamp&epochStartingTimestamp=1713099600&epochPeriod=1296000";
    }
}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IERC6372.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @title  Contract clock properties.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-6372: https://eips.ethereum.org/EIPS/eip-6372
 */
interface IERC6372 {
    /// @notice Returns a machine-readable string description of the clock the contract is operating on.
    function CLOCK_MODE() external view returns (string memory);

    /// @notice Returns the current timepoint according to the mode the contract is operating on.
    function clock() external view returns (uint48);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IZeroToken.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IEpochBasedVoteToken } from "../abstract/interfaces/IEpochBasedVoteToken.sol";

/**
 * @title  An instance of an EpochBasedVoteToken delegating minting control to a Standard Governor,
 *         and enabling range queries for past balances, voting powers, delegations, and  total supplies.
 * @author M^0 Labs
 */
interface IZeroToken is IEpochBasedVoteToken {
    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when the length of some accounts array does not equal the length of some balances array.
     * @param  accountsLength The length of the accounts array.
     * @param  balancesLength The length of the balances array.
     */
    error ArrayLengthMismatch(uint256 accountsLength, uint256 balancesLength);

    /// @notice Revert message when the Standard Governor Deployer specified in the constructor is address(0).
    error InvalidStandardGovernorDeployerAddress();

    /// @notice Revert message when the caller is not the Standard Governor.
    error NotStandardGovernor();

    /// @notice Revert message when the start of an inclusive range query is larger than the end.
    error StartEpochAfterEndEpoch();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Mints `amount` token to `recipient`.
     * @param  recipient The address of the account receiving minted token.
     * @param  amount    The amount of token to mint.
     */
    function mint(address recipient, uint256 amount) external;

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns an array of token balances of `account`
     *         between `startEpoch` and `endEpoch` past inclusive clocks.
     * @param  account    The address of some account.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of token balances, each relating to an epoch in the inclusive range.
     */
    function pastBalancesOf(
        address account,
        uint256 startEpoch,
        uint256 endEpoch
    ) external view returns (uint256[] memory);

    /**
     * @notice Returns an array of total token supplies between `startEpoch` and `endEpoch` clocks inclusively.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return An array of total supplies, each relating to an epoch in the inclusive range.
     */
    function pastTotalSupplies(uint256 startEpoch, uint256 endEpoch) external view returns (uint256[] memory);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Standard Governor Deployer.
    function standardGovernorDeployer() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IDistributionVault.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IStatefulERC712 } from "../../lib/common/src/interfaces/IStatefulERC712.sol";
import { IERC6372 } from "../abstract/interfaces/IERC6372.sol";

/**
 * @title  A contract enabling pro rata distribution of arbitrary tokens to holders of the Zero Token.
 * @author M^0 Labs
 */
interface IDistributionVault is IERC6372, IStatefulERC712 {
    /* ============ Events ============ */

    /**
     * @notice Emitted when `account` claims `token` distribution between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  token      The address of the token being claimed.
     * @param  account    The address of the account claiming the distribution.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @param  amount     The total amount of token claimed by `account`.
     */
    event Claim(address indexed token, address indexed account, uint256 startEpoch, uint256 endEpoch, uint256 amount);

    /**
     * @notice Emitted when `token` is distributed pro rata to all holders at epoch `epoch`.
     * @param  token  The address of the token being distributed.
     * @param  epoch  The epoch number as a clock value.
     * @param  amount The total amount of token being distributed.
     */
    event Distribution(address indexed token, uint256 indexed epoch, uint256 amount);

    /* ============ Custom Errors ============ */

    /// @notice Revert message when the destination address is address(0).
    error InvalidDestinationAddress();

    /// @notice Revert message when the Zero Token address set at deployment is address(0).
    error InvalidZeroTokenAddress();

    /**
     * @notice Revert message when a query for past values is for a timepoint greater or equal to the current clock.
     * @param  timepoint The timepoint being queried.
     * @param  clock     The current timepoint.
     */
    error NotPastTimepoint(uint256 timepoint, uint256 clock);

    /// @notice Revert message when the start epoch is greater than the end epoch.
    error StartEpochAfterEndEpoch(uint256 startEpoch, uint256 endEpoch);

    /// @notice Revert message when a token transfer, from this contract, fails.
    error TransferFailed();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Allows a caller to claim `token` distribution between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  token       The address of the token being claimed.
     * @param  startEpoch  The starting epoch number as a clock value.
     * @param  endEpoch    The ending epoch number as a clock value.
     * @param  destination The address the account where the claimed token will be sent.
     * @return claimed     The total amount of token claimed by `account`.
     */
    function claim(
        address token,
        uint256 startEpoch,
        uint256 endEpoch,
        address destination
    ) external returns (uint256 claimed);

    /**
     * @notice Allows a signer to claim `token` distribution between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  account     The purported address of the signing account.
     * @param  token       The address of the token being claimed.
     * @param  startEpoch  The starting epoch number as a clock value.
     * @param  endEpoch    The ending epoch number as a clock value.
     * @param  destination The address of the account where the claimed token will be sent.
     * @param  deadline    The last timestamp at which the signature is still valid.
     * @param  v           v of the signature.
     * @param  r           r of the signature.
     * @param  s           s of the signature.
     * @return claimed     The total amount of token claimed by `account`.
     */
    function claimBySig(
        address account,
        address token,
        uint256 startEpoch,
        uint256 endEpoch,
        address destination,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 claimed);

    /**
     * @notice Allows a signer to claim `token` distribution between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  account     The purported address of the signing account.
     * @param  token       The address of the token being claimed.
     * @param  startEpoch  The starting epoch number as a clock value.
     * @param  endEpoch    The ending epoch number as a clock value.
     * @param  destination The address of the account where the claimed token will be sent.
     * @param  deadline    The last timestamp at which the signature is still valid.
     * @param  signature   A byte array signature.
     * @return claimed     The total amount of token claimed by `account`.
     */
    function claimBySig(
        address account,
        address token,
        uint256 startEpoch,
        uint256 endEpoch,
        address destination,
        uint256 deadline,
        bytes memory signature
    ) external returns (uint256 claimed);

    /**
     * @notice Distributes the unaccounted balance of `token`.
     * @param  token The address of the token being distributed.
     * @return The total amount of additional tokens accounted in this distribution event.
     */
    function distribute(address token) external returns (uint256);

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the claimBySig function.
    function CLAIM_TYPEHASH() external view returns (bytes32);

    /**
     * @notice Returns the total amount of `token` eligible for distribution to holder at the end of epoch `epoch`.
     * @param  token The address of some token.
     * @param  epoch The epoch number as a clock value.
     * @return The total amount of token eligible for distribution to holder at the end of the epoch.
     */
    function distributionOfAt(address token, uint256 epoch) external view returns (uint256);

    /**
     * @notice Returns the amount of `token` `account` can claim between inclusive epochs `startEpoch` and `endEpoch`.
     * @param  token      The address of some token.
     * @param  account    The address of some account.
     * @param  startEpoch The starting epoch number as a clock value.
     * @param  endEpoch   The ending epoch number as a clock value.
     * @return The amount of token that `account` has yet to claim for these epochs, if any.
     */
    function getClaimable(
        address token,
        address account,
        uint256 startEpoch,
        uint256 endEpoch
    ) external view returns (uint256);

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  account     The purported address of the signing account.
     * @param  token       The address of the token being claimed.
     * @param  startEpoch  The starting epoch number as a clock value.
     * @param  endEpoch    The ending epoch number as a clock value.
     * @param  destination The address the account where the claimed token will be sent.
     * @param  nonce       The nonce of the account claiming the token.
     * @param  deadline    The last timestamp at which the signature is still valid.
     * @return The digest to be signed.
     */
    function getClaimDigest(
        address account,
        address token,
        uint256 startEpoch,
        uint256 endEpoch,
        address destination,
        uint256 nonce,
        uint256 deadline
    ) external view returns (bytes32);

    /**
     * @notice Returns the additional balance of `token_` that is not yet distributed.
     * @param  token The address of some token.
     * @return The total amount of token owned by the vault that is yet to be distributed.
     */
    function getDistributable(address token) external view returns (uint256);

    /**
     * @notice Returns whether `account` has already claimed their `token` distribution for `epoch`.
     * @param  token   The address of some token.
     * @param  account The address of some account.
     * @param  epoch   The epoch number as a clock value.
     * @return Whether `account` has already claimed `token` rewards for `epoch`.
     */
    function hasClaimed(address token, uint256 epoch, address account) external view returns (bool);

    /// @notice Returns the name of the contract.
    function name() external view returns (string memory);

    /// @notice Returns the address of the Zero Token holders must have in order to be eligible for distributions.
    function zeroToken() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IStatefulERC712.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC712Extended } from "./IERC712Extended.sol";

/**
 * @title  Stateful Extension for EIP-712 typed structured data hashing and signing with nonces.
 * @author M^0 Labs
 */
interface IStatefulERC712 is IERC712Extended {
    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when a signing account's nonce is not the expected current nonce.
     * @param  nonce         The nonce used in the signature.
     * @param  expectedNonce The expected nonce to be used in a signature by the signing account.
     */
    error InvalidAccountNonce(uint256 nonce, uint256 expectedNonce);

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns the next nonce to be used in a signature by `account`.
     * @param  account The address of some account.
     * @return nonce   The next nonce to be used in a signature by `account`.
     */
    function nonces(address account) external view returns (uint256 nonce);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/ERC712Extended.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC712 } from "./interfaces/IERC712.sol";
import { IERC712Extended } from "./interfaces/IERC712Extended.sol";

import { SignatureChecker } from "./libs/SignatureChecker.sol";

/**
 * @title  Typed structured data hashing and signing via EIP-712, extended by EIP-5267.
 * @author M^0 Labs
 * @dev    An abstract implementation to satisfy EIP-712: https://eips.ethereum.org/EIPS/eip-712
 */
abstract contract ERC712Extended is IERC712Extended {
    /* ============ Variables ============ */

    /// @dev keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
    bytes32 internal constant _EIP712_DOMAIN_HASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    /// @dev keccak256("1")
    bytes32 internal constant _EIP712_VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;

    /// @dev Initial Chain ID set at deployment.
    uint256 internal immutable _INITIAL_CHAIN_ID;

    /// @dev Initial EIP-712 domain separator set at deployment.
    bytes32 internal immutable _INITIAL_DOMAIN_SEPARATOR;

    /// @dev The name of the contract.
    string internal _name;

    /* ============ Constructor ============ */

    /**
     * @notice Constructs the EIP-712 domain separator.
     * @param  name_ The name of the contract.
     */
    constructor(string memory name_) {
        _name = name_;

        _INITIAL_CHAIN_ID = block.chainid;
        _INITIAL_DOMAIN_SEPARATOR = _getDomainSeparator();
    }

    /* ============ View/Pure Functions ============ */

    /// @inheritdoc IERC712Extended
    function eip712Domain()
        external
        view
        virtual
        returns (
            bytes1 fields_,
            string memory name_,
            string memory version_,
            uint256 chainId_,
            address verifyingContract_,
            bytes32 salt_,
            uint256[] memory extensions_
        )
    {
        return (
            hex"0f", // 01111
            _name,
            "1",
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }

    /// @inheritdoc IERC712
    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return block.chainid == _INITIAL_CHAIN_ID ? _INITIAL_DOMAIN_SEPARATOR : _getDomainSeparator();
    }

    /* ============ Internal View/Pure Functions ============ */

    /**
     * @dev    Computes the EIP-712 domain separator.
     * @return The EIP-712 domain separator.
     */
    function _getDomainSeparator() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    _EIP712_DOMAIN_HASH,
                    keccak256(bytes(_name)),
                    _EIP712_VERSION_HASH,
                    block.chainid,
                    address(this)
                )
            );
    }

    /**
     * @dev    Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  internalDigest_ The internal digest.
     * @return The digest to be signed.
     */
    function _getDigest(bytes32 internalDigest_) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR(), internalDigest_));
    }

    /**
     * @dev   Revert if the signature is expired.
     * @param expiry_ Timestamp at which the signature expires or max uint256 for no expiry.
     */
    function _revertIfExpired(uint256 expiry_) internal view {
        if (block.timestamp > expiry_) revert SignatureExpired(expiry_, block.timestamp);
    }

    /**
     * @dev   Revert if the signature is invalid.
     * @dev   We first validate if the signature is a valid ECDSA signature and return early if it is the case.
     *        Then, we validate if it is a valid ERC-1271 signature, and return early if it is the case.
     *        If not, we revert with the error from the ECDSA signature validation.
     * @param signer_    The signer of the signature.
     * @param digest_    The digest that was signed.
     * @param signature_ The signature.
     */
    function _revertIfInvalidSignature(address signer_, bytes32 digest_, bytes memory signature_) internal view {
        SignatureChecker.Error error_ = SignatureChecker.validateECDSASignature(signer_, digest_, signature_);

        if (error_ == SignatureChecker.Error.NoError) return;

        if (SignatureChecker.isValidERC1271Signature(signer_, digest_, signature_)) return;

        _revertIfError(error_);
    }

    /**
     * @dev    Returns the signer of a signed digest, via EIP-712, and reverts if the signature is invalid.
     * @param  digest_ The digest that was signed.
     * @param  v_      v of the signature.
     * @param  r_      r of the signature.
     * @param  s_      s of the signature.
     * @return signer_ The signer of the digest.
     */
    function _getSignerAndRevertIfInvalidSignature(
        bytes32 digest_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) internal pure returns (address signer_) {
        SignatureChecker.Error error_;

        (error_, signer_) = SignatureChecker.recoverECDSASigner(digest_, v_, r_, s_);

        _revertIfError(error_);
    }

    /**
     * @dev   Revert if the signature is invalid.
     * @param signer_ The signer of the signature.
     * @param digest_ The digest that was signed.
     * @param r_      An ECDSA/secp256k1 signature parameter.
     * @param vs_     An ECDSA/secp256k1 short signature parameter.
     */
    function _revertIfInvalidSignature(address signer_, bytes32 digest_, bytes32 r_, bytes32 vs_) internal pure {
        _revertIfError(SignatureChecker.validateECDSASignature(signer_, digest_, r_, vs_));
    }

    /**
     * @dev   Revert if the signature is invalid.
     * @param signer_ The signer of the signature.
     * @param digest_ The digest that was signed.
     * @param v_      v of the signature.
     * @param r_      r of the signature.
     * @param s_      s of the signature.
     */
    function _revertIfInvalidSignature(
        address signer_,
        bytes32 digest_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) internal pure {
        _revertIfError(SignatureChecker.validateECDSASignature(signer_, digest_, v_, r_, s_));
    }

    /**
     * @dev   Revert if error.
     * @param error_ The SignatureChecker Error enum.
     */
    function _revertIfError(SignatureChecker.Error error_) private pure {
        if (error_ == SignatureChecker.Error.NoError) return;
        if (error_ == SignatureChecker.Error.InvalidSignature) revert InvalidSignature();
        if (error_ == SignatureChecker.Error.InvalidSignatureLength) revert InvalidSignatureLength();
        if (error_ == SignatureChecker.Error.InvalidSignatureS) revert InvalidSignatureS();
        if (error_ == SignatureChecker.Error.InvalidSignatureV) revert InvalidSignatureV();
        if (error_ == SignatureChecker.Error.SignerMismatch) revert SignerMismatch();

        revert InvalidSignature();
    }
}


// ============================================================================
// FILE: lib/ttg/lib/erc20-helper/src/interfaces/IERC20Like.sol
// ============================================================================

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.7;

/// @title Interface of the ERC20 standard as needed by ERC20Helper.
interface IERC20Like {

    function approve(address spender_, uint256 amount_) external returns (bool success_);

    function transfer(address recipient_, uint256 amount_) external returns (bool success_);

    function transferFrom(address owner_, address recipient_, uint256 amount_) external returns (bool success_);

}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IEpochBasedVoteToken.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC20Extended } from "../../../lib/common/src/interfaces/IERC20Extended.sol";

import { IERC5805 } from "./IERC5805.sol";

/**
 * @title  Extension for an ERC5805 token that uses epochs as its clock mode and delegation via IERC1271.
 * @author M^0 Labs
 */
interface IEpochBasedVoteToken is IERC5805, IERC20Extended {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when the provided epoch is zero.
    error EpochZero();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Changes the voting power delegation for `account` to `delegatee`.
     * @param  account   The purported address of the signing account.
     * @param  delegatee The address the voting power of `account` will be delegated to.
     * @param  nonce     The nonce used for the signature.
     * @param  expiry    The timestamp until which the signature is still valid.
     * @param  signature A byte array signature.
     */
    function delegateBySig(
        address account,
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        bytes memory signature
    ) external;

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns the digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  delegatee The address of the delegatee to delegate to.
     * @param  nonce     The nonce of the account delegating.
     * @param  expiry    The timestamp until which the signature is still valid.
     * @return The digest to be signed.
     */
    function getDelegationDigest(address delegatee, uint256 nonce, uint256 expiry) external view returns (bytes32);

    /**
     * @notice Returns the token balance of `account` at a past clock value `epoch`.
     * @param  account The address of some account.
     * @param  epoch   The epoch number as a clock value.
     * @return The token balance `account` at `epoch`.
     */
    function pastBalanceOf(address account, uint256 epoch) external view returns (uint256);

    /**
     * @notice Returns the delegatee of `account` at a past clock value `epoch`.
     * @param  account The address of some account.
     * @param  epoch   The epoch number as a clock value.
     * @return The delegatee of the voting power of `account` at `epoch`.
     */
    function pastDelegates(address account, uint256 epoch) external view returns (address);

    /**
     * @notice Returns the total token supply at a past clock value `epoch`.
     * @param  epoch The epoch number as a clock value.
     * @return The total token supply at `epoch`.
     */
    function pastTotalSupply(uint256 epoch) external view returns (uint256);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IERC712Extended.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC712 } from "./IERC712.sol";

/**
 * @title  EIP-712 extended by EIP-5267.
 * @author M^0 Labs
 * @dev    The additional interface as defined by EIP-5267: https://eips.ethereum.org/EIPS/eip-5267
 */
interface IERC712Extended is IERC712 {
    /* ============ Events ============ */

    /// @notice MAY be emitted to signal that the domain could have changed.
    event EIP712DomainChanged();

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the fields and values that describe the domain separator used by this contract for EIP-712.
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
// FILE: lib/ttg/lib/common/src/interfaces/IERC712.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @title  Typed structured data hashing and signing via EIP-712.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-712: https://eips.ethereum.org/EIPS/eip-712
 */
interface IERC712 {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when an invalid signature is detected.
    error InvalidSignature();

    /// @notice Revert message when a signature with invalid length is detected.
    error InvalidSignatureLength();

    /// @notice Revert message when the S portion of a signature is invalid.
    error InvalidSignatureS();

    /// @notice Revert message when the V portion of a signature is invalid.
    error InvalidSignatureV();

    /**
     * @notice Revert message when a signature is being used beyond its deadline (i.e. expiry).
     * @param  deadline  The deadline of the signature.
     * @param  timestamp The current timestamp.
     */
    error SignatureExpired(uint256 deadline, uint256 timestamp);

    /// @notice Revert message when a recovered signer does not match the account being purported to have signed.
    error SignerMismatch();

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the EIP712 domain separator used in the encoding of a signed digest.
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/libs/SignatureChecker.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC1271 } from "../interfaces/IERC1271.sol";

/**
 * @title  A library to handle ECDSA/secp256k1 and ERC1271 signatures, individually or in arbitrarily in combination.
 * @author M^0 Labs
 */
library SignatureChecker {
    /* ============ Enums ============ */

    /**
     * @notice An enum representing the possible errors that can be emitted during signature validation.
     * @param  NoError                No error occurred during signature validation.
     * @param  InvalidSignature       The signature is invalid.
     * @param  InvalidSignatureLength The signature length is invalid.
     * @param  InvalidSignatureS      The signature parameter S is invalid.
     * @param  InvalidSignatureV      The signature parameter V is invalid.
     * @param  SignerMismatch         The signer does not match the recovered signer.
     */
    enum Error {
        NoError,
        InvalidSignature,
        InvalidSignatureLength,
        InvalidSignatureS,
        InvalidSignatureV,
        SignerMismatch
    }

    /* ============ Internal View/Pure Functions ============ */

    /**
     * @dev    Returns whether a signature is valid (ECDSA/secp256k1 or ERC1271) for a signer and digest.
     * @dev    Signatures must not be used as unique identifiers since the `ecrecover` EVM opcode
     *         allows for malleable (non-unique) signatures.
     *         See https://github.com/OpenZeppelin/openzeppelin-contracts/security/advisories/GHSA-4h98-2769-gh6h
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array signature.
     * @return           Whether the signature is valid or not.
     */
    function isValidSignature(address signer, bytes32 digest, bytes memory signature) internal view returns (bool) {
        return isValidECDSASignature(signer, digest, signature) || isValidERC1271Signature(signer, digest, signature);
    }

    /**
     * @dev    Returns whether an ERC1271 signature is valid for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ERC1271 signature.
     * @return           Whether the signature is valid or not.
     */
    function isValidERC1271Signature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (digest, signature))
        );

        return
            success &&
            result.length >= 32 &&
            abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector);
    }

    /**
     * @dev    Decodes an ECDSA/secp256k1 signature from a byte array to standard v, r, and s parameters.
     * @param  signature A byte array ECDSA/secp256k1 signature.
     * @return v         An ECDSA/secp256k1 signature parameter.
     * @return r         An ECDSA/secp256k1 signature parameter.
     * @return s         An ECDSA/secp256k1 signature parameter.
     */
    function decodeECDSASignature(bytes memory signature) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        // ecrecover takes the signature parameters, and they can be decoded using assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
    }

    /**
     * @dev    Decodes an ECDSA/secp256k1 short signature as defined by EIP2098
     *         from a byte array to standard v, r, and s parameters.
     * @param  signature A byte array ECDSA/secp256k1 short signature.
     * @return r         An ECDSA/secp256k1 signature parameter.
     * @return vs        An ECDSA/secp256k1 short signature parameter.
     */
    function decodeShortECDSASignature(bytes memory signature) internal pure returns (bytes32 r, bytes32 vs) {
        // ecrecover takes the signature parameters, and they can be decoded using assembly.
        /// @solidity memory-safe-assembly
        assembly {
            r := mload(add(signature, 0x20))
            vs := mload(add(signature, 0x40))
        }
    }

    /**
     * @dev    Returns whether an ECDSA/secp256k1 signature is valid for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     * @return           Whether the signature is valid or not.
     */
    function isValidECDSASignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (bool) {
        if (signature.length == 64) {
            (bytes32 r, bytes32 vs) = decodeShortECDSASignature(signature);
            return isValidECDSASignature(signer, digest, r, vs);
        }

        return validateECDSASignature(signer, digest, signature) == Error.NoError;
    }

    /**
     * @dev    Returns whether an ECDSA/secp256k1 short signature is valid for a signer and digest.
     * @param  signer  The address of the account purported to have signed.
     * @param  digest  The hash of the data that was signed.
     * @param  r       An ECDSA/secp256k1 signature parameter.
     * @param  vs      An ECDSA/secp256k1 short signature parameter.
     * @return         Whether the signature is valid or not.
     */
    function isValidECDSASignature(address signer, bytes32 digest, bytes32 r, bytes32 vs) internal pure returns (bool) {
        return validateECDSASignature(signer, digest, r, vs) == Error.NoError;
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 signature for some digest.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ECDSA/secp256k1 signature.
     * @return           An error, if any, that occurred during the signer recovery.
     * @return           The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(bytes32 digest, bytes memory signature) internal pure returns (Error, address) {
        if (signature.length != 65) return (Error.InvalidSignatureLength, address(0));

        (uint8 v, bytes32 r, bytes32 s) = decodeECDSASignature(signature);

        return recoverECDSASigner(digest, v, r, s);
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 short signature for some digest.
     * @dev    See https://eips.ethereum.org/EIPS/eip-2098
     * @param  digest The hash of the data that was signed.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  vs     An ECDSA/secp256k1 short signature parameter.
     * @return        An error, if any, that occurred during the signer recovery.
     * @return        The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(bytes32 digest, bytes32 r, bytes32 vs) internal pure returns (Error, address) {
        unchecked {
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            return recoverECDSASigner(digest, v, r, s);
        }
    }

    /**
     * @dev    Returns the signer of an ECDSA/secp256k1 signature for some digest.
     * @param  digest The hash of the data that was signed.
     * @param  v      An ECDSA/secp256k1 signature parameter.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  s      An ECDSA/secp256k1 signature parameter.
     * @return        An error, if any, that occurred during the signer recovery.
     * @return signer The address of the account recovered form the signature (0 if error).
     */
    function recoverECDSASigner(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (Error, address signer) {
        // Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}.
        if (uint256(s) > uint256(0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0))
            return (Error.InvalidSignatureS, address(0));

        if (v != 27 && v != 28) return (Error.InvalidSignatureV, address(0));

        signer = ecrecover(digest, v, r, s);

        return (signer == address(0)) ? (Error.InvalidSignature, address(0)) : (Error.NoError, signer);
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 signature for a signer and digest.
     * @param  signer    The address of the account purported to have signed.
     * @param  digest    The hash of the data that was signed.
     * @param  signature A byte array ERC1271 signature.
     * @return           An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        bytes memory signature
    ) internal pure returns (Error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, signature);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 short signature for a signer and digest.
     * @param  signer The address of the account purported to have signed.
     * @param  digest The hash of the data that was signed.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  vs     An ECDSA/secp256k1 short signature parameter.
     * @return        An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        bytes32 r,
        bytes32 vs
    ) internal pure returns (Error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, r, vs);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error, if any, in validating an ECDSA/secp256k1 signature for a signer and digest.
     * @param  signer The address of the account purported to have signed.
     * @param  digest The hash of the data that was signed.
     * @param  v      An ECDSA/secp256k1 signature parameter.
     * @param  r      An ECDSA/secp256k1 signature parameter.
     * @param  s      An ECDSA/secp256k1 signature parameter.
     * @return        An error, if any, that occurred during the signer recovery.
     */
    function validateECDSASignature(
        address signer,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (Error) {
        (Error recoverError, address recoveredSigner) = recoverECDSASigner(digest, v, r, s);

        return (recoverError == Error.NoError) ? validateRecoveredSigner(signer, recoveredSigner) : recoverError;
    }

    /**
     * @dev    Returns an error if `signer` is not `recoveredSigner`.
     * @param  signer          The address of the some signer.
     * @param  recoveredSigner The address of the some recoveredSigner.
     * @return                 An error if `signer` is not `recoveredSigner`.
     */
    function validateRecoveredSigner(address signer, address recoveredSigner) internal pure returns (Error) {
        return (signer == recoveredSigner) ? Error.NoError : Error.SignerMismatch;
    }
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IERC20Extended.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC20 } from "./IERC20.sol";
import { IERC3009 } from "./IERC3009.sol";

/**
 * @title  An ERC20 token extended with EIP-2612 permits for signed approvals (via EIP-712
 *         and with EIP-1271 compatibility), and extended with EIP-3009 transfer with authorization (via EIP-712).
 * @author M^0 Labs
 * @dev    The additional interface as defined by EIP-2612: https://eips.ethereum.org/EIPS/eip-2612
 */
interface IERC20Extended is IERC20, IERC3009 {
    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when spender's allowance is not sufficient.
     * @param  spender    Address that may be allowed to operate on tokens without being their owner.
     * @param  allowance  Amount of tokens a `spender` is allowed to operate with.
     * @param  needed     Minimum amount required to perform a transfer.
     */
    error InsufficientAllowance(address spender, uint256 allowance, uint256 needed);

    /**
     * @notice Revert message emitted when the transferred amount is insufficient.
     * @param  amount Amount transferred.
     */
    error InsufficientAmount(uint256 amount);

    /**
     * @notice Revert message emitted when the recipient of a token is invalid.
     * @param  recipient Address of the invalid recipient.
     */
    error InvalidRecipient(address recipient);

    /* ============ Interactive Functions ============ */

    /**
     * @notice Approves `spender` to spend up to `amount` of the token balance of `owner`, via a signature.
     * @param  owner    The address of the account who's token balance is being approved to be spent by `spender`.
     * @param  spender  The address of an account allowed to spend on behalf of `owner`.
     * @param  value    The amount of the allowance being approved.
     * @param  deadline The last block number where the signature is still valid.
     * @param  v        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
     * @param  r        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
     * @param  s        An ECDSA secp256k1 signature parameter (EIP-2612 via EIP-712).
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
     * @notice Approves `spender` to spend up to `amount` of the token balance of `owner`, via a signature.
     * @param  owner     The address of the account who's token balance is being approved to be spent by `spender`.
     * @param  spender   The address of an account allowed to spend on behalf of `owner`.
     * @param  value     The amount of the allowance being approved.
     * @param  deadline  The last block number where the signature is still valid.
     * @param  signature An arbitrary signature (EIP-712).
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, bytes memory signature) external;

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the permit function.
    function PERMIT_TYPEHASH() external view returns (bytes32);
}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IERC5805.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IStatefulERC712 } from "../../../lib/common/src/interfaces/IStatefulERC712.sol";

import { IERC6372 } from "./IERC6372.sol";

/**
 * @title  Voting with voting weight tracking and delegation support.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-5805: https://eips.ethereum.org/EIPS/eip-5805
 */
interface IERC5805 is IStatefulERC712, IERC6372 {
    /* ============ Events ============ */

    /**
     * @notice Emitted when `delegator` changes its voting power delegation from `fromDelegatee` to `toDelegatee`.
     * @param  delegator     The address of the account changing its voting power delegation.
     * @param  fromDelegatee The previous account the voting power of `delegator` was delegated to.
     * @param  toDelegatee   The new account the voting power of `delegator` is delegated to.
     */
    event DelegateChanged(address indexed delegator, address indexed fromDelegatee, address indexed toDelegatee);

    /**
     * @notice Emitted when the available voting power of `delegatee` changes from `previousBalance` to `newBalance`.
     * @param  delegatee       The address of the account whose voting power is changed.
     * @param  previousBalance The previous voting power of `delegatee`.
     * @param  newBalance      The new voting power of `delegatee`.
     */
    event DelegateVotesChanged(address indexed delegatee, uint256 previousBalance, uint256 newBalance);

    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when a query for past values is for a timepoint greater or equal to the current clock.
     * @param  timepoint The timepoint being queried.
     * @param  clock     The current timepoint.
     */
    error NotPastTimepoint(uint48 timepoint, uint48 clock);

    /* ============ Interactive Functions ============ */

    /**
     * @notice Allows a calling account to change its voting power delegation to `delegatee`.
     * @param  delegatee The address of the account the caller's voting power will be delegated to.
     */
    function delegate(address delegatee) external;

    /**
     * @notice Changes the signing account's voting power delegation to `delegatee`.
     * @param  delegatee The address of the account the signing account's voting power will be delegated to.
     * @param  nonce     The nonce of the account delegating.
     * @param  expiry    The timestamp until which the signature is still valid.
     * @param  v         A signature parameter.
     * @param  r         A signature parameter.
     * @param  s         A signature parameter.
     */
    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external;

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for the delegateBySig function.
    function DELEGATION_TYPEHASH() external view returns (bytes32);

    /**
     * @notice Returns the delegatee the voting power of `account` is delegated to.
     * @param  account The address of the account that can delegate its voting power.
     * @return The address of the account the voting power of `account` will be delegated to.
     */
    function delegates(address account) external view returns (address);

    /**
     * @notice Returns the total voting power of `account` at a past clock value `timepoint`.
     * @param  account   The address of some account.
     * @param  timepoint The point in time, according to the clock mode the contract is operating on.
     * @return The total voting power of `account` at clock value `timepoint`.
     */
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @notice Returns the total voting power of `account`.
     * @param  account The address of some account.
     * @return The total voting power of `account`.
     */
    function getVotes(address account) external view returns (uint256);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IERC1271.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @title  Standard Signature Validation Method for Contracts via EIP-1271.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-1271: https://eips.ethereum.org/EIPS/eip-1271
 */
interface IERC1271 {
    /**
     * @dev    Returns a specific magic value if the provided signature is valid for the provided digest.
     * @param  digest     Hash of the data purported to have been signed.
     * @param  signature  Signature byte array associated with the digest.
     * @return magicValue Magic value 0x1626ba7e if the signature is valid.
     */
    function isValidSignature(bytes32 digest, bytes memory signature) external view returns (bytes4 magicValue);
}


// ============================================================================
// FILE: lib/ttg/lib/common/src/interfaces/IERC3009.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IStatefulERC712 } from "./IStatefulERC712.sol";

/**
 * @title  Transfer via signed authorization following EIP-3009 standard.
 * @author M^0 Labs
 * @dev    The interface as defined by EIP-3009: https://eips.ethereum.org/EIPS/eip-3009
 */
interface IERC3009 is IStatefulERC712 {
    /* ============ Events ============ */

    /**
     * @notice Emitted when an authorization has been canceled.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the canceled authorization.
     */
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    /**
     * @notice Emitted when an authorization has been used.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the used authorization.
     */
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);

    /* ============ Custom Errors ============ */

    /**
     * @notice Emitted when an authorization has already been used.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the used authorization.
     */
    error AuthorizationAlreadyUsed(address authorizer, bytes32 nonce);

    /**
     * @notice Emitted when an authorization is expired.
     * @param  timestamp   Timestamp at which the transaction was submitted.
     * @param  validBefore Timestamp before which the authorization would have been valid.
     */
    error AuthorizationExpired(uint256 timestamp, uint256 validBefore);

    /**
     * @notice Emitted when an authorization is not yet valid.
     * @param  timestamp  Timestamp at which the transaction was submitted.
     * @param  validAfter Timestamp after which the authorization will be valid.
     */
    error AuthorizationNotYetValid(uint256 timestamp, uint256 validAfter);

    /**
     * @notice Emitted when the caller of `receiveWithAuthorization` is not the payee.
     * @param  caller Caller's address.
     * @param  payee  Payee's address.
     */
    error CallerMustBePayee(address caller, address payee);

    /* ============ Interactive Functions ============ */

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  signature   A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  r           An ECDSA/secp256k1 signature parameter.
     * @param  vs          An ECDSA/secp256k1 short signature parameter.
     */
    function transferWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes32 r,
        bytes32 vs
    ) external;

    /**
     * @notice Execute a transfer with a signed authorization.
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  v           v of the signature.
     * @param  r           r of the signature.
     * @param  s           s of the signature.
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

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  signature   A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes memory signature
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  r           An ECDSA/secp256k1 signature parameter.
     * @param  vs          An ECDSA/secp256k1 short signature parameter.
     */
    function receiveWithAuthorization(
        address from,
        address to,
        uint256 value,
        uint256 validAfter,
        uint256 validBefore,
        bytes32 nonce,
        bytes32 r,
        bytes32 vs
    ) external;

    /**
     * @notice Receive a transfer with a signed authorization from the payer.
     * @dev    This has an additional check to ensure that the payee's address matches
     *         the caller of this function to prevent front-running attacks.
     *         (See security considerations)
     * @param  from        Payer's address (Authorizer).
     * @param  to          Payee's address.
     * @param  value       Amount to be transferred.
     * @param  validAfter  The time after which this is valid (unix time).
     * @param  validBefore The time before which this is valid (unix time).
     * @param  nonce       Unique nonce.
     * @param  v           v of the signature.
     * @param  r           r of the signature.
     * @param  s           s of the signature.
     */
    function receiveWithAuthorization(
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

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  signature  A byte array ECDSA/secp256k1 signature (encoded r, s, v).
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes memory signature) external;

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  r          An ECDSA/secp256k1 signature parameter.
     * @param  vs         An ECDSA/secp256k1 short signature parameter.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, bytes32 r, bytes32 vs) external;

    /**
     * @notice Attempt to cancel an authorization.
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @param  v          v of the signature.
     * @param  r          r of the signature.
     * @param  s          s of the signature.
     */
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external;

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns the state of an authorization.
     * @dev    Nonces are randomly generated 32-byte data unique to the authorizer's address
     * @param  authorizer Authorizer's address.
     * @param  nonce      Nonce of the authorization.
     * @return True if the nonce is used.
     */
    function authorizationState(address authorizer, bytes32 nonce) external view returns (bool);

    /// @notice Returns `transferWithAuthorization` typehash.
    function TRANSFER_WITH_AUTHORIZATION_TYPEHASH() external view returns (bytes32);

    /// @notice Returns `receiveWithAuthorization` typehash.
    function RECEIVE_WITH_AUTHORIZATION_TYPEHASH() external view returns (bytes32);

    /// @notice Returns `cancelAuthorization` typehash.
    function CANCEL_AUTHORIZATION_TYPEHASH() external view returns (bytes32);
}
