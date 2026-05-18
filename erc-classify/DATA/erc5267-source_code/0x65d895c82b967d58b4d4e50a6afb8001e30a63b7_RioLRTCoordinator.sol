// SPDX-License-Identifier: UNLICENSED
// Source: 0x65d895c82b967d58b4d4e50a6afb8001e30a63b7
// Contract Name: RioLRTCoordinator
// Generated on: 2026-05-14 11:57:09


// ============================================================================
// FILE: contracts/restaking/RioLRTCoordinator.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {EIP712} from '@solady/utils/EIP712.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {SignatureCheckerLib} from '@solady/utils/SignatureCheckerLib.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {IRioLRTWithdrawalQueue} from 'contracts/interfaces/IRioLRTWithdrawalQueue.sol';
import {UUPSUpgradeable} from '@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol';
import {PausableUpgradeable} from '@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol';
import {OwnableUpgradeable} from '@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol';
import {IRioLRTOperatorDelegator} from 'contracts/interfaces/IRioLRTOperatorDelegator.sol';
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {IRioLRTAssetRegistry} from 'contracts/interfaces/IRioLRTAssetRegistry.sol';
import {IETHPOSDeposit} from 'contracts/interfaces/ethereum/IETHPOSDeposit.sol';
import {ETH_ADDRESS, MAX_REBALANCE_DELAY} from 'contracts/utils/Constants.sol';
import {IRioLRTCoordinator} from 'contracts/interfaces/IRioLRTCoordinator.sol';
import {OperatorOperations} from 'contracts/utils/OperatorOperations.sol';
import {RioLRTCore} from 'contracts/restaking/base/RioLRTCore.sol';
import {ETH_ADDRESS} from 'contracts/utils/Constants.sol';
import {Asset} from 'contracts/utils/Asset.sol';

contract RioLRTCoordinator is IRioLRTCoordinator, OwnableUpgradeable, UUPSUpgradeable, PausableUpgradeable, EIP712, RioLRTCore {
    using SafeERC20 for *;
    using Asset for *;

    /// @notice EIP-712 typehash for `DepositRoot` message
    bytes32 public constant DEPOSIT_ROOT_TYPEHASH = keccak256('DepositRoot(bytes32 root)');

    /// @notice The Ethereum POS deposit contract address.
    IETHPOSDeposit public immutable ethPOS;

    /// @notice The required delay between rebalances.
    uint24 public rebalanceDelay;

    /// @notice The guardian signer address.
    address public guardianSigner;

    /// @notice Tracks the timestamp from which each asset is eligible for rebalancing, inclusive of the defined timestamp.
    mapping(address asset => uint40 timestamp) public assetNextRebalanceAfter;

    /// @notice Require that the coordinator is not paused, the asset is supported, the deposit amount is non-zero, and the
    /// deposit cap has not been reached.
    /// @param asset The asset being deposited.
    /// @param amountIn The amount of the asset being deposited.
    modifier checkDeposit(address asset, uint256 amountIn) {
        _requireNotPaused();
        _requireAssetSupported(asset);
        _requireAmountGreaterThanZero(amountIn);
        _requireDepositCapNotReached(asset, amountIn);
        _;
    }

    /// @notice Require that the coordinator is not paused, the asset is supported, and the withdrawal amount is non-zero.
    /// @param asset The asset being deposited.
    /// @param amountIn The amount of the asset being deposited.
    modifier checkWithdrawal(address asset, uint256 amountIn) {
        _requireNotPaused();
        _requireAssetSupported(asset);
        _requireAmountGreaterThanZero(amountIn);
        _;
    }

    /// @notice Require that the coordinator is not paused and the rebalance delay has been met.
    /// @param asset The asset being rebalanced.
    modifier checkRebalance(address asset) {
        _requireNotPaused();
        _requireRebalanceDelayMet(asset);
        _;
    }

    /// @param issuer_ The LRT issuer that's authorized to deploy this contract.
    /// @param ethPOS_ The Ethereum POS deposit contract address.
    constructor(address issuer_, address ethPOS_) RioLRTCore(issuer_) {
        ethPOS = IETHPOSDeposit(ethPOS_);
    }

    /// @dev Initializes the contract.
    /// @param initialOwner The owner of the contract.
    /// @param token_ The address of the liquid restaking token.
    function initialize(address initialOwner, address token_) external initializer {
        __Ownable_init(initialOwner);
        __Pausable_init();
        __UUPSUpgradeable_init();
        __RioLRTCore_init(token_);

        _setRebalanceDelay(24 hours);
    }

    /// @notice Returns the total value of all underlying assets in the unit of account.
    function getTVL() public view returns (uint256 value) {
        return assetRegistry().getTVL();
    }

    // forgefmt: disable-next-item
    /// @notice Deposits ERC20 tokens and mints restaking token(s) to the caller.
    /// @param asset The asset being deposited.
    /// @param amountIn The amount of the asset being deposited.
    /// @dev Reentrancy protection is omitted as tokens with transfer hooks are not supported.
    /// Future inclusion of such tokens could risk reentrancy attacks. Developers should remain vigilant
    /// and consider safeguards if this assumption changes.
    function depositERC20(address asset, uint256 amountIn) external checkDeposit(asset, amountIn) returns (uint256 amountOut) {
        // Convert deposited asset amount to restaking tokens.
        amountOut = convertFromAssetToRestakingTokens(asset, amountIn);

        // Pull tokens from the sender to the deposit pool.
        IERC20(asset).safeTransferFrom(msg.sender, address(depositPool()), amountIn);

        // Mint restaking tokens to the caller.
        token.mint(msg.sender, amountOut);

        emit Deposited(msg.sender, asset, amountIn, amountOut);
    }

    /// @notice Deposits ETH and mints restaking token(s) to the caller.
    function depositETH() external payable returns (uint256) {
        return _depositETH();
    }

    // forgefmt: disable-next-item
    /// @notice Requests a withdrawal to `asset` for `amountIn` restaking tokens.
    /// @param asset The asset being withdrawn.
    /// @param amountIn The amount of restaking tokens being redeemed.
    function requestWithdrawal(address asset, uint256 amountIn) external checkWithdrawal(asset, amountIn) {
        // Pull restaking tokens from the sender to the withdrawal queue.
        token.safeTransferFrom(msg.sender, address(withdrawalQueue()), amountIn);

        IRioLRTWithdrawalQueue withdrawalQueue_ = withdrawalQueue();
        IRioLRTAssetRegistry assetRegistry_ = assetRegistry();

        // Ensure there are enough assets to cover the withdrawal request, and queue the withdrawal.
        uint256 sharesOwedInPastEpochs = withdrawalQueue_.getTotalSharesOwed(asset);
        uint256 sharesOwedInCurrentEpochAfterAmountIn = convertToSharesFromRestakingTokens(
            asset, withdrawalQueue_.getRestakingTokensInCurrentEpoch(asset) + amountIn
        );
        uint256 totalSharesAvailable = assetRegistry_.convertToSharesFromAsset(asset, assetRegistry_.getTotalBalanceForAsset(asset));

        if (sharesOwedInPastEpochs + sharesOwedInCurrentEpochAfterAmountIn > totalSharesAvailable) {
            revert INSUFFICIENT_SHARES_FOR_WITHDRAWAL();
        }
        withdrawalQueue().queueWithdrawal(msg.sender, asset, amountIn);
    }

    // forgefmt: disable-next-item
    /// @notice Rebalances ETH by processing outstanding withdrawals and depositing remaining
    /// ETH into EigenLayer.
    /// @param root The deposit merkle root.
    /// @param signature The guardian signature.
    /// @dev This function requires a guardian signature prior to depositing ETH into EigenLayer. If the
    /// guardian doesn't provide a signature within 24 hours, then the rebalance will be allowed without
    /// a signature, but only for withdrawals. In the future, this may be extended to allow a rebalance
    /// without a guardian signature without waiting 24 hours if withdrawals outnumber deposits.
    function rebalanceETH(bytes32 root, bytes calldata signature) external checkRebalance(ETH_ADDRESS) {
        if (!assetRegistry().isSupportedAsset(ETH_ADDRESS)) revert ASSET_NOT_SUPPORTED(ETH_ADDRESS);
        if (msg.sender != tx.origin) revert CALLER_MUST_BE_EOA();

        // If the guardian signature is verified, check if the deposit root is stale. Otherwise, check
        // the condition for a withdrawal-only rebalance.
        bool isGuardianSignatureVerified = _verifyGuardianSignature(root, signature);
        if (isGuardianSignatureVerified) {
            if (root != ethPOS.get_deposit_root()) {
                revert STALE_DEPOSIT_ROOT();
            }
        } else {
            bool isWithdrawalOnlyRebalanceAllowed = block.timestamp - assetNextRebalanceAfter[ETH_ADDRESS] >= 24 hours;
            if (!isWithdrawalOnlyRebalanceAllowed) {
                revert INVALID_GUARDIAN_SIGNATURE();
            }
        }

        // Process any outstanding withdrawals using funds from the deposit pool and EigenLayer.
        uint256 amountOutstanding = withdrawalQueue().getRestakingTokensInCurrentEpoch(ETH_ADDRESS);
        if (amountOutstanding > 0) {
            _processUserWithdrawalsForCurrentEpoch(ETH_ADDRESS, amountOutstanding);
        }

        // If the guardian signature is not verified, no rebalance should be attempted and the rebalance
        // should be considered complete, increasing the rebalance timestamp by the specified delay.
        if (!isGuardianSignatureVerified) {
            if (amountOutstanding == 0) {
                revert NO_REBALANCE_NEEDED();
            }
            assetNextRebalanceAfter[ETH_ADDRESS] = uint40(block.timestamp) + rebalanceDelay;

            emit PartiallyRebalanced(ETH_ADDRESS);
            return;
        }

        // Deposit remaining ETH into EigenLayer if the guardian signature has been verified. Deposit errors are caught to ensure
        // withdrawals are still processed in the event that deposit caps are reached within EigenLayer, or an unexpected error occurs.
        try depositPool().depositBalanceIntoEigenLayer(ETH_ADDRESS) returns (uint256 ethDeposited, bool canMakeAdditionalDeposit) {
            if (amountOutstanding == 0 && ethDeposited == 0) {
                revert NO_REBALANCE_NEEDED();
            }
            if (ethDeposited > 0) {
                assetRegistry().increaseUnverifiedValidatorETHBalance(ethDeposited);
            }

            // When the deposit is not capped, the rebalance is considered complete, and the asset rebalance
            // timestamp is increased by the specified delay. If capped, the asset may be rebalanced again
            // immediately as there are more assets to deposit.
            if (!canMakeAdditionalDeposit) {
                assetNextRebalanceAfter[ETH_ADDRESS] = uint40(block.timestamp) + rebalanceDelay;
            }
            emit Rebalanced(ETH_ADDRESS);
        } catch {
            // Always increase the next rebalance timestamp if deposits fail.
            assetNextRebalanceAfter[ETH_ADDRESS] = uint40(block.timestamp) + rebalanceDelay;

            emit PartiallyRebalanced(ETH_ADDRESS);
        }
    }

    /// @notice Rebalances the provided ERC20 `token` by processing outstanding withdrawals and
    /// depositing remaining tokens into EigenLayer.
    /// @param token The token to rebalance.
    function rebalanceERC20(address token) external checkRebalance(token) {
        if (!assetRegistry().isSupportedAsset(token)) revert ASSET_NOT_SUPPORTED(token);
        if (token == ETH_ADDRESS) revert INVALID_TOKEN_ADDRESS();
        if (msg.sender != tx.origin) revert CALLER_MUST_BE_EOA();

        // Process any outstanding withdrawals using funds from the deposit pool and EigenLayer.
        uint256 amountOutstanding = withdrawalQueue().getRestakingTokensInCurrentEpoch(token);
        if (amountOutstanding > 0) {
            _processUserWithdrawalsForCurrentEpoch(token, amountOutstanding);
        }

        // Deposit remaining tokens into EigenLayer. Deposit errors are caught to ensure withdrawals are still processed in the
        // event that deposit caps are reached within EigenLayer, or an unexpected error occurs.
        try depositPool().depositBalanceIntoEigenLayer(token) returns (uint256 sharesReceived, bool) {
            if (amountOutstanding == 0 && sharesReceived == 0) {
                revert NO_REBALANCE_NEEDED();
            }
            if (sharesReceived > 0) {
                assetRegistry().increaseSharesHeldForAsset(token, sharesReceived);
            }

            // ERC20 deposits are not currently capped, so the rebalance is considered complete.
            assetNextRebalanceAfter[token] = uint40(block.timestamp) + rebalanceDelay;

            emit Rebalanced(token);
        } catch {
            // Always increase the next rebalance timestamp if deposits fail.
            assetNextRebalanceAfter[token] = uint40(block.timestamp) + rebalanceDelay;

            emit PartiallyRebalanced(token);
        }
    }

    /// @notice Sets the rebalance delay.
    /// @param newRebalanceDelay The new rebalance delay, in seconds.
    function setRebalanceDelay(uint24 newRebalanceDelay) external onlyOwner {
        _setRebalanceDelay(newRebalanceDelay);
    }

    /// @notice Set the guardian signer address.
    /// @param newGuardianSigner The address of the new guardian signer.
    /// @dev Only callable by the owner.
    function setGuardianSigner(address newGuardianSigner) external onlyOwner {
        guardianSigner = newGuardianSigner;
        emit GuardianSignerSet(newGuardianSigner);
    }

    /// @notice Pauses the coordinator if any operator has forcefully undelegated one
    /// of our delegators.
    /// @dev Anyone can call this function.
    function emergencyPauseOperatorUndelegated() external {
        IRioLRTOperatorRegistry operatorRegistry_ = operatorRegistry();
        uint8 totalOperators = operatorRegistry_.operatorCount();

        for (uint8 id = 1; id <= totalOperators; id++) {
            if (!operatorRegistry_.getOperatorDetails(id).active) {
                continue; // Skip inactive operators.
            }

            IRioLRTOperatorDelegator delegator = operatorDelegator(operatorRegistry_, id);
            if (!delegator.delegationManager().isDelegated(address(delegator))) {
                _pause(); // Pause the contract and exit if any operator has been forcefully undelegated.
                return;
            }
        }
        revert NO_OPERATOR_UNDELEGATED();
    }

    /// @notice Pauses deposits, withdrawals, and rebalances.
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpauses deposits, withdrawals, and rebalances.
    function unpause() external onlyOwner {
        _unpause();
    }

    /// @notice Converts the unit of account value to its equivalent in restaking tokens.
    /// The unit of account is the price feed's quote asset.
    /// @param value The restaking token's value in the unit of account.
    function convertFromUnitOfAccountToRestakingTokens(uint256 value) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return value;
        }
        return value * supply / tvl;
    }

    /// @notice Converts an amount of restaking tokens to its equivalent value in the unit of account.
    /// The unit of account is the price feed's quote asset.
    /// @param amount The amount of restaking tokens to convert.
    function convertToUnitOfAccountFromRestakingTokens(uint256 amount) public view returns (uint256) {
        uint256 tvl = getTVL();
        uint256 supply = token.totalSupply();

        if (supply == 0) {
            return amount;
        }
        return tvl * amount / supply;
    }

    /// @notice Converts an asset amount to its equivalent value in restaking tokens.
    /// @param asset The address of the asset to convert.
    /// @param amount The amount of the asset to convert.
    function convertFromAssetToRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = assetRegistry().convertToUnitOfAccountFromAsset(asset, amount);
        return convertFromUnitOfAccountToRestakingTokens(value);
    }

    /// @notice Converts an amount of restaking tokens to the equivalent in the asset.
    /// @param asset The address of the asset to convert to.
    /// @param amount The amount of restaking tokens to convert.
    function convertToAssetFromRestakingTokens(address asset, uint256 amount) public view returns (uint256) {
        uint256 value = convertToUnitOfAccountFromRestakingTokens(amount);
        return assetRegistry().convertFromUnitOfAccountToAsset(asset, value);
    }

    /// @notice Converts an amount of restaking tokens to the equivalent in the provided
    /// asset's EigenLayer shares.
    /// @param asset The address of the asset whose EigenLayer shares to convert to.
    /// @param amount The amount of restaking tokens to convert.
    function convertToSharesFromRestakingTokens(address asset, uint256 amount) public view returns (uint256 shares) {
        uint256 assetAmount = convertToAssetFromRestakingTokens(asset, amount);
        return assetRegistry().convertToSharesFromAsset(asset, assetAmount);
    }

    /// @notice EIP-712 helper.
    /// @param structHash The hash of the struct.
    function hashTypedData(bytes32 structHash) external view returns (bytes32) {
        return _hashTypedData(structHash);
    }

    /// @notice Deposits ETH and mints restaking token(s) to the caller.
    receive() external payable {
        _depositETH();
    }

    /// @notice Deposits ETH and mints restaking token(s) to the caller.
    /// @dev This function assumes that the quote asset is ETH.
    function _depositETH() internal checkDeposit(ETH_ADDRESS, msg.value) returns (uint256 amountOut) {
        // Convert deposited ETH to restaking tokens and mint to the caller.
        amountOut = convertFromUnitOfAccountToRestakingTokens(msg.value);

        // Forward ETH to the deposit pool.
        address(depositPool()).transferETH(msg.value);

        // Mint restaking tokens to the caller.
        token.mint(msg.sender, amountOut);

        emit Deposited(msg.sender, ETH_ADDRESS, msg.value, amountOut);
    }

    /// @dev Sets the rebalance delay.
    /// @param newRebalanceDelay The new rebalance delay, in seconds.
    function _setRebalanceDelay(uint24 newRebalanceDelay) internal {
        if (newRebalanceDelay > MAX_REBALANCE_DELAY) revert REBALANCE_DELAY_TOO_LONG();
        rebalanceDelay = newRebalanceDelay;

        emit RebalanceDelaySet(newRebalanceDelay);
    }

    // forgefmt: disable-next-item
    /// @dev Processes user withdrawals for the provided asset by transferring available
    /// assets from the deposit pool and queueing any remaining amount for withdrawal from
    /// EigenLayer.
    /// @param asset The asset being withdrawn.
    /// @param amountOutstanding The amount restaking tokens requested for withdrawal in the current epoch.
    function _processUserWithdrawalsForCurrentEpoch(address asset, uint256 amountOutstanding) internal {
        IRioLRTWithdrawalQueue withdrawalQueue_ = withdrawalQueue();

        // Determine the share value of all restaking tokens in the epoch. If ETH, we must
        // reduce the precision to the nearest Gwei, which is the smallest unit of account
        // supported by EigenLayer.
        uint256 epochShareValue = convertToSharesFromRestakingTokens(asset, amountOutstanding);
        if (asset == ETH_ADDRESS) {
            epochShareValue = epochShareValue.reducePrecisionToGwei();
        }

        // Pay off as much as possible from the deposit pool.
        (uint256 assetsSent, uint256 sharesSent) = depositPool().transferMaxAssetsForShares(
            asset,
            epochShareValue,
            address(withdrawalQueue_)
        );
        uint256 sharesRemaining = epochShareValue - sharesSent;

        // Exit early if all pending withdrawals were paid from the deposit pool.
        if (sharesRemaining == 0) {
            withdrawalQueue_.settleCurrentEpochFromDepositPool(asset, assetsSent);
            return;
        }

        // Queue the remaining withdrawal amount from EigenLayer, if needed.
        address strategy = assetRegistry().getAssetStrategy(asset);
        bytes32 aggregateRoot = OperatorOperations.queueWithdrawalFromOperatorsForUserSettlement(
            operatorRegistry(),
            strategy,
            sharesRemaining
        );
        withdrawalQueue_.queueCurrentEpochSettlementFromEigenLayer(asset, assetsSent, sharesSent, epochShareValue, aggregateRoot);
    }

    /// @dev Returns the domain name and version for EIP-712 guardian signatures.
    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ('Rio Network', '1');
    }

    /// @dev Verify EIP-712 `DepositDataRoot` signature.
    /// @param root The deposit data merkle root to verify.
    /// @param signature The guardian signature to verify.
    function _verifyGuardianSignature(bytes32 root, bytes calldata signature) internal view returns (bool) {
        bytes32 digest = _hashTypedData(keccak256(abi.encode(DEPOSIT_ROOT_TYPEHASH, root)));
        return SignatureCheckerLib.isValidSignatureNowCalldata(guardianSigner, digest, signature);
    }

    /// @dev Reverts if the asset is not supported.
    /// @param asset The address of the asset.
    function _requireAssetSupported(address asset) internal view {
        if (!assetRegistry().isSupportedAsset(asset)) revert ASSET_NOT_SUPPORTED(asset);
    }

    /// @dev Reverts if the provided amount is zero.
    /// @param amount The amount being checked.
    function _requireAmountGreaterThanZero(uint256 amount) internal pure {
        if (amount == 0) revert AMOUNT_MUST_BE_GREATER_THAN_ZERO();
    }

    /// @dev Reverts if the deposit cap for the asset has been reached.
    /// @param asset The address of the asset.
    /// @param amountIn The amount of the asset being deposited.
    function _requireDepositCapNotReached(address asset, uint256 amountIn) internal view {
        IRioLRTAssetRegistry assetRegistry_ = assetRegistry();

        uint256 depositCap = assetRegistry_.getAssetDepositCap(asset);
        if (depositCap > 0) {
            uint256 existingBalance = assetRegistry_.getTotalBalanceForAsset(asset);
            if (existingBalance + amountIn > depositCap) {
                revert DEPOSIT_CAP_REACHED(asset, depositCap);
            }
        }
    }

    /// @dev Reverts if the rebalance delay has not been met.
    /// @param asset The asset being rebalanced.
    function _requireRebalanceDelayMet(address asset) internal view {
        if (block.timestamp < assetNextRebalanceAfter[asset]) revert REBALANCE_DELAY_NOT_MET();
    }

    /// @dev Allows the owner to upgrade the gateway implementation.
    /// @param newImplementation The implementation to upgrade to.
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {}
}


// ============================================================================
// FILE: lib/solady/src/utils/EIP712.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Contract for EIP-712 typed structured data hashing and signing.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/EIP712.sol)
/// @author Modified from Solbase (https://github.com/Sol-DAO/solbase/blob/main/src/utils/EIP712.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/EIP712.sol)
///
/// @dev Note, this implementation:
/// - Uses `address(this)` for the `verifyingContract` field.
/// - Does NOT use the optional EIP-712 salt.
/// - Does NOT use any EIP-712 extensions.
/// This is for simplicity and to save gas.
/// If you need to customize, please fork / modify accordingly.
abstract contract EIP712 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CONSTANTS AND IMMUTABLES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
    bytes32 internal constant _DOMAIN_TYPEHASH =
        0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    uint256 private immutable _cachedThis;
    uint256 private immutable _cachedChainId;
    bytes32 private immutable _cachedNameHash;
    bytes32 private immutable _cachedVersionHash;
    bytes32 private immutable _cachedDomainSeparator;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CONSTRUCTOR                         */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Cache the hashes for cheaper runtime gas costs.
    /// In the case of upgradeable contracts (i.e. proxies),
    /// or if the chain id changes due to a hard fork,
    /// the domain separator will be seamlessly calculated on-the-fly.
    constructor() {
        _cachedThis = uint256(uint160(address(this)));
        _cachedChainId = block.chainid;

        string memory name;
        string memory version;
        if (!_domainNameAndVersionMayChange()) (name, version) = _domainNameAndVersion();
        bytes32 nameHash = _domainNameAndVersionMayChange() ? bytes32(0) : keccak256(bytes(name));
        bytes32 versionHash =
            _domainNameAndVersionMayChange() ? bytes32(0) : keccak256(bytes(version));
        _cachedNameHash = nameHash;
        _cachedVersionHash = versionHash;

        bytes32 separator;
        if (!_domainNameAndVersionMayChange()) {
            /// @solidity memory-safe-assembly
            assembly {
                let m := mload(0x40) // Load the free memory pointer.
                mstore(m, _DOMAIN_TYPEHASH)
                mstore(add(m, 0x20), nameHash)
                mstore(add(m, 0x40), versionHash)
                mstore(add(m, 0x60), chainid())
                mstore(add(m, 0x80), address())
                separator := keccak256(m, 0xa0)
            }
        }
        _cachedDomainSeparator = separator;
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   FUNCTIONS TO OVERRIDE                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Please override this function to return the domain name and version.
    /// ```
    ///     function _domainNameAndVersion()
    ///         internal
    ///         pure
    ///         virtual
    ///         returns (string memory name, string memory version)
    ///     {
    ///         name = "Solady";
    ///         version = "1";
    ///     }
    /// ```
    ///
    /// Note: If the returned result may change after the contract has been deployed,
    /// you must override `_domainNameAndVersionMayChange()` to return true.
    function _domainNameAndVersion()
        internal
        view
        virtual
        returns (string memory name, string memory version);

    /// @dev Returns if `_domainNameAndVersion()` may change
    /// after the contract has been deployed (i.e. after the constructor).
    /// Default: false.
    function _domainNameAndVersionMayChange() internal pure virtual returns (bool result) {}

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the EIP-712 domain separator.
    function _domainSeparator() internal view virtual returns (bytes32 separator) {
        if (_domainNameAndVersionMayChange()) {
            separator = _buildDomainSeparator();
        } else {
            separator = _cachedDomainSeparator;
            if (_cachedDomainSeparatorInvalidated()) separator = _buildDomainSeparator();
        }
    }

    /// @dev Returns the hash of the fully encoded EIP-712 message for this domain,
    /// given `structHash`, as defined in
    /// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct.
    ///
    /// The hash can be used together with {ECDSA-recover} to obtain the signer of a message:
    /// ```
    ///     bytes32 digest = _hashTypedData(keccak256(abi.encode(
    ///         keccak256("Mail(address to,string contents)"),
    ///         mailTo,
    ///         keccak256(bytes(mailContents))
    ///     )));
    ///     address signer = ECDSA.recover(digest, signature);
    /// ```
    function _hashTypedData(bytes32 structHash) internal view virtual returns (bytes32 digest) {
        // We will use `digest` to store the domain separator to save a bit of gas.
        if (_domainNameAndVersionMayChange()) {
            digest = _buildDomainSeparator();
        } else {
            digest = _cachedDomainSeparator;
            if (_cachedDomainSeparatorInvalidated()) digest = _buildDomainSeparator();
        }
        /// @solidity memory-safe-assembly
        assembly {
            // Compute the digest.
            mstore(0x00, 0x1901000000000000) // Store "\x19\x01".
            mstore(0x1a, digest) // Store the domain separator.
            mstore(0x3a, structHash) // Store the struct hash.
            digest := keccak256(0x18, 0x42)
            // Restore the part of the free memory slot that was overwritten.
            mstore(0x3a, 0)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    EIP-5267 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev See: https://eips.ethereum.org/EIPS/eip-5267
    function eip712Domain()
        public
        view
        virtual
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
        fields = hex"0f"; // `0b01111`.
        (name, version) = _domainNameAndVersion();
        chainId = block.chainid;
        verifyingContract = address(this);
        salt = salt; // `bytes32(0)`.
        extensions = extensions; // `new uint256[](0)`.
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns the EIP-712 domain separator.
    function _buildDomainSeparator() private view returns (bytes32 separator) {
        // We will use `separator` to store the name hash to save a bit of gas.
        bytes32 versionHash;
        if (_domainNameAndVersionMayChange()) {
            (string memory name, string memory version) = _domainNameAndVersion();
            separator = keccak256(bytes(name));
            versionHash = keccak256(bytes(version));
        } else {
            separator = _cachedNameHash;
            versionHash = _cachedVersionHash;
        }
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Load the free memory pointer.
            mstore(m, _DOMAIN_TYPEHASH)
            mstore(add(m, 0x20), separator) // Name hash.
            mstore(add(m, 0x40), versionHash)
            mstore(add(m, 0x60), chainid())
            mstore(add(m, 0x80), address())
            separator := keccak256(m, 0xa0)
        }
    }

    /// @dev Returns if the cached domain separator has been invalidated.
    function _cachedDomainSeparatorInvalidated() private view returns (bool result) {
        uint256 cachedChainId = _cachedChainId;
        uint256 cachedThis = _cachedThis;
        /// @solidity memory-safe-assembly
        assembly {
            result := iszero(and(eq(chainid(), cachedChainId), eq(address(), cachedThis)))
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/IERC20.sol)

pragma solidity ^0.8.20;

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
     * @dev Returns the value of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the value of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves a `value` amount of tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 value) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets a `value` amount of tokens as the allowance of `spender` over the
     * caller's tokens.
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
    function approve(address spender, uint256 value) external returns (bool);

    /**
     * @dev Moves a `value` amount of tokens from `from` to `to` using the
     * allowance mechanism. `value` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}


// ============================================================================
// FILE: lib/solady/src/utils/SignatureCheckerLib.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Signature verification helper that supports both ECDSA signatures from EOAs
/// and ERC1271 signatures from smart contract wallets like Argent and Gnosis safe.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SignatureCheckerLib.sol)
/// @author Modified from OpenZeppelin (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol)
///
/// @dev Note:
/// - The signature checking functions use the ecrecover precompile (0x1).
/// - The `bytes memory signature` variants use the identity precompile (0x4)
///   to copy memory internally.
/// - Unlike ECDSA signatures, contract signatures are revocable.
/// - As of Solady version 0.0.134, all `bytes signature` variants accept both
///   regular 65-byte `(r, s, v)` and EIP-2098 `(r, vs)` short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098
///   This is for calldata efficiency on smart accounts prevalent on L2s.
///
/// WARNING! Do NOT use signatures as unique identifiers:
/// - Use a nonce in the digest to prevent replay attacks on the same contract.
/// - Use EIP-712 for the digest to prevent replay attacks across different chains and contracts.
///   EIP-712 also enables readable signing of typed data for better user safety.
/// This implementation does NOT check if a signature is non-malleable.
library SignatureCheckerLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               SIGNATURE CHECKING OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer` is a smart contract, the signature is validated with ERC1271.
    /// Otherwise, the signature is validated with `ECDSA.recover`.
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Clean the upper 96 bits of `signer` in case they are dirty.
            for { signer := shr(96, shl(96, signer)) } signer {} {
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) // `r`.
                if eq(mload(signature), 64) {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let t :=
                        staticcall(
                            gas(), // Amount of gas left for the transaction.
                            1, // Address of `ecrecover`.
                            0x00, // Start of input.
                            0x80, // Size of input.
                            0x01, // Start of output.
                            0x20 // Size of output.
                        )
                    // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                        isValid := 1
                        mstore(0x60, 0) // Restore the zero slot.
                        mstore(0x40, m) // Restore the free memory pointer.
                        break
                    }
                }
                if eq(mload(signature), 65) {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                    mstore(0x60, mload(add(signature, 0x40))) // `s`.
                    let t :=
                        staticcall(
                            gas(), // Amount of gas left for the transaction.
                            1, // Address of `ecrecover`.
                            0x00, // Start of input.
                            0x80, // Size of input.
                            0x01, // Start of output.
                            0x20 // Size of output.
                        )
                    // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                        isValid := 1
                        mstore(0x60, 0) // Restore the zero slot.
                        mstore(0x40, m) // Restore the free memory pointer.
                        break
                    }
                }
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.

                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                // Copy the `signature` over.
                let n := add(0x20, mload(signature))
                pop(staticcall(gas(), 4, signature, n, add(m, 0x44), n))
                // forgefmt: disable-next-item
                isValid := and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        signer, // The `signer` address.
                        m, // Offset of calldata in memory.
                        add(returndatasize(), 0x44), // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
                break
            }
        }
    }

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer` is a smart contract, the signature is validated with ERC1271.
    /// Otherwise, the signature is validated with `ECDSA.recover`.
    function isValidSignatureNowCalldata(address signer, bytes32 hash, bytes calldata signature)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Clean the upper 96 bits of `signer` in case they are dirty.
            for { signer := shr(96, shl(96, signer)) } signer {} {
                let m := mload(0x40)
                mstore(0x00, hash)
                if eq(signature.length, 64) {
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let t :=
                        staticcall(
                            gas(), // Amount of gas left for the transaction.
                            1, // Address of `ecrecover`.
                            0x00, // Start of input.
                            0x80, // Size of input.
                            0x01, // Start of output.
                            0x20 // Size of output.
                        )
                    // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                        isValid := 1
                        mstore(0x60, 0) // Restore the zero slot.
                        mstore(0x40, m) // Restore the free memory pointer.
                        break
                    }
                }
                if eq(signature.length, 65) {
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                    calldatacopy(0x40, signature.offset, 0x40) // `r`, `s`.
                    let t :=
                        staticcall(
                            gas(), // Amount of gas left for the transaction.
                            1, // Address of `ecrecover`.
                            0x00, // Start of input.
                            0x80, // Size of input.
                            0x01, // Start of output.
                            0x20 // Size of output.
                        )
                    // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                    if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                        isValid := 1
                        mstore(0x60, 0) // Restore the zero slot.
                        mstore(0x40, m) // Restore the free memory pointer.
                        break
                    }
                }
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.

                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), signature.length)
                // Copy the `signature` over.
                calldatacopy(add(m, 0x64), signature.offset, signature.length)
                // forgefmt: disable-next-item
                isValid := and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        signer, // The `signer` address.
                        m, // Offset of calldata in memory.
                        add(signature.length, 0x64), // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
                break
            }
        }
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `signer` and `hash`.
    /// If `signer` is a smart contract, the signature is validated with ERC1271.
    /// Otherwise, the signature is validated with `ECDSA.recover`.
    function isValidSignatureNow(address signer, bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Clean the upper 96 bits of `signer` in case they are dirty.
            for { signer := shr(96, shl(96, signer)) } signer {} {
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x20, add(shr(255, vs), 27)) // `v`.
                mstore(0x40, r) // `r`.
                mstore(0x60, shr(1, shl(1, vs))) // `s`.
                let t :=
                    staticcall(
                        gas(), // Amount of gas left for the transaction.
                        1, // Address of `ecrecover`.
                        0x00, // Start of input.
                        0x80, // Size of input.
                        0x01, // Start of output.
                        0x20 // Size of output.
                    )
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                    isValid := 1
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }

                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), 65) // Length of the signature.
                mstore(add(m, 0x64), r) // `r`.
                mstore(add(m, 0x84), mload(0x60)) // `s`.
                mstore8(add(m, 0xa4), mload(0x20)) // `v`.
                // forgefmt: disable-next-item
                isValid := and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        signer, // The `signer` address.
                        m, // Offset of calldata in memory.
                        0xa5, // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `signer` and `hash`.
    /// If `signer` is a smart contract, the signature is validated with ERC1271.
    /// Otherwise, the signature is validated with `ECDSA.recover`.
    function isValidSignatureNow(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Clean the upper 96 bits of `signer` in case they are dirty.
            for { signer := shr(96, shl(96, signer)) } signer {} {
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x20, and(v, 0xff)) // `v`.
                mstore(0x40, r) // `r`.
                mstore(0x60, s) // `s`.
                let t :=
                    staticcall(
                        gas(), // Amount of gas left for the transaction.
                        1, // Address of `ecrecover`.
                        0x00, // Start of input.
                        0x80, // Size of input.
                        0x01, // Start of output.
                        0x20 // Size of output.
                    )
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                if iszero(or(iszero(returndatasize()), xor(signer, mload(t)))) {
                    isValid := 1
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }

                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), 65) // Length of the signature.
                mstore(add(m, 0x64), r) // `r`.
                mstore(add(m, 0x84), s) // `s`.
                mstore8(add(m, 0xa4), v) // `v`.
                // forgefmt: disable-next-item
                isValid := and(
                    // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                    eq(mload(d), f),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        signer, // The `signer` address.
                        m, // Offset of calldata in memory.
                        0xa5, // Length of calldata in memory.
                        d, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes memory signature)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            // Copy the `signature` over.
            let n := add(0x20, mload(signature))
            pop(staticcall(gas(), 4, signature, n, add(m, 0x44), n))
            // forgefmt: disable-next-item
            isValid := and(
                // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                eq(mload(d), f),
                // Whether the staticcall does not revert.
                // This must be placed at the end of the `and` clause,
                // as the arguments are evaluated from right to left.
                staticcall(
                    gas(), // Remaining gas.
                    signer, // The `signer` address.
                    m, // Offset of calldata in memory.
                    add(returndatasize(), 0x44), // Length of calldata in memory.
                    d, // Offset of returndata.
                    0x20 // Length of returndata to write.
                )
            )
        }
    }

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata signature
    ) internal view returns (bool isValid) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), signature.length)
            // Copy the `signature` over.
            calldatacopy(add(m, 0x64), signature.offset, signature.length)
            // forgefmt: disable-next-item
            isValid := and(
                // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                eq(mload(d), f),
                // Whether the staticcall does not revert.
                // This must be placed at the end of the `and` clause,
                // as the arguments are evaluated from right to left.
                staticcall(
                    gas(), // Remaining gas.
                    signer, // The `signer` address.
                    m, // Offset of calldata in memory.
                    add(signature.length, 0x64), // Length of calldata in memory.
                    d, // Offset of returndata.
                    0x20 // Length of returndata to write.
                )
            )
        }
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes32 r, bytes32 vs)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), 65) // Length of the signature.
            mstore(add(m, 0x64), r) // `r`.
            mstore(add(m, 0x84), shr(1, shl(1, vs))) // `s`.
            mstore8(add(m, 0xa4), add(shr(255, vs), 27)) // `v`.
            // forgefmt: disable-next-item
            isValid := and(
                // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                eq(mload(d), f),
                // Whether the staticcall does not revert.
                // This must be placed at the end of the `and` clause,
                // as the arguments are evaluated from right to left.
                staticcall(
                    gas(), // Remaining gas.
                    signer, // The `signer` address.
                    m, // Offset of calldata in memory.
                    0xa5, // Length of calldata in memory.
                    d, // Offset of returndata.
                    0x20 // Length of returndata to write.
                )
            )
        }
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(address signer, bytes32 hash, uint8 v, bytes32 r, bytes32 s)
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), 65) // Length of the signature.
            mstore(add(m, 0x64), r) // `r`.
            mstore(add(m, 0x84), s) // `s`.
            mstore8(add(m, 0xa4), v) // `v`.
            // forgefmt: disable-next-item
            isValid := and(
                // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                eq(mload(d), f),
                // Whether the staticcall does not revert.
                // This must be placed at the end of the `and` clause,
                // as the arguments are evaluated from right to left.
                staticcall(
                    gas(), // Remaining gas.
                    signer, // The `signer` address.
                    m, // Offset of calldata in memory.
                    0xa5, // Length of calldata in memory.
                    d, // Offset of returndata.
                    0x20 // Length of returndata to write.
                )
            )
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an Ethereum Signed Message, created from a `hash`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            result := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }
    }

    /// @dev Returns an Ethereum Signed Message, created from `s`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    /// Note: Supports lengths of `s` up to 999999 bytes.
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let sLength := mload(s)
            let o := 0x20
            mstore(o, "\x19Ethereum Signed Message:\n") // 26 bytes, zero-right-padded.
            mstore(0x00, 0x00)
            // Convert the `s.length` to ASCII decimal representation: `base10(s.length)`.
            for { let temp := sLength } 1 {} {
                o := sub(o, 1)
                mstore8(o, add(48, mod(temp, 10)))
                temp := div(temp, 10)
                if iszero(temp) { break }
            }
            let n := sub(0x3a, o) // Header length: `26 + 32 - o`.
            // Throw an out-of-offset error (consumes all gas) if the header exceeds 32 bytes.
            returndatacopy(returndatasize(), returndatasize(), gt(n, 0x20))
            mstore(s, or(mload(0x00), mload(n))) // Temporarily store the header.
            result := keccak256(add(s, sub(0x20, n)), add(n, sLength))
            mstore(s, sLength) // Restore the length.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EMPTY CALLDATA HELPERS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an empty calldata bytes.
    function emptySignature() internal pure returns (bytes calldata signature) {
        /// @solidity memory-safe-assembly
        assembly {
            signature.length := 0
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/utils/SafeERC20.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/utils/SafeERC20.sol)

pragma solidity ^0.8.20;

import {IERC20} from "../IERC20.sol";
import {IERC20Permit} from "../extensions/IERC20Permit.sol";
import {Address} from "../../../utils/Address.sol";

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
     * @dev An operation with an ERC20 token failed.
     */
    error SafeERC20FailedOperation(address token);

    /**
     * @dev Indicates a failed `decreaseAllowance` request.
     */
    error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

    /**
     * @dev Transfer `value` amount of `token` from the calling contract to `to`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transfer, (to, value)));
    }

    /**
     * @dev Transfer `value` amount of `token` from `from` to `to`, spending the approval given by `from` to the
     * calling contract. If `token` returns no value, non-reverting calls are assumed to be successful.
     */
    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeCall(token.transferFrom, (from, to, value)));
    }

    /**
     * @dev Increase the calling contract's allowance toward `spender` by `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful.
     */
    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 oldAllowance = token.allowance(address(this), spender);
        forceApprove(token, spender, oldAllowance + value);
    }

    /**
     * @dev Decrease the calling contract's allowance toward `spender` by `requestedDecrease`. If `token` returns no
     * value, non-reverting calls are assumed to be successful.
     */
    function safeDecreaseAllowance(IERC20 token, address spender, uint256 requestedDecrease) internal {
        unchecked {
            uint256 currentAllowance = token.allowance(address(this), spender);
            if (currentAllowance < requestedDecrease) {
                revert SafeERC20FailedDecreaseAllowance(spender, currentAllowance, requestedDecrease);
            }
            forceApprove(token, spender, currentAllowance - requestedDecrease);
        }
    }

    /**
     * @dev Set the calling contract's allowance toward `spender` to `value`. If `token` returns no value,
     * non-reverting calls are assumed to be successful. Meant to be used with tokens that require the approval
     * to be set to zero before setting it to a non-zero value, such as USDT.
     */
    function forceApprove(IERC20 token, address spender, uint256 value) internal {
        bytes memory approvalCall = abi.encodeCall(token.approve, (spender, value));

        if (!_callOptionalReturnBool(token, approvalCall)) {
            _callOptionalReturn(token, abi.encodeCall(token.approve, (spender, 0)));
            _callOptionalReturn(token, approvalCall);
        }
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

        bytes memory returndata = address(token).functionCall(data);
        if (returndata.length != 0 && !abi.decode(returndata, (bool))) {
            revert SafeERC20FailedOperation(address(token));
        }
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
        return success && (returndata.length == 0 || abi.decode(returndata, (bool))) && address(token).code.length > 0;
    }
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTWithdrawalQueue.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IRioLRTWithdrawalQueue {
    /// @notice How many shares are owed to a user in a given epoch,
    /// as well as whether or not the user has completed the withdrawal.
    struct UserWithdrawalSummary {
        /// @dev Indicates whether or not the user has completed the withdrawal.
        bool claimed;
        /// @dev The amount of restaking tokens requested for withdrawal.
        uint120 amountIn;
    }

    /// @notice How many shares owed to all users in a given epoch,
    /// as well as whether or not the epoch's withdrawals have been completed.
    struct EpochWithdrawals {
        /// @dev Indicates whether or not the epoch has been settled.
        bool settled;
        /// @dev The total amount of restaking tokens requested for withdrawal in the epoch.
        uint120 amountIn;
        /// @dev The amount of assets received to settle the epoch.
        uint120 assetsReceived;
        /// @dev The total number of shares outstanding in the epoch.
        uint120 sharesOutstanding;
        /// @dev The amount of restaking tokens that to burn upon epoch settlement.
        uint120 amountToBurnAtSettlement;
        /// @dev The aggregate root of the queued EigenLayer withdrawals.
        bytes32 aggregateRoot;
        /// @dev All user withdrawals in the epoch.
        mapping(address => UserWithdrawalSummary) users;
    }

    /// @notice Epoch withdrawal information without the mapping, which
    /// allows us to return the struct from a view function.
    struct EpochWithdrawalSummary {
        /// @dev Indicates whether or not the epoch has been settled.
        bool settled;
        /// @dev The amount of restaking tokens requested for withdrawal in the epoch.
        uint120 amountIn;
        /// @dev The amount of assets received to settle the epoch.
        uint120 assetsReceived;
        /// @dev The total number of shares outstanding in the epoch.
        uint120 sharesOutstanding;
        /// @dev The amount of restaking tokens that to burn upon epoch settlement.
        uint120 amountToBurnAtSettlement;
        /// @dev The aggregate root of the queued EigenLayer withdrawals.
        bytes32 aggregateRoot;
    }

    /// @notice The information needed to claim an owed asset in a given epoch.
    struct ClaimRequest {
        address asset;
        uint256 epoch;
    }

    /// @notice Thrown when the amount in is zero.
    error NO_AMOUNT_IN();

    /// @notice Thrown when there is nothing to claim.
    error NOTHING_TO_CLAIM();

    /// @notice Thrown when attempting an operation on an epoch with no withdrawals.
    error NO_WITHDRAWALS_IN_EPOCH();

    /// @notice Thrown when attempting to settle an epoch that has already been settled.
    error EPOCH_ALREADY_SETTLED();

    /// @notice Thrown when attempting to withdraw from an epoch that has not been settled.
    error EPOCH_NOT_SETTLED();

    /// @notice Thrown when attempting to queue withdrawals for an epoch that has already been queued.
    error WITHDRAWALS_ALREADY_QUEUED_FOR_EPOCH();

    /// @notice Thrown when attempting to settle an epoch that has not been queued from EigenLayer.
    error WITHDRAWALS_NOT_QUEUED_FOR_EPOCH();

    /// @notice Thrown when attempting to claim a withdrawal that has already been claimed.
    error WITHDRAWAL_ALREADY_CLAIMED();

    /// @notice Thrown when the calculated aggregate withdrawal root does not match the stored root.
    error INVALID_AGGREGATE_WITHDRAWAL_ROOT();

    /// @notice Thrown when an incorrect number of middleware times indexes are provided.
    error INVALID_MIDDLEWARE_TIMES_INDEXES_LENGTH();

    /// @notice Emitted when a user withdrawal is queued.
    /// @param epoch The epoch containing the withdrawal.
    /// @param asset The address of the asset.
    /// @param withdrawer The address of the withdrawer.
    /// @param amountIn The amount of restaking tokens pulled from the user.
    event WithdrawalQueued(uint256 indexed epoch, address asset, address withdrawer, uint256 amountIn);

    /// @notice Emitted when a user claims a withdrawal.
    /// @param epoch The epoch containing the withdrawal.
    /// @param asset The address of the asset.
    /// @param withdrawer The address of the withdrawer.
    /// @param amountOut The amount of assets received.
    event WithdrawalsClaimedForEpoch(uint256 indexed epoch, address asset, address withdrawer, uint256 amountOut);

    /// @notice Emitted when an epoch is settled from the deposit pool.
    /// @param epoch The epoch that was settled.
    /// @param asset The address of the asset that was settled.
    /// @param assetsReceived The amount of assets received to settle the epoch.
    event EpochSettledFromDepositPool(uint256 indexed epoch, address asset, uint256 assetsReceived);

    /// @notice Emitted when an epoch is queued for settlement via EigenLayer.
    /// @param epoch The epoch that was queued.
    /// @param asset The address of the asset that was queued.
    /// @param assetsReceived The amount of assets received from the deposit pool.
    /// @param shareValueOfAssetsReceived The value of the assets received in EigenLayer shares.
    /// @param totalShareValueAtRebalance The total epoch share value at the time of rebalance.
    /// @param restakingTokensBurned The amount of restaking tokens burned.
    /// @param aggregateRoot The aggregate root of the queued EigenLayer withdrawals.
    event EpochQueuedForSettlementFromEigenLayer(
        uint256 indexed epoch,
        address asset,
        uint256 assetsReceived,
        uint256 shareValueOfAssetsReceived,
        uint256 totalShareValueAtRebalance,
        uint256 restakingTokensBurned,
        bytes32 aggregateRoot
    );

    /// @notice Emitted when an epoch is settled from EigenLayer.
    /// @param epoch The epoch that was settled.
    /// @param asset The address of the asset that was settled.
    /// @param assetsReceived The amount of assets received to settle the epoch.
    event EpochSettledFromEigenLayer(uint256 indexed epoch, address asset, uint256 assetsReceived);

    /// @notice Initializes the contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param token The address of the liquid restaking token.
    function initialize(address initialOwner, address token) external;

    /// @notice Retrieve the current withdrawal epoch for a given asset.
    /// @param asset The asset to retrieve the current epoch for.
    function getCurrentEpoch(address asset) external view returns (uint256);

    /// @notice Get the amount of restaking tokens requested for withdrawal in the current `epoch` for `asset`.
    /// @param asset The address of the withdrawal asset.
    function getRestakingTokensInCurrentEpoch(address asset) external view returns (uint256);

    /// @notice Get the total amount of shares owed to withdrawers across all epochs for `asset`.
    /// @param asset The address of the withdrawal asset.
    function getTotalSharesOwed(address asset) external view returns (uint256);

    /// @notice Retrieve withdrawal epoch information for a given asset and epoch.
    /// @param asset The withdrawal asset.
    /// @param epoch The epoch for which to retrieve the information.
    function getEpochWithdrawalSummary(address asset, uint256 epoch)
        external
        view
        returns (EpochWithdrawalSummary memory);

    /// @notice Retrieve a user's withdrawal information for a given asset and epoch.
    /// @param asset The withdrawal asset.
    /// @param epoch The epoch for which to retrieve the information.
    /// @param user The address of the user for which to retrieve the information.
    function getUserWithdrawalSummary(address asset, uint256 epoch, address user)
        external
        view
        returns (UserWithdrawalSummary memory);

    /// @notice Queue withdrawal of `asset` to `withdrawer` in the current epoch. The withdrawal
    /// can be claimed as the underlying asset by the withdrawer once the current epoch is settled.
    /// @param withdrawer The address requesting the withdrawal.
    /// @param asset The address of the asset being withdrawn.
    /// @param amountIn The amount of restaking tokens pulled from the withdrawer.
    function queueWithdrawal(address withdrawer, address asset, uint256 amountIn) external;

    /// @notice Withdraws all `asset` owed to the caller in a given epoch.
    /// @param request The asset claim request.
    function claimWithdrawalsForEpoch(ClaimRequest calldata request) external returns (uint256 amountOut);

    /// @notice Withdraws owed assets owed to the caller from many withdrawal requests.
    /// @param requests The withdrawal claim request.
    function claimWithdrawalsForManyEpochs(ClaimRequest[] calldata requests)
        external
        returns (uint256[] memory amountsOut);

    /// @notice Settle the current epoch for `asset` using `assetsReceived` from the deposit pool.
    /// @param asset The address of the withdrawal asset.
    /// @param assetsReceived The amount of assets received to settle the epoch.
    function settleCurrentEpochFromDepositPool(address asset, uint256 assetsReceived) external;

    /// @notice Queues the current epoch for `asset` settlement via EigenLayer and record
    /// the amount of assets received from the deposit pool.
    /// @param asset The address of the withdrawal asset.
    /// @param assetsReceived The amount of assets received from the deposit pool.
    /// @param shareValueOfAssetsReceived The value of the assets received in EigenLayer shares.
    /// @param totalShareValueAtRebalance The total epoch share value at the time of rebalance.
    /// @param aggregateRoot The aggregate root of the queued EigenLayer withdrawals.
    function queueCurrentEpochSettlementFromEigenLayer(
        address asset,
        uint256 assetsReceived,
        uint256 shareValueOfAssetsReceived,
        uint256 totalShareValueAtRebalance,
        bytes32 aggregateRoot
    ) external;
}


// ============================================================================
// FILE: lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/UUPSUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/UUPSUpgradeable.sol)

pragma solidity ^0.8.20;

import {IERC1822Proxiable} from "@openzeppelin/contracts/interfaces/draft-IERC1822.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Initializable} from "./Initializable.sol";

/**
 * @dev An upgradeability mechanism designed for UUPS proxies. The functions included here can perform an upgrade of an
 * {ERC1967Proxy}, when this contract is set as the implementation behind such a proxy.
 *
 * A security mechanism ensures that an upgrade does not turn off upgradeability accidentally, although this risk is
 * reinstated if the upgrade retains upgradeability but removes the security mechanism, e.g. by replacing
 * `UUPSUpgradeable` with a custom implementation of upgrades.
 *
 * The {_authorizeUpgrade} function must be overridden to include access restriction to the upgrade mechanism.
 */
abstract contract UUPSUpgradeable is Initializable, IERC1822Proxiable {
    /// @custom:oz-upgrades-unsafe-allow state-variable-immutable
    address private immutable __self = address(this);

    /**
     * @dev The version of the upgrade interface of the contract. If this getter is missing, both `upgradeTo(address)`
     * and `upgradeToAndCall(address,bytes)` are present, and `upgradeTo` must be used if no function should be called,
     * while `upgradeToAndCall` will invoke the `receive` function if the second argument is the empty byte string.
     * If the getter returns `"5.0.0"`, only `upgradeToAndCall(address,bytes)` is present, and the second argument must
     * be the empty byte string if no function should be called, making it impossible to invoke the `receive` function
     * during an upgrade.
     */
    string public constant UPGRADE_INTERFACE_VERSION = "5.0.0";

    /**
     * @dev The call is from an unauthorized context.
     */
    error UUPSUnauthorizedCallContext();

    /**
     * @dev The storage `slot` is unsupported as a UUID.
     */
    error UUPSUnsupportedProxiableUUID(bytes32 slot);

    /**
     * @dev Check that the execution is being performed through a delegatecall call and that the execution context is
     * a proxy contract with an implementation (as defined in ERC1967) pointing to self. This should only be the case
     * for UUPS and transparent proxies that are using the current contract as their implementation. Execution of a
     * function through ERC1167 minimal proxies (clones) would not normally pass this test, but is not guaranteed to
     * fail.
     */
    modifier onlyProxy() {
        _checkProxy();
        _;
    }

    /**
     * @dev Check that the execution is not being performed through a delegate call. This allows a function to be
     * callable on the implementing contract but not through proxies.
     */
    modifier notDelegated() {
        _checkNotDelegated();
        _;
    }

    function __UUPSUpgradeable_init() internal onlyInitializing {
    }

    function __UUPSUpgradeable_init_unchained() internal onlyInitializing {
    }
    /**
     * @dev Implementation of the ERC1822 {proxiableUUID} function. This returns the storage slot used by the
     * implementation. It is used to validate the implementation's compatibility when performing an upgrade.
     *
     * IMPORTANT: A proxy pointing at a proxiable contract should not be considered proxiable itself, because this risks
     * bricking a proxy that upgrades to it, by delegating to itself until out of gas. Thus it is critical that this
     * function revert if invoked through a proxy. This is guaranteed by the `notDelegated` modifier.
     */
    function proxiableUUID() external view virtual notDelegated returns (bytes32) {
        return ERC1967Utils.IMPLEMENTATION_SLOT;
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
        _upgradeToAndCallUUPS(newImplementation, data);
    }

    /**
     * @dev Reverts if the execution is not performed via delegatecall or the execution
     * context is not of a proxy with an ERC1967-compliant implementation pointing to self.
     * See {_onlyProxy}.
     */
    function _checkProxy() internal view virtual {
        if (
            address(this) == __self || // Must be called through delegatecall
            ERC1967Utils.getImplementation() != __self // Must be called through an active proxy
        ) {
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Reverts if the execution is performed via delegatecall.
     * See {notDelegated}.
     */
    function _checkNotDelegated() internal view virtual {
        if (address(this) != __self) {
            // Must not be called through delegatecall
            revert UUPSUnauthorizedCallContext();
        }
    }

    /**
     * @dev Function that should revert when `msg.sender` is not authorized to upgrade the contract. Called by
     * {upgradeToAndCall}.
     *
     * Normally, this function will use an xref:access.adoc[access control] modifier such as {Ownable-onlyOwner}.
     *
     * ```solidity
     * function _authorizeUpgrade(address) internal onlyOwner {}
     * ```
     */
    function _authorizeUpgrade(address newImplementation) internal virtual;

    /**
     * @dev Performs an implementation upgrade with a security check for UUPS proxies, and additional setup call.
     *
     * As a security check, {proxiableUUID} is invoked in the new implementation, and the return value
     * is expected to be the implementation slot in ERC1967.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function _upgradeToAndCallUUPS(address newImplementation, bytes memory data) private {
        try IERC1822Proxiable(newImplementation).proxiableUUID() returns (bytes32 slot) {
            if (slot != ERC1967Utils.IMPLEMENTATION_SLOT) {
                revert UUPSUnsupportedProxiableUUID(slot);
            }
            ERC1967Utils.upgradeToAndCall(newImplementation, data);
        } catch {
            // The implementation is not UUPS
            revert ERC1967Utils.ERC1967InvalidImplementation(newImplementation);
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts-upgradeable/contracts/utils/PausableUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/Pausable.sol)

pragma solidity ^0.8.20;

import {ContextUpgradeable} from "../utils/ContextUpgradeable.sol";
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
    /// @custom:storage-location erc7201:openzeppelin.storage.Pausable
    struct PausableStorage {
        bool _paused;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Pausable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant PausableStorageLocation = 0xcd5ed15c6e187e77e9aee88184c21f4f2182ab5827cb3b7e07fbedcd63f03300;

    function _getPausableStorage() private pure returns (PausableStorage storage $) {
        assembly {
            $.slot := PausableStorageLocation
        }
    }

    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    /**
     * @dev The operation failed because the contract is paused.
     */
    error EnforcedPause();

    /**
     * @dev The operation failed because the contract is not paused.
     */
    error ExpectedPause();

    /**
     * @dev Initializes the contract in unpaused state.
     */
    function __Pausable_init() internal onlyInitializing {
        __Pausable_init_unchained();
    }

    function __Pausable_init_unchained() internal onlyInitializing {
        PausableStorage storage $ = _getPausableStorage();
        $._paused = false;
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
        PausableStorage storage $ = _getPausableStorage();
        return $._paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        if (paused()) {
            revert EnforcedPause();
        }
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        if (!paused()) {
            revert ExpectedPause();
        }
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        PausableStorage storage $ = _getPausableStorage();
        $._paused = true;
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
        PausableStorage storage $ = _getPausableStorage();
        $._paused = false;
        emit Unpaused(_msgSender());
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts-upgradeable/contracts/access/OwnableUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (access/Ownable.sol)

pragma solidity ^0.8.20;

import {ContextUpgradeable} from "../utils/ContextUpgradeable.sol";
import {Initializable} from "../proxy/utils/Initializable.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * The initial owner is set to the address provided by the deployer. This can
 * later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract OwnableUpgradeable is Initializable, ContextUpgradeable {
    /// @custom:storage-location erc7201:openzeppelin.storage.Ownable
    struct OwnableStorage {
        address _owner;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Ownable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant OwnableStorageLocation = 0x9016d09d72d40fdae2fd8ceac6b6234c7706214fd39c1cd1e609a0528c199300;

    function _getOwnableStorage() private pure returns (OwnableStorage storage $) {
        assembly {
            $.slot := OwnableStorageLocation
        }
    }

    /**
     * @dev The caller account is not authorized to perform an operation.
     */
    error OwnableUnauthorizedAccount(address account);

    /**
     * @dev The owner is not a valid owner account. (eg. `address(0)`)
     */
    error OwnableInvalidOwner(address owner);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the address provided by the deployer as the initial owner.
     */
    function __Ownable_init(address initialOwner) internal onlyInitializing {
        __Ownable_init_unchained(initialOwner);
    }

    function __Ownable_init_unchained(address initialOwner) internal onlyInitializing {
        if (initialOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(initialOwner);
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
        OwnableStorage storage $ = _getOwnableStorage();
        return $._owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        if (owner() != _msgSender()) {
            revert OwnableUnauthorizedAccount(_msgSender());
        }
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
        if (newOwner == address(0)) {
            revert OwnableInvalidOwner(address(0));
        }
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        OwnableStorage storage $ = _getOwnableStorage();
        address oldOwner = $._owner;
        $._owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTOperatorDelegator.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IEigenPod} from 'contracts/interfaces/eigenlayer/IEigenPod.sol';
import {IBeaconChainProofs} from 'contracts/interfaces/eigenlayer/IBeaconChainProofs.sol';
import {IDelegationManager} from 'contracts/interfaces/eigenlayer/IDelegationManager.sol';

interface IRioLRTOperatorDelegator {
    /// @notice Thrown when the earnings receiver is not set to the reward distributor.
    error INVALID_EARNINGS_RECEIVER();

    /// @notice Thrown when the delegation approver is not the zero address.
    error INVALID_DELEGATION_APPROVER();

    /// @notice Thrown when the operator's staker opt out blocks is below the minimum.
    error INVALID_STAKER_OPT_OUT_BLOCKS();

    /// @notice Thrown when the validator count is `0` or does not match the provided ETH value.
    error INVALID_VALIDATOR_COUNT();

    /// @notice Thrown when the asset provided for the beacon chain strategy is not valid.
    error INVALID_ASSET_FOR_BEACON_CHAIN_STRATEGY();

    /// @notice Thrown when the public keys batch length does not match the validator count.
    /// @param actual The actual length of the batch.
    /// @param expected The expected length of the batch.
    error INVALID_PUBLIC_KEYS_BATCH_LENGTH(uint256 actual, uint256 expected);

    /// @notice Thrown when the signatures batch length does not match the validator count.
    /// @param actual The actual length of the batch.
    /// @param expected The expected length of the batch.
    error INVALID_SIGNATURES_BATCH_LENGTH(uint256 actual, uint256 expected);

    /// @notice Thrown when there isn't enough excess full withdrawal ETH to initiate a scrape from the EigenPod.
    error INSUFFICIENT_EXCESS_FULL_WITHDRAWAL_ETH();

    /// @notice Thrown when the calling account is not authorized to claim a withdrawal.
    error UNAUTHORIZED_CLAIMER();

    /// @notice Thrown when the caller is not the owner of the operator registry contract.
    error ONLY_REGISTRY_OWNER();

    /// @notice Initializes the contract by delegating to the provided EigenLayer operator.
    /// @param token The address of the liquid restaking token.
    /// @param operator The operator's address.
    function initialize(address token, address operator) external;

    /// @notice The primary delegation contract for EigenLayer.
    function delegationManager() external view returns (IDelegationManager);

    /// @notice The operator delegator's EigenPod.
    function eigenPod() external view returns (IEigenPod);

    /// @notice Returns the number of shares in the operator delegator's EigenPod.
    function getEigenPodShares() external view returns (int256);

    /// @notice The amount of ETH queued for withdrawal from EigenLayer, in wei.
    function getETHQueuedForWithdrawal() external view returns (uint256);

    /// @notice Returns the total amount of ETH under management by the operator delegator.
    /// @dev This includes EigenPod shares (verified validator balances minus queued withdrawals)
    /// and ETH in the operator delegator's EigenPod.
    function getETHUnderManagement() external view returns (uint256);

    /// @notice Verifies withdrawal credentials of validator(s) owned by this operator.
    /// It also verifies the effective balance of the validator(s).
    /// @param oracleTimestamp The Beacon Chain timestamp whose state root the `proof` will be proven against.
    /// @param stateRootProof Proves a `beaconStateRoot` against a block root fetched from the oracle.
    /// @param validatorIndices The list of indices of the validators being proven, refer to consensus specs.
    /// @param validatorFieldsProofs Proofs against the `beaconStateRoot` for each validator in `validatorFields`.
    /// @param validatorFields The fields of the "Validator Container", refer to consensus specs.
    function verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        IBeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields
    ) external;

    /// @notice Approve EigenLayer to spend an ERC20 token, then stake it into an EigenLayer strategy.
    /// @param strategy The strategy to stake the tokens into.
    /// @param token The token to stake.
    /// @param amount The amount of tokens to stake.
    function stakeERC20(address strategy, address token, uint256 amount) external returns (uint256 shares);

    // forgefmt: disable-next-item
    /// Stake ETH via the operator delegator's EigenPod, using the provided validator information.
    /// @param validatorCount The number of validators to deposit into.
    /// @param pubkeyBatch Batched validator public keys.
    /// @param signatureBatch Batched validator signatures.
    function stakeETH(uint256 validatorCount, bytes calldata pubkeyBatch, bytes calldata signatureBatch) external payable;

    /// @notice Queues a withdrawal of the specified amount of `shares` from the given `strategy` to the withdrawal queue,
    /// intended for settling user withdrawals.
    /// @param strategy The strategy from which to withdraw.
    /// @param shares The amount of shares to withdraw.
    function queueWithdrawalForUserSettlement(address strategy, uint256 shares) external returns (bytes32 root);

    /// @notice Queues a withdrawal of the specified amount of `shares` from the given `strategy` to the deposit pool,
    /// specifically for facilitating operator exits.
    /// @param strategy The strategy from which to withdraw.
    /// @param shares The amount of shares to withdraw.
    function queueWithdrawalForOperatorExit(address strategy, uint256 shares) external returns (bytes32 root);

    /// @notice Completes a queued withdrawal of the specified `queuedWithdrawal` for the given `asset`.
    /// @param queuedWithdrawal The withdrawal to complete.
    /// @param asset The asset to withdraw.
    /// @param middlewareTimesIndex The index of the middleware times to use for the withdrawal.
    function completeQueuedWithdrawal(
        IDelegationManager.Withdrawal calldata queuedWithdrawal,
        address asset,
        uint256 middlewareTimesIndex
    ) external returns (bytes32 root);
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTOperatorRegistry.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IRioLRTOperatorRegistry {
    /// @dev The information needed to add a new operator.
    struct OperatorConfig {
        /// @dev The operator's address.
        address operator;
        /// @dev The initial manager of the operator.
        address initialManager;
        /// @dev The initial reward address of the operator.
        address initialEarningsReceiver;
        /// @dev The initial metadata URI of the operator.
        string initialMetadataURI;
        /// @dev The maximum number of shares that can be allocated to
        /// the operator for each strategy.
        StrategyShareCap[] strategyShareCaps;
        /// @dev The maximum number of active validators allowed.
        uint40 validatorCap;
    }

    /// @dev Configuration used to track the maximum number of shares that can be
    /// allocated to an operator for a given strategy.
    struct StrategyShareCap {
        /// @dev The strategy address.
        address strategy;
        /// @dev The maximum amount of strategy shares that can be allocated to the operator.
        uint128 cap;
    }

    /// @dev Tracks both the cap and current allocation of strategy shares for an operator.
    struct OperatorShareDetails {
        /// @dev The maximum amount of strategy shares that can be allocated to the operator.
        uint128 cap;
        /// @dev The current amount of strategy shares allocated to the operator.
        uint128 allocation;
    }

    /// @dev Aggregate validator information for a single operator.
    struct OperatorValidatorDetails {
        /// @dev The timestamp at which the next batch of pending validators will be considered
        /// "confirmed".
        uint40 nextConfirmationTimestamp;
        /// @dev The maximum number of validators approved by the DAO.
        uint40 cap;
        /// @dev The total number of keys that have been uploaded (all-time). This number will be
        /// decremented in the event that pending keys are removed.
        uint40 total;
        /// @dev The total number of validator keys that have been confirmed following
        /// review by the security daemon (all-time).
        uint40 confirmed;
        /// @dev The number of validators that have reached the deposited state (all-time).
        uint40 deposited;
        /// @dev The number of validators that have reached the exited state (all-time).
        uint40 exited;
    }

    /// @dev Details for a single operator.
    struct OperatorDetails {
        /// @dev Flag indicating if the operator can participate in further staking and reward distribution.
        bool active;
        /// @dev The staker contract that delegates to the operator.
        address delegator;
        /// @dev The address that manages the operator.
        address manager;
        /// @dev The address that will manage the operator once confirmed.
        address pendingManager;
        /// @dev The address that will receive operator rewards.
        address earningsReceiver;
        /// @dev Aggregate validator information for the operator.
        OperatorValidatorDetails validatorDetails;
        /// @dev Operator strategy share allocation caps and current allocations.
        mapping(address => OperatorShareDetails) shareDetails;
    }

    /// @dev Details for a single operator, excluding the share details, so we can expose externally.
    struct OperatorPublicDetails {
        /// @dev Flag indicating if the operator can participate in further staking and reward distribution.
        bool active;
        /// @dev The staker contract that delegates to the operator.
        address delegator;
        /// @dev The address that manages the operator.
        address manager;
        /// @dev The address that will manage the operator once confirmed.
        address pendingManager;
        /// @dev The address that will receive operator rewards.
        address earningsReceiver;
        /// @dev Aggregate validator information for the operator.
        OperatorValidatorDetails validatorDetails;
    }

    /// @notice An operator address and strategy share allocation.
    struct OperatorStrategyAllocation {
        /// @dev The operator delegator's contract address.
        address delegator;
        /// @dev The amount of shares allocated to the operator.
        uint256 shares;
        /// @dev The amount of tokens allocated to the operator.
        uint256 tokens;
    }

    /// @notice An operator address, ETH deposit allocation, and validator details.
    struct OperatorETHAllocation {
        /// @dev The operator delegator's contract address.
        address delegator;
        /// @dev The amount of ETH deposits allocated to the operator.
        uint256 deposits;
        /// @dev One or more validator public keys, concatenated together.
        bytes pubKeyBatch;
        /// @dev One or more validator signatures, concatenated together.
        bytes signatureBatch;
    }

    /// @notice An operator address and strategy share deallocation.
    struct OperatorStrategyDeallocation {
        /// @dev The operator delegator's contract address.
        address delegator;
        /// @dev The amount of shares deallocated from the operator.
        uint256 shares;
        /// @dev The amount of tokens deallocated from the operator.
        uint256 tokens;
    }

    /// @notice An operator address and ETH deposit deallocation.
    struct OperatorETHDeallocation {
        /// @dev The operator delegator's contract address.
        address delegator;
        /// @dev The amount of ETH deposits deallocated from the operator.
        uint256 deposits;
    }

    /// @notice Thrown when the caller is not the operator's manager.
    error ONLY_OPERATOR_MANAGER();

    /// @notice Thrown when the caller is not the operator's manager OR the security daemon.
    error ONLY_OPERATOR_MANAGER_OR_SECURITY_DAEMON();

    /// @notice Thrown when the caller is not the operator's manager OR the proof uploader.
    error ONLY_OPERATOR_MANAGER_OR_PROOF_UPLOADER();

    /// @notice Thrown when the caller is not the operator's pending manager.
    error ONLY_OPERATOR_PENDING_MANAGER();

    /// @notice Thrown when the operator is `address(0)`.
    error INVALID_OPERATOR();

    /// @notice Thrown when the manager is `address(0)`.
    error INVALID_MANAGER();

    /// @notice Thrown when the operator's earnings receiver is `address(0)`.
    error INVALID_EARNINGS_RECEIVER();

    /// @notice Thrown when an invalid (non-existent) operator delegator contract address is provided.
    error INVALID_OPERATOR_DELEGATOR();

    /// @notice Thrown when a validator public key length is invalid.
    error INVALID_PUBLIC_KEY_LENGTH();

    /// @notice Thrown when the pending manager is `address(0)`.
    error INVALID_PENDING_MANAGER();

    /// @notice Thrown when the provided validator count is invalid (zero).
    error INVALID_VALIDATOR_COUNT();

    /// @notice Thrown when an invalid index is provided.
    error INVALID_INDEX();

    /// @notice Thrown when attempting to report an out of order exit for a validator
    /// that has not exited.
    error VALIDATOR_NOT_EXITED();

    /// @notice Thrown when the maximum number of operators has been reached.
    error MAX_OPERATOR_COUNT_EXCEEDED();

    /// @notice Thrown when the maximum number of active operators has been reached.
    error MAX_ACTIVE_OPERATOR_COUNT_EXCEEDED();

    /// @notice Thrown when attempting to activate an operator that is already active.
    error OPERATOR_ALREADY_ACTIVE();

    /// @notice Thrown when attempting to deactivate an operator that is already inactive.
    error OPERATOR_ALREADY_INACTIVE();

    /// @notice Thrown when attempting to queue the exit of zero shares.
    error CANNOT_EXIT_ZERO_SHARES();

    /// @notice Thrown when there are no available operators for deallocation.
    error NO_AVAILABLE_OPERATORS_FOR_DEALLOCATION();

    /// @notice Emitted when a new operator is added to the registry.
    /// @param operatorId The operator's ID.
    /// @param operator The operator's contract address.
    /// @param delegator The operator's delegator contract address.
    /// @param initialManager The initial manager of the operator.
    /// @param initialEarningsReceiver The initial reward address of the operator.
    /// @param initialMetadataURI The initial metadata URI of the operator.
    event OperatorAdded(
        uint8 indexed operatorId,
        address indexed operator,
        address indexed delegator,
        address initialManager,
        address initialEarningsReceiver,
        string initialMetadataURI
    );

    /// @notice Emitted when an operator is activated.
    /// @param operatorId The operator's ID.
    event OperatorActivated(uint8 indexed operatorId);

    /// @notice Emitted when an operator is deactivated.
    /// @param operatorId The operator's ID.
    event OperatorDeactivated(uint8 indexed operatorId);

    /// @notice Emitted when an operator's strategy share allocation cap is set.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy whose cap was set.
    /// @param cap The new strategy share cap for the operator.
    event OperatorStrategyShareCapSet(uint8 indexed operatorId, address strategy, uint128 cap);

    /// @notice Emitted when an operator's validator cap is set.
    /// @param operatorId The operator's ID.
    /// @param cap The new maximum active validator cap.
    event OperatorValidatorCapSet(uint8 indexed operatorId, uint40 cap);

    /// @notice Emitted when the security daemon is set.
    /// @param securityDaemon The new security daemon.
    event SecurityDaemonSet(address securityDaemon);

    /// @notice Emitted when the proof uploader is set.
    /// @param proofUploader The new proof uploader.
    event ProofUploaderSet(address proofUploader);

    /// @notice Emitted when the min staker opt out blocks is set.
    event MinStakerOptOutBlocksSet(uint24 minStakerOptOutBlocks);

    /// @notice Emitted when the validator key review period is set.
    /// @param validatorKeyReviewPeriod The new validator key review period.
    event ValidatorKeyReviewPeriodSet(uint24 validatorKeyReviewPeriod);

    /// @notice Emitted when a strategy exit is queued for an operator.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy to exit.
    /// @param sharesToExit The number of shares to exit.
    /// @param withdrawalRoot The withdrawal root for the exit.
    event OperatorStrategyExitQueued(
        uint8 indexed operatorId, address strategy, uint256 sharesToExit, bytes32 withdrawalRoot
    );

    /// @notice Emitted when an operator's earnings receiver is set.
    /// @param operatorId The operator's ID.
    /// @param earningsReceiver The new earnings receiver for the operator.
    event OperatorEarningsReceiverSet(uint8 indexed operatorId, address earningsReceiver);

    /// @notice Emitted when an operator's pending manager is set.
    /// @param operatorId The operator's ID.
    /// @param pendingManager The new pending manager of the operator.
    event OperatorPendingManagerSet(uint8 indexed operatorId, address pendingManager);

    /// @notice Emitted when an operator's manager is set.
    /// @param operatorId The operator's ID.
    /// @param manager The new manager of the operator.
    event OperatorManagerSet(uint8 indexed operatorId, address manager);

    /// @notice Emitted following the verification of withdrawal credentials for one or more validators.
    /// @param operatorId The operator's ID.
    /// @param oracleTimestamp The Beacon Chain timestamp whose state root the `proof` will be proven against.
    /// @param validatorIndices The list of indices of the validators being proven, refer to consensus specs.
    event OperatorWithdrawalCredentialsVerified(
        uint8 indexed operatorId, uint64 oracleTimestamp, uint40[] validatorIndices
    );

    /// @notice Emitted when an operator uploads a new set of validator details (public keys and signatures).
    /// @param operatorId The operator's ID.
    /// @param validatorCount The number of validator details that were added.
    event OperatorPendingValidatorDetailsAdded(uint8 indexed operatorId, uint256 validatorCount);

    /// @notice Emitted when an operator removes pending or confirmed validator details (public keys and signatures).
    /// @param operatorId The operator's ID.
    /// @param validatorCount The number of validator details that were removed.
    event OperatorValidatorDetailsRemoved(uint8 indexed operatorId, uint256 validatorCount);

    /// @notice Emitted when out of order validator exits are reported.
    /// @param operatorId The operator's ID.
    /// @param validatorCount The number of validators that were exited out of order.
    event OperatorOutOfOrderValidatorExitsReported(uint8 indexed operatorId, uint256 validatorCount);

    /// @notice Emitted when the number of shares allocated to an operator has been synced.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy that the shares were synced for.
    /// @param oldShares The previous number of shares allocated to the operator.
    /// @param newShares The new number of shares allocated to the operator.
    event StrategySharesSynced(uint8 indexed operatorId, address strategy, uint256 oldShares, uint256 newShares);

    /// @notice Emitted when strategy shares have been allocated to an operator.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy that the shares were allocated to.
    /// @param sharesAllocated The amount of shares allocated.
    /// @param tokensAllocated The token value of the allocated shares.
    event StrategySharesAllocated(
        uint8 indexed operatorId, address indexed strategy, uint256 sharesAllocated, uint256 tokensAllocated
    );

    /// @notice Emitted when ETH deposits have been allocated to an operator.
    /// @param operatorId The operator's ID.
    /// @param depositsAllocated The amount of deposits allocated.
    /// @param pubKeyBatch The public keys of the validators that were allocated to.
    event ETHDepositsAllocated(uint8 indexed operatorId, uint256 depositsAllocated, bytes pubKeyBatch);

    /// @notice Emitted when strategy shares have been deallocated from an operator.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy that the shares were deallocated from.
    /// @param sharesDeallocated The amount of shares deallocated.
    /// @param tokensDeallocated The token value of the deallocated shares.
    event StrategySharesDeallocated(
        uint8 indexed operatorId, address indexed strategy, uint256 sharesDeallocated, uint256 tokensDeallocated
    );

    /// @notice Emitted when ETH deposits have been deallocated from an operator.
    /// @param operatorId The operator's ID.
    /// @param depositsDeallocated The amount of deposits deallocated.
    /// @param pubKeyBatch The public keys of the validators that must be exited.
    event ETHDepositsDeallocated(uint8 indexed operatorId, uint256 depositsDeallocated, bytes pubKeyBatch);

    // forgefmt: disable-next-item
    /// @notice Initializes the contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param token The address of the liquid restaking token.
    function initialize(address initialOwner, address token) external;

    /// @notice Returns the operator details for the provided operator ID.
    /// @param operatorId The operator's ID.
    function getOperatorDetails(uint8 operatorId) external view returns (OperatorPublicDetails memory);

    /// @notice Returns the operator share cap and allocation for the provided operator ID and strategy.
    /// @param operatorId The operator's ID.
    /// @param strategy The strategy to get the share details for.
    function getOperatorShareDetails(uint8 operatorId, address strategy)
        external
        view
        returns (OperatorShareDetails memory);

    /// @notice Returns the total number of operators in the registry.
    function operatorCount() external view returns (uint8);

    /// @notice Returns the total number of active operators in the registry.
    function activeOperatorCount() external view returns (uint8);

    /// @notice The minimum acceptable delay between an operator signaling intent to register
    // for an AVS and completing registration.
    function minStakerOptOutBlocks() external view returns (uint24);

    /// @notice The amount of time (in seconds) before uploaded validator keys are considered "vetted".
    function validatorKeyReviewPeriod() external view returns (uint24);

    /// @notice Adds a new operator to the registry, deploying a delegator contract and
    /// delegating to the provided operator address.
    /// @param config The new operator's configuration.
    function addOperator(OperatorConfig calldata config) external returns (uint8 operatorId, address delegator);

    /// @notice Activates an operator.
    /// @param operatorId The operator's ID.
    function activateOperator(uint8 operatorId) external;

    /// Deactivates an operator, exiting all remaining stake to the
    /// deposit pool.
    /// @param operatorId The operator's ID.
    function deactivateOperator(uint8 operatorId) external;

    /// @notice Adds pending validator details (public keys and signatures) to storage for the provided operator.
    /// Each added batch extends the timestamp at which the details will be considered confirmed.
    /// @param operatorId The operator's ID.
    /// @param validatorCount The number of validators in the batch.
    /// @param publicKeys The validator public keys.
    /// @param signatures The validator signatures.
    function addValidatorDetails(
        uint8 operatorId,
        uint256 validatorCount,
        bytes calldata publicKeys,
        bytes calldata signatures
    ) external;

    // forgefmt: disable-next-item
    /// @notice Removes pending validator details (public keys and signatures) from storage for the provided operator.
    /// @param operatorId The operator's ID.
    /// @param fromIndex The index of the first validator to remove.
    /// @param validatorCount The number of validator to remove.
    function removeValidatorDetails(uint8 operatorId, uint256 fromIndex, uint256 validatorCount) external;

    /// @notice Reports validator exits that occur prior to instruction by the protocol.
    /// @param operatorId The operator's ID.
    /// @param fromIndex The index of the first validator to report.
    /// @param validatorCount The number of validators to report.
    function reportOutOfOrderValidatorExits(uint8 operatorId, uint256 fromIndex, uint256 validatorCount) external;

    // forgefmt: disable-next-item
    /// @notice Allocates a specified amount of shares for the provided strategy to the operators with the lowest utilization.
    /// @param strategy The strategy to allocate the shares to.
    /// @param sharesToAllocate The amount of shares to allocate.
    function allocateStrategyShares(address strategy, uint256 sharesToAllocate) external returns (uint256 sharesAllocated, OperatorStrategyAllocation[] memory allocations);

    // forgefmt: disable-next-item
    /// @notice Allocates a specified amount of ETH deposits to the operators with the lowest utilization.
    /// @param depositsToAllocate The amount of deposits to allocate (32 ETH each)
    function allocateETHDeposits(uint256 depositsToAllocate) external returns (uint256 depositsAllocated, OperatorETHAllocation[] memory allocations);

    // forgefmt: disable-next-item
    /// @notice Deallocates a specified amount of shares for the provided strategy from the operators with the highest utilization.
    /// @param strategy The strategy to deallocate the shares from.
    /// @param sharesToDeallocate The amount of shares to deallocate.
    function deallocateStrategyShares(address strategy, uint256 sharesToDeallocate) external returns (uint256 sharesDeallocated, OperatorStrategyDeallocation[] memory deallocations);

    // forgefmt: disable-next-item
    /// @notice Deallocates a specified amount of ETH deposits from the operators with the highest utilization.
    /// @param depositsToDeallocate The amount of deposits to deallocate (32 ETH each)
    function deallocateETHDeposits(uint256 depositsToDeallocate) external returns (uint256 depositsDeallocated, OperatorETHDeallocation[] memory deallocations);
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTAssetRegistry.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IRioLRTAssetRegistry {
    /// @notice The configuration used to add a new asset.
    struct AssetConfig {
        /// @dev The address of the asset.
        address asset;
        /// @dev The asset's deposit cap (disabled if 0).
        uint96 depositCap;
        /// @dev The price feed for the asset.
        address priceFeed;
        /// @dev The EigenLayer strategy used by the asset.
        address strategy;
    }

    /// @notice Information about a supported asset.
    struct AssetInfo {
        /// @dev The asset's deposit cap (disabled if 0).
        uint96 depositCap;
        /// @dev The price feed for the asset.
        address priceFeed;
        /// @dev The number of EigenLayer strategy shares held for the asset.
        /// This value is NOT used for the beacon chain strategy as its shares
        /// can fluctuate outside the system.
        uint256 shares;
        /// @dev The EigenLayer strategy used by the asset.
        address strategy;
        /// @dev The number of decimals used to get its user representation.
        uint8 decimals;
    }

    /// @notice Thrown when the caller is not the LRT withdrawal queue or deposit pool.
    error ONLY_WITHDRAWAL_QUEUE_OR_DEPOSIT_POOL();

    /// @notice Thrown when attempting an action on an unsupported asset.
    /// @param asset The address of the asset.
    error ASSET_NOT_SUPPORTED(address asset);

    /// @notice Thrown when attempting to add an asset that is already supported.
    /// @param asset The address of the asset.
    error ASSET_ALREADY_SUPPORTED(address asset);

    /// @notice Thrown when attempting to remove an asset with a non-zero balance.
    error ASSET_HAS_BALANCE();

    /// @notice Thrown when attempting to add an asset with an invalid address.
    error INVALID_ASSET_ADDRESS();

    /// @notice Thrown when an asset has greater than 18 decimals.
    error INVALID_ASSET_DECIMALS();

    /// @notice Thrown when a srategy's underlying token does not match the asset.
    error INVALID_STRATEGY();

    /// @notice Thrown when a provided price feed has an unexpected amount of decimals.
    error INVALID_PRICE_FEED_DECIMALS();

    /// @notice Thrown when a price feed is provided when not needed, or not provided when required.
    error INVALID_PRICE_FEED();

    /// @notice Emitted when a new asset is added.
    /// @param config The asset's configuration.
    event AssetAdded(AssetConfig config);

    /// @notice Emitted when an asset is removed.
    /// @param asset The address of the asset.
    /// @param forced True if the asset was removed by force, regardless of its balance.
    event AssetRemoved(address indexed asset, bool forced);

    /// @notice Emitted when an asset's EigenLayer strategy is set.
    /// @param asset The address of the asset.
    /// @param newDepositCap The new deposit cap.
    event AssetDepositCapSet(address indexed asset, uint96 newDepositCap);

    /// @notice Emitted when an asset's price feed is set.
    /// @param asset The address of the asset.
    /// @param newPriceFeed The new price feed.
    event AssetPriceFeedSet(address indexed asset, address newPriceFeed);

    /// @notice Emitted when the number of EigenLayer shares held for an asset is increased.
    /// @param asset The address of the asset.
    /// @param amount The amount of EigenLayer shares to increase.
    event AssetSharesIncreased(address indexed asset, uint256 amount);

    /// @notice Emitted when the number of EigenLayer shares held for an asset is decreased.
    /// @param asset The address of the asset.
    /// @param amount The amount of EigenLayer shares to decrease.
    event AssetSharesDecreased(address indexed asset, uint256 amount);

    /// @notice Emitted when the unverified validator ETH balance is increased.
    /// @param amount The amount of ETH to increase.
    event UnverifiedValidatorETHBalanceIncreased(uint256 amount);

    /// @notice Emitted when the unverified validator ETH balance is decreased.
    /// @param amount The amount of ETH to decrease.
    event UnverifiedValidatorETHBalanceDecreased(uint256 amount);

    /// @notice Initializes the asset registry contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param token The address of the liquid restaking token.
    /// @param priceFeedDecimals The number of decimals that all price feeds must use.
    /// @param initialAssets The initial supported asset configurations.
    function initialize(
        address initialOwner,
        address token,
        uint8 priceFeedDecimals,
        AssetConfig[] calldata initialAssets
    ) external;

    /// @notice Returns the total value of all assets in the unit of account.
    function getTVL() external view returns (uint256 value);

    /// @notice Returns the total value of the underlying asset in the unit of account.
    /// @param asset The address of the asset.
    function getTVLForAsset(address asset) external view returns (uint256);

    /// @notice Returns the total balance of the asset, including the deposit pool and EigenLayer.
    /// @param asset The address of the asset.
    function getTotalBalanceForAsset(address asset) external view returns (uint256);

    /// @notice Checks if a given asset is supported.
    /// @param asset The address of the asset to check.
    function isSupportedAsset(address asset) external view returns (bool);

    /// @notice Returns information about an asset.
    /// @param asset The address of the asset.
    function getAssetInfoByAddress(address asset) external view returns (AssetInfo memory);

    /// @notice Returns the asset's EigenLayer strategy.
    /// @param asset The address of the asset.
    function getAssetStrategy(address asset) external view returns (address);

    /// @notice Returns the amount of EigenLayer shares held for an asset.
    /// @param asset The address of the asset.
    function getAssetSharesHeld(address asset) external view returns (uint256);

    /// @notice Returns the asset's current deposit cap.
    /// @param asset The address of the asset.
    function getAssetDepositCap(address asset) external view returns (uint256);

    /// @notice Returns an array of all supported assets.
    function getSupportedAssets() external view returns (address[] memory);

    /// @notice Returns the EigenLayer strategies for all supported assets.
    function getAssetStrategies() external view returns (address[] memory);

    /// @notice Increases the number of EigenLayer shares held for an asset.
    /// @param asset The address of the asset.
    /// @param amount The amount of EigenLayer shares to increase.
    function increaseSharesHeldForAsset(address asset, uint256 amount) external;

    /// @notice Decreases the number of EigenLayer shares held for an asset.
    /// @param asset The address of the asset.
    /// @param amount The amount of EigenLayer shares to decrease.
    function decreaseSharesHeldForAsset(address asset, uint256 amount) external;

    /// @notice Increases the unverified validator ETH balance.
    /// @param amount The amount of ETH to increase.
    function increaseUnverifiedValidatorETHBalance(uint256 amount) external;

    /// @notice Decreases the unverified validator ETH balance.
    /// @param amount The amount of ETH to decrease.
    function decreaseUnverifiedValidatorETHBalance(uint256 amount) external;

    /// @notice Converts an asset amount to its equivalent value in the unit of account. The unit of
    /// account is the price feed's quote asset.
    /// @param asset The address of the asset to convert.
    /// @param amount The amount of the asset to convert.
    function convertToUnitOfAccountFromAsset(address asset, uint256 amount) external view returns (uint256);

    /// @notice Converts the unit of account value to its equivalent in the asset. The unit of
    /// account is the price feed's quote asset.
    /// @param asset The address of the asset to convert to.
    /// @param value The asset's value in the unit of account.
    function convertFromUnitOfAccountToAsset(address asset, uint256 value) external view returns (uint256);

    /// @notice Converts an amount of an asset to the equivalent amount of EigenLayer shares.
    /// @param asset The address of the asset to convert.
    /// @param amount The amount of the asset to convert.
    function convertToSharesFromAsset(address asset, uint256 amount) external view returns (uint256 shares);

    /// @notice Converts an amount of EigenLayer shares to the equivalent amount of an asset.
    /// @param strategy The EigenLayer strategy.
    /// @param shares The amount of EigenLayer shares.
    function convertFromSharesToAsset(address strategy, uint256 shares) external view returns (uint256 amount);
}


// ============================================================================
// FILE: contracts/interfaces/ethereum/IETHPOSDeposit.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IETHPOSDeposit {
    /// @notice A processed deposit event.
    event DepositEvent(bytes pubkey, bytes withdrawal_credentials, bytes amount, bytes signature, bytes index);

    /// @notice Submit a Phase 0 DepositData object.
    /// @param pubkey A BLS12-381 public key.
    /// @param withdrawal_credentials Commitment to a public key for withdrawals.
    /// @param signature A BLS12-381 signature.
    /// @param deposit_data_root The SHA-256 hash of the SSZ-encoded DepositData object.
    /// Used as a protection against malformed input.
    function deposit(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        bytes32 deposit_data_root
    ) external payable;

    /// @notice Query the current deposit root hash.
    /// @return The deposit root hash.
    function get_deposit_root() external view returns (bytes32);

    /// @notice Query the current deposit count.
    /// @return The deposit count encoded as a little endian 64-bit number.
    function get_deposit_count() external view returns (bytes memory);
}


// ============================================================================
// FILE: contracts/utils/Constants.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

/// @dev The minimum allowed sacrificial deposit amount.
uint256 constant MIN_SACRIFICIAL_DEPOSIT = 1_000;

/// @dev The maximum rebalance delay, in seconds.
uint256 constant MAX_REBALANCE_DELAY = 3 days;

/// @dev The Beacon Chain ETH strategy pseudo-address.
address constant BEACON_CHAIN_STRATEGY = 0xbeaC0eeEeeeeEEeEeEEEEeeEEeEeeeEeeEEBEaC0;

/// @dev The ETH pseudo-address.
address constant ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

/// @dev The per-validator ETH deposit amount.
uint256 constant ETH_DEPOSIT_SIZE = 32 ether;

/// @dev A soft cap on the amount of ETH that can be deposited in a single transaction (100 validators).
/// Depending on the ETH deposit buffer limit, the actual maximum deposit amount may slightly higher.
uint256 constant ETH_DEPOSIT_SOFT_CAP = ETH_DEPOSIT_SIZE * 100;

/// @dev Defines the maximum allowable excess amount of ETH above the soft cap that can still be deposited
/// in a single transaction. This allows for deposits slightly over the soft cap (up to 10 validators extra) to
/// be included without requiring additional transactions.
uint256 constant ETH_DEPOSIT_BUFFER_LIMIT = ETH_DEPOSIT_SIZE * 10;

/// @dev The deposit amount in gwei, converted to little endian.
/// ETH_DEPOSIT_SIZE_IN_GWEI_LE64 = toLittleEndian64(32 ether / 1 gwei)
uint64 constant ETH_DEPOSIT_SIZE_IN_GWEI_LE64 = 0x0040597307000000;

/// @dev The conversion factor from gwei to wei.
uint256 constant GWEI_TO_WEI = 1e9;

/// @dev The length of a BLS12-381 public key.
uint256 constant BLS_PUBLIC_KEY_LENGTH = 48;

/// @dev The length of a BLS12-381 signature.
uint256 constant BLS_SIGNATURE_LENGTH = 96;

/// @dev LRT supporting contract types.
enum ContractType {
    Coordinator,
    AssetRegistry,
    OperatorRegistry,
    AVSRegistry,
    DepositPool,
    WithdrawalQueue,
    RewardDistributor
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTCoordinator.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IETHPOSDeposit} from 'contracts/interfaces/ethereum/IETHPOSDeposit.sol';

interface IRioLRTCoordinator {
    /// @notice Thrown when attempting an action on an unsupported asset.
    /// @param asset The address of the asset.
    error ASSET_NOT_SUPPORTED(address asset);

    /// @notice Thrown when attempting to deposit an amount of zero.
    error AMOUNT_MUST_BE_GREATER_THAN_ZERO();

    /// @notice Thrown when attempting to deposit an amount that would exceed the deposit cap.
    /// @param asset The address of the asset.
    /// @param depositCap The asset's deposit cap.
    error DEPOSIT_CAP_REACHED(address asset, uint256 depositCap);

    /// @notice Thrown when attempting to request a withdrawal for an amount that would exceed the
    /// total share value available.
    error INSUFFICIENT_SHARES_FOR_WITHDRAWAL();

    /// @notice Thrown when the `msg.sender` is a contract.
    error CALLER_MUST_BE_EOA();

    /// @notice Thrown when the ETH pseudo-address is passed to the ERC20 rebalance function.
    error INVALID_TOKEN_ADDRESS();

    /// @notice Thrown when the guardian signer is invalid.
    error INVALID_GUARDIAN_SIGNATURE();

    /// @notice Thrown when the guardian deposit root is stale.
    error STALE_DEPOSIT_ROOT();

    /// @notice Thrown when attempting rebalance before the rebalance delay has elapsed.
    error REBALANCE_DELAY_NOT_MET();

    /// @notice Thrown when attempting to set the rebalance delay to a value greater than the maximum.
    error REBALANCE_DELAY_TOO_LONG();

    /// @notice Thrown when attempting to rebalance an asset that does not need to be rebalanced.
    error NO_REBALANCE_NEEDED();

    /// @notice Thrown when attempting to pause the coordinator due to forceful undelegation
    /// when no operator has forcefully undelegated.
    error NO_OPERATOR_UNDELEGATED();

    /// @notice Emitted when a user deposits an asset into Rio.
    /// @param user The address of the user.
    /// @param asset The address of the asset.
    /// @param amountIn The amount of the asset deposited.
    /// @param amountOut The amount of restaking tokens minted.
    event Deposited(address indexed user, address indexed asset, uint256 amountIn, uint256 amountOut);

    /// @notice Emitted when both withdrawals and deposits succeed during a rebalance, or
    /// when withdrawals succeed and a deposit was not needed.
    /// @param asset The address of the asset.
    event Rebalanced(address indexed asset);

    /// @notice Emitted when withdrawals succeed, but deposits fail or were unable to be attempted
    /// during an asset rebalance.
    /// @param asset The address of the asset.
    event PartiallyRebalanced(address indexed asset);

    /// @notice Emitted when the rebalance delay is set.
    /// @param newRebalanceDelay The new rebalance delay.
    event RebalanceDelaySet(uint24 newRebalanceDelay);

    /// @notice Emitted when the guardian signer is set.
    /// @param newGuardianSigner The address of the new guardian signer.
    event GuardianSignerSet(address newGuardianSigner);

    /// @dev Initializes the contract.
    /// @param initialOwner The owner of the contract.
    /// @param token The address of the liquid restaking token.
    function initialize(address initialOwner, address token) external;

    /// @notice Returns the EIP-712 typehash for `DepositRoot` message.
    function DEPOSIT_ROOT_TYPEHASH() external view returns (bytes32);

    /// @notice The Ethereum POS deposit contract address.
    function ethPOS() external view returns (IETHPOSDeposit);

    /// @notice Returns the total value of all underlying assets in the unit of account.
    function getTVL() external view returns (uint256);

    /// @notice Converts an amount of restaking tokens to its equivalent value in the unit of account.
    /// The unit of account is the price feed's quote asset.
    /// @param amount The amount of restaking tokens to convert.
    function convertToUnitOfAccountFromRestakingTokens(uint256 amount) external view returns (uint256);

    /// @notice Converts the unit of account value to its equivalent in restaking tokens. The unit of
    /// account is the price feed's quote asset.
    /// @param value The restaking token's value in the unit of account.
    function convertFromUnitOfAccountToRestakingTokens(uint256 value) external view returns (uint256);

    /// @notice Converts an asset amount to its equivalent value in restaking tokens.
    /// @param asset The address of the asset to convert.
    /// @param amount The amount of the asset to convert.
    function convertFromAssetToRestakingTokens(address asset, uint256 amount) external view returns (uint256);

    /// @notice Converts an amount of restaking tokens to the equivalent in the asset.
    /// @param asset The address of the asset to convert to.
    /// @param amount The amount of restaking tokens to convert.
    function convertToAssetFromRestakingTokens(address asset, uint256 amount) external view returns (uint256);

    /// @notice Converts an amount of restaking tokens to the equivalent in the provided
    /// asset's EigenLayer shares.
    /// @param asset The address of the asset whose EigenLayer shares to convert to.
    /// @param amount The amount of restaking tokens to convert.
    function convertToSharesFromRestakingTokens(address asset, uint256 amount) external view returns (uint256);

    /// @notice EIP-712 helper.
    /// @param structHash The hash of the struct.
    function hashTypedData(bytes32 structHash) external view returns (bytes32);

    /// @notice Deposits ERC20 tokens and mints restaking token(s) to the caller.
    /// @param asset The asset being deposited.
    /// @param amountIn The amount of the asset being deposited.
    function depositERC20(address asset, uint256 amountIn) external returns (uint256);

    /// @notice Deposits ETH and mints restaking token(s) to the caller.
    function depositETH() external payable returns (uint256);

    /// @notice Requests a withdrawal to `asset` for `amountIn` restaking tokens.
    /// @param asset The asset being withdrawn.
    /// @param amountIn The amount of restaking tokens requested for withdrawal.
    function requestWithdrawal(address asset, uint256 amountIn) external;

    /// @notice Rebalances ETH by processing outstanding withdrawals and depositing remaining
    /// ETH into EigenLayer.
    /// @param root The deposit merkle root.
    /// @param signature The guardian signature.
    /// @dev This function requires a guardian signature prior to depositing ETH into EigenLayer. If the
    /// guardian doesn't provide a signature within 24 hours, then the rebalance will be allowed without
    /// a signature, but only for withdrawals. In the future, this may be extended to allow a rebalance
    /// without a guardian signature without waiting 24 hours if withdrawals outnumber deposits.
    function rebalanceETH(bytes32 root, bytes calldata signature) external;

    /// @notice Rebalances the provided ERC20 `token` by processing outstanding withdrawals and
    /// depositing remaining tokens into EigenLayer.
    /// @param token The token to rebalance.
    function rebalanceERC20(address token) external;
}


// ============================================================================
// FILE: contracts/utils/OperatorOperations.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {FixedPointMathLib} from '@solady/utils/FixedPointMathLib.sol';
import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {IRioLRTOperatorDelegator} from 'contracts/interfaces/IRioLRTOperatorDelegator.sol';
import {BEACON_CHAIN_STRATEGY, ETH_DEPOSIT_SIZE} from 'contracts/utils/Constants.sol';

/// @title Operator delegator deposit and withdrawal operations.
library OperatorOperations {
    using FixedPointMathLib for uint256;
    using SafeERC20 for IERC20;

    /// @notice Thrown when the number of shares queued for withdrawal from EigenLayer
    /// do not match the number of shares requested.
    error INCORRECT_NUMBER_OF_SHARES_QUEUED();

    /// @notice Deposits ETH into EigenLayer through the operators that are returned from the registry.
    /// @param operatorRegistry The operator registry used allocate to and deallocate from EigenLayer operators.
    /// @param amount The amount of ETH to deposit.
    function depositETHToOperators(IRioLRTOperatorRegistry operatorRegistry, uint256 amount) internal returns (uint256 depositAmount) {
        uint256 depositCount = amount / ETH_DEPOSIT_SIZE;
        if (depositCount == 0) return depositAmount;

        // forgefmt: disable-next-item
        (uint256 depositsAllocated, IRioLRTOperatorRegistry.OperatorETHAllocation[] memory allocations) = operatorRegistry.allocateETHDeposits(
            depositCount
        );
        depositAmount = depositsAllocated * ETH_DEPOSIT_SIZE;

        for (uint256 i = 0; i < allocations.length; ++i) {
            uint256 deposits = allocations[i].deposits;

            IRioLRTOperatorDelegator(allocations[i].delegator).stakeETH{value: deposits * ETH_DEPOSIT_SIZE}(
                deposits, allocations[i].pubKeyBatch, allocations[i].signatureBatch
            );
        }
    }

    /// @notice Deposits the given `amount` of tokens into EigenLayer the provided
    /// EigenLayer `strategy` via the operators that are returned from the registry.
    /// @param operatorRegistry The operator registry used allocate to and deallocate from EigenLayer operators.
    /// @param token The address of the token to deposit.
    /// @param strategy The strategy to deposit the funds into.
    /// @param sharesToAllocate The amount of strategy shares to allocate.
    function depositTokenToOperators(
        IRioLRTOperatorRegistry operatorRegistry,
        address token,
        address strategy,
        uint256 sharesToAllocate
    ) internal returns (uint256 sharesReceived) {
        (, IRioLRTOperatorRegistry.OperatorStrategyAllocation[] memory  allocations) = operatorRegistry.allocateStrategyShares(
            strategy, sharesToAllocate
        );

        for (uint256 i = 0; i < allocations.length; ++i) {
            IRioLRTOperatorRegistry.OperatorStrategyAllocation memory allocation = allocations[i];

            IERC20(token).safeTransfer(allocation.delegator, allocation.tokens);
            sharesReceived += IRioLRTOperatorDelegator(allocation.delegator).stakeERC20(strategy, token, allocation.tokens);
        }
    }

    /// @notice Queues withdrawals from EigenLayer through the operators that are returned from the registry.
    /// @param operatorRegistry The operator registry used allocate to and deallocate from EigenLayer operators.
    /// @param strategy The strategy to withdraw the funds from.
    /// @param amount The amount needed.
    function queueWithdrawalFromOperatorsForUserSettlement(
        IRioLRTOperatorRegistry operatorRegistry,
        address strategy,
        uint256 amount
    ) internal returns (bytes32 aggregateRoot) {
        if (strategy == BEACON_CHAIN_STRATEGY) {
            return queueETHWithdrawalFromOperatorsForUserSettlement(operatorRegistry, amount);
        }
        return queueTokenWithdrawalFromOperatorsForUserSettlement(operatorRegistry, strategy, amount);
    }

    /// @notice Queues ETH withdrawals from EigenLayer through the operators that are returned from the registry.
    /// @param operatorRegistry The operator registry used allocate to and deallocate from EigenLayer operators.
    /// @param amount The amount of ETH needed.
    function queueETHWithdrawalFromOperatorsForUserSettlement(IRioLRTOperatorRegistry operatorRegistry, uint256 amount) internal returns (bytes32 aggregateRoot) {
        uint256 depositCount = amount.divUp(ETH_DEPOSIT_SIZE);
        (, IRioLRTOperatorRegistry.OperatorETHDeallocation[] memory operatorDepositDeallocations) = operatorRegistry.deallocateETHDeposits(
            depositCount
        );
        uint256 length = operatorDepositDeallocations.length;
        bytes32[] memory roots = new bytes32[](length);

        uint256 remainingAmount = amount;
        for (uint256 i = 0; i < length; ++i) {
            address delegator = operatorDepositDeallocations[i].delegator;

            // Ensure we do not send more than needed to the withdrawal queue. The remaining will stay in the Eigen Pod.
            uint256 amountToWithdraw = (i == length - 1) ? remainingAmount : operatorDepositDeallocations[i].deposits * ETH_DEPOSIT_SIZE;

            remainingAmount -= amountToWithdraw;
            roots[i] = IRioLRTOperatorDelegator(delegator).queueWithdrawalForUserSettlement(BEACON_CHAIN_STRATEGY, amountToWithdraw);
        }
        aggregateRoot = keccak256(abi.encode(roots));
    }

    /// @notice Queues a withdrawal from EigenLayer through the operators that are returned from the registry.
    /// @param operatorRegistry The operator registry used allocate to and deallocate from EigenLayer operators.
    /// @param strategy The strategy to withdraw the funds from.
    /// @param sharesToWithdraw The number of shares to withdraw.
    function queueTokenWithdrawalFromOperatorsForUserSettlement(
        IRioLRTOperatorRegistry operatorRegistry,
        address strategy,
        uint256 sharesToWithdraw
    ) internal returns (bytes32 aggregateRoot) {
        (, IRioLRTOperatorRegistry.OperatorStrategyDeallocation[] memory operatorDeallocations) = operatorRegistry.deallocateStrategyShares(
            strategy, sharesToWithdraw
        );
        bytes32[] memory roots = new bytes32[](operatorDeallocations.length);

        uint256 sharesQueued;
        for (uint256 i = 0; i < operatorDeallocations.length; ++i) {
            address delegator = operatorDeallocations[i].delegator;
            uint256 shares = operatorDeallocations[i].shares;

            sharesQueued += shares;
            roots[i] = IRioLRTOperatorDelegator(delegator).queueWithdrawalForUserSettlement(strategy, shares);
        }
        if (sharesToWithdraw != sharesQueued) revert INCORRECT_NUMBER_OF_SHARES_QUEUED();

        aggregateRoot = keccak256(abi.encode(roots));
    }
}


// ============================================================================
// FILE: contracts/restaking/base/RioLRTCore.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {Initializable} from '@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol';
import {IRioLRTRewardDistributor} from 'contracts/interfaces/IRioLRTRewardDistributor.sol';
import {IRioLRTOperatorDelegator} from 'contracts/interfaces/IRioLRTOperatorDelegator.sol';
import {IRioLRTOperatorRegistry} from 'contracts/interfaces/IRioLRTOperatorRegistry.sol';
import {IRioLRTWithdrawalQueue} from 'contracts/interfaces/IRioLRTWithdrawalQueue.sol';
import {IRioLRTAssetRegistry} from 'contracts/interfaces/IRioLRTAssetRegistry.sol';
import {IRioLRTAVSRegistry} from 'contracts/interfaces/IRioLRTAVSRegistry.sol';
import {IRioLRTDepositPool} from 'contracts/interfaces/IRioLRTDepositPool.sol';
import {IRioLRTCoordinator} from 'contracts/interfaces/IRioLRTCoordinator.sol';
import {LRTAddressCalculator} from 'contracts/utils/LRTAddressCalculator.sol';
import {IRioLRT} from 'contracts/interfaces/IRioLRT.sol';

/// @title Utilities inherited by all core LRT contracts.
abstract contract RioLRTCore is Initializable {
    using LRTAddressCalculator for address;

    /// @notice Thrown when the initializer is not the LRT issuer.
    error ONLY_ISSUER();

    /// @notice Thrown when the caller is not the LRT coordinator.
    error ONLY_COORDINATOR();

    /// @notice Thrown when the caller is not the LRT deposit pool.
    error ONLY_DEPOSIT_POOL();

    /// @notice Thrown when the caller is not the LRT withdrawal queue.
    error ONLY_WITHDRAWAL_QUEUE();

    /// @notice Thrown when the caller is not the operator registry.
    error ONLY_OPERATOR_REGISTRY();

    /// @notice The LRT issuer that's authorized to deploy this contract.
    address public immutable issuer;

    /// @notice The liquid restaking token (LRT) address.
    IRioLRT public token;

    /// @notice Require that the caller is the coordinator.
    modifier onlyCoordinator() {
        if (msg.sender != address(coordinator())) revert ONLY_COORDINATOR();
        _;
    }

    /// @notice Require that the caller is the deposit pool.
    modifier onlyDepositPool() {
        if (msg.sender != address(depositPool())) revert ONLY_DEPOSIT_POOL();
        _;
    }

    /// @notice Require that the caller is the withdrawal queue.
    modifier onlyWithdrawalQueue() {
        if (msg.sender != address(withdrawalQueue())) revert ONLY_WITHDRAWAL_QUEUE();
        _;
    }

    /// @notice Require that the caller is the LRT's operator registry.
    modifier onlyOperatorRegistry() {
        if (msg.sender != address(operatorRegistry())) revert ONLY_OPERATOR_REGISTRY();
        _;
    }

    /// @dev Prevent any future reinitialization.
    /// @param issuer_ The LRT issuer that's authorized to deploy this contract.
    constructor(address issuer_) {
        _disableInitializers();

        issuer = issuer_;
    }

    /// @notice Initializes the restaking contract.
    /// @param token_ The address of the liquid restaking token.
    function __RioLRTCore_init(address token_) internal onlyInitializing {
        if (msg.sender != issuer) revert ONLY_ISSUER();

        token = IRioLRT(token_);
    }

    /// @notice Initializes the restaking contract without verifying the caller.
    /// @param token_ The address of the liquid restaking token.
    function __RioLRTCore_init_noVerify(address token_) internal onlyInitializing {
        token = IRioLRT(token_);
    }

    /// @notice The LRT coordinator contract.
    function coordinator() internal view returns (IRioLRTCoordinator) {
        return IRioLRTCoordinator(issuer.getCoordinator(address(token)));
    }

    /// @notice The LRT asset registry contract.
    function assetRegistry() internal view returns (IRioLRTAssetRegistry) {
        return IRioLRTAssetRegistry(issuer.getAssetRegistry(address(token)));
    }

    /// @notice The LRT operator registry contract.
    function operatorRegistry() internal view returns (IRioLRTOperatorRegistry) {
        return IRioLRTOperatorRegistry(issuer.getOperatorRegistry(address(token)));
    }

    /// @notice The LRT AVS registry contract.
    function avsRegistry() internal view returns (IRioLRTAVSRegistry) {
        return IRioLRTAVSRegistry(issuer.getAVSRegistry(address(token)));
    }

    /// @notice The LRT deposit pool contract.
    function depositPool() internal view returns (IRioLRTDepositPool) {
        return IRioLRTDepositPool(issuer.getDepositPool(address(token)));
    }

    /// @notice The LRT withdrawal queue contract.
    function withdrawalQueue() internal view returns (IRioLRTWithdrawalQueue) {
        return IRioLRTWithdrawalQueue(issuer.getWithdrawalQueue(address(token)));
    }

    /// @notice The LRT reward distributor contract.
    function rewardDistributor() internal view returns (IRioLRTRewardDistributor) {
        return IRioLRTRewardDistributor(issuer.getRewardDistributor(address(token)));
    }

    // forgefmt: disable-next-item
    /// @notice Calculates the address of an operator delegator.
    /// @param registry The operator registry address.
    /// @param operatorId The operator's ID.
    function operatorDelegator(IRioLRTOperatorRegistry registry, uint8 operatorId) internal pure returns (IRioLRTOperatorDelegator) {
        return IRioLRTOperatorDelegator(address(registry).getOperatorDelegatorAddress(operatorId));
    }
}


// ============================================================================
// FILE: contracts/utils/Asset.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {SafeERC20} from '@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol';
import {SafeCast} from '@openzeppelin/contracts/utils/math/SafeCast.sol';
import {ETH_ADDRESS, GWEI_TO_WEI} from 'contracts/utils/Constants.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

/// @title Asset utility functions.
library Asset {
    using SafeERC20 for IERC20;
    using Asset for address;

    /// @notice Thrown when an ETH transfer fails.
    error ETH_TRANSFER_FAILED();

    /// @notice Returns the amount of the asset held by this contract.
    /// @param asset The asset to check.
    function getSelfBalance(address asset) internal view returns (uint256) {
        if (asset == ETH_ADDRESS) {
            return address(this).balance;
        }
        return IERC20(asset).balanceOf(address(this));
    }

    /// @dev Sends `amount` of the given asset to `recipient`.
    /// @param asset The asset to send.
    /// @param recipient The asset recipient.
    /// @param amount The amount of the asset to send.
    function transferTo(address asset, address recipient, uint256 amount) internal {
        if (asset == ETH_ADDRESS) {
            return recipient.transferETH(amount);
        }
        IERC20(asset).safeTransfer(recipient, amount);
    }

    /// @dev Sends `amount` of ETH to `recipient`.
    /// @param recipient The asset recipient.
    /// @param amount The amount of ETH to send.
    function transferETH(address recipient, uint256 amount) internal {
        (bool success,) = recipient.call{value: amount}('');
        if (!success) {
            revert ETH_TRANSFER_FAILED();
        }
    }

    /// @dev Converts an amount of Gwei to Wei.
    /// @param amountGwei The amount in Gwei to convert.
    function toWei(uint256 amountGwei) internal pure returns (uint256) {
        return amountGwei * GWEI_TO_WEI;
    }

    /// @dev Converts an amount of Wei to Gwei.
    /// @param amountWei The amount in Wei to convert.
    function toGwei(uint256 amountWei) internal pure returns (uint64) {
        return SafeCast.toUint64(amountWei / GWEI_TO_WEI);
    }

    /// @notice Reduces the precision of the given amount to the nearest Gwei.
    /// @param amountWei The amount whose precision is to be reduced.
    function reducePrecisionToGwei(uint256 amountWei) internal pure returns (uint256) {
        return amountWei - (amountWei % GWEI_TO_WEI);
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity ^0.8.20;

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
// FILE: lib/openzeppelin-contracts/contracts/utils/Address.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/Address.sol)

pragma solidity ^0.8.20;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev The ETH balance of the account is not enough to perform the operation.
     */
    error AddressInsufficientBalance(address account);

    /**
     * @dev There's no code at `target` (it is not a contract).
     */
    error AddressEmptyCode(address target);

    /**
     * @dev A call to an address target failed. The target may have reverted.
     */
    error FailedInnerCall();

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
     * https://solidity.readthedocs.io/en/v0.8.20/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        if (address(this).balance < amount) {
            revert AddressInsufficientBalance(address(this));
        }

        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert FailedInnerCall();
        }
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain `call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason or custom error, it is bubbled
     * up by this function (like regular Solidity function calls). However, if
     * the call reverted with no returned reason, this function reverts with a
     * {FailedInnerCall} error.
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        if (address(this).balance < value) {
            revert AddressInsufficientBalance(address(this));
        }
        (bool success, bytes memory returndata) = target.call{value: value}(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        (bool success, bytes memory returndata) = target.staticcall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return verifyCallResultFromTarget(target, success, returndata);
    }

    /**
     * @dev Tool to verify that a low level call to smart-contract was successful, and reverts if the target
     * was not a contract or bubbling up the revert reason (falling back to {FailedInnerCall}) in case of an
     * unsuccessful call.
     */
    function verifyCallResultFromTarget(
        address target,
        bool success,
        bytes memory returndata
    ) internal view returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            // only check if target is a contract if the call was successful and the return data is empty
            // otherwise we already know that it was a contract
            if (returndata.length == 0 && target.code.length == 0) {
                revert AddressEmptyCode(target);
            }
            return returndata;
        }
    }

    /**
     * @dev Tool to verify that a low level call was successful, and reverts if it wasn't, either by bubbling the
     * revert reason or with a default {FailedInnerCall} error.
     */
    function verifyCallResult(bool success, bytes memory returndata) internal pure returns (bytes memory) {
        if (!success) {
            _revert(returndata);
        } else {
            return returndata;
        }
    }

    /**
     * @dev Reverts with returndata if present. Otherwise reverts with {FailedInnerCall}.
     */
    function _revert(bytes memory returndata) private pure {
        // Look for revert reason and bubble it up if present
        if (returndata.length > 0) {
            // The easiest way to bubble the revert reason is using memory via assembly
            /// @solidity memory-safe-assembly
            assembly {
                let returndata_size := mload(returndata)
                revert(add(32, returndata), returndata_size)
            }
        } else {
            revert FailedInnerCall();
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/interfaces/draft-IERC1822.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/draft-IERC1822.sol)

pragma solidity ^0.8.20;

/**
 * @dev ERC1822: Universal Upgradeable Proxy Standard (UUPS) documents a method for upgradeability through a simplified
 * proxy whose upgrades are fully controlled by the current implementation.
 */
interface IERC1822Proxiable {
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
// FILE: lib/openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Utils.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/ERC1967/ERC1967Utils.sol)

pragma solidity ^0.8.20;

import {IBeacon} from "../beacon/IBeacon.sol";
import {Address} from "../../utils/Address.sol";
import {StorageSlot} from "../../utils/StorageSlot.sol";

/**
 * @dev This abstract contract provides getters and event emitting update functions for
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967] slots.
 */
library ERC1967Utils {
    // We re-declare ERC-1967 events here because they can't be used directly from IERC1967.
    // This will be fixed in Solidity 0.8.21. At that point we should remove these events.
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

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev The `implementation` of the proxy is invalid.
     */
    error ERC1967InvalidImplementation(address implementation);

    /**
     * @dev The `admin` of the proxy is invalid.
     */
    error ERC1967InvalidAdmin(address admin);

    /**
     * @dev The `beacon` of the proxy is invalid.
     */
    error ERC1967InvalidBeacon(address beacon);

    /**
     * @dev An upgrade function sees `msg.value > 0` that may be lost.
     */
    error ERC1967NonPayable();

    /**
     * @dev Returns the current implementation address.
     */
    function getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        if (newImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(newImplementation);
        }
        StorageSlot.getAddressSlot(IMPLEMENTATION_SLOT).value = newImplementation;
    }

    /**
     * @dev Performs implementation upgrade with additional setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-Upgraded} event.
     */
    function upgradeToAndCall(address newImplementation, bytes memory data) internal {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);

        if (data.length > 0) {
            Address.functionDelegateCall(newImplementation, data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Returns the current admin.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using
     * the https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
     */
    function getAdmin() internal view returns (address) {
        return StorageSlot.getAddressSlot(ADMIN_SLOT).value;
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        if (newAdmin == address(0)) {
            revert ERC1967InvalidAdmin(address(0));
        }
        StorageSlot.getAddressSlot(ADMIN_SLOT).value = newAdmin;
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {IERC1967-AdminChanged} event.
     */
    function changeAdmin(address newAdmin) internal {
        emit AdminChanged(getAdmin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is the keccak-256 hash of "eip1967.proxy.beacon" subtracted by 1.
     */
    // solhint-disable-next-line private-vars-leading-underscore
    bytes32 internal constant BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Returns the current beacon.
     */
    function getBeacon() internal view returns (address) {
        return StorageSlot.getAddressSlot(BEACON_SLOT).value;
    }

    /**
     * @dev Stores a new beacon in the EIP1967 beacon slot.
     */
    function _setBeacon(address newBeacon) private {
        if (newBeacon.code.length == 0) {
            revert ERC1967InvalidBeacon(newBeacon);
        }

        StorageSlot.getAddressSlot(BEACON_SLOT).value = newBeacon;

        address beaconImplementation = IBeacon(newBeacon).implementation();
        if (beaconImplementation.code.length == 0) {
            revert ERC1967InvalidImplementation(beaconImplementation);
        }
    }

    /**
     * @dev Change the beacon and trigger a setup call if data is nonempty.
     * This function is payable only if the setup call is performed, otherwise `msg.value` is rejected
     * to avoid stuck value in the contract.
     *
     * Emits an {IERC1967-BeaconUpgraded} event.
     *
     * CAUTION: Invoking this function has no effect on an instance of {BeaconProxy} since v5, since
     * it uses an immutable beacon without looking at the value of the ERC-1967 beacon slot for
     * efficiency.
     */
    function upgradeBeaconToAndCall(address newBeacon, bytes memory data) internal {
        _setBeacon(newBeacon);
        emit BeaconUpgraded(newBeacon);

        if (data.length > 0) {
            Address.functionDelegateCall(IBeacon(newBeacon).implementation(), data);
        } else {
            _checkNonPayable();
        }
    }

    /**
     * @dev Reverts if `msg.value` is not zero. It can be used to avoid `msg.value` stuck in the contract
     * if an upgrade doesn't perform an initialization call.
     */
    function _checkNonPayable() private {
        if (msg.value > 0) {
            revert ERC1967NonPayable();
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts-upgradeable/contracts/proxy/utils/Initializable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/utils/Initializable.sol)

pragma solidity ^0.8.20;

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
     * @dev Storage of the initializable contract.
     *
     * It's implemented on a custom ERC-7201 namespace to reduce the risk of storage collisions
     * when using with upgradeable contracts.
     *
     * @custom:storage-location erc7201:openzeppelin.storage.Initializable
     */
    struct InitializableStorage {
        /**
         * @dev Indicates that the contract has been initialized.
         */
        uint64 _initialized;
        /**
         * @dev Indicates that the contract is in the process of being initialized.
         */
        bool _initializing;
    }

    // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant INITIALIZABLE_STORAGE = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00;

    /**
     * @dev The contract is already initialized.
     */
    error InvalidInitialization();

    /**
     * @dev The contract is not initializing.
     */
    error NotInitializing();

    /**
     * @dev Triggered when the contract has been initialized or reinitialized.
     */
    event Initialized(uint64 version);

    /**
     * @dev A modifier that defines a protected initializer function that can be invoked at most once. In its scope,
     * `onlyInitializing` functions can be used to initialize parent contracts.
     *
     * Similar to `reinitializer(1)`, except that in the context of a constructor an `initializer` may be invoked any
     * number of times. This behavior in the constructor can be useful during testing and is not expected to be used in
     * production.
     *
     * Emits an {Initialized} event.
     */
    modifier initializer() {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        // Cache values to avoid duplicated sloads
        bool isTopLevelCall = !$._initializing;
        uint64 initialized = $._initialized;

        // Allowed calls:
        // - initialSetup: the contract is not in the initializing state and no previous version was
        //                 initialized
        // - construction: the contract is initialized at version 1 (no reininitialization) and the
        //                 current contract is just being deployed
        bool initialSetup = initialized == 0 && isTopLevelCall;
        bool construction = initialized == 1 && address(this).code.length == 0;

        if (!initialSetup && !construction) {
            revert InvalidInitialization();
        }
        $._initialized = 1;
        if (isTopLevelCall) {
            $._initializing = true;
        }
        _;
        if (isTopLevelCall) {
            $._initializing = false;
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
     * WARNING: Setting the version to 2**64 - 1 will prevent any future reinitialization.
     *
     * Emits an {Initialized} event.
     */
    modifier reinitializer(uint64 version) {
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing || $._initialized >= version) {
            revert InvalidInitialization();
        }
        $._initialized = version;
        $._initializing = true;
        _;
        $._initializing = false;
        emit Initialized(version);
    }

    /**
     * @dev Modifier to protect an initialization function so that it can only be invoked by functions with the
     * {initializer} and {reinitializer} modifiers, directly or indirectly.
     */
    modifier onlyInitializing() {
        _checkInitializing();
        _;
    }

    /**
     * @dev Reverts if the contract is not in an initializing state. See {onlyInitializing}.
     */
    function _checkInitializing() internal view virtual {
        if (!_isInitializing()) {
            revert NotInitializing();
        }
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
        // solhint-disable-next-line var-name-mixedcase
        InitializableStorage storage $ = _getInitializableStorage();

        if ($._initializing) {
            revert InvalidInitialization();
        }
        if ($._initialized != type(uint64).max) {
            $._initialized = type(uint64).max;
            emit Initialized(type(uint64).max);
        }
    }

    /**
     * @dev Returns the highest version that has been initialized. See {reinitializer}.
     */
    function _getInitializedVersion() internal view returns (uint64) {
        return _getInitializableStorage()._initialized;
    }

    /**
     * @dev Returns `true` if the contract is currently initializing. See {onlyInitializing}.
     */
    function _isInitializing() internal view returns (bool) {
        return _getInitializableStorage()._initializing;
    }

    /**
     * @dev Returns a pointer to the storage namespace.
     */
    // solhint-disable-next-line var-name-mixedcase
    function _getInitializableStorage() private pure returns (InitializableStorage storage $) {
        assembly {
            $.slot := INITIALIZABLE_STORAGE
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts-upgradeable/contracts/utils/ContextUpgradeable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;
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
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IEigenPod.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IBeaconChainProofs} from 'contracts/interfaces/eigenlayer/IBeaconChainProofs.sol';
import {IEigenPodManager} from 'contracts/interfaces/eigenlayer/IEigenPodManager.sol';

/// @title The implementation contract used for restaking beacon chain ETH on EigenLayer
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice The main functionalities are:
/// - creating new ETH validators with their withdrawal credentials pointed to this contract
/// - proving from beacon chain state roots that withdrawal credentials are pointed to this contract
/// - proving from beacon chain state roots the balances of ETH validators with their withdrawal credentials
///   pointed to this contract
/// - updating aggregate balances in the EigenPodManager
/// - withdrawing eth when withdrawals are initiated
/// @dev Note that all beacon chain balances are stored as gwei within the beacon chain datastructures. We choose
///   to account balances in terms of gwei in the EigenPod contract and convert to wei when making calls to other contracts
interface IEigenPod {
    enum VALIDATOR_STATUS {
        // doesnt exist
        INACTIVE,
        // staked on ethpos and withdrawal credentials are pointed to the EigenPod
        ACTIVE,
        // withdrawn from the Beacon Chain
        WITHDRAWN
    }

    struct ValidatorInfo {
        // index of the validator in the beacon chain
        uint64 validatorIndex;
        // amount of beacon chain ETH restaked on EigenLayer in gwei
        uint64 restakedBalanceGwei;
        //timestamp of the validator's most recent balance update
        uint64 mostRecentBalanceUpdateTimestamp;
        // status of the validator
        VALIDATOR_STATUS status;
    }

    /// @notice struct used to store amounts related to proven withdrawals in memory. Used to help
    /// manage stack depth and optimize the number of external calls, when batching withdrawal operations.
    struct VerifiedWithdrawal {
        // amount to send to a podOwner from a proven withdrawal
        uint256 amountToSendGwei;
        // difference in shares to be recorded in the eigenPodManager, as a result of the withdrawal
        int256 sharesDeltaGwei;
    }

    enum PARTIAL_WITHDRAWAL_CLAIM_STATUS {
        REDEEMED,
        PENDING,
        FAILED
    }

    /// @notice Emitted when an ETH validator stakes via this eigenPod
    event EigenPodStaked(bytes pubkey);

    /// @notice Emitted when an ETH validator's withdrawal credentials are successfully verified to be pointed to this eigenPod
    event ValidatorRestaked(uint40 validatorIndex);

    /// @notice Emitted when an ETH validator's  balance is proven to be updated.  Here newValidatorBalanceGwei
    /// is the validator's balance that is credited on EigenLayer.
    event ValidatorBalanceUpdated(uint40 validatorIndex, uint64 balanceTimestamp, uint64 newValidatorBalanceGwei);

    /// @notice Emitted when an ETH validator is prove to have withdrawn from the beacon chain
    event FullWithdrawalRedeemed(
        uint40 validatorIndex, uint64 withdrawalTimestamp, address indexed recipient, uint64 withdrawalAmountGwei
    );

    /// @notice Emitted when a partial withdrawal claim is successfully redeemed
    event PartialWithdrawalRedeemed(
        uint40 validatorIndex, uint64 withdrawalTimestamp, address indexed recipient, uint64 partialWithdrawalAmountGwei
    );

    /// @notice Emitted when restaked beacon chain ETH is withdrawn from the eigenPod.
    event RestakedBeaconChainETHWithdrawn(address indexed recipient, uint256 amount);

    /// @notice Emitted when podOwner enables restaking
    event RestakingActivated(address indexed podOwner);

    /// @notice Emitted when ETH is received via the `receive` fallback
    event NonBeaconChainETHReceived(uint256 amountReceived);

    /// @notice Emitted when ETH that was previously received via the `receive` fallback is withdrawn
    event NonBeaconChainETHWithdrawn(address indexed recipient, uint256 amountWithdrawn);

    /// @notice The max amount of eth, in gwei, that can be restaked per validator
    function MAX_RESTAKED_BALANCE_GWEI_PER_VALIDATOR() external view returns (uint64);

    /// @notice Contract used for withdrawal routing, to provide an extra "safety net" mechanism
    function delayedWithdrawalRouter() external view returns (address);

    /// @notice the amount of execution layer ETH in this contract that is staked in EigenLayer (i.e. withdrawn from beaconchain but not EigenLayer),
    function withdrawableRestakedExecutionLayerGwei() external view returns (uint64);

    /// @notice any ETH deposited into the EigenPod contract via the `receive` fallback function
    function nonBeaconChainETHBalanceWei() external view returns (uint256);

    /// @notice Used to initialize the pointers to contracts crucial to the pod's functionality, in beacon proxy construction from EigenPodManager
    function initialize(address owner) external;

    /// @notice Called by EigenPodManager when the owner wants to create another ETH validator.
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /// @notice Transfers `amountWei` in ether from this contract to the specified `recipient` address
    /// @notice Called by EigenPodManager to withdrawBeaconChainETH that has been added to the EigenPod's balance due to a withdrawal from the beacon chain.
    /// @dev The podOwner must have already proved sufficient withdrawals, so that this pod's `withdrawableRestakedExecutionLayerGwei` exceeds the
    /// `amountWei` input (when converted to GWEI).
    /// @dev Reverts if `amountWei` is not a whole Gwei amount
    function withdrawRestakedBeaconChainETH(address recipient, uint256 amount) external;

    /// @notice The single EigenPodManager for EigenLayer
    function eigenPodManager() external view returns (IEigenPodManager);

    /// @notice The owner of this EigenPod
    function podOwner() external view returns (address);

    /// @notice an indicator of whether or not the podOwner has ever "fully restaked" by successfully calling `verifyCorrectWithdrawalCredentials`.
    function hasRestaked() external view returns (bool);

    /// @notice The latest timestamp at which the pod owner withdrew the balance of the pod, via calling `withdrawBeforeRestaking`.
    /// @dev This variable is only updated when the `withdrawBeforeRestaking` function is called, which can only occur before `hasRestaked` is set to true for this pod.
    /// Proofs for this pod are only valid against Beacon Chain state roots corresponding to timestamps after the stored `mostRecentWithdrawalTimestamp`.
    function mostRecentWithdrawalTimestamp() external view returns (uint64);

    /// @notice Returns the validatorInfo struct for the provided pubkeyHash
    function validatorPubkeyHashToInfo(bytes32 validatorPubkeyHash) external view returns (ValidatorInfo memory);

    ///@notice mapping that tracks proven withdrawals
    function provenWithdrawal(bytes32 validatorPubkeyHash, uint64 slot) external view returns (bool);

    /// @notice This returns the status of a given validator
    function validatorStatus(bytes32 pubkeyHash) external view returns (VALIDATOR_STATUS);

    /// @notice This function verifies that the withdrawal credentials of validator(s) owned by the podOwner are pointed to
    /// this contract. It also verifies the effective balance  of the validator.  It verifies the provided proof of the ETH validator against the beacon chain state
    /// root, marks the validator as 'active' in EigenLayer, and credits the restaked ETH in Eigenlayer.
    /// @param oracleTimestamp is the Beacon Chain timestamp whose state root the `proof` will be proven against.
    /// @param validatorIndices is the list of indices of the validators being proven, refer to consensus specs
    /// @param withdrawalCredentialProofs is an array of proofs, where each proof proves each ETH validator's balance and withdrawal credentials
    /// against a beacon chain state root
    /// @param validatorFields are the fields of the "Validator Container", refer to consensus specs
    /// for details: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    function verifyWithdrawalCredentials(
        uint64 oracleTimestamp,
        IBeaconChainProofs.StateRootProof calldata stateRootProof,
        uint40[] calldata validatorIndices,
        bytes[] calldata withdrawalCredentialProofs,
        bytes32[][] calldata validatorFields
    ) external;

    /// @notice This function records an update (either increase or decrease) in the pod's balance in the StrategyManager.
    ///         It also verifies a merkle proof of the validator's current beacon chain balance.
    /// @param oracleTimestamp The oracleTimestamp whose state root the `proof` will be proven against.
    ///        Must be within `VERIFY_BALANCE_UPDATE_WINDOW_SECONDS` of the current block.
    /// @param validatorIndex is the index of the validator being proven, refer to consensus specs
    /// @param balanceUpdateProof is the proof of the validator's balance and validatorFields in the balance tree and the balanceRoot to prove for
    ///                                    the StrategyManager in case it must be removed from the list of the podOwner's strategies
    /// @param validatorFields are the fields of the "Validator Container", refer to consensus specs
    /// @dev For more details on the Beacon Chain spec, see: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#validator
    function verifyBalanceUpdate(
        uint64 oracleTimestamp,
        uint40 validatorIndex,
        IBeaconChainProofs.StateRootProof calldata stateRootProof,
        IBeaconChainProofs.BalanceUpdateProof calldata balanceUpdateProof,
        bytes32[] calldata validatorFields
    ) external;

    /// @notice This function records full and partial withdrawals on behalf of one of the Ethereum validators for this EigenPod
    /// @param oracleTimestamp is the timestamp of the oracle slot that the withdrawal is being proven against
    /// @param withdrawalProofs is the information needed to check the veracity of the block numbers and withdrawals being proven
    /// @param validatorFieldsProofs is the proof of the validator's fields' in the validator tree
    /// @param withdrawalFields are the fields of the withdrawals being proven
    /// @param validatorFields are the fields of the validators being proven
    function verifyAndProcessWithdrawals(
        uint64 oracleTimestamp,
        IBeaconChainProofs.StateRootProof calldata stateRootProof,
        IBeaconChainProofs.WithdrawalProof[] calldata withdrawalProofs,
        bytes[] calldata validatorFieldsProofs,
        bytes32[][] calldata validatorFields,
        bytes32[][] calldata withdrawalFields
    ) external;

    /// @notice Called by the pod owner to activate restaking by withdrawing
    /// all existing ETH from the pod and preventing further withdrawals via
    /// "withdrawBeforeRestaking()"
    function activateRestaking() external;

    /// @notice Called by the pod owner to withdraw the balance of the pod when `hasRestaked` is set to false
    function withdrawBeforeRestaking() external;

    /// @notice Called by the pod owner to withdraw the nonBeaconChainETHBalanceWei
    function withdrawNonBeaconChainETHBalanceWei(address recipient, uint256 amountToWithdraw) external;

    /// @notice called by owner of a pod to remove any ERC20s deposited in the pod
    function recoverTokens(IERC20[] memory tokenList, uint256[] memory amountsToWithdraw, address recipient) external;
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IBeaconChainProofs.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

interface IBeaconChainProofs {
    /// @notice This struct contains the merkle proofs and leaves needed to verify a partial/full withdrawal
    struct WithdrawalProof {
        bytes withdrawalProof;
        bytes slotProof;
        bytes executionPayloadProof;
        bytes timestampProof;
        bytes historicalSummaryBlockRootProof;
        uint64 blockRootIndex;
        uint64 historicalSummaryIndex;
        uint64 withdrawalIndex;
        bytes32 blockRoot;
        bytes32 slotRoot;
        bytes32 timestampRoot;
        bytes32 executionPayloadRoot;
    }

    /// @notice This struct contains the merkle proofs and leaves needed to verify a balance update
    struct BalanceUpdateProof {
        bytes validatorBalanceProof;
        bytes validatorFieldsProof;
        bytes32 balanceRoot;
    }

    /// @notice This struct contains the root and proof for verifying the state root against the oracle block root
    struct StateRootProof {
        bytes32 beaconStateRoot;
        bytes proof;
    }
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IDelegationManager.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IStrategy} from 'contracts/interfaces/eigenlayer/IStrategy.sol';
import {IStakeRegistry} from 'contracts/interfaces/eigenlayer/IStakeRegistry.sol';
import {ISignatureUtils} from 'contracts/interfaces/eigenlayer/ISignatureUtils.sol';

/// @title DelegationManager
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice  This is the contract for delegation in EigenLayer. The main functionalities of this contract are
/// - enabling anyone to register as an operator in EigenLayer
/// - allowing operators to specify parameters related to stakers who delegate to them
/// - enabling any staker to delegate its stake to the operator of its choice (a given staker can only delegate to a single operator at a time)
/// - enabling a staker to undelegate its assets from the operator it is delegated to (performed as part of the withdrawal process, initiated through the StrategyManager)
interface IDelegationManager is ISignatureUtils {
    /// @notice Struct used for storing information about a single operator who has registered with EigenLayer
    struct OperatorDetails {
        // @notice address to receive the rewards that the operator earns via serving applications built on EigenLayer.
        address earningsReceiver;
        /// @notice Address to verify signatures when a staker wishes to delegate to the operator, as well as controlling "forced undelegations".
        /// @dev Signature verification follows these rules:
        /// 1) If this address is left as address(0), then any staker will be free to delegate to the operator, i.e. no signature verification will be performed.
        /// 2) If this address is an EOA (i.e. it has no code), then we follow standard ECDSA signature verification for delegations to the operator.
        /// 3) If this address is a contract (i.e. it has code) then we forward a call to the contract and verify that it returns the correct EIP-1271 "magic value".
        address delegationApprover;
        /// @notice A minimum delay -- measured in blocks -- enforced between:
        /// 1) the operator signalling their intent to register for a service, via calling `Slasher.optIntoSlashing`
        /// and
        /// 2) the operator completing registration for the service, via the service ultimately calling `Slasher.recordFirstStakeUpdate`
        /// @dev note that for a specific operator, this value *cannot decrease*, i.e. if the operator wishes to modify their OperatorDetails,
        /// then they are only allowed to either increase this value or keep it the same.
        uint32 stakerOptOutWindowBlocks;
    }

    /// @notice Abstract struct used in calculating an EIP712 signature for a staker to approve that they (the staker themselves) delegate to a specific operator.
    /// @dev Used in computing the `STAKER_DELEGATION_TYPEHASH` and as a reference in the computation of the stakerDigestHash in the `delegateToBySignature` function.
    struct StakerDelegation {
        // the staker who is delegating
        address staker;
        // the operator being delegated to
        address operator;
        // the staker's nonce
        uint256 nonce;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }

    /// @notice Abstract struct used in calculating an EIP712 signature for an operator's delegationApprover to approve that a specific staker delegate to the operator.
    /// @dev Used in computing the `DELEGATION_APPROVAL_TYPEHASH` and as a reference in the computation of the approverDigestHash in the `_delegate` function.
    struct DelegationApproval {
        // the staker who is delegating
        address staker;
        // the operator being delegated to
        address operator;
        // the operator's provided salt
        bytes32 salt;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }

    /// @notice Emitted when the StakeRegistry is set
    event StakeRegistrySet(IStakeRegistry stakeRegistry);

    /// @notice Struct type used to specify an existing queued withdrawal. Rather than storing the entire struct, only a hash is stored.
    /// In functions that operate on existing queued withdrawals -- e.g. completeQueuedWithdrawal`, the data is resubmitted and the hash of the submitted
    /// data is computed by `calculateWithdrawalRoot` and checked against the stored hash in order to confirm the integrity of the submitted data.
    struct Withdrawal {
        // The address that originated the Withdrawal
        address staker;
        // The address that the staker was delegated to at the time that the Withdrawal was created
        address delegatedTo;
        // The address that can complete the Withdrawal + will receive funds when completing the withdrawal
        address withdrawer;
        // Nonce used to guarantee that otherwise identical withdrawals have unique hashes
        uint256 nonce;
        // Block number when the Withdrawal was created
        uint32 startBlock;
        // Array of strategies that the Withdrawal contains
        address[] strategies;
        // Array containing the amount of shares in each Strategy in the `strategies` array
        uint256[] shares;
    }

    struct QueuedWithdrawalParams {
        // Array of strategies that the QueuedWithdrawal contains
        address[] strategies;
        // Array containing the amount of shares in each Strategy in the `strategies` array
        uint256[] shares;
        // The address of the withdrawer
        address withdrawer;
    }

    /// @notice Emitted when a new operator registers in EigenLayer and provides their OperatorDetails.
    event OperatorRegistered(address indexed operator, OperatorDetails operatorDetails);

    /// @notice Emitted when an operator updates their OperatorDetails to @param newOperatorDetails
    event OperatorDetailsModified(address indexed operator, OperatorDetails newOperatorDetails);

    /// @notice Emitted when @param operator indicates that they are updating their MetadataURI string
    /// @dev Note that these strings are *never stored in storage* and are instead purely emitted in events for off-chain indexing
    event OperatorMetadataURIUpdated(address indexed operator, string metadataURI);

    /// @notice Emitted whenever an operator's shares are increased for a given strategy. Note that shares is the delta in the operator's shares.
    event OperatorSharesIncreased(address indexed operator, address staker, IStrategy strategy, uint256 shares);

    /// @notice Emitted whenever an operator's shares are decreased for a given strategy. Note that shares is the delta in the operator's shares.
    event OperatorSharesDecreased(address indexed operator, address staker, IStrategy strategy, uint256 shares);

    /// @notice Emitted when @param staker delegates to @param operator.
    event StakerDelegated(address indexed staker, address indexed operator);

    /// @notice Emitted when @param staker undelegates from @param operator.
    event StakerUndelegated(address indexed staker, address indexed operator);

    /// @notice Emitted when @param staker is undelegated via a call not originating from the staker themself
    event StakerForceUndelegated(address indexed staker, address indexed operator);

    /// @notice Emitted when a new withdrawal is queued.
    /// @param withdrawalRoot Is the hash of the `withdrawal`.
    /// @param withdrawal Is the withdrawal itself.
    event WithdrawalQueued(bytes32 withdrawalRoot, Withdrawal withdrawal);

    /// @notice Emitted when a queued withdrawal is completed
    event WithdrawalCompleted(bytes32 withdrawalRoot);

    /// @notice Emitted when a queued withdrawal is *migrated* from the StrategyManager to the DelegationManager
    event WithdrawalMigrated(bytes32 oldWithdrawalRoot, bytes32 newWithdrawalRoot);

    /// @notice Emitted when the `withdrawalDelayBlocks` variable is modified from `previousValue` to `newValue`.
    event WithdrawalDelayBlocksSet(uint256 previousValue, uint256 newValue);

    /// @notice Registers the caller as an operator in EigenLayer.
    /// @param registeringOperatorDetails is the `OperatorDetails` for the operator.
    /// @param metadataURI is a URI for the operator's metadata, i.e. a link providing more details on the operator.
    /// @dev Once an operator is registered, they cannot 'deregister' as an operator, and they will forever be considered "delegated to themself".
    /// @dev This function will revert if the caller attempts to set their `earningsReceiver` to address(0).
    /// @dev Note that the `metadataURI` is *never stored * and is only emitted in the `OperatorMetadataURIUpdated` event
    function registerAsOperator(OperatorDetails calldata registeringOperatorDetails, string calldata metadataURI)
        external;

    /// @notice Updates an operator's stored `OperatorDetails`.
    /// @param newOperatorDetails is the updated `OperatorDetails` for the operator, to replace their current OperatorDetails`.
    /// @dev The caller must have previously registered as an operator in EigenLayer.
    /// @dev This function will revert if the caller attempts to set their `earningsReceiver` to address(0).
    function modifyOperatorDetails(OperatorDetails calldata newOperatorDetails) external;

    /// @notice Called by an operator to emit an `OperatorMetadataURIUpdated` event indicating the information has updated.
    /// @param metadataURI The URI for metadata associated with an operator
    function updateOperatorMetadataURI(string calldata metadataURI) external;

    /// @notice Caller delegates their stake to an operator.
    /// @param operator The account (`msg.sender`) is delegating its assets to for use in serving applications built on EigenLayer.
    /// @param approverSignatureAndExpiry Verifies the operator approves of this delegation
    /// @param approverSalt A unique single use value tied to an individual signature.
    /// @dev The approverSignatureAndExpiry is used in the event that:
    ///          1) the operator's `delegationApprover` address is set to a non-zero value.
    ///                  AND
    ///          2) neither the operator nor their `delegationApprover` is the `msg.sender`, since in the event that the operator
    ///             or their delegationApprover is the `msg.sender`, then approval is assumed.
    /// @dev In the event that `approverSignatureAndExpiry` is not checked, its content is ignored entirely; it's recommended to use an empty input
    /// in this case to save on complexity + gas costs
    function delegateTo(address operator, SignatureWithExpiry memory approverSignatureAndExpiry, bytes32 approverSalt)
        external;

    /// @notice Caller delegates a staker's stake to an operator with valid signatures from both parties.
    /// @param staker The account delegating stake to an `operator` account
    /// @param operator The account (`staker`) is delegating its assets to for use in serving applications built on EigenLayer.
    /// @param stakerSignatureAndExpiry Signed data from the staker authorizing delegating stake to an operator
    /// @param approverSignatureAndExpiry is a parameter that will be used for verifying that the operator approves of this delegation action in the event that:
    /// @param approverSalt Is a salt used to help guarantee signature uniqueness. Each salt can only be used once by a given approver.
    ///
    /// @dev If `staker` is an EOA, then `stakerSignature` is verified to be a valid ECDSA stakerSignature from `staker`, indicating their intention for this action.
    /// @dev If `staker` is a contract, then `stakerSignature` will be checked according to EIP-1271.
    /// @dev the operator's `delegationApprover` address is set to a non-zero value.
    /// @dev neither the operator nor their `delegationApprover` is the `msg.sender`, since in the event that the operator or their delegationApprover
    /// is the `msg.sender`, then approval is assumed.
    /// @dev This function will revert if the current `block.timestamp` is equal to or exceeds the expiry
    /// @dev In the case that `approverSignatureAndExpiry` is not checked, its content is ignored entirely; it's recommended to use an empty input
    /// in this case to save on complexity + gas costs
    function delegateToBySignature(
        address staker,
        address operator,
        SignatureWithExpiry memory stakerSignatureAndExpiry,
        SignatureWithExpiry memory approverSignatureAndExpiry,
        bytes32 approverSalt
    ) external;

    /// @notice Undelegates the staker from the operator who they are delegated to. Puts the staker into the "undelegation limbo" mode of the EigenPodManager
    /// and queues a withdrawal of all of the staker's shares in the StrategyManager (to the staker), if necessary.
    /// @param staker The account to be undelegated.
    /// @return withdrawalRoot The root of the newly queued withdrawal, if a withdrawal was queued. Otherwise just bytes32(0).
    /// @dev Reverts if the `staker` is also an operator, since operators are not allowed to undelegate from themselves.
    /// @dev Reverts if the caller is not the staker, nor the operator who the staker is delegated to, nor the operator's specified "delegationApprover"
    /// @dev Reverts if the `staker` is already undelegated.
    function undelegate(address staker) external returns (bytes32 withdrawalRoot);

    /// Allows a staker to withdraw some shares. Withdrawn shares/strategies are immediately removed
    /// from the staker. If the staker is delegated, withdrawn shares/strategies are also removed from
    /// their operator.
    /// All withdrawn shares/strategies are placed in a queue and can be fully withdrawn after a delay.
    function queueWithdrawals(QueuedWithdrawalParams[] calldata queuedWithdrawalParams)
        external
        returns (bytes32[] memory);

    /// @notice Used to complete the specified `withdrawal`. The caller must match `withdrawal.withdrawer`
    /// @param withdrawal The Withdrawal to complete.
    /// @param tokens Array in which the i-th entry specifies the `token` input to the 'withdraw' function of the i-th Strategy in the `withdrawal.strategies` array.
    /// This input can be provided with zero length if `receiveAsTokens` is set to 'false' (since in that case, this input will be unused)
    /// @param middlewareTimesIndex is the index in the operator that the staker who triggered the withdrawal was delegated to's middleware times array
    /// @param receiveAsTokens If true, the shares specified in the withdrawal will be withdrawn from the specified strategies themselves
    /// and sent to the caller, through calls to `withdrawal.strategies[i].withdraw`. If false, then the shares in the specified strategies
    /// will simply be transferred to the caller directly.
    /// @dev middlewareTimesIndex should be calculated off chain before calling this function by finding the first index that satisfies `slasher.canWithdraw`
    /// @dev beaconChainETHStrategy shares are non-transferrable, so if `receiveAsTokens = false` and `withdrawal.withdrawer != withdrawal.staker`, note that
    /// any beaconChainETHStrategy shares in the `withdrawal` will be _returned to the staker_, rather than transferred to the withdrawer, unlike shares in
    /// any other strategies, which will be transferred to the withdrawer.
    function completeQueuedWithdrawal(
        Withdrawal calldata withdrawal,
        address[] calldata tokens,
        uint256 middlewareTimesIndex,
        bool receiveAsTokens
    ) external;

    /// @notice Array-ified version of `completeQueuedWithdrawal`.
    /// Used to complete the specified `withdrawals`. The function caller must match `withdrawals[...].withdrawer`
    /// @param withdrawals The Withdrawals to complete.
    /// @param tokens Array of tokens for each Withdrawal. See `completeQueuedWithdrawal` for the usage of a single array.
    /// @param middlewareTimesIndexes One index to reference per Withdrawal. See `completeQueuedWithdrawal` for the usage of a single index.
    /// @param receiveAsTokens Whether or not to complete each withdrawal as tokens. See `completeQueuedWithdrawal` for the usage of a single boolean.
    /// @dev See `completeQueuedWithdrawal` for relevant dev tags
    function completeQueuedWithdrawals(
        Withdrawal[] calldata withdrawals,
        address[][] calldata tokens,
        uint256[] calldata middlewareTimesIndexes,
        bool[] calldata receiveAsTokens
    ) external;

    /// @notice Increases a staker's delegated share balance in a strategy.
    /// @param staker The address to increase the delegated shares for their operator.
    /// @param strategy The strategy in which to increase the delegated shares.
    /// @param shares The number of shares to increase.
    /// @dev *If the staker is actively delegated*, then increases the `staker`'s delegated shares in `strategy` by `shares`. Otherwise does nothing.
    /// @dev Callable only by the StrategyManager or EigenPodManager.
    function increaseDelegatedShares(address staker, IStrategy strategy, uint256 shares) external;

    /// @notice Decreases a staker's delegated share balance in a strategy.
    /// @param staker The address to increase the delegated shares for their operator.
    /// @param strategy The strategy in which to decrease the delegated shares.
    /// @param shares The number of shares to decrease.
    /// @dev *If the staker is actively delegated*, then decreases the `staker`'s delegated shares in `strategy` by `shares`. Otherwise does nothing.
    /// @dev Callable only by the StrategyManager or EigenPodManager.
    function decreaseDelegatedShares(address staker, IStrategy strategy, uint256 shares) external;

    /// @notice the address of the StakeRegistry contract to call for stake updates when operator shares are changed
    function stakeRegistry() external view returns (IStakeRegistry);

    /// @notice returns the address of the operator that `staker` is delegated to.
    /// @notice Mapping: staker => operator whom the staker is currently delegated to.
    /// @dev Note that returning address(0) indicates that the staker is not actively delegated to any operator.
    function delegatedTo(address staker) external view returns (address);

    /// @notice Returns the OperatorDetails struct associated with an `operator`.
    function operatorDetails(address operator) external view returns (OperatorDetails memory);

    /// @notice Returns the earnings receiver address for an operator
    function earningsReceiver(address operator) external view returns (address);

    /// @notice Returns the delegationApprover account for an operator
    function delegationApprover(address operator) external view returns (address);

    /// @notice Returns the stakerOptOutWindowBlocks for an operator
    function stakerOptOutWindowBlocks(address operator) external view returns (uint256);

    /// @notice returns the total number of shares in `strategy` that are delegated to `operator`.
    /// @notice Mapping: operator => strategy => total number of shares in the strategy delegated to the operator.
    /// @dev By design, the following invariant should hold for each Strategy:
    /// (operator's shares in delegation manager) = sum (shares above zero of all stakers delegated to operator)
    /// = sum (delegateable shares of all stakers delegated to the operator)
    function operatorShares(address operator, IStrategy strategy) external view returns (uint256);

    /// @notice Returns 'true' if `staker` *is* actively delegated, and 'false' otherwise.
    function isDelegated(address staker) external view returns (bool);

    /// @notice Returns true is an operator has previously registered for delegation.
    function isOperator(address operator) external view returns (bool);

    /// @notice Mapping: staker => number of signed delegation nonces (used in `delegateToBySignature`) from the staker that the contract has already checked
    function stakerNonce(address staker) external view returns (uint256);

    /// @notice Mapping: delegationApprover => 32-byte salt => whether or not the salt has already been used by the delegationApprover.
    /// @dev Salts are used in the `delegateTo` and `delegateToBySignature` functions. Note that these functions only process the delegationApprover's
    /// signature + the provided salt if the operator being delegated to has specified a nonzero address as their `delegationApprover`.
    function delegationApproverSaltIsSpent(address _delegationApprover, bytes32 salt) external view returns (bool);

    /// @notice Calculates the digestHash for a `staker` to sign to delegate to an `operator`
    /// @param staker The signing staker
    /// @param operator The operator who is being delegated to
    /// @param expiry The desired expiry time of the staker's signature
    function calculateCurrentStakerDelegationDigestHash(address staker, address operator, uint256 expiry)
        external
        view
        returns (bytes32);

    /// @notice Calculates the digest hash to be signed and used in the `delegateToBySignature` function
    /// @param staker The signing staker
    /// @param _stakerNonce The nonce of the staker. In practice we use the staker's current nonce, stored at `stakerNonce[staker]`
    /// @param operator The operator who is being delegated to
    /// @param expiry The desired expiry time of the staker's signature
    function calculateStakerDelegationDigestHash(address staker, uint256 _stakerNonce, address operator, uint256 expiry)
        external
        view
        returns (bytes32);

    /// @notice Calculates the digest hash to be signed by the operator's delegationApprove and used in the `delegateTo` and `delegateToBySignature` functions.
    /// @param staker The account delegating their stake
    /// @param operator The account receiving delegated stake
    /// @param _delegationApprover the operator's `delegationApprover` who will be signing the delegationHash (in general)
    /// @param approverSalt A unique and single use value associated with the approver signature.
    /// @param expiry Time after which the approver's signature becomes invalid
    function calculateDelegationApprovalDigestHash(
        address staker,
        address operator,
        address _delegationApprover,
        bytes32 approverSalt,
        uint256 expiry
    ) external view returns (bytes32);

    /// @notice The EIP-712 typehash for the contract's domain
    function DOMAIN_TYPEHASH() external view returns (bytes32);

    /// @notice The EIP-712 typehash for the StakerDelegation struct used by the contract
    function STAKER_DELEGATION_TYPEHASH() external view returns (bytes32);

    /// @notice The EIP-712 typehash for the DelegationApproval struct used by the contract
    function DELEGATION_APPROVAL_TYPEHASH() external view returns (bytes32);

    /// @notice Getter function for the current EIP-712 domain separator for this contract.
    /// @dev The domain separator will change in the event of a fork that changes the ChainID.
    /// @dev By introducing a domain separator the DApp developers are guaranteed that there can be no signature collision.
    /// for more detailed information please read EIP-712.
    function domainSeparator() external view returns (bytes32);

    /// @notice Mapping: staker => cumulative number of queued withdrawals they have ever initiated.
    /// @dev This only increments (doesn't decrement), and is used to help ensure that otherwise identical withdrawals have unique hashes.
    function cumulativeWithdrawalsQueued(address staker) external view returns (uint256);

    /// @notice Returns the keccak256 hash of `withdrawal`.
    function calculateWithdrawalRoot(Withdrawal memory withdrawal) external pure returns (bytes32);
}


// ============================================================================
// FILE: lib/solady/src/utils/FixedPointMathLib.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Arithmetic library with operations for fixed-point numbers.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/FixedPointMathLib.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/FixedPointMathLib.sol)
library FixedPointMathLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The operation failed, as the output exceeds the maximum value of uint256.
    error ExpOverflow();

    /// @dev The operation failed, as the output exceeds the maximum value of uint256.
    error FactorialOverflow();

    /// @dev The operation failed, due to an overflow.
    error RPowOverflow();

    /// @dev The mantissa is too big to fit.
    error MantissaOverflow();

    /// @dev The operation failed, due to an multiplication overflow.
    error MulWadFailed();

    /// @dev The operation failed, either due to a
    /// multiplication overflow, or a division by a zero.
    error DivWadFailed();

    /// @dev The multiply-divide operation failed, either due to a
    /// multiplication overflow, or a division by a zero.
    error MulDivFailed();

    /// @dev The division failed, as the denominator is zero.
    error DivFailed();

    /// @dev The full precision multiply-divide operation failed, either due
    /// to the result being larger than 256 bits, or a division by a zero.
    error FullMulDivFailed();

    /// @dev The output is undefined, as the input is less-than-or-equal to zero.
    error LnWadUndefined();

    /// @dev The input outside the acceptable domain.
    error OutOfDomain();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The scalar of ETH and most ERC20s.
    uint256 internal constant WAD = 1e18;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              SIMPLIFIED FIXED POINT OPERATIONS             */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Equivalent to `(x * y) / WAD` rounded down.
    function mulWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to `require(y == 0 || x <= type(uint256).max / y)`.
            if mul(y, gt(x, div(not(0), y))) {
                mstore(0x00, 0xbac65e5b) // `MulWadFailed()`.
                revert(0x1c, 0x04)
            }
            z := div(mul(x, y), WAD)
        }
    }

    /// @dev Equivalent to `(x * y) / WAD` rounded up.
    function mulWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to `require(y == 0 || x <= type(uint256).max / y)`.
            if mul(y, gt(x, div(not(0), y))) {
                mstore(0x00, 0xbac65e5b) // `MulWadFailed()`.
                revert(0x1c, 0x04)
            }
            z := add(iszero(iszero(mod(mul(x, y), WAD))), div(mul(x, y), WAD))
        }
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded down.
    function divWad(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to `require(y != 0 && (WAD == 0 || x <= type(uint256).max / WAD))`.
            if iszero(mul(y, iszero(mul(WAD, gt(x, div(not(0), WAD)))))) {
                mstore(0x00, 0x7c5f487d) // `DivWadFailed()`.
                revert(0x1c, 0x04)
            }
            z := div(mul(x, WAD), y)
        }
    }

    /// @dev Equivalent to `(x * WAD) / y` rounded up.
    function divWadUp(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to `require(y != 0 && (WAD == 0 || x <= type(uint256).max / WAD))`.
            if iszero(mul(y, iszero(mul(WAD, gt(x, div(not(0), WAD)))))) {
                mstore(0x00, 0x7c5f487d) // `DivWadFailed()`.
                revert(0x1c, 0x04)
            }
            z := add(iszero(iszero(mod(mul(x, WAD), y))), div(mul(x, WAD), y))
        }
    }

    /// @dev Equivalent to `x` to the power of `y`.
    /// because `x ** y = (e ** ln(x)) ** y = e ** (ln(x) * y)`.
    function powWad(int256 x, int256 y) internal pure returns (int256) {
        // Using `ln(x)` means `x` must be greater than 0.
        return expWad((lnWad(x) * y) / int256(WAD));
    }

    /// @dev Returns `exp(x)`, denominated in `WAD`.
    function expWad(int256 x) internal pure returns (int256 r) {
        unchecked {
            // When the result is less than 0.5 we return zero.
            // This happens when `x <= floor(log(0.5e18) * 1e18) ≈ -42e18`.
            if (x <= -42139678854452767551) return r;

            /// @solidity memory-safe-assembly
            assembly {
                // When the result is greater than `(2**255 - 1) / 1e18` we can not represent it as
                // an int. This happens when `x >= floor(log((2**255 - 1) / 1e18) * 1e18) ≈ 135`.
                if iszero(slt(x, 135305999368893231589)) {
                    mstore(0x00, 0xa37bfec9) // `ExpOverflow()`.
                    revert(0x1c, 0x04)
                }
            }

            // `x` is now in the range `(-42, 136) * 1e18`. Convert to `(-42, 136) * 2**96`
            // for more intermediate precision and a binary basis. This base conversion
            // is a multiplication by 1e18 / 2**96 = 5**18 / 2**78.
            x = (x << 78) / 5 ** 18;

            // Reduce range of x to (-½ ln 2, ½ ln 2) * 2**96 by factoring out powers
            // of two such that exp(x) = exp(x') * 2**k, where k is an integer.
            // Solving this gives k = round(x / log(2)) and x' = x - k * log(2).
            int256 k = ((x << 96) / 54916777467707473351141471128 + 2 ** 95) >> 96;
            x = x - k * 54916777467707473351141471128;

            // `k` is in the range `[-61, 195]`.

            // Evaluate using a (6, 7)-term rational approximation.
            // `p` is made monic, we'll multiply by a scale factor later.
            int256 y = x + 1346386616545796478920950773328;
            y = ((y * x) >> 96) + 57155421227552351082224309758442;
            int256 p = y + x - 94201549194550492254356042504812;
            p = ((p * y) >> 96) + 28719021644029726153956944680412240;
            p = p * x + (4385272521454847904659076985693276 << 96);

            // We leave `p` in `2**192` basis so we don't need to scale it back up for the division.
            int256 q = x - 2855989394907223263936484059900;
            q = ((q * x) >> 96) + 50020603652535783019961831881945;
            q = ((q * x) >> 96) - 533845033583426703283633433725380;
            q = ((q * x) >> 96) + 3604857256930695427073651918091429;
            q = ((q * x) >> 96) - 14423608567350463180887372962807573;
            q = ((q * x) >> 96) + 26449188498355588339934803723976023;

            /// @solidity memory-safe-assembly
            assembly {
                // Div in assembly because solidity adds a zero check despite the unchecked.
                // The q polynomial won't have zeros in the domain as all its roots are complex.
                // No scaling is necessary because p is already `2**96` too large.
                r := sdiv(p, q)
            }

            // r should be in the range `(0.09, 0.25) * 2**96`.

            // We now need to multiply r by:
            // - The scale factor `s ≈ 6.031367120`.
            // - The `2**k` factor from the range reduction.
            // - The `1e18 / 2**96` factor for base conversion.
            // We do this all at once, with an intermediate result in `2**213`
            // basis, so the final right shift is always by a positive amount.
            r = int256(
                (uint256(r) * 3822833074963236453042738258902158003155416615667) >> uint256(195 - k)
            );
        }
    }

    /// @dev Returns `ln(x)`, denominated in `WAD`.
    function lnWad(int256 x) internal pure returns (int256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(sgt(x, 0)) {
                mstore(0x00, 0x1615e638) // `LnWadUndefined()`.
                revert(0x1c, 0x04)
            }
            // We want to convert `x` from `10**18` fixed point to `2**96` fixed point.
            // We do this by multiplying by `2**96 / 10**18`. But since
            // `ln(x * C) = ln(x) + ln(C)`, we can simply do nothing here
            // and add `ln(2**96 / 10**18)` at the end.

            // Compute `k = log2(x) - 96`, `t = 159 - k = 255 - log2(x) = 255 ^ log2(x)`.
            let t := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            t := or(t, shl(6, lt(0xffffffffffffffff, shr(t, x))))
            t := or(t, shl(5, lt(0xffffffff, shr(t, x))))
            t := or(t, shl(4, lt(0xffff, shr(t, x))))
            t := or(t, shl(3, lt(0xff, shr(t, x))))
            // forgefmt: disable-next-item
            t := xor(t, byte(and(0x1f, shr(shr(t, x), 0x8421084210842108cc6318c6db6d54be)),
                0xf8f9f9faf9fdfafbf9fdfcfdfafbfcfef9fafdfafcfcfbfefafafcfbffffffff))

            // Reduce range of x to (1, 2) * 2**96
            // ln(2^k * x) = k * ln(2) + ln(x)
            x := shr(159, shl(t, x))

            // Evaluate using a (8, 8)-term rational approximation.
            // `p` is made monic, we will multiply by a scale factor later.
            // forgefmt: disable-next-item
            let p := sub( // This heavily nested expression is to avoid stack-too-deep for via-ir.
                sar(96, mul(add(43456485725739037958740375743393,
                sar(96, mul(add(24828157081833163892658089445524,
                sar(96, mul(add(3273285459638523848632254066296,
                    x), x))), x))), x)), 11111509109440967052023855526967)
            p := sub(sar(96, mul(p, x)), 45023709667254063763336534515857)
            p := sub(sar(96, mul(p, x)), 14706773417378608786704636184526)
            p := sub(mul(p, x), shl(96, 795164235651350426258249787498))

            // We leave `p` in `2**192` basis so we don't need to scale it back up for the division.
            // `q` is monic by convention.
            let q := add(5573035233440673466300451813936, x)
            q := add(71694874799317883764090561454958, sar(96, mul(x, q)))
            q := add(283447036172924575727196451306956, sar(96, mul(x, q)))
            q := add(401686690394027663651624208769553, sar(96, mul(x, q)))
            q := add(204048457590392012362485061816622, sar(96, mul(x, q)))
            q := add(31853899698501571402653359427138, sar(96, mul(x, q)))
            q := add(909429971244387300277376558375, sar(96, mul(x, q)))

            // `r` is in the range `(0, 0.125) * 2**96`.

            // Finalization, we need to:
            // - Multiply by the scale factor `s = 5.549…`.
            // - Add `ln(2**96 / 10**18)`.
            // - Add `k * ln(2)`.
            // - Multiply by `10**18 / 2**96 = 5**18 >> 78`.

            // The q polynomial is known not to have zeros in the domain.
            // No scaling required because p is already `2**96` too large.
            r := sdiv(p, q)
            // Multiply by the scaling factor: `s * 5e18 * 2**96`, base is now `5**18 * 2**192`.
            r := mul(1677202110996718588342820967067443963516166, r)
            // Add `ln(2) * k * 5e18 * 2**192`.
            // forgefmt: disable-next-item
            r := add(mul(16597577552685614221487285958193947469193820559219878177908093499208371, sub(159, t)), r)
            // Add `ln(2**96 / 10**18) * 5e18 * 2**192`.
            r := add(600920179829731861736702779321621459595472258049074101567377883020018308, r)
            // Base conversion: mul `2**18 / 2**192`.
            r := sar(174, r)
        }
    }

    /// @dev Returns `W_0(x)`, denominated in `WAD`.
    /// See: https://en.wikipedia.org/wiki/Lambert_W_function
    /// a.k.a. Product log function. This is an approximation of the principal branch.
    function lambertW0Wad(int256 x) internal pure returns (int256 w) {
        if ((w = x) <= -367879441171442322) revert OutOfDomain(); // `x` less than `-1/e`.
        uint256 c; // Whether we need to avoid catastrophic cancellation.
        uint256 i = 4; // Number of iterations.
        if (w <= 0x1ffffffffffff) {
            if (-0x4000000000000 <= w) {
                i = 1; // Inputs near zero only take one step to converge.
            } else if (w <= -0x3ffffffffffffff) {
                i = 32; // Inputs near `-1/e` take very long to converge.
            }
        } else if (w >> 63 == 0) {
            /// @solidity memory-safe-assembly
            assembly {
                // Inline log2 for more performance, since the range is small.
                let v := shr(49, w)
                let l := shl(3, lt(0xff, v))
                // forgefmt: disable-next-item
                l := add(or(l, byte(and(0x1f, shr(shr(l, v), 0x8421084210842108cc6318c6db6d54be)),
                    0x0706060506020504060203020504030106050205030304010505030400000000)), 49)
                w := sdiv(shl(l, 7), byte(sub(l, 31), 0x0303030303030303040506080c13))
                c := gt(l, 60)
                i := add(2, add(gt(l, 53), c))
            }
        } else {
            // `ln(x) - ln(ln(x)) + b * ln(ln(x)) / ln(x)`.
            int256 ll = lnWad(w = lnWad(w));
            /// @solidity memory-safe-assembly
            assembly {
                w := add(sdiv(mul(ll, 1023715080943847266), w), sub(w, ll))
                i := add(3, iszero(shr(68, x)))
                c := iszero(shr(143, x))
            }
            if (c == 0) {
                int256 wad = int256(WAD);
                int256 p = x;
                // If `x` is big, use Newton's so that intermediate values won't overflow.
                do {
                    int256 e = expWad(w);
                    /// @solidity memory-safe-assembly
                    assembly {
                        let t := mul(w, div(e, wad))
                        w := sub(w, sdiv(sub(t, x), div(add(e, t), wad)))
                        i := sub(i, 1)
                    }
                    if (p <= w) break;
                    p = w;
                } while (i != 0);
                /// @solidity memory-safe-assembly
                assembly {
                    w := sub(w, sgt(w, 2))
                }
                return w;
            }
        }
        // forgefmt: disable-next-item
        unchecked {
            int256 wad = int256(WAD);
            int256 p = x;
            do { // Otherwise, use Halley's for faster convergence.
                int256 e = expWad(w);
                /// @solidity memory-safe-assembly
                assembly {
                    let t := add(w, wad)
                    let s := sub(mul(w, e), mul(x, wad))
                    w := sub(w, sdiv(mul(s, wad), sub(mul(e, t), sdiv(mul(add(t, wad), s), add(t, t)))))
                }
                if (p <= w) break;
                p = w;
            } while (--i != c);
            /// @solidity memory-safe-assembly
            assembly {
                w := sub(w, sgt(w, 2))
            }
            // For certain ranges of `x`, we'll use the quadratic-rate recursive formula of
            // R. Iacono and J.P. Boyd for the last iteration, to avoid catastrophic cancellation.
            if (c != 0) {
                /// @solidity memory-safe-assembly
                assembly {
                    x := sdiv(mul(x, wad), w)
                }
                x = (w * (wad + lnWad(x)));
                /// @solidity memory-safe-assembly
                assembly {
                    w := sdiv(x, add(wad, w))
                }
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  GENERAL NUMBER UTILITIES                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Calculates `floor(a * b / d)` with full precision.
    /// Throws if result overflows a uint256 or when `d` is zero.
    /// Credit to Remco Bloemen under MIT license: https://2π.com/21/muldiv
    function fullMulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            for {} 1 {} {
                // 512-bit multiply `[p1 p0] = x * y`.
                // Compute the product mod `2**256` and mod `2**256 - 1`
                // then use the Chinese Remainder Theorem to reconstruct
                // the 512 bit result. The result is stored in two 256
                // variables such that `product = p1 * 2**256 + p0`.

                // Least significant 256 bits of the product.
                let p0 := mul(x, y)
                let mm := mulmod(x, y, not(0))
                // Most significant 256 bits of the product.
                let p1 := sub(mm, add(p0, lt(mm, p0)))

                // Handle non-overflow cases, 256 by 256 division.
                if iszero(p1) {
                    if iszero(d) {
                        mstore(0x00, 0xae47f702) // `FullMulDivFailed()`.
                        revert(0x1c, 0x04)
                    }
                    result := div(p0, d)
                    break
                }

                // Make sure the result is less than `2**256`. Also prevents `d == 0`.
                if iszero(gt(d, p1)) {
                    mstore(0x00, 0xae47f702) // `FullMulDivFailed()`.
                    revert(0x1c, 0x04)
                }

                /*------------------- 512 by 256 division --------------------*/

                // Make division exact by subtracting the remainder from `[p1 p0]`.
                // Compute remainder using mulmod.
                let r := mulmod(x, y, d)
                // `t` is the least significant bit of `d`.
                // Always greater or equal to 1.
                let t := and(d, sub(0, d))
                // Divide `d` by `t`, which is a power of two.
                d := div(d, t)
                // Invert `d mod 2**256`
                // Now that `d` is an odd number, it has an inverse
                // modulo `2**256` such that `d * inv = 1 mod 2**256`.
                // Compute the inverse by starting with a seed that is correct
                // correct for four bits. That is, `d * inv = 1 mod 2**4`.
                let inv := xor(mul(3, d), 2)
                // Now use Newton-Raphson iteration to improve the precision.
                // Thanks to Hensel's lifting lemma, this also works in modular
                // arithmetic, doubling the correct bits in each step.
                inv := mul(inv, sub(2, mul(d, inv))) // inverse mod 2**8
                inv := mul(inv, sub(2, mul(d, inv))) // inverse mod 2**16
                inv := mul(inv, sub(2, mul(d, inv))) // inverse mod 2**32
                inv := mul(inv, sub(2, mul(d, inv))) // inverse mod 2**64
                inv := mul(inv, sub(2, mul(d, inv))) // inverse mod 2**128
                result :=
                    mul(
                        // Divide [p1 p0] by the factors of two.
                        // Shift in bits from `p1` into `p0`. For this we need
                        // to flip `t` such that it is `2**256 / t`.
                        or(mul(sub(p1, gt(r, p0)), add(div(sub(0, t), t), 1)), div(sub(p0, r), t)),
                        // inverse mod 2**256
                        mul(inv, sub(2, mul(d, inv)))
                    )
                break
            }
        }
    }

    /// @dev Calculates `floor(x * y / d)` with full precision, rounded up.
    /// Throws if result overflows a uint256 or when `d` is zero.
    /// Credit to Uniswap-v3-core under MIT license:
    /// https://github.com/Uniswap/v3-core/blob/contracts/libraries/FullMath.sol
    function fullMulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 result) {
        result = fullMulDiv(x, y, d);
        /// @solidity memory-safe-assembly
        assembly {
            if mulmod(x, y, d) {
                result := add(result, 1)
                if iszero(result) {
                    mstore(0x00, 0xae47f702) // `FullMulDivFailed()`.
                    revert(0x1c, 0x04)
                }
            }
        }
    }

    /// @dev Returns `floor(x * y / d)`.
    /// Reverts if `x * y` overflows, or `d` is zero.
    function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to require(d != 0 && (y == 0 || x <= type(uint256).max / y))
            if iszero(mul(d, iszero(mul(y, gt(x, div(not(0), y)))))) {
                mstore(0x00, 0xad251c27) // `MulDivFailed()`.
                revert(0x1c, 0x04)
            }
            z := div(mul(x, y), d)
        }
    }

    /// @dev Returns `ceil(x * y / d)`.
    /// Reverts if `x * y` overflows, or `d` is zero.
    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // Equivalent to require(d != 0 && (y == 0 || x <= type(uint256).max / y))
            if iszero(mul(d, iszero(mul(y, gt(x, div(not(0), y)))))) {
                mstore(0x00, 0xad251c27) // `MulDivFailed()`.
                revert(0x1c, 0x04)
            }
            z := add(iszero(iszero(mod(mul(x, y), d))), div(mul(x, y), d))
        }
    }

    /// @dev Returns `ceil(x / d)`.
    /// Reverts if `d` is zero.
    function divUp(uint256 x, uint256 d) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(d) {
                mstore(0x00, 0x65244e4e) // `DivFailed()`.
                revert(0x1c, 0x04)
            }
            z := add(iszero(iszero(mod(x, d))), div(x, d))
        }
    }

    /// @dev Returns `max(0, x - y)`.
    function zeroFloorSub(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := mul(gt(x, y), sub(x, y))
        }
    }

    /// @dev Exponentiate `x` to `y` by squaring, denominated in base `b`.
    /// Reverts if the computation overflows.
    function rpow(uint256 x, uint256 y, uint256 b) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := mul(b, iszero(y)) // `0 ** 0 = 1`. Otherwise, `0 ** n = 0`.
            if x {
                z := xor(b, mul(xor(b, x), and(y, 1))) // `z = isEven(y) ? scale : x`
                let half := shr(1, b) // Divide `b` by 2.
                // Divide `y` by 2 every iteration.
                for { y := shr(1, y) } y { y := shr(1, y) } {
                    let xx := mul(x, x) // Store x squared.
                    let xxRound := add(xx, half) // Round to the nearest number.
                    // Revert if `xx + half` overflowed, or if `x ** 2` overflows.
                    if or(lt(xxRound, xx), shr(128, x)) {
                        mstore(0x00, 0x49f7642b) // `RPowOverflow()`.
                        revert(0x1c, 0x04)
                    }
                    x := div(xxRound, b) // Set `x` to scaled `xxRound`.
                    // If `y` is odd:
                    if and(y, 1) {
                        let zx := mul(z, x) // Compute `z * x`.
                        let zxRound := add(zx, half) // Round to the nearest number.
                        // If `z * x` overflowed or `zx + half` overflowed:
                        if or(xor(div(zx, x), z), lt(zxRound, zx)) {
                            // Revert if `x` is non-zero.
                            if iszero(iszero(x)) {
                                mstore(0x00, 0x49f7642b) // `RPowOverflow()`.
                                revert(0x1c, 0x04)
                            }
                        }
                        z := div(zxRound, b) // Return properly scaled `zxRound`.
                    }
                }
            }
        }
    }

    /// @dev Returns the square root of `x`.
    function sqrt(uint256 x) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            // `floor(sqrt(2**15)) = 181`. `sqrt(2**15) - 181 = 2.84`.
            z := 181 // The "correct" value is 1, but this saves a multiplication later.

            // This segment is to get a reasonable initial estimate for the Babylonian method. With a bad
            // start, the correct # of bits increases ~linearly each iteration instead of ~quadratically.

            // Let `y = x / 2**r`. We check `y >= 2**(k + 8)`
            // but shift right by `k` bits to ensure that if `x >= 256`, then `y >= 256`.
            let r := shl(7, lt(0xffffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffffff, shr(r, x))))
            z := shl(shr(1, r), z)

            // Goal was to get `z*z*y` within a small factor of `x`. More iterations could
            // get y in a tighter range. Currently, we will have y in `[256, 256*(2**16))`.
            // We ensured `y >= 256` so that the relative difference between `y` and `y+1` is small.
            // That's not possible if `x < 256` but we can just verify those cases exhaustively.

            // Now, `z*z*y <= x < z*z*(y+1)`, and `y <= 2**(16+8)`, and either `y >= 256`, or `x < 256`.
            // Correctness can be checked exhaustively for `x < 256`, so we assume `y >= 256`.
            // Then `z*sqrt(y)` is within `sqrt(257)/sqrt(256)` of `sqrt(x)`, or about 20bps.

            // For `s` in the range `[1/256, 256]`, the estimate `f(s) = (181/1024) * (s+1)`
            // is in the range `(1/2.84 * sqrt(s), 2.84 * sqrt(s))`,
            // with largest error when `s = 1` and when `s = 256` or `1/256`.

            // Since `y` is in `[256, 256*(2**16))`, let `a = y/65536`, so that `a` is in `[1/256, 256)`.
            // Then we can estimate `sqrt(y)` using
            // `sqrt(65536) * 181/1024 * (a + 1) = 181/4 * (y + 65536)/65536 = 181 * (y + 65536)/2**18`.

            // There is no overflow risk here since `y < 2**136` after the first branch above.
            z := shr(18, mul(z, add(shr(r, x), 65536))) // A `mul()` is saved from starting `z` at 181.

            // Given the worst case multiplicative error of 2.84 above, 7 iterations should be enough.
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))
            z := shr(1, add(z, div(x, z)))

            // If `x+1` is a perfect square, the Babylonian method cycles between
            // `floor(sqrt(x))` and `ceil(sqrt(x))`. This statement ensures we return floor.
            // See: https://en.wikipedia.org/wiki/Integer_square_root#Using_only_integer_division
            z := sub(z, lt(div(x, z), z))
        }
    }

    /// @dev Returns the cube root of `x`.
    /// Credit to bout3fiddy and pcaversaccio under AGPLv3 license:
    /// https://github.com/pcaversaccio/snekmate/blob/main/src/utils/Math.vy
    function cbrt(uint256 x) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            let r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))

            z := div(shl(div(r, 3), shl(lt(0xf, shr(r, x)), 0xf)), xor(7, mod(r, 3)))

            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)
            z := div(add(add(div(x, mul(z, z)), z), z), 3)

            z := sub(z, lt(div(x, mul(z, z)), z))
        }
    }

    /// @dev Returns the square root of `x`, denominated in `WAD`.
    function sqrtWad(uint256 x) internal pure returns (uint256 z) {
        unchecked {
            z = 10 ** 9;
            if (x <= type(uint256).max / 10 ** 36 - 1) {
                x *= 10 ** 18;
                z = 1;
            }
            z *= sqrt(x);
        }
    }

    /// @dev Returns the cube root of `x`, denominated in `WAD`.
    function cbrtWad(uint256 x) internal pure returns (uint256 z) {
        unchecked {
            z = 10 ** 12;
            if (x <= (type(uint256).max / 10 ** 36) * 10 ** 18 - 1) {
                if (x >= type(uint256).max / 10 ** 36) {
                    x *= 10 ** 18;
                    z = 10 ** 6;
                } else {
                    x *= 10 ** 36;
                    z = 1;
                }
            }
            z *= cbrt(x);
        }
    }

    /// @dev Returns the factorial of `x`.
    function factorial(uint256 x) internal pure returns (uint256 result) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(lt(x, 58)) {
                mstore(0x00, 0xaba0f2a2) // `FactorialOverflow()`.
                revert(0x1c, 0x04)
            }
            for { result := 1 } x { x := sub(x, 1) } { result := mul(result, x) }
        }
    }

    /// @dev Returns the log2 of `x`.
    /// Equivalent to computing the index of the most significant bit (MSB) of `x`.
    /// Returns 0 if `x` is zero.
    function log2(uint256 x) internal pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(r, shl(3, lt(0xff, shr(r, x))))
            // forgefmt: disable-next-item
            r := or(r, byte(and(0x1f, shr(shr(r, x), 0x8421084210842108cc6318c6db6d54be)),
                0x0706060506020504060203020504030106050205030304010505030400000000))
        }
    }

    /// @dev Returns the log2 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log2Up(uint256 x) internal pure returns (uint256 r) {
        r = log2(x);
        /// @solidity memory-safe-assembly
        assembly {
            r := add(r, lt(shl(r, 1), x))
        }
    }

    /// @dev Returns the log10 of `x`.
    /// Returns 0 if `x` is zero.
    function log10(uint256 x) internal pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(lt(x, 100000000000000000000000000000000000000)) {
                x := div(x, 100000000000000000000000000000000000000)
                r := 38
            }
            if iszero(lt(x, 100000000000000000000)) {
                x := div(x, 100000000000000000000)
                r := add(r, 20)
            }
            if iszero(lt(x, 10000000000)) {
                x := div(x, 10000000000)
                r := add(r, 10)
            }
            if iszero(lt(x, 100000)) {
                x := div(x, 100000)
                r := add(r, 5)
            }
            r := add(r, add(gt(x, 9), add(gt(x, 99), add(gt(x, 999), gt(x, 9999)))))
        }
    }

    /// @dev Returns the log10 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log10Up(uint256 x) internal pure returns (uint256 r) {
        r = log10(x);
        /// @solidity memory-safe-assembly
        assembly {
            r := add(r, lt(exp(10, r), x))
        }
    }

    /// @dev Returns the log256 of `x`.
    /// Returns 0 if `x` is zero.
    function log256(uint256 x) internal pure returns (uint256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            r := shl(7, lt(0xffffffffffffffffffffffffffffffff, x))
            r := or(r, shl(6, lt(0xffffffffffffffff, shr(r, x))))
            r := or(r, shl(5, lt(0xffffffff, shr(r, x))))
            r := or(r, shl(4, lt(0xffff, shr(r, x))))
            r := or(shr(3, r), lt(0xff, shr(r, x)))
        }
    }

    /// @dev Returns the log256 of `x`, rounded up.
    /// Returns 0 if `x` is zero.
    function log256Up(uint256 x) internal pure returns (uint256 r) {
        r = log256(x);
        /// @solidity memory-safe-assembly
        assembly {
            r := add(r, lt(shl(shl(3, r), 1), x))
        }
    }

    /// @dev Returns the scientific notation format `mantissa * 10 ** exponent` of `x`.
    /// Useful for compressing prices (e.g. using 25 bit mantissa and 7 bit exponent).
    function sci(uint256 x) internal pure returns (uint256 mantissa, uint256 exponent) {
        /// @solidity memory-safe-assembly
        assembly {
            mantissa := x
            if mantissa {
                if iszero(mod(mantissa, 1000000000000000000000000000000000)) {
                    mantissa := div(mantissa, 1000000000000000000000000000000000)
                    exponent := 33
                }
                if iszero(mod(mantissa, 10000000000000000000)) {
                    mantissa := div(mantissa, 10000000000000000000)
                    exponent := add(exponent, 19)
                }
                if iszero(mod(mantissa, 1000000000000)) {
                    mantissa := div(mantissa, 1000000000000)
                    exponent := add(exponent, 12)
                }
                if iszero(mod(mantissa, 1000000)) {
                    mantissa := div(mantissa, 1000000)
                    exponent := add(exponent, 6)
                }
                if iszero(mod(mantissa, 10000)) {
                    mantissa := div(mantissa, 10000)
                    exponent := add(exponent, 4)
                }
                if iszero(mod(mantissa, 100)) {
                    mantissa := div(mantissa, 100)
                    exponent := add(exponent, 2)
                }
                if iszero(mod(mantissa, 10)) {
                    mantissa := div(mantissa, 10)
                    exponent := add(exponent, 1)
                }
            }
        }
    }

    /// @dev Convenience function for packing `x` into a smaller number using `sci`.
    /// The `mantissa` will be in bits [7..255] (the upper 249 bits).
    /// The `exponent` will be in bits [0..6] (the lower 7 bits).
    /// Use `SafeCastLib` to safely ensure that the `packed` number is small
    /// enough to fit in the desired unsigned integer type:
    /// ```
    ///     uint32 packed = SafeCastLib.toUint32(FixedPointMathLib.packSci(777 ether));
    /// ```
    function packSci(uint256 x) internal pure returns (uint256 packed) {
        (x, packed) = sci(x); // Reuse for `mantissa` and `exponent`.
        /// @solidity memory-safe-assembly
        assembly {
            if shr(249, x) {
                mstore(0x00, 0xce30380c) // `MantissaOverflow()`.
                revert(0x1c, 0x04)
            }
            packed := or(shl(7, x), packed)
        }
    }

    /// @dev Convenience function for unpacking a packed number from `packSci`.
    function unpackSci(uint256 packed) internal pure returns (uint256 unpacked) {
        unchecked {
            unpacked = (packed >> 7) * 10 ** (packed & 0x7f);
        }
    }

    /// @dev Returns the average of `x` and `y`.
    function avg(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = (x & y) + ((x ^ y) >> 1);
        }
    }

    /// @dev Returns the average of `x` and `y`.
    function avg(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = (x >> 1) + (y >> 1) + (((x & 1) + (y & 1)) >> 1);
        }
    }

    /// @dev Returns the absolute value of `x`.
    function abs(int256 x) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(sub(0, shr(255, x)), add(sub(0, shr(255, x)), x))
        }
    }

    /// @dev Returns the absolute distance between `x` and `y`.
    function dist(int256 x, int256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(mul(xor(sub(y, x), sub(x, y)), sgt(x, y)), sub(y, x))
        }
    }

    /// @dev Returns the minimum of `x` and `y`.
    function min(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, y), lt(y, x)))
        }
    }

    /// @dev Returns the minimum of `x` and `y`.
    function min(int256 x, int256 y) internal pure returns (int256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, y), slt(y, x)))
        }
    }

    /// @dev Returns the maximum of `x` and `y`.
    function max(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, y), gt(y, x)))
        }
    }

    /// @dev Returns the maximum of `x` and `y`.
    function max(int256 x, int256 y) internal pure returns (int256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, y), sgt(y, x)))
        }
    }

    /// @dev Returns `x`, bounded to `minValue` and `maxValue`.
    function clamp(uint256 x, uint256 minValue, uint256 maxValue)
        internal
        pure
        returns (uint256 z)
    {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, minValue), gt(minValue, x)))
            z := xor(z, mul(xor(z, maxValue), lt(maxValue, z)))
        }
    }

    /// @dev Returns `x`, bounded to `minValue` and `maxValue`.
    function clamp(int256 x, int256 minValue, int256 maxValue) internal pure returns (int256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := xor(x, mul(xor(x, minValue), sgt(minValue, x)))
            z := xor(z, mul(xor(z, maxValue), slt(maxValue, z)))
        }
    }

    /// @dev Returns greatest common divisor of `x` and `y`.
    function gcd(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            for { z := x } y {} {
                let t := y
                y := mod(z, y)
                z := t
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   RAW NUMBER OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns `x + y`, without checking for overflow.
    function rawAdd(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x + y;
        }
    }

    /// @dev Returns `x + y`, without checking for overflow.
    function rawAdd(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x + y;
        }
    }

    /// @dev Returns `x - y`, without checking for underflow.
    function rawSub(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x - y;
        }
    }

    /// @dev Returns `x - y`, without checking for underflow.
    function rawSub(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x - y;
        }
    }

    /// @dev Returns `x * y`, without checking for overflow.
    function rawMul(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Returns `x * y`, without checking for overflow.
    function rawMul(int256 x, int256 y) internal pure returns (int256 z) {
        unchecked {
            z = x * y;
        }
    }

    /// @dev Returns `x / y`, returning 0 if `y` is zero.
    function rawDiv(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := div(x, y)
        }
    }

    /// @dev Returns `x / y`, returning 0 if `y` is zero.
    function rawSDiv(int256 x, int256 y) internal pure returns (int256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := sdiv(x, y)
        }
    }

    /// @dev Returns `x % y`, returning 0 if `y` is zero.
    function rawMod(uint256 x, uint256 y) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := mod(x, y)
        }
    }

    /// @dev Returns `x % y`, returning 0 if `y` is zero.
    function rawSMod(int256 x, int256 y) internal pure returns (int256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := smod(x, y)
        }
    }

    /// @dev Returns `(x + y) % d`, return 0 if `d` if zero.
    function rawAddMod(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := addmod(x, y, d)
        }
    }

    /// @dev Returns `(x * y) % d`, return 0 if `d` if zero.
    function rawMulMod(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        /// @solidity memory-safe-assembly
        assembly {
            z := mulmod(x, y, d)
        }
    }
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTRewardDistributor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IRioLRTRewardDistributor {
    /// @notice Thrown when there are no ETH validator rewards to distribute.
    error NO_ETH_VALIDATOR_REWARDS_TO_DISTRIBUTE();

    /// @notice Thrown when the ETH validator reward share is too high.
    error ETH_VALIDATOR_SHARE_BPS_TOO_HIGH();

    /// @notice Thrown when the treasury ETH validator reward share is too high.
    error TREASURY_ETH_VALIDATOR_SHARE_BPS_TOO_HIGH();

    /// @notice Thrown when the operator ETH validator reward share is too high.
    error OPERATOR_ETH_VALIDATOR_SHARE_BPS_TOO_HIGH();

    /// @notice Emitted when ETH validator rewards are distributed.
    /// @param treasuryShare The amount of rewards sent to the treasury.
    /// @param operatorShare The amount of rewards sent to the operator.
    /// @param poolShare The amount of rewards burned to realize the pool's gain.
    event ETHValidatorRewardsDistributed(uint256 treasuryShare, uint256 operatorShare, uint256 poolShare);

    /// @notice Emitted when the treasury's share of Ethereum validator rewards is updated.
    /// @param newTreasuryETHValidatorRewardShareBPS The new treasury share in basis points.
    event TreasuryETHValidatorRewardShareBPSSet(uint16 newTreasuryETHValidatorRewardShareBPS);

    /// @notice Emitted when the operator's share of Ethereum validator rewards is updated.
    /// @param newOperatorETHValidatorRewardShareBPS The new operator share.
    event OperatorETHValidatorRewardShareBPSSet(uint16 newOperatorETHValidatorRewardShareBPS);

    /// @notice Initializes the contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param treasury The treasury address.
    /// @param operatorRewardPool The operator reward pool address.
    /// @param depositPool The contract that holds funds awaiting deposit into EigenLayer.
    function initialize(address initialOwner, address treasury, address operatorRewardPool, address depositPool)
        external;
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTAVSRegistry.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

interface IRioLRTAVSRegistry {
    /// @dev Information about an AVS.
    struct AVS {
        /// @dev A name for the AVS.
        string name;
        /// @dev Whether the AVS is active.
        bool active;
        /// @dev The address of the AVS' slashing contract.
        address slashingContract;
        /// @dev The address of the AVS' registry contract.
        address registryContract;
    }

    /// @dev Thrown when the provided name is empty.
    error INVALID_NAME();

    /// @dev Thrown when the provided slashing contract address is not `address(0)` or a contract.
    error INVALID_SLASHING_CONTRACT();

    /// @dev Thrown when the provided registry contract address is not a contract.
    error INVALID_REGISTRY_CONTRACT();

    /// @dev Thrown when attempting add or activate an AVS with a slashing contract that is already active
    /// in another AVS.
    error SLASHING_CONTRACT_ALREADY_ACTIVE();

    /// @dev Thrown when attempting add or activate an AVS with a registry contract that is already active
    /// in another AVS.
    error REGISTRY_CONTRACT_ALREADY_ACTIVE();

    /// @dev Thrown when attempting to activate or deactivate an AVS that is not registered.
    error AVS_NOT_REGISTERED();

    /// @dev Thrown when attempting to activate an AVS that is already active.
    error AVS_ALREADY_ACTIVE();

    /// @dev Thrown when attempting to deactivate an AVS that is already inactive.
    error AVS_ALREADY_INACTIVE();

    /// @dev Emitted when a new AVS is added to the registry.
    /// @param avsId The ID of the newly added AVS.
    /// @param name The name of the AVS.
    /// @param slashingContract The address of the slashing contract.
    /// @param registryContract The address of the registry contract.
    event AVSAdded(uint128 indexed avsId, string name, address slashingContract, address registryContract);

    /// @dev Emitted when an AVS is activated in the registry.
    /// @param avsId The ID of the activated AVS.
    event AVSActivated(uint128 indexed avsId);

    /// @dev Emitted when an AVS is deactivated in the registry.
    /// @param avsId The ID of the deactivated AVS.
    event AVSDeactivated(uint128 indexed avsId);

    /// @notice Initializes the contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param token The address of the liquid restaking token.
    function initialize(address initialOwner, address token) external;

    /// @notice Returns the AVS associated with the given ID.
    /// @param avsId The ID of the AVS to retrieve.
    /// @return The AVS corresponding to the given ID.
    function getAVS(uint128 avsId) external view returns (AVS memory);

    /// @notice Checks if the provided slashing contract is active.
    /// @param slashingContract The address of the slashing contract to check.
    /// @return True if the slashing contract is active, false otherwise.
    function isActiveSlashingContract(address slashingContract) external view returns (bool);

    /// @notice Checks if the provided registry contract is active.
    /// @param registryContract The address of the registry contract to check.
    /// @return True if the registry contract is active, false otherwise.
    function isActiveRegistryContract(address registryContract) external view returns (bool);

    // forgefmt: disable-next-item
    /// @notice Adds a new AVS to the registry.
    /// @param name The name of the AVS.
    /// @param slashingContract The address of the slashing contract.
    /// @param registryContract The address of the registry contract.
    function addAVS(string calldata name, address slashingContract, address registryContract) external returns (uint128);

    /// @notice Activates an AVS in the registry.
    /// @param avsId The ID of the AVS to activate.
    function activateAVS(uint128 avsId) external;

    /// @notice Deactivates an AVS in the registry.
    /// @param avsId The ID of the AVS to deactivate.
    function deactivateAVS(uint128 avsId) external;
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRTDepositPool.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IDelegationManager} from 'contracts/interfaces/eigenlayer/IDelegationManager.sol';

interface IRioLRTDepositPool {
    /// @notice Thrown when a withdrawal was not queued through an operator delegator.
    error INVALID_WITHDRAWAL_ORIGIN();

    /// @notice Thrown when the length of the strategies array is not 1.
    error INVALID_WITHDRAWAL_STRATEGY_LENGTH();

    /// @notice Emitted when an operator's asset withdrawal to the deposit pool is completed.
    /// @param operatorId The ID of the operator from which the asset was withdrawn.
    /// @param asset The address of the asset that was withdrawn.
    /// @param withdrawalRoot The root of the withdrawal that was completed.
    event OperatorAssetWithdrawalCompleted(uint8 indexed operatorId, address asset, bytes32 withdrawalRoot);

    /// @notice Initializes the deposit pool contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param token The address of the liquid restaking token.
    function initialize(address initialOwner, address token) external;

    /// @notice Deposits the entire deposit pool balance of the specified `asset` into EigenLayer.
    /// @param asset The address of the asset to be deposited.
    function depositBalanceIntoEigenLayer(address asset) external returns (uint256, bool);

    /// @notice Transfers the maximum possible amount of assets based on the available
    /// pool balance and requested shares.
    /// @param asset The address of the asset to be transferred.
    /// @param sharesRequested The number of shares to convert into assets for transfer.
    /// @param recipient The address of the recipient of the transferred assets.
    /// @dev This function handles asset transfer by converting the share value to assets and
    /// ensures that either the requested amount or the maximum possible amount is transferred.
    function transferMaxAssetsForShares(address asset, uint256 sharesRequested, address recipient)
        external
        returns (uint256, uint256);

    /// @notice Completes a withdrawal from EigenLayer for the specified `asset` and `operatorId`.
    /// Withdrawals directly to the deposit pool can occur for two reasons:
    /// 1. The operator has exited the strategy and the assets have been returned to the deposit pool.
    /// 2. Excess ETH from full withdrawals had accumulated in the EigenPod and was scraped to the deposit pool.
    /// @param asset The address of the asset to be withdrawn.
    /// @param operatorId The ID of the operator from which the asset is being withdrawn.
    /// @param queuedWithdrawal The withdrawal to be completed.
    /// @param middlewareTimesIndex The index of the middleware times to use for the withdrawal.
    function completeOperatorWithdrawalForAsset(
        address asset,
        uint8 operatorId,
        IDelegationManager.Withdrawal calldata queuedWithdrawal,
        uint256 middlewareTimesIndex
    ) external;
}


// ============================================================================
// FILE: contracts/utils/LRTAddressCalculator.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {CREATE3} from '@solady/utils/CREATE3.sol';
import {ContractType} from 'contracts/utils/Constants.sol';

/// @title LRT supporting contract address calculator.
library LRTAddressCalculator {
    /// @notice Calculates the address of the LRT coordinator.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getCoordinator(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.Coordinator);
    }

    /// @notice Calculates the address of the LRT asset registry.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getAssetRegistry(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.AssetRegistry);
    }

    /// @notice Calculates the address of the LRT operator registry.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getOperatorRegistry(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.OperatorRegistry);
    }

    /// @notice Calculates the address of the LRT AVS registry.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getAVSRegistry(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.AVSRegistry);
    }

    /// @notice Calculates the address of the LRT deposit pool.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getDepositPool(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.DepositPool);
    }

    /// @notice Calculates the address of the LRT withdrawal queue.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getWithdrawalQueue(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.WithdrawalQueue);
    }

    /// @notice Calculates the address of the LRT reward distributor.
    /// @param issuer The address of the LRT issuer.
    /// @param token The LRT contract address.
    function getRewardDistributor(address issuer, address token) internal pure returns (address) {
        return getContractAddress(issuer, token, ContractType.RewardDistributor);
    }

    /// @notice Calculates the address of an operator delegator.
    /// @param operatorRegistry The operator registry address.
    /// @param operatorId The operator's ID.
    function getOperatorDelegatorAddress(address operatorRegistry, uint8 operatorId) internal pure returns (address) {
        return CREATE3.getDeployed(computeOperatorSalt(operatorId), operatorRegistry);
    }

    // forgefmt: disable-next-item
    /// @notice Calculates the address of a deployed contract using CREATE3,
    /// based on a computed salt (token & contract type), and the deployer's address.
    /// @param issuer The LRT issuer contract address.
    /// @param token The LRT contract address.
    /// @param contractType The type of supporting contract.
    function getContractAddress(address issuer, address token, ContractType contractType) internal pure returns (address) {
        return CREATE3.getDeployed(computeSalt(token, contractType), issuer);
    }

    /// @notice Computes the salt for a supporting contract using the token
    /// address and contract type.
    /// @param token The token address.
    /// @param contractType The contract type.
    function computeSalt(address token, ContractType contractType) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(token)) << 96 | uint8(contractType));
    }

    /// @notice Computes the salt for an operator delegator, which is the
    /// operator ID converted to `bytes32`.
    /// @param operatorId The operator's ID.
    function computeOperatorSalt(uint8 operatorId) internal pure returns (bytes32) {
        return bytes32(uint256(operatorId));
    }
}


// ============================================================================
// FILE: contracts/interfaces/IRioLRT.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0
pragma solidity 0.8.23;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

interface IRioLRT is IERC20 {
    /// @notice Thrown when the initializer is not the LRT issuer.
    error ONLY_ISSUER();

    /// @notice Thrown when the caller is not the LRT coordinator.
    error ONLY_COORDINATOR();

    /// @notice Thrown when the caller is not the LRT withdrawal queue.
    error ONLY_WITHDRAWAL_QUEUE();

    /// @notice Initializes the contract.
    /// @param initialOwner The initial owner of the contract.
    /// @param name The name of the token.
    /// @param symbol The symbol of the token.
    function initialize(address initialOwner, string memory name, string memory symbol) external;

    /// @notice Mint `amount` tokens to the specified address.
    /// @param to The address to mint tokens to.
    /// @param amount The amount of tokens to mint.
    function mint(address to, uint256 amount) external;

    /// @notice Burn `amount` tokens from the `msg.sender`.
    /// @param amount The amount of tokens to burn.
    function burn(uint256 amount) external;
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/math/SafeCast.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SafeCast.sol)
// This file was procedurally generated from scripts/generate/templates/SafeCast.js.

pragma solidity ^0.8.20;

/**
 * @dev Wrappers over Solidity's uintXX/intXX casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeCast {
    /**
     * @dev Value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedUintDowncast(uint8 bits, uint256 value);

    /**
     * @dev An int value doesn't fit in an uint of `bits` size.
     */
    error SafeCastOverflowedIntToUint(int256 value);

    /**
     * @dev Value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedIntDowncast(uint8 bits, int256 value);

    /**
     * @dev An uint value doesn't fit in an int of `bits` size.
     */
    error SafeCastOverflowedUintToInt(uint256 value);

    /**
     * @dev Returns the downcasted uint248 from uint256, reverting on
     * overflow (when the input is greater than largest uint248).
     *
     * Counterpart to Solidity's `uint248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toUint248(uint256 value) internal pure returns (uint248) {
        if (value > type(uint248).max) {
            revert SafeCastOverflowedUintDowncast(248, value);
        }
        return uint248(value);
    }

    /**
     * @dev Returns the downcasted uint240 from uint256, reverting on
     * overflow (when the input is greater than largest uint240).
     *
     * Counterpart to Solidity's `uint240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toUint240(uint256 value) internal pure returns (uint240) {
        if (value > type(uint240).max) {
            revert SafeCastOverflowedUintDowncast(240, value);
        }
        return uint240(value);
    }

    /**
     * @dev Returns the downcasted uint232 from uint256, reverting on
     * overflow (when the input is greater than largest uint232).
     *
     * Counterpart to Solidity's `uint232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toUint232(uint256 value) internal pure returns (uint232) {
        if (value > type(uint232).max) {
            revert SafeCastOverflowedUintDowncast(232, value);
        }
        return uint232(value);
    }

    /**
     * @dev Returns the downcasted uint224 from uint256, reverting on
     * overflow (when the input is greater than largest uint224).
     *
     * Counterpart to Solidity's `uint224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toUint224(uint256 value) internal pure returns (uint224) {
        if (value > type(uint224).max) {
            revert SafeCastOverflowedUintDowncast(224, value);
        }
        return uint224(value);
    }

    /**
     * @dev Returns the downcasted uint216 from uint256, reverting on
     * overflow (when the input is greater than largest uint216).
     *
     * Counterpart to Solidity's `uint216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toUint216(uint256 value) internal pure returns (uint216) {
        if (value > type(uint216).max) {
            revert SafeCastOverflowedUintDowncast(216, value);
        }
        return uint216(value);
    }

    /**
     * @dev Returns the downcasted uint208 from uint256, reverting on
     * overflow (when the input is greater than largest uint208).
     *
     * Counterpart to Solidity's `uint208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toUint208(uint256 value) internal pure returns (uint208) {
        if (value > type(uint208).max) {
            revert SafeCastOverflowedUintDowncast(208, value);
        }
        return uint208(value);
    }

    /**
     * @dev Returns the downcasted uint200 from uint256, reverting on
     * overflow (when the input is greater than largest uint200).
     *
     * Counterpart to Solidity's `uint200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toUint200(uint256 value) internal pure returns (uint200) {
        if (value > type(uint200).max) {
            revert SafeCastOverflowedUintDowncast(200, value);
        }
        return uint200(value);
    }

    /**
     * @dev Returns the downcasted uint192 from uint256, reverting on
     * overflow (when the input is greater than largest uint192).
     *
     * Counterpart to Solidity's `uint192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toUint192(uint256 value) internal pure returns (uint192) {
        if (value > type(uint192).max) {
            revert SafeCastOverflowedUintDowncast(192, value);
        }
        return uint192(value);
    }

    /**
     * @dev Returns the downcasted uint184 from uint256, reverting on
     * overflow (when the input is greater than largest uint184).
     *
     * Counterpart to Solidity's `uint184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toUint184(uint256 value) internal pure returns (uint184) {
        if (value > type(uint184).max) {
            revert SafeCastOverflowedUintDowncast(184, value);
        }
        return uint184(value);
    }

    /**
     * @dev Returns the downcasted uint176 from uint256, reverting on
     * overflow (when the input is greater than largest uint176).
     *
     * Counterpart to Solidity's `uint176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toUint176(uint256 value) internal pure returns (uint176) {
        if (value > type(uint176).max) {
            revert SafeCastOverflowedUintDowncast(176, value);
        }
        return uint176(value);
    }

    /**
     * @dev Returns the downcasted uint168 from uint256, reverting on
     * overflow (when the input is greater than largest uint168).
     *
     * Counterpart to Solidity's `uint168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toUint168(uint256 value) internal pure returns (uint168) {
        if (value > type(uint168).max) {
            revert SafeCastOverflowedUintDowncast(168, value);
        }
        return uint168(value);
    }

    /**
     * @dev Returns the downcasted uint160 from uint256, reverting on
     * overflow (when the input is greater than largest uint160).
     *
     * Counterpart to Solidity's `uint160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toUint160(uint256 value) internal pure returns (uint160) {
        if (value > type(uint160).max) {
            revert SafeCastOverflowedUintDowncast(160, value);
        }
        return uint160(value);
    }

    /**
     * @dev Returns the downcasted uint152 from uint256, reverting on
     * overflow (when the input is greater than largest uint152).
     *
     * Counterpart to Solidity's `uint152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toUint152(uint256 value) internal pure returns (uint152) {
        if (value > type(uint152).max) {
            revert SafeCastOverflowedUintDowncast(152, value);
        }
        return uint152(value);
    }

    /**
     * @dev Returns the downcasted uint144 from uint256, reverting on
     * overflow (when the input is greater than largest uint144).
     *
     * Counterpart to Solidity's `uint144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toUint144(uint256 value) internal pure returns (uint144) {
        if (value > type(uint144).max) {
            revert SafeCastOverflowedUintDowncast(144, value);
        }
        return uint144(value);
    }

    /**
     * @dev Returns the downcasted uint136 from uint256, reverting on
     * overflow (when the input is greater than largest uint136).
     *
     * Counterpart to Solidity's `uint136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toUint136(uint256 value) internal pure returns (uint136) {
        if (value > type(uint136).max) {
            revert SafeCastOverflowedUintDowncast(136, value);
        }
        return uint136(value);
    }

    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        if (value > type(uint128).max) {
            revert SafeCastOverflowedUintDowncast(128, value);
        }
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint120 from uint256, reverting on
     * overflow (when the input is greater than largest uint120).
     *
     * Counterpart to Solidity's `uint120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toUint120(uint256 value) internal pure returns (uint120) {
        if (value > type(uint120).max) {
            revert SafeCastOverflowedUintDowncast(120, value);
        }
        return uint120(value);
    }

    /**
     * @dev Returns the downcasted uint112 from uint256, reverting on
     * overflow (when the input is greater than largest uint112).
     *
     * Counterpart to Solidity's `uint112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toUint112(uint256 value) internal pure returns (uint112) {
        if (value > type(uint112).max) {
            revert SafeCastOverflowedUintDowncast(112, value);
        }
        return uint112(value);
    }

    /**
     * @dev Returns the downcasted uint104 from uint256, reverting on
     * overflow (when the input is greater than largest uint104).
     *
     * Counterpart to Solidity's `uint104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toUint104(uint256 value) internal pure returns (uint104) {
        if (value > type(uint104).max) {
            revert SafeCastOverflowedUintDowncast(104, value);
        }
        return uint104(value);
    }

    /**
     * @dev Returns the downcasted uint96 from uint256, reverting on
     * overflow (when the input is greater than largest uint96).
     *
     * Counterpart to Solidity's `uint96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toUint96(uint256 value) internal pure returns (uint96) {
        if (value > type(uint96).max) {
            revert SafeCastOverflowedUintDowncast(96, value);
        }
        return uint96(value);
    }

    /**
     * @dev Returns the downcasted uint88 from uint256, reverting on
     * overflow (when the input is greater than largest uint88).
     *
     * Counterpart to Solidity's `uint88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toUint88(uint256 value) internal pure returns (uint88) {
        if (value > type(uint88).max) {
            revert SafeCastOverflowedUintDowncast(88, value);
        }
        return uint88(value);
    }

    /**
     * @dev Returns the downcasted uint80 from uint256, reverting on
     * overflow (when the input is greater than largest uint80).
     *
     * Counterpart to Solidity's `uint80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toUint80(uint256 value) internal pure returns (uint80) {
        if (value > type(uint80).max) {
            revert SafeCastOverflowedUintDowncast(80, value);
        }
        return uint80(value);
    }

    /**
     * @dev Returns the downcasted uint72 from uint256, reverting on
     * overflow (when the input is greater than largest uint72).
     *
     * Counterpart to Solidity's `uint72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toUint72(uint256 value) internal pure returns (uint72) {
        if (value > type(uint72).max) {
            revert SafeCastOverflowedUintDowncast(72, value);
        }
        return uint72(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        if (value > type(uint64).max) {
            revert SafeCastOverflowedUintDowncast(64, value);
        }
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint56 from uint256, reverting on
     * overflow (when the input is greater than largest uint56).
     *
     * Counterpart to Solidity's `uint56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toUint56(uint256 value) internal pure returns (uint56) {
        if (value > type(uint56).max) {
            revert SafeCastOverflowedUintDowncast(56, value);
        }
        return uint56(value);
    }

    /**
     * @dev Returns the downcasted uint48 from uint256, reverting on
     * overflow (when the input is greater than largest uint48).
     *
     * Counterpart to Solidity's `uint48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toUint48(uint256 value) internal pure returns (uint48) {
        if (value > type(uint48).max) {
            revert SafeCastOverflowedUintDowncast(48, value);
        }
        return uint48(value);
    }

    /**
     * @dev Returns the downcasted uint40 from uint256, reverting on
     * overflow (when the input is greater than largest uint40).
     *
     * Counterpart to Solidity's `uint40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toUint40(uint256 value) internal pure returns (uint40) {
        if (value > type(uint40).max) {
            revert SafeCastOverflowedUintDowncast(40, value);
        }
        return uint40(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        if (value > type(uint32).max) {
            revert SafeCastOverflowedUintDowncast(32, value);
        }
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint24 from uint256, reverting on
     * overflow (when the input is greater than largest uint24).
     *
     * Counterpart to Solidity's `uint24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toUint24(uint256 value) internal pure returns (uint24) {
        if (value > type(uint24).max) {
            revert SafeCastOverflowedUintDowncast(24, value);
        }
        return uint24(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        if (value > type(uint16).max) {
            revert SafeCastOverflowedUintDowncast(16, value);
        }
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        if (value > type(uint8).max) {
            revert SafeCastOverflowedUintDowncast(8, value);
        }
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        if (value < 0) {
            revert SafeCastOverflowedIntToUint(value);
        }
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int248 from int256, reverting on
     * overflow (when the input is less than smallest int248 or
     * greater than largest int248).
     *
     * Counterpart to Solidity's `int248` operator.
     *
     * Requirements:
     *
     * - input must fit into 248 bits
     */
    function toInt248(int256 value) internal pure returns (int248 downcasted) {
        downcasted = int248(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(248, value);
        }
    }

    /**
     * @dev Returns the downcasted int240 from int256, reverting on
     * overflow (when the input is less than smallest int240 or
     * greater than largest int240).
     *
     * Counterpart to Solidity's `int240` operator.
     *
     * Requirements:
     *
     * - input must fit into 240 bits
     */
    function toInt240(int256 value) internal pure returns (int240 downcasted) {
        downcasted = int240(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(240, value);
        }
    }

    /**
     * @dev Returns the downcasted int232 from int256, reverting on
     * overflow (when the input is less than smallest int232 or
     * greater than largest int232).
     *
     * Counterpart to Solidity's `int232` operator.
     *
     * Requirements:
     *
     * - input must fit into 232 bits
     */
    function toInt232(int256 value) internal pure returns (int232 downcasted) {
        downcasted = int232(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(232, value);
        }
    }

    /**
     * @dev Returns the downcasted int224 from int256, reverting on
     * overflow (when the input is less than smallest int224 or
     * greater than largest int224).
     *
     * Counterpart to Solidity's `int224` operator.
     *
     * Requirements:
     *
     * - input must fit into 224 bits
     */
    function toInt224(int256 value) internal pure returns (int224 downcasted) {
        downcasted = int224(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(224, value);
        }
    }

    /**
     * @dev Returns the downcasted int216 from int256, reverting on
     * overflow (when the input is less than smallest int216 or
     * greater than largest int216).
     *
     * Counterpart to Solidity's `int216` operator.
     *
     * Requirements:
     *
     * - input must fit into 216 bits
     */
    function toInt216(int256 value) internal pure returns (int216 downcasted) {
        downcasted = int216(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(216, value);
        }
    }

    /**
     * @dev Returns the downcasted int208 from int256, reverting on
     * overflow (when the input is less than smallest int208 or
     * greater than largest int208).
     *
     * Counterpart to Solidity's `int208` operator.
     *
     * Requirements:
     *
     * - input must fit into 208 bits
     */
    function toInt208(int256 value) internal pure returns (int208 downcasted) {
        downcasted = int208(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(208, value);
        }
    }

    /**
     * @dev Returns the downcasted int200 from int256, reverting on
     * overflow (when the input is less than smallest int200 or
     * greater than largest int200).
     *
     * Counterpart to Solidity's `int200` operator.
     *
     * Requirements:
     *
     * - input must fit into 200 bits
     */
    function toInt200(int256 value) internal pure returns (int200 downcasted) {
        downcasted = int200(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(200, value);
        }
    }

    /**
     * @dev Returns the downcasted int192 from int256, reverting on
     * overflow (when the input is less than smallest int192 or
     * greater than largest int192).
     *
     * Counterpart to Solidity's `int192` operator.
     *
     * Requirements:
     *
     * - input must fit into 192 bits
     */
    function toInt192(int256 value) internal pure returns (int192 downcasted) {
        downcasted = int192(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(192, value);
        }
    }

    /**
     * @dev Returns the downcasted int184 from int256, reverting on
     * overflow (when the input is less than smallest int184 or
     * greater than largest int184).
     *
     * Counterpart to Solidity's `int184` operator.
     *
     * Requirements:
     *
     * - input must fit into 184 bits
     */
    function toInt184(int256 value) internal pure returns (int184 downcasted) {
        downcasted = int184(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(184, value);
        }
    }

    /**
     * @dev Returns the downcasted int176 from int256, reverting on
     * overflow (when the input is less than smallest int176 or
     * greater than largest int176).
     *
     * Counterpart to Solidity's `int176` operator.
     *
     * Requirements:
     *
     * - input must fit into 176 bits
     */
    function toInt176(int256 value) internal pure returns (int176 downcasted) {
        downcasted = int176(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(176, value);
        }
    }

    /**
     * @dev Returns the downcasted int168 from int256, reverting on
     * overflow (when the input is less than smallest int168 or
     * greater than largest int168).
     *
     * Counterpart to Solidity's `int168` operator.
     *
     * Requirements:
     *
     * - input must fit into 168 bits
     */
    function toInt168(int256 value) internal pure returns (int168 downcasted) {
        downcasted = int168(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(168, value);
        }
    }

    /**
     * @dev Returns the downcasted int160 from int256, reverting on
     * overflow (when the input is less than smallest int160 or
     * greater than largest int160).
     *
     * Counterpart to Solidity's `int160` operator.
     *
     * Requirements:
     *
     * - input must fit into 160 bits
     */
    function toInt160(int256 value) internal pure returns (int160 downcasted) {
        downcasted = int160(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(160, value);
        }
    }

    /**
     * @dev Returns the downcasted int152 from int256, reverting on
     * overflow (when the input is less than smallest int152 or
     * greater than largest int152).
     *
     * Counterpart to Solidity's `int152` operator.
     *
     * Requirements:
     *
     * - input must fit into 152 bits
     */
    function toInt152(int256 value) internal pure returns (int152 downcasted) {
        downcasted = int152(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(152, value);
        }
    }

    /**
     * @dev Returns the downcasted int144 from int256, reverting on
     * overflow (when the input is less than smallest int144 or
     * greater than largest int144).
     *
     * Counterpart to Solidity's `int144` operator.
     *
     * Requirements:
     *
     * - input must fit into 144 bits
     */
    function toInt144(int256 value) internal pure returns (int144 downcasted) {
        downcasted = int144(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(144, value);
        }
    }

    /**
     * @dev Returns the downcasted int136 from int256, reverting on
     * overflow (when the input is less than smallest int136 or
     * greater than largest int136).
     *
     * Counterpart to Solidity's `int136` operator.
     *
     * Requirements:
     *
     * - input must fit into 136 bits
     */
    function toInt136(int256 value) internal pure returns (int136 downcasted) {
        downcasted = int136(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(136, value);
        }
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toInt128(int256 value) internal pure returns (int128 downcasted) {
        downcasted = int128(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(128, value);
        }
    }

    /**
     * @dev Returns the downcasted int120 from int256, reverting on
     * overflow (when the input is less than smallest int120 or
     * greater than largest int120).
     *
     * Counterpart to Solidity's `int120` operator.
     *
     * Requirements:
     *
     * - input must fit into 120 bits
     */
    function toInt120(int256 value) internal pure returns (int120 downcasted) {
        downcasted = int120(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(120, value);
        }
    }

    /**
     * @dev Returns the downcasted int112 from int256, reverting on
     * overflow (when the input is less than smallest int112 or
     * greater than largest int112).
     *
     * Counterpart to Solidity's `int112` operator.
     *
     * Requirements:
     *
     * - input must fit into 112 bits
     */
    function toInt112(int256 value) internal pure returns (int112 downcasted) {
        downcasted = int112(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(112, value);
        }
    }

    /**
     * @dev Returns the downcasted int104 from int256, reverting on
     * overflow (when the input is less than smallest int104 or
     * greater than largest int104).
     *
     * Counterpart to Solidity's `int104` operator.
     *
     * Requirements:
     *
     * - input must fit into 104 bits
     */
    function toInt104(int256 value) internal pure returns (int104 downcasted) {
        downcasted = int104(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(104, value);
        }
    }

    /**
     * @dev Returns the downcasted int96 from int256, reverting on
     * overflow (when the input is less than smallest int96 or
     * greater than largest int96).
     *
     * Counterpart to Solidity's `int96` operator.
     *
     * Requirements:
     *
     * - input must fit into 96 bits
     */
    function toInt96(int256 value) internal pure returns (int96 downcasted) {
        downcasted = int96(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(96, value);
        }
    }

    /**
     * @dev Returns the downcasted int88 from int256, reverting on
     * overflow (when the input is less than smallest int88 or
     * greater than largest int88).
     *
     * Counterpart to Solidity's `int88` operator.
     *
     * Requirements:
     *
     * - input must fit into 88 bits
     */
    function toInt88(int256 value) internal pure returns (int88 downcasted) {
        downcasted = int88(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(88, value);
        }
    }

    /**
     * @dev Returns the downcasted int80 from int256, reverting on
     * overflow (when the input is less than smallest int80 or
     * greater than largest int80).
     *
     * Counterpart to Solidity's `int80` operator.
     *
     * Requirements:
     *
     * - input must fit into 80 bits
     */
    function toInt80(int256 value) internal pure returns (int80 downcasted) {
        downcasted = int80(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(80, value);
        }
    }

    /**
     * @dev Returns the downcasted int72 from int256, reverting on
     * overflow (when the input is less than smallest int72 or
     * greater than largest int72).
     *
     * Counterpart to Solidity's `int72` operator.
     *
     * Requirements:
     *
     * - input must fit into 72 bits
     */
    function toInt72(int256 value) internal pure returns (int72 downcasted) {
        downcasted = int72(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(72, value);
        }
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toInt64(int256 value) internal pure returns (int64 downcasted) {
        downcasted = int64(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(64, value);
        }
    }

    /**
     * @dev Returns the downcasted int56 from int256, reverting on
     * overflow (when the input is less than smallest int56 or
     * greater than largest int56).
     *
     * Counterpart to Solidity's `int56` operator.
     *
     * Requirements:
     *
     * - input must fit into 56 bits
     */
    function toInt56(int256 value) internal pure returns (int56 downcasted) {
        downcasted = int56(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(56, value);
        }
    }

    /**
     * @dev Returns the downcasted int48 from int256, reverting on
     * overflow (when the input is less than smallest int48 or
     * greater than largest int48).
     *
     * Counterpart to Solidity's `int48` operator.
     *
     * Requirements:
     *
     * - input must fit into 48 bits
     */
    function toInt48(int256 value) internal pure returns (int48 downcasted) {
        downcasted = int48(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(48, value);
        }
    }

    /**
     * @dev Returns the downcasted int40 from int256, reverting on
     * overflow (when the input is less than smallest int40 or
     * greater than largest int40).
     *
     * Counterpart to Solidity's `int40` operator.
     *
     * Requirements:
     *
     * - input must fit into 40 bits
     */
    function toInt40(int256 value) internal pure returns (int40 downcasted) {
        downcasted = int40(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(40, value);
        }
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toInt32(int256 value) internal pure returns (int32 downcasted) {
        downcasted = int32(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(32, value);
        }
    }

    /**
     * @dev Returns the downcasted int24 from int256, reverting on
     * overflow (when the input is less than smallest int24 or
     * greater than largest int24).
     *
     * Counterpart to Solidity's `int24` operator.
     *
     * Requirements:
     *
     * - input must fit into 24 bits
     */
    function toInt24(int256 value) internal pure returns (int24 downcasted) {
        downcasted = int24(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(24, value);
        }
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toInt16(int256 value) internal pure returns (int16 downcasted) {
        downcasted = int16(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(16, value);
        }
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits
     */
    function toInt8(int256 value) internal pure returns (int8 downcasted) {
        downcasted = int8(value);
        if (downcasted != value) {
            revert SafeCastOverflowedIntDowncast(8, value);
        }
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        // Note: Unsafe cast below is okay because `type(int256).max` is guaranteed to be positive
        if (value > uint256(type(int256).max)) {
            revert SafeCastOverflowedUintToInt(value);
        }
        return int256(value);
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/proxy/beacon/IBeacon.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (proxy/beacon/IBeacon.sol)

pragma solidity ^0.8.20;

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {UpgradeableBeacon} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/StorageSlot.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/StorageSlot.sol)
// This file was procedurally generated from scripts/generate/templates/StorageSlot.js.

pragma solidity ^0.8.20;

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
 *         require(newImplementation.code.length > 0);
 *         StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
 *     }
 * }
 * ```
 */
library StorageSlot {
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
// FILE: contracts/interfaces/eigenlayer/IEigenPodManager.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IETHPOSDeposit} from 'contracts/interfaces/ethereum/IETHPOSDeposit.sol';
import {IBeaconChainOracle} from 'contracts/interfaces/eigenlayer/IBeaconChainOracle.sol';
import {IStrategyManager} from 'contracts/interfaces/eigenlayer/IStrategyManager.sol';
import {IStrategy} from 'contracts/interfaces/eigenlayer/IStrategy.sol';
import {IEigenPod} from 'contracts/interfaces/eigenlayer/IEigenPod.sol';
import {ISlasher} from 'contracts/interfaces/eigenlayer/ISlasher.sol';
import {IBeacon} from 'contracts/interfaces/eigenlayer/IBeacon.sol';

/// @title Interface for factory that creates and manages solo staking pods that have their withdrawal credentials pointed to EigenLayer.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
interface IEigenPodManager {
    /// @notice Emitted to notify the update of the beaconChainOracle address
    event BeaconOracleUpdated(address indexed newOracleAddress);

    /// @notice Emitted to notify the deployment of an EigenPod
    event PodDeployed(address indexed eigenPod, address indexed podOwner);

    /// @notice Emitted to notify a deposit of beacon chain ETH recorded in the strategy manager
    event BeaconChainETHDeposited(address indexed podOwner, uint256 amount);

    /// @notice Emitted when `maxPods` value is updated from `previousValue` to `newValue`
    event MaxPodsUpdated(uint256 previousValue, uint256 newValue);

    /// @notice Emitted when a withdrawal of beacon chain ETH is completed
    event BeaconChainETHWithdrawalCompleted(
        address indexed podOwner,
        uint256 shares,
        uint96 nonce,
        address delegatedAddress,
        address withdrawer,
        bytes32 withdrawalRoot
    );

    /// @notice Creates an EigenPod for the sender.
    /// @dev Function will revert if the `msg.sender` already has an EigenPod.
    /// @dev Returns EigenPod address.
    function createPod() external returns (address);

    /// @notice Stakes for a new beacon chain validator on the sender's EigenPod.
    /// Also creates an EigenPod for the sender if they don't have one already.
    /// @param pubkey The 48 bytes public key of the beacon chain validator.
    /// @param signature The validator's signature of the deposit data.
    /// @param depositDataRoot The root/hash of the deposit data for the validator's deposit.
    function stake(bytes calldata pubkey, bytes calldata signature, bytes32 depositDataRoot) external payable;

    /// @notice Changes the `podOwner`'s shares by `sharesDelta` and performs a call to the DelegationManager
    /// to ensure that delegated shares are also tracked correctly
    /// @param podOwner is the pod owner whose balance is being updated.
    /// @param sharesDelta is the change in podOwner's beaconChainETHStrategy shares
    /// @dev Callable only by the podOwner's EigenPod contract.
    /// @dev Reverts if `sharesDelta` is not a whole Gwei amount
    function recordBeaconChainETHBalanceUpdate(address podOwner, int256 sharesDelta) external;

    /// @notice Updates the oracle contract that provides the beacon chain state root
    /// @param newBeaconChainOracle is the new oracle contract being pointed to
    /// @dev Callable only by the owner of this contract (i.e. governance)
    function updateBeaconChainOracle(IBeaconChainOracle newBeaconChainOracle) external;

    /// @notice Returns the address of the `podOwner`'s EigenPod if it has been deployed.
    function ownerToPod(address podOwner) external view returns (IEigenPod);

    /// @notice Returns the address of the `podOwner`'s EigenPod (whether it is deployed yet or not).
    function getPod(address podOwner) external view returns (IEigenPod);

    /// @notice The ETH2 Deposit Contract
    function ethPOS() external view returns (IETHPOSDeposit);

    /// @notice Beacon proxy to which the EigenPods point
    function eigenPodBeacon() external view returns (IBeacon);

    /// @notice Oracle contract that provides updates to the beacon chain's state
    function beaconChainOracle() external view returns (IBeaconChainOracle);

    /// @notice Returns the beacon block root at `timestamp`. Reverts if the Beacon block root at `timestamp` has not yet been finalized.
    function getBlockRootAtTimestamp(uint64 timestamp) external view returns (bytes32);

    /// @notice EigenLayer's StrategyManager contract
    function strategyManager() external view returns (IStrategyManager);

    /// @notice EigenLayer's Slasher contract
    function slasher() external view returns (ISlasher);

    /// @notice Whether the `podOwner` has an EigenPod deployed.
    function hasPod(address podOwner) external view returns (bool);

    /// @notice Mapping from Pod owner owner to the number of shares they have in the virtual beacon chain ETH strategy.
    /// @dev The share amount can become negative. This is necessary to accommodate the fact that a pod owner's virtual beacon chain ETH shares can
    /// decrease between the pod owner queuing and completing a withdrawal.
    /// When the pod owner's shares would otherwise increase, this "deficit" is decreased first _instead_.
    /// Likewise, when a withdrawal is completed, this "deficit" is decreased and the withdrawal amount is decreased; We can think of this
    /// as the withdrawal "paying off the deficit".
    function podOwnerShares(address podOwner) external view returns (int256);

    /// @notice returns canonical, virtual beaconChainETH strategy
    function beaconChainETHStrategy() external view returns (IStrategy);

    /// @notice Used by the DelegationManager to remove a pod owner's shares while they're in the withdrawal queue.
    /// Simply decreases the `podOwner`'s shares by `shares`, down to a minimum of zero.
    /// @dev This function reverts if it would result in `podOwnerShares[podOwner]` being less than zero, i.e. it is forbidden for this function to
    /// result in the `podOwner` incurring a "share deficit". This behavior prevents a Staker from queuing a withdrawal which improperly removes excessive
    /// shares from the operator to whom the staker is delegated.
    /// @dev Reverts if `shares` is not a whole Gwei amount
    function removeShares(address podOwner, uint256 shares) external;

    /// @notice Increases the `podOwner`'s shares by `shares`, paying off deficit if possible.
    /// Used by the DelegationManager to award a pod owner shares on exiting the withdrawal queue
    /// @dev Returns the number of shares added to `podOwnerShares[podOwner]` above zero, which will be less than the `shares` input
    /// in the event that the podOwner has an existing shares deficit (i.e. `podOwnerShares[podOwner]` starts below zero)
    /// @dev Reverts if `shares` is not a whole Gwei amount
    function addShares(address podOwner, uint256 shares) external returns (uint256);

    /// @notice Used by the DelegationManager to complete a withdrawal, sending tokens to some destination address
    /// @dev Prioritizes decreasing the podOwner's share deficit, if they have one
    /// @dev Reverts if `shares` is not a whole Gwei amount
    function withdrawSharesAsTokens(address podOwner, address destination, uint256 shares) external;
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IStrategy.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';

/// @title Minimal interface for an `Strategy` contract.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice Custom `Strategy` implementations may expand extensively on this interface.
interface IStrategy {
    /// @notice Used to deposit tokens into this Strategy
    /// @param token is the ERC20 token being deposited
    /// @param amount is the amount of token being deposited
    /// @dev This function is only callable by the strategyManager contract.
    /// It is invoked inside of the strategyManager's `depositIntoStrategy` function,
    /// and individual share balances are recorded in the strategyManager as well.
    /// @return newShares is the number of new shares issued at the current exchange ratio.
    function deposit(IERC20 token, uint256 amount) external returns (uint256);

    /// @notice Used to withdraw tokens from this Strategy, to the `recipient`'s address
    /// @param recipient is the address to receive the withdrawn funds
    /// @param token is the ERC20 token being transferred out
    /// @param amountShares is the amount of shares being withdrawn
    /// @dev This function is only callable by the strategyManager contract.
    /// It is invoked inside of the strategyManager's other functions,
    /// and individual share balances are recorded in the strategyManager as well.
    function withdraw(address recipient, IERC20 token, uint256 amountShares) external;

    /// @notice Used to convert a number of shares to the equivalent amount of underlying tokens for this strategy.
    /// @notice In contrast to `sharesToUnderlyingView`, this function **may** make state modifications
    /// @param amountShares is the amount of shares to calculate its conversion into the underlying token
    /// @return The amount of underlying tokens corresponding to the input `amountShares`
    /// @dev Implementation for these functions in particular may vary significantly for different strategies
    function sharesToUnderlying(uint256 amountShares) external returns (uint256);

    /// @notice Used to convert an amount of underlying tokens to the equivalent amount of shares in this strategy.
    /// @notice In contrast to `underlyingToSharesView`, this function **may** make state modifications
    /// @param amountUnderlying is the amount of `underlyingToken` to calculate its conversion into strategy shares
    /// @return The amount of underlying tokens corresponding to the input `amountShares`
    /// @dev Implementation for these functions in particular may vary significantly for different strategies
    function underlyingToShares(uint256 amountUnderlying) external returns (uint256);

    /// @notice convenience function for fetching the current underlying value of all of the `user`'s shares in
    /// this strategy. In contrast to `userUnderlyingView`, this function **may** make state modifications
    function userUnderlying(address user) external returns (uint256);

    /// @notice convenience function for fetching the current total shares of `user` in this strategy,
    /// by querying the `strategyManager` contract
    function shares(address user) external view returns (uint256);

    /// @notice Used to convert a number of shares to the equivalent amount of underlying tokens for this strategy.
    /// @notice In contrast to `sharesToUnderlying`, this function guarantees no state modifications
    /// @param amountShares is the amount of shares to calculate its conversion into the underlying token
    /// @return The amount of shares corresponding to the input `amountUnderlying`
    /// @dev Implementation for these functions in particular may vary significantly for different strategies
    function sharesToUnderlyingView(uint256 amountShares) external view returns (uint256);

    /// @notice Used to convert an amount of underlying tokens to the equivalent amount of shares in this strategy.
    /// @notice In contrast to `underlyingToShares`, this function guarantees no state modifications
    /// @param amountUnderlying is the amount of `underlyingToken` to calculate its conversion into strategy shares
    /// @return The amount of shares corresponding to the input `amountUnderlying`
    /// @dev Implementation for these functions in particular may vary significantly for different strategies
    function underlyingToSharesView(uint256 amountUnderlying) external view returns (uint256);

    /// @notice convenience function for fetching the current underlying value of all of the `user`'s shares in
    /// this strategy. In contrast to `userUnderlying`, this function guarantees no state modifications
    function userUnderlyingView(address user) external view returns (uint256);

    /// @notice The underlying token for shares in this Strategy
    function underlyingToken() external view returns (address);

    /// @notice The total number of extant shares in this Strategy
    function totalShares() external view returns (uint256);

    /// @notice Returns either a brief string explaining the strategy's goal & purpose,
    /// or a link to metadata that explains in more detail.
    function explanation() external view returns (string memory);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IStakeRegistry.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IRegistry} from 'contracts/interfaces/eigenlayer/IRegistry.sol';

/// @title Interface for a `Registry` that keeps track of stakes of operators for up to 256 quorums.
/// @author Layr Labs, Inc.
interface IStakeRegistry is IRegistry {
    /// @notice emitted whenever the stake of `operator` is updated
    event StakeUpdate(bytes32 indexed operatorId, uint8 quorumNumber, uint96 stake);

    event MinimumStakeForQuorumUpdated(uint8 indexed quorumNumber, uint96 minimumStake);

    /// @notice struct used to store the stakes of an individual operator or the sum of all operators' stakes, for storage
    struct OperatorStakeUpdate {
        // the block number at which the stake amounts were updated and stored
        uint32 updateBlockNumber;
        // the block number at which the *next update* occurred.
        /// @notice This entry has the value **0** until another update takes place.
        uint32 nextUpdateBlockNumber;
        // stake weight for the quorum
        uint96 stake;
    }

    /// @notice Registers the `operator` with `operatorId` for the specified `quorumNumbers`.
    /// @param operator The address of the operator to register.
    /// @param operatorId The id of the operator to register.
    /// @param quorumNumbers The quorum numbers the operator is registering for, where each byte is an 8 bit integer quorumNumber.
    /// @dev access restricted to the RegistryCoordinator
    /// @dev Preconditions (these are assumed, not validated in this contract):
    ///         1) `quorumNumbers` has no duplicates
    ///         2) `quorumNumbers.length` != 0
    ///         3) `quorumNumbers` is ordered in ascending order
    ///         4) the operator is not already registered
    function registerOperator(address operator, bytes32 operatorId, bytes memory quorumNumbers) external;

    /// @notice Deregisters the operator with `operatorId` for the specified `quorumNumbers`.
    /// @param operatorId The id of the operator to deregister.
    /// @param quorumNumbers The quorum numbers the operator is deregistering from, where each byte is an 8 bit integer quorumNumber.
    /// @dev access restricted to the RegistryCoordinator
    /// @dev Preconditions (these are assumed, not validated in this contract):
    ///         1) `quorumNumbers` has no duplicates
    ///         2) `quorumNumbers.length` != 0
    ///         3) `quorumNumbers` is ordered in ascending order
    ///         4) the operator is not already deregistered
    ///         5) `quorumNumbers` is a subset of the quorumNumbers that the operator is registered for
    function deregisterOperator(bytes32 operatorId, bytes memory quorumNumbers) external;

    /// @notice In order to register for a quorum i, an operator must have at least `minimumStakeForQuorum[i]`
    function minimumStakeForQuorum(uint256 quorumNumber) external view returns (uint96);

    /// @notice Returns the entire `operatorIdToStakeHistory[operatorId][quorumNumber]` array.
    /// @param operatorId The id of the operator of interest.
    /// @param quorumNumber The quorum number to get the stake for.
    function getOperatorIdToStakeHistory(bytes32 operatorId, uint8 quorumNumber)
        external
        view
        returns (OperatorStakeUpdate[] memory);

    function getLengthOfTotalStakeHistoryForQuorum(uint8 quorumNumber) external view returns (uint256);

    /// @notice Returns the `index`-th entry in the dynamic array of total stake, `totalStakeHistory` for quorum `quorumNumber`.
    /// @param quorumNumber The quorum number to get the stake for.
    /// @param index Array index for lookup, within the dynamic array `totalStakeHistory[quorumNumber]`.
    function getTotalStakeUpdateForQuorumFromIndex(uint8 quorumNumber, uint256 index)
        external
        view
        returns (OperatorStakeUpdate memory);

    /// @notice Returns the indices of the operator stakes for the provided `quorumNumber` at the given `blockNumber`
    function getStakeUpdateIndexForOperatorIdForQuorumAtBlockNumber(
        bytes32 operatorId,
        uint8 quorumNumber,
        uint32 blockNumber
    ) external view returns (uint32);

    /// @notice Returns the indices of the total stakes for the provided `quorumNumbers` at the given `blockNumber`
    function getTotalStakeIndicesByQuorumNumbersAtBlockNumber(uint32 blockNumber, bytes calldata quorumNumbers)
        external
        view
        returns (uint32[] memory);

    /// @notice Returns the `index`-th entry in the `operatorIdToStakeHistory[operatorId][quorumNumber]` array.
    /// @param quorumNumber The quorum number to get the stake for.
    /// @param operatorId The id of the operator of interest.
    /// @param index Array index for lookup, within the dynamic array `operatorIdToStakeHistory[operatorId][quorumNumber]`.
    /// @dev Function will revert if `index` is out-of-bounds.
    function getStakeUpdateForQuorumFromOperatorIdAndIndex(uint8 quorumNumber, bytes32 operatorId, uint256 index)
        external
        view
        returns (OperatorStakeUpdate memory);

    /// @notice Returns the most recent stake weight for the `operatorId` for a certain quorum
    /// @dev Function returns an OperatorStakeUpdate struct with **every entry equal to 0** in the event that the operator has no stake history
    function getMostRecentStakeUpdateByOperatorId(bytes32 operatorId, uint8 quorumNumber)
        external
        view
        returns (OperatorStakeUpdate memory);

    /// @notice Returns the stake weight corresponding to `operatorId` for quorum `quorumNumber`, at the
    /// `index`-th entry in the `operatorIdToStakeHistory[operatorId][quorumNumber]` array if the entry
    /// corresponds to the operator's stake at `blockNumber`. Reverts otherwise.
    /// @param quorumNumber The quorum number to get the stake for.
    /// @param operatorId The id of the operator of interest.
    /// @param index Array index for lookup, within the dynamic array `operatorIdToStakeHistory[operatorId][quorumNumber]`.
    /// @param blockNumber Block number to make sure the stake is from.
    /// @dev Function will revert if `index` is out-of-bounds.
    /// @dev used the BLSSignatureChecker to get past stakes of signing operators
    function getStakeForQuorumAtBlockNumberFromOperatorIdAndIndex(
        uint8 quorumNumber,
        uint32 blockNumber,
        bytes32 operatorId,
        uint256 index
    ) external view returns (uint96);

    /// @notice Returns the total stake weight for quorum `quorumNumber`, at the `index`-th entry in the
    /// `totalStakeHistory[quorumNumber]` array if the entry corresponds to the total stake at `blockNumber`.
    /// Reverts otherwise.
    /// @param quorumNumber The quorum number to get the stake for.
    /// @param index Array index for lookup, within the dynamic array `totalStakeHistory[quorumNumber]`.
    /// @param blockNumber Block number to make sure the stake is from.
    /// @dev Function will revert if `index` is out-of-bounds.
    /// @dev used the BLSSignatureChecker to get past stakes of signing operators
    function getTotalStakeAtBlockNumberFromIndex(uint8 quorumNumber, uint32 blockNumber, uint256 index)
        external
        view
        returns (uint96);

    /// @notice Returns the most recent stake weight for the `operatorId` for quorum `quorumNumber`
    /// @dev Function returns weight of **0** in the event that the operator has no stake history
    function getCurrentOperatorStakeForQuorum(bytes32 operatorId, uint8 quorumNumber) external view returns (uint96);

    /// @notice Returns the stake of the operator for the provided `quorumNumber` at the given `blockNumber`
    function getStakeForOperatorIdForQuorumAtBlockNumber(bytes32 operatorId, uint8 quorumNumber, uint32 blockNumber)
        external
        view
        returns (uint96);

    /// @notice Returns the stake weight from the latest entry in `_totalStakeHistory` for quorum `quorumNumber`.
    /// @dev Will revert if `_totalStakeHistory[quorumNumber]` is empty.
    function getCurrentTotalStakeForQuorum(uint8 quorumNumber) external view returns (uint96);

    /// @notice Used for updating information on deposits of nodes.
    /// @param operators are the addresses of the operators whose stake information is getting updated
    function updateStakes(address[] memory operators) external;
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/ISignatureUtils.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

/// @title The interface for common signature utilities.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
interface ISignatureUtils {
    /// @notice Struct that bundles together a signature and an expiration time for the signature. Used primarily for stack management.
    struct SignatureWithExpiry {
        // the signature itself, formatted as a single bytes object
        bytes signature;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }

    /// @notice Struct that bundles together a signature, a salt for uniqueness, and an expiration time for the signature. Used primarily for stack management.
    struct SignatureWithSaltAndExpiry {
        // the signature itself, formatted as a single bytes object
        bytes signature;
        // the salt used to generate the signature
        bytes32 salt;
        // the expiration timestamp (UTC) of the signature
        uint256 expiry;
    }
}


// ============================================================================
// FILE: lib/solady/src/utils/CREATE3.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

/// @notice Deploy to deterministic addresses without an initcode factor.
/// @author Solady (https://github.com/vectorized/solmady/blob/main/src/utils/CREATE3.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/CREATE3.sol)
/// @author Modified from 0xSequence (https://github.com/0xSequence/create3/blob/master/contracts/Create3.sol)
library CREATE3 {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Unable to deploy the contract.
    error DeploymentFailed();

    /// @dev Unable to initialize the contract.
    error InitializationFailed();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      BYTECODE CONSTANTS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * -------------------------------------------------------------------+
     * Opcode      | Mnemonic         | Stack        | Memory             |
     * -------------------------------------------------------------------|
     * 36          | CALLDATASIZE     | cds          |                    |
     * 3d          | RETURNDATASIZE   | 0 cds        |                    |
     * 3d          | RETURNDATASIZE   | 0 0 cds      |                    |
     * 37          | CALLDATACOPY     |              | [0..cds): calldata |
     * 36          | CALLDATASIZE     | cds          | [0..cds): calldata |
     * 3d          | RETURNDATASIZE   | 0 cds        | [0..cds): calldata |
     * 34          | CALLVALUE        | value 0 cds  | [0..cds): calldata |
     * f0          | CREATE           | newContract  | [0..cds): calldata |
     * -------------------------------------------------------------------|
     * Opcode      | Mnemonic         | Stack        | Memory             |
     * -------------------------------------------------------------------|
     * 67 bytecode | PUSH8 bytecode   | bytecode     |                    |
     * 3d          | RETURNDATASIZE   | 0 bytecode   |                    |
     * 52          | MSTORE           |              | [0..8): bytecode   |
     * 60 0x08     | PUSH1 0x08       | 0x08         | [0..8): bytecode   |
     * 60 0x18     | PUSH1 0x18       | 0x18 0x08    | [0..8): bytecode   |
     * f3          | RETURN           |              | [0..8): bytecode   |
     * -------------------------------------------------------------------+
     */

    /// @dev The proxy bytecode.
    uint256 private constant _PROXY_BYTECODE = 0x67363d3d37363d34f03d5260086018f3;

    /// @dev Hash of the `_PROXY_BYTECODE`.
    /// Equivalent to `keccak256(abi.encodePacked(hex"67363d3d37363d34f03d5260086018f3"))`.
    bytes32 private constant _PROXY_BYTECODE_HASH =
        0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      CREATE3 OPERATIONS                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Deploys `creationCode` deterministically with a `salt`.
    /// The deployed contract is funded with `value` (in wei) ETH.
    /// Returns the deterministic address of the deployed contract,
    /// which solely depends on `salt`.
    function deploy(bytes32 salt, bytes memory creationCode, uint256 value)
        internal
        returns (address deployed)
    {
        /// @solidity memory-safe-assembly
        assembly {
            // Store the `_PROXY_BYTECODE` into scratch space.
            mstore(0x00, _PROXY_BYTECODE)
            // Deploy a new contract with our pre-made bytecode via CREATE2.
            let proxy := create2(0, 0x10, 0x10, salt)

            // If the result of `create2` is the zero address, revert.
            if iszero(proxy) {
                // Store the function selector of `DeploymentFailed()`.
                mstore(0x00, 0x30116425)
                // Revert with (offset, size).
                revert(0x1c, 0x04)
            }

            // Store the proxy's address.
            mstore(0x14, proxy)
            // 0xd6 = 0xc0 (short RLP prefix) + 0x16 (length of: 0x94 ++ proxy ++ 0x01).
            // 0x94 = 0x80 + 0x14 (0x14 = the length of an address, 20 bytes, in hex).
            mstore(0x00, 0xd694)
            // Nonce of the proxy contract (1).
            mstore8(0x34, 0x01)

            deployed := keccak256(0x1e, 0x17)

            // If the `call` fails, revert.
            if iszero(
                call(
                    gas(), // Gas remaining.
                    proxy, // Proxy's address.
                    value, // Ether value.
                    add(creationCode, 0x20), // Start of `creationCode`.
                    mload(creationCode), // Length of `creationCode`.
                    0x00, // Offset of output.
                    0x00 // Length of output.
                )
            ) {
                // Store the function selector of `InitializationFailed()`.
                mstore(0x00, 0x19b991a8)
                // Revert with (offset, size).
                revert(0x1c, 0x04)
            }

            // If the code size of `deployed` is zero, revert.
            if iszero(extcodesize(deployed)) {
                // Store the function selector of `InitializationFailed()`.
                mstore(0x00, 0x19b991a8)
                // Revert with (offset, size).
                revert(0x1c, 0x04)
            }
        }
    }

    /// @dev Returns the deterministic address for `salt` with `deployer`.
    function getDeployed(bytes32 salt, address deployer) internal pure returns (address deployed) {
        /// @solidity memory-safe-assembly
        assembly {
            // Cache the free memory pointer.
            let m := mload(0x40)
            // Store `deployer`.
            mstore(0x00, deployer)
            // Store the prefix.
            mstore8(0x0b, 0xff)
            // Store the salt.
            mstore(0x20, salt)
            // Store the bytecode hash.
            mstore(0x40, _PROXY_BYTECODE_HASH)

            // Store the proxy's address.
            mstore(0x14, keccak256(0x0b, 0x55))
            // Restore the free memory pointer.
            mstore(0x40, m)
            // 0xd6 = 0xc0 (short RLP prefix) + 0x16 (length of: 0x94 ++ proxy ++ 0x01).
            // 0x94 = 0x80 + 0x14 (0x14 = the length of an address, 20 bytes, in hex).
            mstore(0x00, 0xd694)
            // Nonce of the proxy contract (1).
            mstore8(0x34, 0x01)

            deployed := keccak256(0x1e, 0x17)
        }
    }

    /// @dev Returns the deterministic address for `salt`.
    function getDeployed(bytes32 salt) internal view returns (address deployed) {
        deployed = getDeployed(salt, address(this));
    }
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IBeaconChainOracle.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

/// @title Interface for the BeaconStateOracle contract.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
interface IBeaconChainOracle {
    /// @notice The block number to state root mapping.
    function timestampToBlockRoot(uint256 timestamp) external view returns (bytes32);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IStrategyManager.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {IDelegationManager} from 'contracts/interfaces/eigenlayer/IDelegationManager.sol';
import {IEigenPodManager} from 'contracts/interfaces/eigenlayer/IEigenPodManager.sol';
import {IStrategy} from 'contracts/interfaces/eigenlayer/IStrategy.sol';
import {ISlasher} from 'contracts/interfaces/eigenlayer/ISlasher.sol';

/// @title Interface for the primary entrypoint for funds into EigenLayer.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice See the `StrategyManager` contract itself for implementation details.
interface IStrategyManager {
    /// @notice Emitted when a new deposit occurs on behalf of `staker`.
    /// @param staker Is the staker who is depositing funds into EigenLayer.
    /// @param strategy Is the strategy that `staker` has deposited into.
    /// @param token Is the token that `staker` deposited.
    /// @param shares Is the number of new shares `staker` has been granted in `strategy`.
    event Deposit(address staker, IERC20 token, IStrategy strategy, uint256 shares);

    /// @notice Emitted when the `strategyWhitelister` is changed
    event StrategyWhitelisterChanged(address previousAddress, address newAddress);

    /// @notice Emitted when a strategy is added to the approved list of strategies for deposit
    event StrategyAddedToDepositWhitelist(IStrategy strategy);

    /// @notice Emitted when a strategy is removed from the approved list of strategies for deposit
    event StrategyRemovedFromDepositWhitelist(IStrategy strategy);

    /// @notice Deposits `amount` of `token` into the specified `strategy`, with the resultant shares credited to `msg.sender`
    /// @param strategy is the specified strategy where deposit is to be made,
    /// @param token is the denomination in which the deposit is to be made,
    /// @param amount is the amount of token to be deposited in the strategy by the staker
    /// @return shares The amount of new shares in the `strategy` created as part of the action.
    /// @dev The `msg.sender` must have previously approved this contract to transfer at least `amount` of `token` on their behalf.
    /// @dev Cannot be called by an address that is 'frozen' (this function will revert if the `msg.sender` is frozen).
    /// WARNING: Depositing tokens that allow reentrancy (eg. ERC-777) into a strategy is not recommended.  This can lead to attack vectors
    /// where the token balance and corresponding strategy shares are not in sync upon reentrancy.
    function depositIntoStrategy(address strategy, address token, uint256 amount) external returns (uint256 shares);

    /// @notice Used for depositing an asset into the specified strategy with the resultant shares credited to `staker`,
    /// who must sign off on the action.
    /// Note that the assets are transferred out/from the `msg.sender`, not from the `staker`; this function is explicitly designed
    /// purely to help one address deposit 'for' another.
    /// @param strategy is the specified strategy where deposit is to be made,
    /// @param token is the denomination in which the deposit is to be made,
    /// @param amount is the amount of token to be deposited in the strategy by the staker
    /// @param staker the staker that the deposited assets will be credited to
    /// @param expiry the timestamp at which the signature expires
    /// @param signature is a valid signature from the `staker`. either an ECDSA signature if the `staker` is an EOA, or data to forward
    /// following EIP-1271 if the `staker` is a contract
    /// @return shares The amount of new shares in the `strategy` created as part of the action.
    /// @dev The `msg.sender` must have previously approved this contract to transfer at least `amount` of `token` on their behalf.
    /// @dev A signature is required for this function to eliminate the possibility of griefing attacks, specifically those
    /// targeting stakers who may be attempting to undelegate.
    /// @dev Cannot be called on behalf of a staker that is 'frozen' (this function will revert if the `staker` is frozen).
    /// WARNING: Depositing tokens that allow reentrancy (eg. ERC-777) into a strategy is not recommended.  This can lead to attack vectors
    /// where the token balance and corresponding strategy shares are not in sync upon reentrancy
    function depositIntoStrategyWithSignature(
        IStrategy strategy,
        IERC20 token,
        uint256 amount,
        address staker,
        uint256 expiry,
        bytes memory signature
    ) external returns (uint256 shares);

    /// @notice Used by the DelegationManager to remove a Staker's shares from a particular strategy when entering the withdrawal queue
    function removeShares(address staker, IStrategy strategy, uint256 shares) external;

    /// @notice Used by the DelegationManager to award a Staker some shares that have passed through the withdrawal queue
    function addShares(address staker, IStrategy strategy, uint256 shares) external;

    /// @notice Used by the DelegationManager to convert withdrawn shares to tokens and send them to a recipient
    function withdrawSharesAsTokens(address recipient, IStrategy strategy, uint256 shares, IERC20 token) external;

    /// @notice Returns the current shares of `user` in `strategy`
    function stakerStrategyShares(address user, address strategy) external view returns (uint256 shares);

    /// @notice Get all details on the staker's deposits and corresponding shares
    /// @return (staker's strategies, shares in these strategies)
    function getDeposits(address staker) external view returns (IStrategy[] memory, uint256[] memory);

    /// @notice Simple getter function that returns `stakerStrategyList[staker].length`.
    function stakerStrategyListLength(address staker) external view returns (uint256);

    /// @notice Owner-only function that adds the provided Strategies to the 'whitelist' of strategies that stakers can deposit into
    /// @param strategiesToWhitelist Strategies that will be added to the `strategyIsWhitelistedForDeposit` mapping (if they aren't in it already)
    function addStrategiesToDepositWhitelist(address[] calldata strategiesToWhitelist) external;

    /// @notice Owner-only function that removes the provided Strategies from the 'whitelist' of strategies that stakers can deposit into
    /// @param strategiesToRemoveFromWhitelist Strategies that will be removed to the `strategyIsWhitelistedForDeposit` mapping (if they are in it)
    function removeStrategiesFromDepositWhitelist(IStrategy[] calldata strategiesToRemoveFromWhitelist) external;

    /// @notice Returns the single, central Delegation contract of EigenLayer
    function delegation() external view returns (IDelegationManager);

    /// @notice Returns the single, central Slasher contract of EigenLayer
    function slasher() external view returns (ISlasher);

    /// @notice Returns the EigenPodManager contract of EigenLayer
    function eigenPodManager() external view returns (IEigenPodManager);

    // LIMITED BACKWARDS-COMPATIBILITY FOR DEPRECATED FUNCTIONALITY

    // packed struct for queued withdrawals; helps deal with stack-too-deep errors
    struct DeprecatedStruct_WithdrawerAndNonce {
        address withdrawer;
        uint96 nonce;
    }

    /// Struct type used to specify an existing queued withdrawal. Rather than storing the entire struct, only a hash is stored.
    /// In functions that operate on existing queued withdrawals -- e.g. `startQueuedWithdrawalWaitingPeriod` or `completeQueuedWithdrawal`,
    /// the data is resubmitted and the hash of the submitted data is computed by `calculateWithdrawalRoot` and checked against the
    /// stored hash in order to confirm the integrity of the submitted data.
    struct DeprecatedStruct_QueuedWithdrawal {
        IStrategy[] strategies;
        uint256[] shares;
        address staker;
        DeprecatedStruct_WithdrawerAndNonce withdrawerAndNonce;
        uint32 withdrawalStartBlock;
        address delegatedAddress;
    }

    function migrateQueuedWithdrawal(DeprecatedStruct_QueuedWithdrawal memory queuedWithdrawal)
        external
        returns (bool, bytes32);

    function calculateWithdrawalRoot(DeprecatedStruct_QueuedWithdrawal memory queuedWithdrawal)
        external
        pure
        returns (bytes32);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/ISlasher.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IStrategyManager} from 'contracts/interfaces/eigenlayer/IStrategyManager.sol';
import {IDelegationManager} from 'contracts/interfaces/eigenlayer/IDelegationManager.sol';

/// @title Interface for the primary 'slashing' contract for EigenLayer.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice See the `Slasher` contract itself for implementation details.
interface ISlasher {
    /// @notice struct used to store information about the current state of an operator's obligations to middlewares they are serving
    struct MiddlewareTimes {
        // The update block for the middleware whose most recent update was earliest, i.e. the 'stalest' update out of all middlewares the operator is serving
        uint32 stalestUpdateBlock;
        // The latest 'serveUntilBlock' from all of the middleware that the operator is serving
        uint32 latestServeUntilBlock;
    }

    /// @notice struct used to store details relevant to a single middleware that an operator has opted-in to serving
    struct MiddlewareDetails {
        // the block at which the contract begins being able to finalize the operator's registration with the service via calling `recordFirstStakeUpdate`
        uint32 registrationMayBeginAtBlock;
        // the block before which the contract is allowed to slash the user
        uint32 contractCanSlashOperatorUntilBlock;
        // the block at which the middleware's view of the operator's stake was most recently updated
        uint32 latestUpdateBlock;
    }

    /// @notice Emitted when a middleware times is added to `operator`'s array.
    event MiddlewareTimesAdded(
        address operator, uint256 index, uint32 stalestUpdateBlock, uint32 latestServeUntilBlock
    );

    /// @notice Emitted when `operator` begins to allow `contractAddress` to slash them.
    event OptedIntoSlashing(address indexed operator, address indexed contractAddress);

    /// @notice Emitted when `contractAddress` signals that it will no longer be able to slash `operator` after the `contractCanSlashOperatorUntilBlock`.
    event SlashingAbilityRevoked(
        address indexed operator, address indexed contractAddress, uint32 contractCanSlashOperatorUntilBlock
    );

    /// @notice Emitted when `slashingContract` 'freezes' the `slashedOperator`.
    /// @dev The `slashingContract` must have permission to slash the `slashedOperator`, i.e. `canSlash(slasherOperator, slashingContract)` must return 'true'.
    event OperatorFrozen(address indexed slashedOperator, address indexed slashingContract);

    /// @notice Emitted when `previouslySlashedAddress` is 'unfrozen', allowing them to again move deposited funds within EigenLayer.
    event FrozenStatusReset(address indexed previouslySlashedAddress);

    /// @notice Gives the `contractAddress` permission to slash the funds of the caller.
    /// @dev Typically, this function must be called prior to registering for a middleware.
    function optIntoSlashing(address contractAddress) external;

    /// @notice Used for 'slashing' a certain operator.
    /// @param toBeFrozen The operator to be frozen.
    /// @dev Technically the operator is 'frozen' (hence the name of this function), and then subject to slashing pending a decision by a human-in-the-loop.
    /// @dev The operator must have previously given the caller (which should be a contract) the ability to slash them, through a call to `optIntoSlashing`.
    function freezeOperator(address toBeFrozen) external;

    /// @notice Removes the 'frozen' status from each of the `frozenAddresses`
    /// @dev Callable only by the contract owner (i.e. governance).
    function resetFrozenStatus(address[] calldata frozenAddresses) external;

    /// @notice this function is a called by middlewares during an operator's registration to make sure the operator's stake at registration
    ///         is slashable until serveUntil
    /// @param operator the operator whose stake update is being recorded
    /// @param serveUntilBlock the block until which the operator's stake at the current block is slashable
    /// @dev adds the middleware's slashing contract to the operator's linked list
    function recordFirstStakeUpdate(address operator, uint32 serveUntilBlock) external;

    /// @notice this function is a called by middlewares during a stake update for an operator (perhaps to free pending withdrawals)
    ///         to make sure the operator's stake at updateBlock is slashable until serveUntil
    /// @param operator the operator whose stake update is being recorded
    /// @param updateBlock the block for which the stake update is being recorded
    /// @param serveUntilBlock the block until which the operator's stake at updateBlock is slashable
    /// @param insertAfter the element of the operators linked list that the currently updating middleware should be inserted after
    /// @dev insertAfter should be calculated offchain before making the transaction that calls this. this is subject to race conditions,
    ///      but it is anticipated to be rare and not detrimental.
    function recordStakeUpdate(address operator, uint32 updateBlock, uint32 serveUntilBlock, uint256 insertAfter)
        external;

    /// @notice this function is a called by middlewares during an operator's deregistration to make sure the operator's stake at deregistration
    ///         is slashable until serveUntil
    /// @param operator the operator whose stake update is being recorded
    /// @param serveUntilBlock the block until which the operator's stake at the current block is slashable
    /// @dev removes the middleware's slashing contract to the operator's linked list and revokes the middleware's (i.e. caller's) ability to
    /// slash `operator` once `serveUntil` is reached
    function recordLastStakeUpdateAndRevokeSlashingAbility(address operator, uint32 serveUntilBlock) external;

    /// @notice The StrategyManager contract of EigenLayer
    function strategyManager() external view returns (IStrategyManager);

    /// @notice The DelegationManager contract of EigenLayer
    function delegation() external view returns (IDelegationManager);

    /// @notice Used to determine whether `staker` is actively 'frozen'. If a staker is frozen, then they are potentially subject to
    /// slashing of their funds, and cannot cannot deposit or withdraw from the strategyManager until the slashing process is completed
    /// and the staker's status is reset (to 'unfrozen').
    /// @param staker The staker of interest.
    /// @return Returns 'true' if `staker` themselves has their status set to frozen, OR if the staker is delegated
    /// to an operator who has their status set to frozen. Otherwise returns 'false'.
    function isFrozen(address staker) external view returns (bool);

    /// @notice Returns true if `slashingContract` is currently allowed to slash `toBeSlashed`.
    function canSlash(address toBeSlashed, address slashingContract) external view returns (bool);

    /// @notice Returns the block until which `serviceContract` is allowed to slash the `operator`.
    function contractCanSlashOperatorUntilBlock(address operator, address serviceContract)
        external
        view
        returns (uint32);

    /// @notice Returns the block at which the `serviceContract` last updated its view of the `operator`'s stake
    function latestUpdateBlock(address operator, address serviceContract) external view returns (uint32);

    /// @notice A search routine for finding the correct input value of `insertAfter` to `recordStakeUpdate` / `_updateMiddlewareList`.
    function getCorrectValueForInsertAfter(address operator, uint32 updateBlock) external view returns (uint256);

    /// @notice Returns 'true' if `operator` can currently complete a withdrawal started at the `withdrawalStartBlock`, with `middlewareTimesIndex` used
    /// to specify the index of a `MiddlewareTimes` struct in the operator's list (i.e. an index in `operatorToMiddlewareTimes[operator]`). The specified
    /// struct is consulted as proof of the `operator`'s ability (or lack thereof) to complete the withdrawal.
    /// This function will return 'false' if the operator cannot currently complete a withdrawal started at the `withdrawalStartBlock`, *or* in the event
    /// that an incorrect `middlewareTimesIndex` is supplied, even if one or more correct inputs exist.
    /// @param operator Either the operator who queued the withdrawal themselves, or if the withdrawing party is a staker who delegated to an operator,
    /// this address is the operator *who the staker was delegated to* at the time of the `withdrawalStartBlock`.
    /// @param withdrawalStartBlock The block number at which the withdrawal was initiated.
    /// @param middlewareTimesIndex Indicates an index in `operatorToMiddlewareTimes[operator]` to consult as proof of the `operator`'s ability to withdraw
    /// @dev The correct `middlewareTimesIndex` input should be computable off-chain.
    function canWithdraw(address operator, uint32 withdrawalStartBlock, uint256 middlewareTimesIndex)
        external
        returns (bool);

    /// operator =>
    ///  [
    ///      (
    ///          the least recent update block of all of the middlewares it's serving/served,
    ///          latest time that the stake bonded at that update needed to serve until
    ///      )
    ///  ]
    function operatorToMiddlewareTimes(address operator, uint256 arrayIndex)
        external
        view
        returns (MiddlewareTimes memory);

    /// @notice Getter function for fetching `operatorToMiddlewareTimes[operator].length`
    function middlewareTimesLength(address operator) external view returns (uint256);

    /// @notice Getter function for fetching `operatorToMiddlewareTimes[operator][index].stalestUpdateBlock`.
    function getMiddlewareTimesIndexStalestUpdateBlock(address operator, uint32 index) external view returns (uint32);

    /// @notice Getter function for fetching `operatorToMiddlewareTimes[operator][index].latestServeUntil`.
    function getMiddlewareTimesIndexServeUntilBlock(address operator, uint32 index) external view returns (uint32);

    /// @notice Getter function for fetching `_operatorToWhitelistedContractsByUpdate[operator].size`.
    function operatorWhitelistedContractsLinkedListSize(address operator) external view returns (uint256);

    /// @notice Getter function for fetching a single node in the operator's linked list (`_operatorToWhitelistedContractsByUpdate[operator]`).
    function operatorWhitelistedContractsLinkedListEntry(address operator, address node)
        external
        view
        returns (bool, uint256, uint256);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IBeacon.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

/// @dev This is the interface that {BeaconProxy} expects of its beacon.
interface IBeacon {
    /// @dev Must return an address that can be used as a delegate call target.
    /// {BeaconProxy} will check that this address is a contract.
    function implementation() external view returns (address);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IRegistry.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

import {IRegistryCoordinator} from 'contracts/interfaces/eigenlayer/IRegistryCoordinator.sol';

/// @title Minimal interface for a `Registry`-type contract.
/// @author Layr Labs, Inc.
/// @notice Terms of Service: https://docs.eigenlayer.xyz/overview/terms-of-service
/// @notice Functions related to the registration process itself have been intentionally excluded
/// because their function signatures may vary significantly.
interface IRegistry {
    function registryCoordinator() external view returns (IRegistryCoordinator);
}


// ============================================================================
// FILE: contracts/interfaces/eigenlayer/IRegistryCoordinator.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.23;

/// @title Interface for a contract that coordinates between various registries for an AVS.
/// @author Layr Labs, Inc.
interface IRegistryCoordinator {
    /// @notice Emits when an operator is registered
    event OperatorRegistered(address indexed operator, bytes32 indexed operatorId);

    /// @notice Emits when an operator is deregistered
    event OperatorDeregistered(address indexed operator, bytes32 indexed operatorId);

    enum OperatorStatus {
        // default is NEVER_REGISTERED
        NEVER_REGISTERED,
        REGISTERED,
        DEREGISTERED
    }

    /// @notice Data structure for storing info on operators
    struct Operator {
        // the id of the operator, which is likely the keccak256 hash of the operator's public key if using BLSRegsitry
        bytes32 operatorId;
        // indicates whether the operator is actively registered for serving the middleware or not
        OperatorStatus status;
    }

    /// @notice Data structure for storing info on quorum bitmap updates where the `quorumBitmap` is the bitmap of the
    /// quorums the operator is registered for starting at (inclusive)`updateBlockNumber` and ending at (exclusive) `nextUpdateBlockNumber`
    /// @dev nextUpdateBlockNumber is initialized to 0 for the latest update
    struct QuorumBitmapUpdate {
        uint32 updateBlockNumber;
        uint32 nextUpdateBlockNumber;
        uint192 quorumBitmap;
    }

    /// @notice Returns the operator struct for the given `operator`
    function getOperator(address operator) external view returns (Operator memory);

    /// @notice Returns the operatorId for the given `operator`
    function getOperatorId(address operator) external view returns (bytes32);

    /// @notice Returns the operator address for the given `operatorId`
    function getOperatorFromId(bytes32 operatorId) external view returns (address operator);

    /// @notice Returns the status for the given `operator`
    function getOperatorStatus(address operator) external view returns (IRegistryCoordinator.OperatorStatus);

    /// @notice Returns the indices of the quorumBitmaps for the provided `operatorIds` at the given `blockNumber`
    function getQuorumBitmapIndicesByOperatorIdsAtBlockNumber(uint32 blockNumber, bytes32[] memory operatorIds)
        external
        view
        returns (uint32[] memory);

    /// @notice Returns the quorum bitmap for the given `operatorId` at the given `blockNumber` via the `index`
    /// @dev reverts if `index` is incorrect
    function getQuorumBitmapByOperatorIdAtBlockNumberByIndex(bytes32 operatorId, uint32 blockNumber, uint256 index)
        external
        view
        returns (uint192);

    /// @notice Returns the `index`th entry in the operator with `operatorId`'s bitmap history
    function getQuorumBitmapUpdateByOperatorIdByIndex(bytes32 operatorId, uint256 index)
        external
        view
        returns (QuorumBitmapUpdate memory);

    /// @notice Returns the current quorum bitmap for the given `operatorId`
    function getCurrentQuorumBitmapByOperatorId(bytes32 operatorId) external view returns (uint192);

    /// @notice Returns the length of the quorum bitmap history for the given `operatorId`
    function getQuorumBitmapUpdateByOperatorIdLength(bytes32 operatorId) external view returns (uint256);

    /// @notice Returns the registry at the desired index
    function registries(uint256) external view returns (address);

    /// @notice Returns the number of registries
    function numRegistries() external view returns (uint256);

    /// @notice Registers msg.sender as an operator with the middleware
    /// @param quorumNumbers are the bytes representing the quorum numbers that the operator is registering for
    /// @param registrationData is the data that is decoded to get the operator's registration information
    function registerOperatorWithCoordinator(bytes memory quorumNumbers, bytes calldata registrationData) external;

    /// @notice Deregisters the msg.sender as an operator from the middleware
    /// @param quorumNumbers are the bytes representing the quorum numbers that the operator is registered for
    /// @param deregistrationData is the the data that is decoded to get the operator's deregistration information
    function deregisterOperatorWithCoordinator(bytes calldata quorumNumbers, bytes calldata deregistrationData)
        external;
}
