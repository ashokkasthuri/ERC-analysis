// SPDX-License-Identifier: UNLICENSED
// Source: 0x2d7bd1c4e7720084d535b36de1b4327462d63078
// Contract Name: VeANGLEVotingDelegation
// Generated on: 2026-05-14 11:56:21


// ============================================================================
// FILE: contracts/VeANGLEVotingDelegation.sol
// ============================================================================

// SPDX-License-Identifier: ISC
pragma solidity ^0.8.20;

import { ECDSA } from "oz/utils/cryptography/ECDSA.sol";
import { EIP712 } from "oz/utils/cryptography/EIP712.sol";
import { Math } from "oz/utils/math/Math.sol";
import { SafeCast } from "oz/utils/math/SafeCast.sol";
import { IERC5805 } from "oz/interfaces/IERC5805.sol";
import { IveANGLE } from "./interfaces/IveANGLE.sol";
import { IveANGLEVotingDelegation } from "./interfaces/IveANGLEVotingDelegation.sol";

/// @title VeANGLEVotingDelegation
/// @notice Contract that keeps track of voting weights and delegations, leveraging veANGLE
/// @author Jon Walch (Frax Finance) https://github.com/jonwalch
// solhint-disable-next-line
/// @dev Fork from Frax Finance: https://github.com/FraxFinance/frax-governance/blob/e465513ac282aa7bfd6744b3136354fae51fed3c/src/VeFxsVotingDelegation.sol
/// @dev The Fxs in the variable names and comments have been replaced by ANGLE
contract VeANGLEVotingDelegation is EIP712, IERC5805 {
    using SafeCast for uint256;

    /// @notice A week
    uint256 public constant WEEK = 7 days;

    /// @notice Max veANGLE lock duration
    uint256 public constant MAX_LOCK_DURATION = 365 days * 4;

    /// @notice Vote weight multiplier taken from veANGLE
    uint256 public constant VOTE_WEIGHT_MULTIPLIER = 1;

    /// @notice Typehash needed for delegations by signature
    /// @dev keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)")
    bytes32 public constant DELEGATION_TYPEHASH = 0xe48329057bfd03d55e49b547132e39cffd9c1820ad7b9d4c5307691425d15adf;

    /// @notice veANGLE contract
    IveANGLE public immutable VE_ANGLE;

    /// @notice Nonces needed for delegations by signature
    mapping(address signer => uint256 nonce) public $nonces;

    /// @notice Mapping from delegator to delegate including additional parameters for our weight calculations.
    mapping(address delegator => IveANGLEVotingDelegation.Delegation delegate) public $delegations;

    /// @notice Mapping from delegate to their checkpoints. Checkpoints correspond to daily rounded dates of delegation.
    mapping(address delegate => IveANGLEVotingDelegation.DelegateCheckpoint[]) public $delegateCheckpoints;

    /// @notice Mapping from delegate to weekly rounded time of expiry to the aggregated values at time of expiration.
    /// Mirrors veANGLE expiration.
    mapping(address delegate => mapping(uint256 week => IveANGLEVotingDelegation.Expiration))
        public $expiredDelegations;

    /// @notice Constructor of the contract, called on deployment
    /// @param veANGLE Address of veANGLE contract
    constructor(address veANGLE, string memory name, string memory version) EIP712(name, version) {
        VE_ANGLE = IveANGLE(veANGLE);
    }

    /// @notice Retrieves a specific delegation checkpoint for a delegate at a given index
    /// @param delegateAddress Address of delegate
    /// @param index Integer index of the checkpoint
    /// @return delegateCheckpoint DelegateCheckpoint of ```delegate``` at ```index```
    function getCheckpoint(
        address delegateAddress,
        uint32 index
    ) external view returns (IveANGLEVotingDelegation.DelegateCheckpoint memory) {
        return $delegateCheckpoints[delegateAddress][index];
    }

    /// @notice Calculates weight delegated to ```account``` accounting for any weight that expired
    /// since the nearest checkpoint
    /// @dev May include own weight if account previously delegated to someone else and then back to themselves
    /// @param voter Address of voter
    /// @param timestamp A block.timestamp, typically corresponding to a proposal snapshot
    /// @return delegatedWeight Voting weight corresponding to all ```delegateAccount```'s received delegations
    function _calculateDelegatedWeight(
        address voter,
        uint256 timestamp
    ) internal view returns (uint256 delegatedWeight) {
        // Check if delegate account has any delegations
        IveANGLEVotingDelegation.DelegateCheckpoint memory checkpoint = _checkpointBinarySearch({
            _$checkpoints: $delegateCheckpoints[voter],
            timestamp: timestamp
        });

        // If checkpoint is empty, short circuit and return 0 delegated weight
        if (checkpoint.timestamp == 0) {
            return 0;
        }

        // It's possible that some delegated veANGLE has expired.
        // Add up all expirations during this time period, week by week.
        (uint256 totalExpiredBias, uint256 totalExpiredSlope) = _calculateExpirations({
            account: voter,
            start: checkpoint.timestamp,
            end: timestamp,
            checkpoint: checkpoint
        });

        uint256 expirationAdjustedBias = checkpoint.normalizedBias - totalExpiredBias;
        uint256 expirationAdjustedSlope = checkpoint.normalizedSlope - totalExpiredSlope;

        uint256 voteDecay = expirationAdjustedSlope * timestamp;
        uint256 biasAtTimestamp = (expirationAdjustedBias > voteDecay) ? expirationAdjustedBias - voteDecay : 0;

        // If all delegations are expired they have no voting weight.
        // This differs from veANGLE, which returns the locked ANGLE amount if it has not yet been withdrawn.
        delegatedWeight = VOTE_WEIGHT_MULTIPLIER * biasAtTimestamp;
    }

    /// @notice Calculates ```account```'s voting weight.
    /// @dev Is 0 if they ever delegated and the delegation is in effect.
    /// @param voter Address of voter
    /// @param timestamp A block.timestamp, typically corresponding to a proposal snapshot
    /// @return votingWeight Voting weight corresponding to ```account```'s veANGLE balance
    function _calculateVotingWeight(address voter, uint256 timestamp) internal view returns (uint256) {
        // If lock is expired they have no voting weight.
        // This differs from veANGLE, which returns the locked ANGLE amount if it has not yet been withdrawn.
        if (VE_ANGLE.locked(voter).end <= timestamp) return 0;

        uint256 firstDelegationTimestamp = $delegations[voter].firstDelegationTimestamp;
        // Never delegated OR this timestamp is before the first delegation by account
        if (firstDelegationTimestamp == 0 || timestamp < firstDelegationTimestamp) {
            try VE_ANGLE.balanceOf({ addr: voter, _t: timestamp }) returns (uint256 _balance) {
                return _balance;
            } catch {}
        }
        return 0;
    }

    /// @notice Calculates all expired delegations for an account since last checkpoint.
    /// @dev Can be used in tandem with writeNewCheckpointForExpirations() to write a new checkpoint
    /// @dev Long time periods between checkpoints can increase gas costs for delegate() and castVote()
    /// @dev See _calculateExpirations
    /// @param delegateAddress Address of delegate
    /// @return calculatedCheckpoint A new DelegateCheckpoint to write based on expirations since previous checkpoint
    function calculateExpiredDelegations(
        address delegateAddress
    ) public view returns (IveANGLEVotingDelegation.DelegateCheckpoint memory calculatedCheckpoint) {
        IveANGLEVotingDelegation.DelegateCheckpoint[] storage $userDelegationCheckpoints = $delegateCheckpoints[
            delegateAddress
        ];

        // This ensures that checkpoints take effect at the next epoch
        uint256 checkpointTimestamp = ((block.timestamp / 1 days) * 1 days) + 1 days;
        uint256 checkpointsLength = $userDelegationCheckpoints.length;

        // Nothing to expire if no one delegated to you
        if (checkpointsLength == 0) return calculatedCheckpoint;

        IveANGLEVotingDelegation.DelegateCheckpoint memory lastCheckpoint = $userDelegationCheckpoints[
            checkpointsLength - 1
        ];

        // Nothing expired because the most recent checkpoint is already written
        if (lastCheckpoint.timestamp == checkpointTimestamp) {
            return calculatedCheckpoint;
        }

        (uint256 totalExpiredBias, uint256 totalExpiredSlope) = _calculateExpirations({
            account: delegateAddress,
            start: lastCheckpoint.timestamp,
            end: checkpointTimestamp,
            checkpoint: lastCheckpoint
        });

        // All will be 0 if no expirations, only need to check one of them
        if (totalExpiredBias == 0) return calculatedCheckpoint;

        /// NOTE: Checkpoint values will always be larger than or equal to expired values
        unchecked {
            calculatedCheckpoint = IveANGLEVotingDelegation.DelegateCheckpoint({
                timestamp: uint128(checkpointTimestamp),
                normalizedBias: uint128(lastCheckpoint.normalizedBias - totalExpiredBias),
                normalizedSlope: uint128(lastCheckpoint.normalizedSlope - totalExpiredSlope)
            });
        }
    }

    /// @notice Writes a new checkpoint if any weight has expired since the previous checkpoint
    /// @dev Long time periods between checkpoints can increase gas costs for delegate() and castVote()
    /// @dev See _calculateExpirations
    /// @param delegateAddress Address of delegate
    function writeNewCheckpointForExpiredDelegations(address delegateAddress) external {
        IveANGLEVotingDelegation.DelegateCheckpoint memory newCheckpoint = calculateExpiredDelegations(delegateAddress);

        if (newCheckpoint.timestamp == 0) revert IveANGLEVotingDelegation.NoExpirations();

        $delegateCheckpoints[delegateAddress].push(newCheckpoint);
    }

    // solhint-disable-next-line
    function CLOCK_MODE() public pure override returns (string memory) {
        return "mode=timestamp";
    }

    function clock() public view override returns (uint48) {
        return uint48(block.timestamp);
    }

    /// @notice Calculates a voter's voting weight at ```timestamp```
    /// @param voter Address of voter
    /// @param timestamp A block.timestamp, typically corresponding to a proposal snapshot
    /// @return totalVotingWeight Voting weight of ```voter``` at ```timestamp```
    function _getVotingWeight(address voter, uint256 timestamp) internal view returns (uint256 totalVotingWeight) {
        totalVotingWeight =
            _calculateVotingWeight({ voter: voter, timestamp: timestamp }) +
            _calculateDelegatedWeight({ voter: voter, timestamp: timestamp });
    }

    /// @notice Calculates a voter's weight at ```timestamp```
    /// @param voter Address of voter
    /// @param timepoint A block.timestamp, typically corresponding to a proposal snapshot
    /// @return votingWeight Voting weight of ```voterAddress``` at ```timepoint```
    function getVotes(address voter, uint256 timepoint) external view returns (uint256) {
        return _getVotingWeight({ voter: voter, timestamp: timepoint });
    }

    /// @notice Calculates a voter's weight at the current block.timestamp
    /// @param voter Address of voter
    /// @return votingWeight Voting weight of ```voterAddress``` at ```block.timestamp```
    function getVotes(address voter) external view returns (uint256 votingWeight) {
        votingWeight = _getVotingWeight({ voter: voter, timestamp: block.timestamp });
    }

    /// @notice Calculates a voter's weight at ```timepoint```
    /// @param voter Address of voter
    /// @param timepoint A block.timestamp, typically corresponding to a proposal snapshot, must be in past
    /// @return pastVotingWeight Voting weight of ```account``` at ```timepoint``` in past
    function getPastVotes(address voter, uint256 timepoint) external view returns (uint256 pastVotingWeight) {
        if (timepoint >= block.timestamp) revert IveANGLEVotingDelegation.TimestampInFuture();

        pastVotingWeight = _getVotingWeight({ voter: voter, timestamp: timepoint });
    }

    /// @notice Retrieves the total supply of veANGLE at ```blockNumber```
    /// @dev Must use block.number instead of timestamp
    /// because VE_ANGLE.totalSupply(timestamp) doesn't work for historical values.
    /// @param blockNumber block.number of total supply, must be in past
    /// @return pastTotalSupply veANGLE supply at ```blockNumber```
    function getPastTotalSupply(uint256 blockNumber) external view returns (uint256 pastTotalSupply) {
        // Future blocks are not valid
        if (blockNumber >= block.number) revert IveANGLEVotingDelegation.BlockNumberInFuture();

        // Our total voting weight isn't the same as VE_ANGLE.totalSupplyAt(blockNumber) because
        // we expire all voting weight when the lock ends, which also may not be accounted for yet.
        // This is close enough.
        pastTotalSupply = VE_ANGLE.totalSupplyAt(blockNumber);
    }

    /// @notice Returns who the address of the delegate, that delegatorAddress has chosen
    /// @param delegator Address of delegator
    /// @return delegateAddress Address of the delegate
    function delegates(address delegator) external view returns (address delegateAddress) {
        delegateAddress = $delegations[delegator].delegate;
    }

    /// @notice Delegates votes from signer to ```delegatee``` at the next epoch
    /// @param delegatee Address to delegate to
    function delegate(address delegatee) external {
        _delegate({ delegator: msg.sender, delegatee: delegatee });
    }

    /// @notice Delegates votes from signer to ```delegatee```
    /// @param delegatee Address to delegate to
    /// @param nonce Nonce of signed message
    /// @param expiry Expiry time of message
    /// @param v Recovery ID
    /// @param r Output of an ECDSA signature
    /// @param s Output of an ECDSA signature
    function delegateBySig(
        address delegatee,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public virtual override {
        // Revert if signature is expired
        if (block.timestamp > expiry) revert IveANGLEVotingDelegation.SignatureExpired();

        address signer = ECDSA.recover(
            _hashTypedDataV4(keccak256(abi.encode(DELEGATION_TYPEHASH, delegatee, nonce, expiry))),
            v,
            r,
            s
        );

        // Increment nonce and check against incremented value
        if (nonce != $nonces[signer]++) revert IveANGLEVotingDelegation.InvalidSignatureNonce();
        _delegate(signer, delegatee);
    }

    /// @notice Delegates votes from signer to ```delegatee``` at the next epoch
    /// @param delegator Caller delegating their weight
    /// @param delegatee Address to delegate to
    /// @dev An account can only delegate to one account at a time. The previous delegation will be overwritten.
    /// @dev To undelegate, ```delegatee``` should be ```address(delegator)```
    function _delegate(address delegator, address delegatee) internal {
        // Revert if delegating to self with address(0), should be address(delegator)
        if (delegatee == address(0)) revert IveANGLEVotingDelegation.IncorrectSelfDelegation();

        IveANGLEVotingDelegation.Delegation memory previousDelegation = $delegations[delegator];

        // This ensures that checkpoints take effect at the next epoch
        uint256 checkpointTimestamp = ((block.timestamp / 1 days) * 1 days) + 1 days;

        IveANGLEVotingDelegation.NormalizedVeANGLELockInfo
            memory normalizedDelegatorVeANGLELockInfo = _getNormalizedveANGLELockInfo({
                delegator: delegator,
                checkpointTimestamp: checkpointTimestamp
            });

        _moveVotingPowerFromPreviousDelegate({
            previousDelegation: previousDelegation,
            checkpointTimestamp: checkpointTimestamp
        });

        _moveVotingPowerToNewDelegate({
            newDelegate: delegatee,
            delegatorVeANGLELockInfo: normalizedDelegatorVeANGLELockInfo,
            checkpointTimestamp: checkpointTimestamp
        });

        // NOTE: Unsafe casting because these values will never exceed the size of their respective types
        $delegations[delegator] = IveANGLEVotingDelegation.Delegation({
            delegate: delegatee,
            firstDelegationTimestamp: previousDelegation.firstDelegationTimestamp == 0
                ? uint48(checkpointTimestamp)
                : previousDelegation.firstDelegationTimestamp,
            expiry: uint48(normalizedDelegatorVeANGLELockInfo.expiry),
            bias: uint96(normalizedDelegatorVeANGLELockInfo.bias),
            slope: uint64(normalizedDelegatorVeANGLELockInfo.slope)
        });

        emit DelegateChanged({
            delegator: delegator,
            fromDelegate: previousDelegation.delegate,
            toDelegate: delegatee
        });
    }

    /// @notice Retrieves lock information from veANGLE.
    /// @notice We normalize and store this information to calculate voting weights
    /// @param delegator Address of the delegator
    /// @param checkpointTimestamp block.timestamp of the next checkpoint epoch
    /// @return normalizedVeANGLELockInfo Information about delegator's lock from veANGLE contract, normalized
    function _getNormalizedveANGLELockInfo(
        address delegator,
        uint256 checkpointTimestamp
    ) private view returns (IveANGLEVotingDelegation.NormalizedVeANGLELockInfo memory normalizedVeANGLELockInfo) {
        // Check expiry in case we need to revert
        uint256 expiry = VE_ANGLE.locked(delegator).end;
        if (expiry <= checkpointTimestamp) revert IveANGLEVotingDelegation.CantDelegateLockExpired();

        // Most recent epoch
        uint256 epoch = VE_ANGLE.user_point_epoch(delegator);
        // Values for delegator at the most recent epoch
        (int128 userBias, int128 userSlope, , ) = VE_ANGLE.user_point_history({ _addr: delegator, _idx: epoch });
        // Get the timestamp of the last update in veANGLE user history
        uint256 lastUpdate = VE_ANGLE.user_point_history__ts({ _addr: delegator, _idx: epoch });

        // Set return values
        normalizedVeANGLELockInfo.slope = SafeCast.toUint256(userSlope);
        normalizedVeANGLELockInfo.expiry = expiry;
        // Normalize bias to unix epoch, so all biases can be added and subtracted directly
        normalizedVeANGLELockInfo.bias = SafeCast.toUint256(userBias) + normalizedVeANGLELockInfo.slope * lastUpdate;
    }

    /// @notice Does a binary search for the closest checkpoint before ```timestamp```
    /// @param _$checkpoints Storage pointer to the account's DelegateCheckpoints
    /// @param timestamp block.timestamp to get voting power at, frequently proposal snapshot
    /// @return closestCheckpoint The closest DelegateCheckpoint before timestamp
    function _checkpointBinarySearch(
        IveANGLEVotingDelegation.DelegateCheckpoint[] storage _$checkpoints,
        uint256 timestamp
    ) private view returns (IveANGLEVotingDelegation.DelegateCheckpoint memory closestCheckpoint) {
        uint256 checkpointsLength = _$checkpoints.length;

        // What the newest checkpoint could be for timestamp (rounded to whole days).
        // It will be earlier when checkpoints are sparse.
        uint256 roundedDownTimestamp = (timestamp / 1 days) * 1 days;
        // Newest checkpoint's timestamp (already rounded to whole days)
        uint256 lastCheckpointTimestamp = checkpointsLength > 0 ? _$checkpoints[checkpointsLength - 1].timestamp : 0;
        // The furthest back a checkpoint will ever be is the number of days delta between timestamp and the last
        // checkpoints timestamp. This happens when there was a checkpoint written every single day over that period.
        // If roundedDownTimestamp > lastCheckpointTimestamp that means that we can just use the last index as
        // the checkpoint.
        uint256 delta = lastCheckpointTimestamp > roundedDownTimestamp
            ? (lastCheckpointTimestamp - roundedDownTimestamp) / 1 days
            : 0;
        // low index is equal to the last checkpoints index minus the index delta
        uint256 low = (checkpointsLength > 0 && checkpointsLength - 1 > delta) ? checkpointsLength - 1 - delta : 0;

        uint256 high = checkpointsLength;
        while (low < high) {
            uint256 mid = Math.average(low, high);
            if (_$checkpoints[mid].timestamp > timestamp) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        closestCheckpoint = high == 0 ? closestCheckpoint : _$checkpoints[high - 1];
    }

    /// @notice Removes voting power from the previous delegate, handling expirations and writing
    /// a new DelegateCheckpoint
    /// @param previousDelegation The delegator's previous delegation
    /// @param checkpointTimestamp block.timestamp of the next DelegateCheckpoint's epoch
    function _moveVotingPowerFromPreviousDelegate(
        IveANGLEVotingDelegation.Delegation memory previousDelegation,
        uint256 checkpointTimestamp
    ) private {
        // Remove voting power from previous delegate, if they exist
        if (previousDelegation.delegate != address(0)) {
            // Get the last Checkpoint for previous delegate
            IveANGLEVotingDelegation.DelegateCheckpoint[] storage $previousDelegationCheckpoints = $delegateCheckpoints[
                previousDelegation.delegate
            ];
            uint256 accountCheckpointsLength = $previousDelegationCheckpoints.length;
            // NOTE: we know that _accountsCheckpointLength > 0
            // because we have already checked that the previous delegation exists
            IveANGLEVotingDelegation.DelegateCheckpoint memory lastCheckpoint = $previousDelegationCheckpoints[
                accountCheckpointsLength - 1
            ];
            uint256 oldWeightOldDelegate = _getVotingWeight(previousDelegation.delegate, checkpointTimestamp);

            // Handle Expirations

            // Only subtract when the delegator's expiration is in the future.
            // This way, the former delegates voting power  will still properly expire
            // for proposals that happen between previousDelegation.expiry and a new delegation.
            // See testExpiredLockRedelegateNoVotingWeight().
            if (previousDelegation.expiry > checkpointTimestamp) {
                // Calculations
                IveANGLEVotingDelegation.Expiration memory expiration = $expiredDelegations[
                    previousDelegation.delegate
                ][previousDelegation.expiry];
                // All expiration fields will never exceed their size so subtraction doesnt need to be checked
                // and they can be unsafely cast
                unchecked {
                    expiration.bias -= uint96(previousDelegation.bias);
                    expiration.slope -= uint64(previousDelegation.slope);
                }

                // Effects
                $expiredDelegations[previousDelegation.delegate][previousDelegation.expiry] = expiration;
            }

            {
                // Calculate new checkpoint
                IveANGLEVotingDelegation.DelegateCheckpoint memory newCheckpoint = _calculateCheckpoint({
                    previousCheckpoint: lastCheckpoint,
                    account: previousDelegation.delegate,
                    isDeltaPositive: false,
                    deltaBias: previousDelegation.bias,
                    deltaSlope: previousDelegation.slope,
                    checkpointTimestamp: checkpointTimestamp,
                    previousDelegationExpiry: previousDelegation.expiry
                });

                // Write new checkpoint
                _writeCheckpoint({
                    $userDelegationCheckpoints: $previousDelegationCheckpoints,
                    accountCheckpointsLength: accountCheckpointsLength,
                    newCheckpoint: newCheckpoint,
                    lastCheckpoint: lastCheckpoint
                });
            }

            // NOTE: oldWeightOldDelegate has had voting power decay since the previous event, meaning that
            // this event shouldn't be relied on. We did our best to conform to the standard.
            emit DelegateVotesChanged({
                delegate: previousDelegation.delegate,
                previousVotes: oldWeightOldDelegate,
                newVotes: _getVotingWeight({ voter: previousDelegation.delegate, timestamp: checkpointTimestamp })
            });
        }
    }

    /// @notice Adds voting power to the new delegate, handling expirations and writing a new DelegateCheckpoint
    /// @param newDelegate The new delegate that is being delegated to
    /// @param delegatorVeANGLELockInfo Information about the delegator's veANGLE lock
    /// @param checkpointTimestamp block.timestamp of the next DelegateCheckpoint's epoch
    function _moveVotingPowerToNewDelegate(
        address newDelegate,
        IveANGLEVotingDelegation.NormalizedVeANGLELockInfo memory delegatorVeANGLELockInfo,
        uint256 checkpointTimestamp
    ) private {
        // Get the last checkpoint for the new delegate
        IveANGLEVotingDelegation.DelegateCheckpoint[] storage $newDelegateCheckpoints = $delegateCheckpoints[
            newDelegate
        ];
        uint256 accountCheckpointsLength = $newDelegateCheckpoints.length;
        IveANGLEVotingDelegation.DelegateCheckpoint memory lastCheckpoint = accountCheckpointsLength == 0
            ? IveANGLEVotingDelegation.DelegateCheckpoint(0, 0, 0)
            : $newDelegateCheckpoints[accountCheckpointsLength - 1];
        uint256 oldWeightNewDelegate = _getVotingWeight(newDelegate, checkpointTimestamp);

        // Handle expiration
        // Calculations
        IveANGLEVotingDelegation.Expiration memory expiration = $expiredDelegations[newDelegate][
            delegatorVeANGLELockInfo.expiry
        ];

        // NOTE: All expiration fields will never exceed their size so addition doesnt need to be checked
        // and can be unsafely cast
        unchecked {
            expiration.bias += uint96(delegatorVeANGLELockInfo.bias);
            expiration.slope += uint64(delegatorVeANGLELockInfo.slope);
        }
        // Effects
        $expiredDelegations[newDelegate][delegatorVeANGLELockInfo.expiry] = expiration;

        // Calculate new checkpoint
        IveANGLEVotingDelegation.DelegateCheckpoint memory newCheckpoint = _calculateCheckpoint({
            previousCheckpoint: lastCheckpoint,
            isDeltaPositive: true,
            account: newDelegate,
            deltaBias: delegatorVeANGLELockInfo.bias,
            deltaSlope: delegatorVeANGLELockInfo.slope,
            checkpointTimestamp: checkpointTimestamp,
            previousDelegationExpiry: 0 // not used
        });

        // Write new checkpoint
        _writeCheckpoint({
            $userDelegationCheckpoints: $newDelegateCheckpoints,
            accountCheckpointsLength: accountCheckpointsLength,
            newCheckpoint: newCheckpoint,
            lastCheckpoint: lastCheckpoint
        });

        // NOTE: oldWeightNewDelegate has had voting power decay since the previous event, meaning that
        // this event shouldn't be relied on. We did our best to conform to the standard.
        emit DelegateVotesChanged({
            delegate: newDelegate,
            previousVotes: oldWeightNewDelegate,
            newVotes: _getVotingWeight({ voter: newDelegate, timestamp: checkpointTimestamp })
        });
    }

    /// @notice Calculates the values to be written for the new DelegateCheckpoint
    /// @param previousCheckpoint The previous checkpoint for account
    /// @param account The account to calculate the expirations for
    /// @param isDeltaPositive Whether adding or subtracting from the previous checkpoint
    /// @param deltaBias Amount of bias to add or subtract
    /// @param deltaSlope Amount of slope to add or subtract
    /// @param checkpointTimestamp block.timestamp of the next DelegateCheckpoint's epoch
    /// @param previousDelegationExpiry When the previous delegation expires
    /// @return newCheckpoint The new DelegateCheckpoint to be stored
    function _calculateCheckpoint(
        IveANGLEVotingDelegation.DelegateCheckpoint memory previousCheckpoint,
        address account,
        bool isDeltaPositive,
        uint256 deltaBias,
        uint256 deltaSlope,
        uint256 checkpointTimestamp,
        uint256 previousDelegationExpiry
    ) private view returns (IveANGLEVotingDelegation.DelegateCheckpoint memory newCheckpoint) {
        // If this is the first checkpoint, create a new one and early return
        if (previousCheckpoint.timestamp == 0) {
            return
                IveANGLEVotingDelegation.DelegateCheckpoint({
                    // can be unsafely cast because values will never exceed uint128 max
                    timestamp: uint128(checkpointTimestamp),
                    normalizedBias: uint128(deltaBias),
                    normalizedSlope: uint128(deltaSlope)
                });
        }

        newCheckpoint.timestamp = previousCheckpoint.timestamp;
        newCheckpoint.normalizedBias = previousCheckpoint.normalizedBias;
        newCheckpoint.normalizedSlope = previousCheckpoint.normalizedSlope;

        // All checkpoint fields will never exceed their size so addition and subtraction doesnt need to be checked
        unchecked {
            // Add or subtract the delta to the previous checkpoint
            if (isDeltaPositive) {
                newCheckpoint.normalizedBias += uint128(deltaBias);
                newCheckpoint.normalizedSlope += uint128(deltaSlope);
            } else {
                // only subtract the weight from this account if it has not already expired in a previous checkpoint
                if (previousDelegationExpiry > previousCheckpoint.timestamp) {
                    newCheckpoint.normalizedBias -= uint128(deltaBias);
                    newCheckpoint.normalizedSlope -= uint128(deltaSlope);
                }
            }

            // If there have been expirations, incorporate the adjustments by subtracting them from the checkpoint
            if (newCheckpoint.timestamp != checkpointTimestamp) {
                (uint256 totalExpiredBias, uint256 totalExpiredSlope) = _calculateExpirations({
                    account: account,
                    start: newCheckpoint.timestamp,
                    end: checkpointTimestamp,
                    checkpoint: previousCheckpoint
                });

                newCheckpoint.timestamp = uint128(checkpointTimestamp);
                newCheckpoint.normalizedBias -= uint128(totalExpiredBias);
                newCheckpoint.normalizedSlope -= uint128(totalExpiredSlope);
            }
        }
    }

    /// @notice Pushes a new checkpoint to the array or updates the most recent one if it already
    /// exists for the current epoch
    /// @param $userDelegationCheckpoints Pointer to the user's delegation checkpoints
    /// @param accountCheckpointsLength The length of the user's delegation checkpoints
    /// @param newCheckpoint The new checkpoint returned from _calculateCheckpoint()
    /// @param lastCheckpoint The most recent delegate checkpoint
    function _writeCheckpoint(
        IveANGLEVotingDelegation.DelegateCheckpoint[] storage $userDelegationCheckpoints,
        uint256 accountCheckpointsLength,
        IveANGLEVotingDelegation.DelegateCheckpoint memory newCheckpoint,
        IveANGLEVotingDelegation.DelegateCheckpoint memory lastCheckpoint
    ) internal {
        // If the newCheckpoint has the same timestamp as the last checkpoint, overwrite it
        if (accountCheckpointsLength > 0 && lastCheckpoint.timestamp == newCheckpoint.timestamp) {
            $userDelegationCheckpoints[accountCheckpointsLength - 1] = newCheckpoint;
        } else {
            // Otherwise, push a new checkpoint
            $userDelegationCheckpoints.push(newCheckpoint);
        }
    }

    /// @notice Generates a summation of all bias, slope, and angle for all delegations that expire during the
    /// specified time window for ```account```
    /// @param account Delegate account to generate summations for
    /// @param start Timestamp to start the summations from. The start is not included
    /// @param end Timestamp to end the summations. The end is included
    /// @param checkpoint Checkpoint to start expirations at
    /// @return totalExpiredBias Total bias that expired for delegate ```account``` during timeframe
    /// @return totalExpiredSlope Total slope that expired for delegate ```account``` during timeframe
    function _calculateExpirations(
        address account,
        uint256 start,
        uint256 end,
        IveANGLEVotingDelegation.DelegateCheckpoint memory checkpoint
    ) private view returns (uint256 totalExpiredBias, uint256 totalExpiredSlope) {
        unchecked {
            // Maximum lock time for veANGLE is 4 years, it will all be expired
            if (end > start + MAX_LOCK_DURATION) {
                totalExpiredBias = checkpoint.normalizedBias;
                totalExpiredSlope = checkpoint.normalizedSlope;
            } else {
                // Total values will always be less than or equal to a checkpoint's values
                uint256 currentWeek = WEEK + (start / WEEK) * WEEK;
                mapping(uint256 => IveANGLEVotingDelegation.Expiration)
                    storage $delegateExpirations = $expiredDelegations[account];
                // Sum values from currentWeek until end
                while (currentWeek <= end) {
                    IveANGLEVotingDelegation.Expiration memory expiration = $delegateExpirations[currentWeek];
                    totalExpiredBias += expiration.bias;
                    totalExpiredSlope += expiration.slope;
                    currentWeek += WEEK;
                }
            }
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.20;

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
        InvalidSignatureS
    }

    /**
     * @dev The signature derives the `address(0)`.
     */
    error ECDSAInvalidSignature();

    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    /**
     * @dev The signature has an S value that is in the upper half order.
     */
    error ECDSAInvalidSignatureS(bytes32 s);

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not
     * return address(0) without also returning an error description. Errors are documented using an enum (error type)
     * and a bytes32 providing additional information about the error.
     *
     * If no error is returned, then the address can be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError, bytes32) {
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
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[ERC-2098 short signatures]
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError, bytes32) {
        unchecked {
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            return tryRecover(hash, v, r, s);
        }
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError, bytes32) {
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
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.
     */
    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/EIP712.sol)

pragma solidity ^0.8.20;

import {MessageHashUtils} from "./MessageHashUtils.sol";
import {ShortStrings, ShortString} from "../ShortStrings.sol";
import {IERC5267} from "../../interfaces/IERC5267.sol";

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP-712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding scheme specified in the EIP requires a domain separator and a hash of the typed structured data, whose
 * encoding is very generic and therefore its implementation in Solidity is not feasible, thus this contract
 * does not implement the encoding itself. Protocols need to implement the type-specific encoding they need in order to
 * produce the hash of their typed data using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP-712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
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
 * separator of the implementation contract. This will cause the {_domainSeparatorV4} function to always rebuild the
 * separator from the immutable values, which is cheaper than accessing a cached version in cold storage.
 *
 * @custom:oz-upgrades-unsafe-allow state-variable-immutable
 */
abstract contract EIP712 is IERC5267 {
    using ShortStrings for *;

    bytes32 private constant TYPE_HASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _cachedDomainSeparator;
    uint256 private immutable _cachedChainId;
    address private immutable _cachedThis;

    bytes32 private immutable _hashedName;
    bytes32 private immutable _hashedVersion;

    ShortString private immutable _name;
    ShortString private immutable _version;
    string private _nameFallback;
    string private _versionFallback;

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP-712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) {
        _name = name.toShortStringWithFallback(_nameFallback);
        _version = version.toShortStringWithFallback(_versionFallback);
        _hashedName = keccak256(bytes(name));
        _hashedVersion = keccak256(bytes(version));

        _cachedChainId = block.chainid;
        _cachedDomainSeparator = _buildDomainSeparator();
        _cachedThis = address(this);
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (address(this) == _cachedThis && block.chainid == _cachedChainId) {
            return _cachedDomainSeparator;
        } else {
            return _buildDomainSeparator();
        }
    }

    function _buildDomainSeparator() private view returns (bytes32) {
        return keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
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
        return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
    }

    /**
     * @dev See {IERC-5267}.
     */
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
     * NOTE: By default this function reads _name which is an immutable value.
     * It only reads from storage if necessary (in case the value is too large to fit in a ShortString).
     */
    // solhint-disable-next-line func-name-mixedcase
    function _EIP712Name() internal view returns (string memory) {
        return _name.toStringWithFallback(_nameFallback);
    }

    /**
     * @dev The version parameter for the EIP712 domain.
     *
     * NOTE: By default this function reads _version which is an immutable value.
     * It only reads from storage if necessary (in case the value is too large to fit in a ShortString).
     */
    // solhint-disable-next-line func-name-mixedcase
    function _EIP712Version() internal view returns (string memory) {
        return _version.toStringWithFallback(_versionFallback);
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/math/Math.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Muldiv operation overflow.
     */
    error MathOverflowedMulDiv();

    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
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
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            return a / b;
        }

        // The following calculation ensures accurate ceiling division without overflow.
        // Since a is non-zero, (a - 1) / b will not overflow.
        // The largest possible result occurs when (a - 1) / b is type(uint256).max,
        // but the largest value we can obtain is type(uint256).max - 1, which happens
        // when a = type(uint256).max and b = 1.
        unchecked {
            return a == 0 ? 0 : (a - 1) / b + 1;
        }
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0 = x * y; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
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
            if (denominator <= prod1) {
                revert MathOverflowedMulDiv();
            }

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

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
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

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
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
        if (unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
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
            return result + (unsignedRoundsUp(rounding) && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 1 << (result << 3) < value ? 1 : 0);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
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
// FILE: lib/openzeppelin-contracts/contracts/interfaces/IERC5805.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC5805.sol)

pragma solidity ^0.8.20;

import {IVotes} from "../governance/utils/IVotes.sol";
import {IERC6372} from "./IERC6372.sol";

interface IERC5805 is IERC6372, IVotes {}


// ============================================================================
// FILE: contracts/interfaces/IveANGLE.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.19;

/// @title IveANGLE
/// @notice Interface for the veANGLE contract
//solhint-disable
interface IveANGLE {
    struct LockedBalance {
        int128 amount;
        uint256 end;
    }

    function commit_transfer_ownership(address addr) external;

    function apply_transfer_ownership() external;

    function commit_smart_wallet_checker(address addr) external;

    function apply_smart_wallet_checker() external;

    function toggleEmergencyUnlock() external;

    function recoverERC20(address token_addr, uint256 amount) external;

    function get_last_user_slope(address addr) external view returns (int128);

    function user_point_history__ts(address _addr, uint256 _idx) external view returns (uint256);

    function locked__end(address _addr) external view returns (uint256);

    function checkpoint() external;

    function deposit_for(address _addr, uint256 _value) external;

    function create_lock(uint256 _value, uint256 _unlock_time) external;

    function increase_amount(uint256 _value) external;

    function increase_unlock_time(uint256 _unlock_time) external;

    function withdraw() external;

    function balanceOf(address addr) external view returns (uint256);

    function balanceOf(address addr, uint256 _t) external view returns (uint256);

    function balanceOfAt(address addr, uint256 _block) external view returns (uint256);

    function totalSupply() external view returns (uint256);

    function totalSupply(uint256 t) external view returns (uint256);

    function totalSupplyAt(uint256 _block) external view returns (uint256);

    function totalFXSSupply() external view returns (uint256);

    function totalFXSSupplyAt(uint256 _block) external view returns (uint256);

    function changeController(address _newController) external;

    function token() external view returns (address);

    function supply() external view returns (uint256);

    function locked(address addr) external view returns (LockedBalance memory);

    function epoch() external view returns (uint256);

    function point_history(uint256 arg0) external view returns (int128 bias, int128 slope, uint256 ts, uint256 blk);

    function user_point_history(
        address _addr,
        uint256 _idx
    ) external view returns (int128 bias, int128 slope, uint256 ts, uint256 blk);

    function user_point_epoch(address arg0) external view returns (uint256);

    function slope_changes(uint256 arg0) external view returns (int128);

    function controller() external view returns (address);

    function transfersEnabled() external view returns (bool);

    function emergencyUnlockActive() external view returns (bool);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function version() external view returns (string memory);

    function decimals() external view returns (uint256);

    function future_smart_wallet_checker() external view returns (address);

    function smart_wallet_checker() external view returns (address);

    function admin() external view returns (address);

    function future_admin() external view returns (address);
}


// ============================================================================
// FILE: contracts/interfaces/IveANGLEVotingDelegation.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

//solhint-disable
/// @title IveANGLEVotingDelegation
/// @notice Interface for the contract that keeps track of voting weights and delegations, leveraging veANGLE
/// @author Frax Finance https://github.com/FraxFinance
//solhint-disable-next-line
/// @notice Fork from Frax Finance: https://github.com/FraxFinance/frax-governance/blob/e465513ac282aa7bfd6744b3136354fae51fed3c/src/interfaces/IVeFxsVotingDelegation.sol
interface IveANGLEVotingDelegation {
    /// Represents the values of a single delegation at the time `delegate()` is called,
    /// to be subtracted when removing delegation
    struct Delegation {
        address delegate;
        uint48 firstDelegationTimestamp;
        uint48 expiry;
        // __________
        uint96 bias;
        uint64 slope;
    }

    /// A representation of a delegate and all its delegators at a particular timestamp
    struct DelegateCheckpoint {
        uint128 normalizedBias;
        // _________
        uint128 normalizedSlope;
        uint128 timestamp; // Rounded up to the nearest day
    }

    /// Represents the total bias, slope, and ANGLE amount of all accounts that expire for a specific delegate
    /// in a particular week
    struct Expiration {
        uint96 bias;
        uint64 slope;
    }

    // Only used in memory
    struct NormalizedVeANGLELockInfo {
        uint256 bias;
        uint256 slope;
        uint256 expiry;
    }

    function $delegateCheckpoints(
        address,
        uint256
    ) external view returns (uint128 normalizedBias, uint128 normalizedSlope, uint128 timestamp);

    function $delegations(
        address
    )
        external
        view
        returns (address delegate, uint48 firstDelegationTimestamp, uint48 expiry, uint96 bias, uint64 slope);

    function $expiredDelegations(address, uint256) external view returns (uint96 bias, uint96 angle, uint64 slope);

    function $nonces(address) external view returns (uint256);

    function CLOCK_MODE() external pure returns (string memory);

    function DELEGATION_TYPEHASH() external view returns (bytes32);

    function MAX_LOCK_DURATION() external view returns (uint256);

    function VE_ANGLE() external view returns (address);

    function VOTE_WEIGHT_MULTIPLIER() external view returns (uint256);

    function WEEK() external view returns (uint256);

    function calculateExpiredDelegations(
        address delegateAddress
    ) external view returns (DelegateCheckpoint memory calculatedCheckpoint);

    function clock() external view returns (uint48);

    function delegate(address delegatee) external;

    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external;

    function delegates(address delegator) external view returns (address delegateAddress);

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

    function getCheckpoint(address delegateAddress, uint32 index) external view returns (DelegateCheckpoint memory);

    function getPastTotalSupply(uint256 blockNumber) external view returns (uint256 pastTotalSupply);

    function getPastVotes(address voter, uint256 timepoint) external view returns (uint256 pastVotingWeight);

    function getVotes(address voter) external view returns (uint256 votingWeight);

    function getVotes(address voter, uint256 timepoint) external view returns (uint256);

    function writeNewCheckpointForExpiredDelegations(address delegateAddress) external;

    error BlockNumberInFuture();
    error CantDelegateLockExpired();
    error IncorrectSelfDelegation();
    error InvalidSignatureNonce();
    error NoExpirations();
    error SignatureExpired();
    error TimestampInFuture();
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/MessageHashUtils.sol)

pragma solidity ^0.8.20;

import {Strings} from "../Strings.sol";

/**
 * @dev Signature message hash utilities for producing digests to be consumed by {ECDSA} recovery or signing.
 *
 * The library provides methods for generating a hash of a message that conforms to the
 * https://eips.ethereum.org/EIPS/eip-191[ERC-191] and https://eips.ethereum.org/EIPS/eip-712[EIP 712]
 * specifications.
 */
library MessageHashUtils {
    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing a bytes32 `messageHash` with
     * `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
     * keccak256, although any bytes32 value can be safely used because the final digest will
     * be re-hashed.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }

    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing an arbitrary `message` with
     * `"\x19Ethereum Signed Message:\n" + len(message)` and hashing the result. It corresponds with the
     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes memory message) internal pure returns (bytes32) {
        return
            keccak256(bytes.concat("\x19Ethereum Signed Message:\n", bytes(Strings.toString(message.length)), message));
    }

    /**
     * @dev Returns the keccak256 digest of an ERC-191 signed data with version
     * `0x00` (data with intended validator).
     *
     * The digest is calculated by prefixing an arbitrary `data` with `"\x19\x00"` and the intended
     * `validator` address. Then hashing the result.
     *
     * See {ECDSA-recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"19_00", validator, data));
    }

    /**
     * @dev Returns the keccak256 digest of an EIP-712 typed data (ERC-191 version `0x01`).
     *
     * The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them with
     * `\x19\x01` and hashing the result. It corresponds to the hash signed by the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of EIP-712.
     *
     * See {ECDSA-recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/ShortStrings.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/ShortStrings.sol)

pragma solidity ^0.8.20;

import {StorageSlot} from "./StorageSlot.sol";

// | string  | 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA   |
// | length  | 0x                                                              BB |
type ShortString is bytes32;

/**
 * @dev This library provides functions to convert short memory strings
 * into a `ShortString` type that can be used as an immutable variable.
 *
 * Strings of arbitrary length can be optimized using this library if
 * they are short enough (up to 31 bytes) by packing them with their
 * length (1 byte) in a single EVM word (32 bytes). Additionally, a
 * fallback mechanism can be used for every other case.
 *
 * Usage example:
 *
 * ```solidity
 * contract Named {
 *     using ShortStrings for *;
 *
 *     ShortString private immutable _name;
 *     string private _nameFallback;
 *
 *     constructor(string memory contractName) {
 *         _name = contractName.toShortStringWithFallback(_nameFallback);
 *     }
 *
 *     function name() external view returns (string memory) {
 *         return _name.toStringWithFallback(_nameFallback);
 *     }
 * }
 * ```
 */
library ShortStrings {
    // Used as an identifier for strings longer than 31 bytes.
    bytes32 private constant FALLBACK_SENTINEL = 0x00000000000000000000000000000000000000000000000000000000000000FF;

    error StringTooLong(string str);
    error InvalidShortString();

    /**
     * @dev Encode a string of at most 31 chars into a `ShortString`.
     *
     * This will trigger a `StringTooLong` error is the input string is too long.
     */
    function toShortString(string memory str) internal pure returns (ShortString) {
        bytes memory bstr = bytes(str);
        if (bstr.length > 31) {
            revert StringTooLong(str);
        }
        return ShortString.wrap(bytes32(uint256(bytes32(bstr)) | bstr.length));
    }

    /**
     * @dev Decode a `ShortString` back to a "normal" string.
     */
    function toString(ShortString sstr) internal pure returns (string memory) {
        uint256 len = byteLength(sstr);
        // using `new string(len)` would work locally but is not memory safe.
        string memory str = new string(32);
        /// @solidity memory-safe-assembly
        assembly {
            mstore(str, len)
            mstore(add(str, 0x20), sstr)
        }
        return str;
    }

    /**
     * @dev Return the length of a `ShortString`.
     */
    function byteLength(ShortString sstr) internal pure returns (uint256) {
        uint256 result = uint256(ShortString.unwrap(sstr)) & 0xFF;
        if (result > 31) {
            revert InvalidShortString();
        }
        return result;
    }

    /**
     * @dev Encode a string into a `ShortString`, or write it to storage if it is too long.
     */
    function toShortStringWithFallback(string memory value, string storage store) internal returns (ShortString) {
        if (bytes(value).length < 32) {
            return toShortString(value);
        } else {
            StorageSlot.getStringSlot(store).value = value;
            return ShortString.wrap(FALLBACK_SENTINEL);
        }
    }

    /**
     * @dev Decode a string that was encoded to `ShortString` or written to storage using {setWithFallback}.
     */
    function toStringWithFallback(ShortString value, string storage store) internal pure returns (string memory) {
        if (ShortString.unwrap(value) != FALLBACK_SENTINEL) {
            return toString(value);
        } else {
            return store;
        }
    }

    /**
     * @dev Return the length of a string that was encoded to `ShortString` or written to storage using
     * {setWithFallback}.
     *
     * WARNING: This will return the "byte length" of the string. This may not reflect the actual length in terms of
     * actual characters as the UTF-8 encoding of a single character can span over multiple bytes.
     */
    function byteLengthWithFallback(ShortString value, string storage store) internal view returns (uint256) {
        if (ShortString.unwrap(value) != FALLBACK_SENTINEL) {
            return byteLength(value);
        } else {
            return bytes(store).length;
        }
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/interfaces/IERC5267.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC5267.sol)

pragma solidity ^0.8.20;

interface IERC5267 {
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
// FILE: lib/openzeppelin-contracts/contracts/governance/utils/IVotes.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (governance/utils/IVotes.sol)
pragma solidity ^0.8.20;

/**
 * @dev Common interface for {ERC20Votes}, {ERC721Votes}, and other {Votes}-enabled contracts.
 */
interface IVotes {
    /**
     * @dev The signature used has expired.
     */
    error VotesExpiredSignature(uint256 expiry);

    /**
     * @dev Emitted when an account changes their delegate.
     */
    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);

    /**
     * @dev Emitted when a token transfer or delegate change results in changes to a delegate's number of voting units.
     */
    event DelegateVotesChanged(address indexed delegate, uint256 previousVotes, uint256 newVotes);

    /**
     * @dev Returns the current amount of votes that `account` has.
     */
    function getVotes(address account) external view returns (uint256);

    /**
     * @dev Returns the amount of votes that `account` had at a specific moment in the past. If the `clock()` is
     * configured to use block numbers, this will return the value at the end of the corresponding block.
     */
    function getPastVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @dev Returns the total supply of votes available at a specific moment in the past. If the `clock()` is
     * configured to use block numbers, this will return the value at the end of the corresponding block.
     *
     * NOTE: This value is the sum of all available votes, which is not necessarily the sum of all delegated votes.
     * Votes that have not been delegated are still part of total supply, even though they would not participate in a
     * vote.
     */
    function getPastTotalSupply(uint256 timepoint) external view returns (uint256);

    /**
     * @dev Returns the delegate that `account` has chosen.
     */
    function delegates(address account) external view returns (address);

    /**
     * @dev Delegates votes from the sender to `delegatee`.
     */
    function delegate(address delegatee) external;

    /**
     * @dev Delegates votes from signer to `delegatee`.
     */
    function delegateBySig(address delegatee, uint256 nonce, uint256 expiry, uint8 v, bytes32 r, bytes32 s) external;
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/interfaces/IERC6372.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC6372.sol)

pragma solidity ^0.8.20;

interface IERC6372 {
    /**
     * @dev Clock used for flagging checkpoints. Can be overridden to implement timestamp based checkpoints (and voting).
     */
    function clock() external view returns (uint48);

    /**
     * @dev Description of the clock
     */
    // solhint-disable-next-line func-name-mixedcase
    function CLOCK_MODE() external view returns (string memory);
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/Strings.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/Strings.sol)

pragma solidity ^0.8.20;

import {Math} from "./math/Math.sol";
import {SignedMath} from "./math/SignedMath.sol";

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;

    /**
     * @dev The `value` string doesn't fit in the specified `length`.
     */
    error StringsInsufficientHexLength(uint256 value, uint256 length);

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
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
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
    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
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
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal
     * representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }
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
 * Example usage to set ERC-1967 implementation slot:
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
// FILE: lib/openzeppelin-contracts/contracts/utils/math/SignedMath.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.20;

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
