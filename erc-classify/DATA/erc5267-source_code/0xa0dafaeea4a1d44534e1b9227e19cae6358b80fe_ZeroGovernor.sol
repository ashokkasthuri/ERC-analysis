// SPDX-License-Identifier: UNLICENSED
// Source: 0xa0dafaeea4a1d44534e1b9227e19cae6358b80fe
// Contract Name: ZeroGovernor
// Generated on: 2026-05-14 12:00:33


// ============================================================================
// FILE: lib/ttg/src/ZeroGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { ThresholdGovernor } from "./abstract/ThresholdGovernor.sol";

import { IEmergencyGovernor } from "./interfaces/IEmergencyGovernor.sol";
import { IEmergencyGovernorDeployer } from "./interfaces/IEmergencyGovernorDeployer.sol";
import { IPowerTokenDeployer } from "./interfaces/IPowerTokenDeployer.sol";
import { IStandardGovernor } from "./interfaces/IStandardGovernor.sol";
import { IStandardGovernorDeployer } from "./interfaces/IStandardGovernorDeployer.sol";
import { IZeroGovernor } from "./interfaces/IZeroGovernor.sol";

/**
 * @title  An instance of a ThresholdGovernor with a unique and limited set of possible proposals.
 * @author M^0 Labs
 */
contract ZeroGovernor is IZeroGovernor, ThresholdGovernor {
    /* ============ Variables ============ */

    /// @dev The maximum number of Zero tokens that can be rewarded per active epoch.
    uint256 internal constant _MAX_TOTAL_ZERO_REWARD_PER_ACTIVE_EPOCH = 5_000_000e6;

    /// @inheritdoc IZeroGovernor
    address public immutable emergencyGovernorDeployer;

    /// @inheritdoc IZeroGovernor
    address public immutable powerTokenDeployer;

    /// @inheritdoc IZeroGovernor
    address public immutable standardGovernorDeployer;

    /// @dev The set of allowed cash tokens.
    mapping(address token => bool allowed) internal _allowedCashTokens;

    /* ============ Constructor ============ */

    /**
     * @notice Construct a new ZeroGovernor contract.
     * @param  voteToken_                       The address of the token used to vote.
     * @param  emergencyGovernorDeployer_       The address of the Emergency Governor Deployer contract.
     * @param  powerTokenDeployer_              The address of the Power Token Deployer contract.
     * @param  standardGovernorDeployer_        The address of the Standard Governor Deployer contract.
     * @param  bootstrapToken_                  The address of the token that bootstraps the reset.
     * @param  standardProposalFee_             The proposal fee for the Standard Governor.
     * @param  emergencyProposalThresholdRatio_ The threshold ratio for the Emergency Governor.
     * @param  zeroProposalThresholdRatio_      The threshold ratio for the Zero Governor.
     * @param  allowedCashTokens_               The set of allowed cash tokens.
     */
    constructor(
        address voteToken_,
        address emergencyGovernorDeployer_,
        address powerTokenDeployer_,
        address standardGovernorDeployer_,
        address bootstrapToken_,
        uint256 standardProposalFee_,
        uint16 emergencyProposalThresholdRatio_,
        uint16 zeroProposalThresholdRatio_,
        address[] memory allowedCashTokens_
    ) ThresholdGovernor("ZeroGovernor", voteToken_, zeroProposalThresholdRatio_) {
        if ((emergencyGovernorDeployer = emergencyGovernorDeployer_) == address(0)) {
            revert InvalidEmergencyGovernorDeployerAddress();
        }

        if ((powerTokenDeployer = powerTokenDeployer_) == address(0)) {
            revert InvalidPowerTokenDeployerAddress();
        }

        if ((standardGovernorDeployer = standardGovernorDeployer_) == address(0)) {
            revert InvalidStandardGovernorDeployerAddress();
        }

        if (allowedCashTokens_.length == 0) revert NoAllowedCashTokens();

        for (uint256 index_; index_ < allowedCashTokens_.length; ++index_) {
            address allowedCashToken_ = allowedCashTokens_[index_];

            if (allowedCashToken_ == address(0)) revert InvalidCashTokenAddress();

            _allowedCashTokens[allowedCashToken_] = true;
        }

        emit AllowedCashTokensSet(allowedCashTokens_);

        // Deploy the ephemeral `standardGovernor`, `emergencyGovernor`, and `powerToken` contracts, where:
        // - the token to bootstrap the `powerToken` balances and voting powers is defined in the constructor
        // - the starting cash token is the first token in the `_allowedCashTokens` array
        // - the starting `emergencyGovernor` threshold ratio is defined in the constructor
        // - the starting `standardGovernor` proposal fee is defined in the constructor
        _deployEphemeralContracts(
            emergencyGovernorDeployer_,
            powerTokenDeployer_,
            standardGovernorDeployer_,
            bootstrapToken_,
            allowedCashTokens_[0],
            emergencyProposalThresholdRatio_,
            standardProposalFee_
        );
    }

    /* ============ Proposal Functions ============ */

    /// @inheritdoc IZeroGovernor
    function resetToPowerHolders() external onlySelf {
        _resetContracts(IStandardGovernor(standardGovernor()).voteToken());
    }

    /// @inheritdoc IZeroGovernor
    function resetToZeroHolders() external onlySelf {
        _resetContracts(voteToken);
    }

    /// @inheritdoc IZeroGovernor
    function setCashToken(address newCashToken_, uint256 newProposalFee_) external onlySelf {
        if (!_allowedCashTokens[newCashToken_]) revert InvalidCashToken();

        IStandardGovernor(standardGovernor()).setCashToken(newCashToken_, newProposalFee_);
    }

    /// @inheritdoc IZeroGovernor
    function setEmergencyProposalThresholdRatio(uint16 newThresholdRatio_) external onlySelf {
        IEmergencyGovernor(emergencyGovernor()).setThresholdRatio(newThresholdRatio_);
    }

    /// @inheritdoc IZeroGovernor
    function setZeroProposalThresholdRatio(uint16 newThresholdRatio_) external onlySelf {
        _setThresholdRatio(newThresholdRatio_);
    }

    /* ============ View/Pure Functions ============ */

    /// @inheritdoc IZeroGovernor
    function isAllowedCashToken(address token_) external view returns (bool) {
        return _allowedCashTokens[token_];
    }

    /// @inheritdoc IZeroGovernor
    function emergencyGovernor() public view returns (address) {
        return IEmergencyGovernorDeployer(emergencyGovernorDeployer).lastDeploy();
    }

    /// @inheritdoc IZeroGovernor
    function standardGovernor() public view returns (address) {
        return IStandardGovernorDeployer(standardGovernorDeployer).lastDeploy();
    }

    /* ============ Internal Interactive Functions ============ */

    /**
     * @dev    Deploys the ephemeral `standardGovernor`, `emergencyGovernor`, and `powerToken` contracts.
     * @param  emergencyGovernorDeployer_       The address of the Emergency Governor Deployer contract.
     * @param  powerTokenDeployer_              The address of the Power Token Deployer contract.
     * @param  standardGovernorDeployer_        The address of the Standard Governor Deployer contract.
     * @param  bootstrapToken_                  The address of a token to bootstrap the new Power Token.
     * @param  cashToken_                       The address of the Cash Token contract.
     * @param  emergencyProposalThresholdRatio_ The threshold ratio for the Emergency Governor.
     * @param  proposalFee_                     The proposal fee for the Standard Governor.
     * @return standardGovernor_                The address of the deployed Standard Governor contract.
     * @return emergencyGovernor_               The address of the deployed Emergency Governor contract.
     * @return powerToken_                      The address of the deployed Power Token contract.
     */
    function _deployEphemeralContracts(
        address emergencyGovernorDeployer_,
        address powerTokenDeployer_,
        address standardGovernorDeployer_,
        address bootstrapToken_,
        address cashToken_,
        uint16 emergencyProposalThresholdRatio_,
        uint256 proposalFee_
    ) internal returns (address standardGovernor_, address emergencyGovernor_, address powerToken_) {
        address expectedPowerToken_ = IPowerTokenDeployer(powerTokenDeployer_).nextDeploy();
        address expectedStandardGovernor_ = IStandardGovernorDeployer(standardGovernorDeployer_).nextDeploy();

        emergencyGovernor_ = IEmergencyGovernorDeployer(emergencyGovernorDeployer_).deploy(
            expectedPowerToken_,
            expectedStandardGovernor_,
            emergencyProposalThresholdRatio_
        );

        standardGovernor_ = IStandardGovernorDeployer(standardGovernorDeployer_).deploy(
            expectedPowerToken_,
            emergencyGovernor_,
            cashToken_,
            proposalFee_,
            _MAX_TOTAL_ZERO_REWARD_PER_ACTIVE_EPOCH
        );

        if (expectedStandardGovernor_ != standardGovernor_) {
            revert UnexpectedStandardGovernorDeployed(expectedStandardGovernor_, standardGovernor_);
        }

        powerToken_ = IPowerTokenDeployer(powerTokenDeployer_).deploy(bootstrapToken_, standardGovernor_, cashToken_);

        if (expectedPowerToken_ != powerToken_) revert UnexpectedPowerTokenDeployed(expectedPowerToken_, powerToken_);
    }

    /**
     * @dev   Redeploy the ephemeral `standardGovernor`, `emergencyGovernor`, and `powerToken` contracts, where:
     *         - the cash token is the same cash token in the existing `standardGovernor`
     *         - the `emergencyGovernor` threshold ratio is the same threshold ratio in the existing `emergencyGovernor`
     *         - the `standardGovernor` proposal fee is the same proposal fee in the existing `standardGovernor`
     * @param bootstrapToken_ The token to bootstrap the `powerToken` balances and voting powers.
     */
    function _resetContracts(address bootstrapToken_) internal {
        IStandardGovernor standardGovernor_ = IStandardGovernor(standardGovernor());

        (
            address newStandardGovernor_,
            address newEmergencyGovernor_,
            address newPowerToken_
        ) = _deployEphemeralContracts(
                emergencyGovernorDeployer,
                powerTokenDeployer,
                standardGovernorDeployer,
                bootstrapToken_,
                standardGovernor_.cashToken(),
                IEmergencyGovernor(emergencyGovernor()).thresholdRatio(),
                standardGovernor_.proposalFee()
            );

        emit ResetExecuted(bootstrapToken_, newStandardGovernor_, newEmergencyGovernor_, newPowerToken_);
    }

    /* ============ Internal View/Pure Functions ============ */

    /**
     * @dev   All proposals target this contract itself, and must call one of the listed functions to be valid.
     * @param callData_ The call data to check.
     */
    function _revertIfInvalidCalldata(bytes memory callData_) internal pure override {
        bytes4 func_ = bytes4(callData_);
        uint256 length = callData_.length;

        if (
            !(func_ == this.resetToPowerHolders.selector && length == _SELECTOR_PLUS_0_ARGS) &&
            !(func_ == this.resetToZeroHolders.selector && length == _SELECTOR_PLUS_0_ARGS) &&
            !(func_ == this.setCashToken.selector && length == _SELECTOR_PLUS_2_ARGS) &&
            !(func_ == this.setEmergencyProposalThresholdRatio.selector && length == _SELECTOR_PLUS_1_ARGS) &&
            !(func_ == this.setZeroProposalThresholdRatio.selector && length == _SELECTOR_PLUS_1_ARGS)
        ) revert InvalidCallData();
    }
}


// ============================================================================
// FILE: lib/ttg/src/abstract/ThresholdGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IGovernor } from "./interfaces/IGovernor.sol";
import { IThresholdGovernor } from "./interfaces/IThresholdGovernor.sol";

import { BatchGovernor } from "./BatchGovernor.sol";

/**
 * @title  Extension for BatchGovernor with a threshold ratio used to determine quorum and yes-threshold requirements.
 * @author M^0 Labs
 */
abstract contract ThresholdGovernor is IThresholdGovernor, BatchGovernor {
    /* ============ Variables ============ */

    /// @dev The minimum allowed threshold ratio.
    uint16 internal constant _MIN_THRESHOLD_RATIO = 271;

    /// @inheritdoc IThresholdGovernor
    uint256 public constant ONE = 10_000;

    /// @inheritdoc IThresholdGovernor
    uint16 public thresholdRatio;

    /* ============ Constructor ============ */

    /**
     * @notice Construct a new ThresholdGovernor contract.
     * @param  name_           The name of the contract. Used to compute EIP712 domain separator.
     * @param  voteToken_      The address of the token used to vote.
     * @param  thresholdRatio_ The ratio of yes votes votes required for a proposal to meet quorum and succeed.
     */
    constructor(string memory name_, address voteToken_, uint16 thresholdRatio_) BatchGovernor(name_, voteToken_) {
        _setThresholdRatio(thresholdRatio_);
    }

    /* ============ Interactive Functions ============ */

    /// @inheritdoc IGovernor
    function execute(
        address[] memory targets_,
        uint256[] memory values_,
        bytes[] memory callDatas_,
        bytes32
    ) external payable returns (uint256 proposalId_) {
        _revertIfInvalidProposal(targets_, values_, callDatas_);

        uint16 latestPossibleVoteStart_ = _clock();

        // Proposals have voteStart=N and voteEnd=N+1, and can be executed only during epochs N and N+1.
        proposalId_ = _tryExecute(callDatas_[0], latestPossibleVoteStart_, latestPossibleVoteStart_ - 1);
    }

    /// @inheritdoc IGovernor
    function propose(
        address[] memory targets_,
        uint256[] memory values_,
        bytes[] memory callDatas_,
        string memory description_
    ) external returns (uint256 proposalId_) {
        (proposalId_, ) = _propose(targets_, values_, callDatas_, description_);
    }

    /* ============ View/Pure Functions ============ */

    /// @inheritdoc IGovernor
    function COUNTING_MODE() external pure returns (string memory) {
        return "support=against,for&quorum=for&success=quorum";
    }

    /// @inheritdoc IThresholdGovernor
    function getProposal(
        uint256 proposalId_
    )
        external
        view
        returns (
            uint48 voteStart_,
            uint48 voteEnd_,
            ProposalState state_,
            uint256 noVotes_,
            uint256 yesVotes_,
            address proposer_,
            uint256 quorum_,
            uint16 quorumNumerator_
        )
    {
        Proposal storage proposal_ = _proposals[proposalId_];

        voteStart_ = proposal_.voteStart;
        voteEnd_ = _getVoteEnd(proposal_.voteStart);
        state_ = state(proposalId_);
        noVotes_ = proposal_.noWeight;
        yesVotes_ = proposal_.yesWeight;
        proposer_ = proposal_.proposer;
        quorum_ = _getQuorum(proposal_.voteStart, proposal_.thresholdRatio);
        quorumNumerator_ = proposal_.thresholdRatio;
    }

    /// @inheritdoc IThresholdGovernor
    function proposalQuorum(uint256 proposalId) external view returns (uint256) {
        Proposal storage proposal_ = _proposals[proposalId];

        return _getQuorum(proposal_.voteStart, proposal_.thresholdRatio);
    }

    /// @inheritdoc IGovernor
    function quorum() external view returns (uint256) {
        // NOTE: This only provides the quorum required for a proposal created at this moment.
        return _getQuorum(_clock(), thresholdRatio);
    }

    /// @inheritdoc IThresholdGovernor
    function quorumNumerator() external view returns (uint256) {
        return thresholdRatio;
    }

    /// @inheritdoc IThresholdGovernor
    function quorumDenominator() external pure returns (uint256) {
        return ONE;
    }

    /// @inheritdoc IGovernor
    function state(uint256 proposalId_) public view override(BatchGovernor, IGovernor) returns (ProposalState state_) {
        Proposal storage proposal_ = _proposals[proposalId_];

        if (proposal_.executed) return ProposalState.Executed;

        uint16 voteStart_ = proposal_.voteStart;

        if (voteStart_ == 0) revert ProposalDoesNotExist();

        uint256 totalSupply_ = _getTotalSupply(voteStart_ - 1);
        bool isVotingOpen_ = _clock() <= _getVoteEnd(voteStart_);

        // If the total supply of Vote Tokens is 0 and the vote has not ended yet, the proposal is active.
        // The proposal will expire once the voting period closes.
        if (totalSupply_ == 0) return isVotingOpen_ ? ProposalState.Active : ProposalState.Expired;

        uint16 thresholdRatio_ = proposal_.thresholdRatio;

        // If proposal is currently succeeding, it has either succeeded or expired.
        if (proposal_.yesWeight * ONE >= thresholdRatio_ * totalSupply_) {
            return isVotingOpen_ ? ProposalState.Succeeded : ProposalState.Expired;
        }

        // If proposal can succeed while voting is open, it is active.
        if (((totalSupply_ - proposal_.noWeight) * ONE >= thresholdRatio_ * totalSupply_) && isVotingOpen_) {
            return ProposalState.Active;
        }

        return ProposalState.Defeated;
    }

    /* ============ Internal Interactive Functions ============ */

    /**
     * @dev   Creates a new proposal with the given parameters.
     * @param proposalId_ The unique identifier of the proposal.
     * @param voteStart_  The epoch at which the proposal will start collecting votes.
     */
    function _createProposal(uint256 proposalId_, uint16 voteStart_) internal override {
        _proposals[proposalId_] = Proposal({
            voteStart: voteStart_,
            executed: false,
            proposer: msg.sender,
            thresholdRatio: thresholdRatio,
            noWeight: 0,
            yesWeight: 0
        });
    }

    /**
     * @dev   Set the threshold ratio to be applied to determine the threshold/quorum for a proposal.
     * @param newThresholdRatio_ The new threshold ratio.
     */
    function _setThresholdRatio(uint16 newThresholdRatio_) internal {
        if (newThresholdRatio_ > ONE || newThresholdRatio_ < _MIN_THRESHOLD_RATIO) {
            revert InvalidThresholdRatio(newThresholdRatio_, _MIN_THRESHOLD_RATIO, ONE);
        }

        emit QuorumNumeratorUpdated(thresholdRatio, newThresholdRatio_);
        emit ThresholdRatioSet(thresholdRatio = newThresholdRatio_);
    }

    /* ============ Internal View/Pure Functions ============ */

    /**
     * @dev    Returns the quorum given a snapshot and quorum numerator.
     * @param  voteStart_       The epoch at which the proposal will start collecting votes.
     * @param  quorumNumerator_ The quorum numerator.
     * @return quorum_          The quorum of yes voted needed for a successful proposal.
     */
    function _getQuorum(uint16 voteStart_, uint16 quorumNumerator_) internal view returns (uint256 quorum_) {
        return (quorumNumerator_ * _getTotalSupply(voteStart_ - 1)) / ONE;
    }

    /**
     * @dev    Returns the number of clock values that must elapse before voting begins for a newly created proposal.
     * @return The voting delay.
     */
    function _votingDelay() internal pure override returns (uint16) {
        return 0;
    }

    /**
     * @dev    Returns the number of clock values between the vote start and vote end.
     * @return The voting period.
     */
    function _votingPeriod() internal pure override returns (uint16) {
        return 1;
    }
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IEmergencyGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IThresholdGovernor } from "../abstract/interfaces/IThresholdGovernor.sol";

/**
 * @title  An instance of a ThresholdGovernor with a unique and limited set of possible proposals.
 * @author M^0 Labs
 */
interface IEmergencyGovernor is IThresholdGovernor {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Standard Governor specified in the constructor is address(0).
    error InvalidStandardGovernorAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Sets the threshold ratio to use going forward for newly created proposals.
     * @param  newThresholdRatio The new threshold ratio.
     */
    function setThresholdRatio(uint16 newThresholdRatio) external;

    /* ============ Proposal Functions ============ */

    /**
     * @notice One of the valid proposals. Adds `account` to `list` at the Registrar.
     * @param  list    The key for some list.
     * @param  account The address of some account to be added.
     */
    function addToList(bytes32 list, address account) external;

    /**
     * @notice One of the valid proposals. Removes `account` to `list` at the Registrar.
     * @param  list    The key for some list.
     * @param  account The address of some account to be removed.
     */
    function removeFromList(bytes32 list, address account) external;

    /**
     * @notice One of the valid proposals. Removes `accountToRemove` and adds `accountToAdd` to `list` at the Registrar.
     * @param  list            The key for some list.
     * @param  accountToRemove The address of some account to be removed.
     * @param  accountToAdd    The address of some account to be added.
     */
    function removeFromAndAddToList(bytes32 list, address accountToRemove, address accountToAdd) external;

    /**
     * @notice One of the valid proposals. Sets `key` to `value` at the Registrar.
     * @param  key   Some key.
     * @param  value Some value.
     */
    function setKey(bytes32 key, bytes32 value) external;

    /**
     * @notice One of the valid proposals. Sets the proposal fee of the Standard Governor.
     * @param  newProposalFee The new proposal fee.
     */
    function setStandardProposalFee(uint256 newProposalFee) external;

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IEmergencyGovernorDeployer.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IDeployer } from "./IDeployer.sol";

/**
 * @title  A Deterministic deployer of Emergency Governor contracts using CREATE.
 * @author M^0 Labs
 */
interface IEmergencyGovernorDeployer is IDeployer {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Deploys a new instance of an Emergency Governor.
     * @param  powerToken       The address of some Power Token that will be used by voters.
     * @param  standardGovernor The address of some Standard Governor.
     * @param  thresholdRatio   The threshold ratio to use for proposals.
     * @return The address of the deployed Emergency Governor.
     */
    function deploy(address powerToken, address standardGovernor, uint16 thresholdRatio) external returns (address);

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IPowerTokenDeployer.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IDeployer } from "./IDeployer.sol";

/**
 * @title  A Deterministic deployer of Power Token contracts using CREATE.
 * @author M^0 Labs
 */
interface IPowerTokenDeployer is IDeployer {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Deploys a new instance of a Power Token.
     * @dev    Callable only by the Zero Governor.
     * @param  bootstrapToken   The address of some token to bootstrap from.
     * @param  standardGovernor The address of some Standard Governor.
     * @param  cashToken        The address of some Cash Token.
     * @return The address of the deployed Emergency Governor.
     */
    function deploy(address bootstrapToken, address standardGovernor, address cashToken) external returns (address);

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IStandardGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IBatchGovernor } from "../abstract/interfaces/IBatchGovernor.sol";

/**
 * @title  An instance of a BatchGovernor with a unique and limited set of possible proposals with proposal fees.
 * @author M^0 Labs
 */
interface IStandardGovernor is IBatchGovernor {
    /* ============ Events ============ */

    /**
     * @notice Emitted when the cash token is set to `cashToken`.
     * @param  cashToken The address of the cash token taking effect.
     */
    event CashTokenSet(address indexed cashToken);

    /**
     * @notice Emitted when `voter` has voted on all the proposals in the current epoch `currentEpoch`.
     * @param  voter        The address of the account voting.
     * @param  currentEpoch The current epoch number as a clock value.
     */
    event HasVotedOnAllProposals(address indexed voter, uint256 indexed currentEpoch);

    /**
     * @notice Emitted when the proposal fee for the proposal, with identifier `proposalFee`, is sent to the vault.
     * @param  proposalId The unique identifier of the proposal.
     * @param  cashToken  The address of the cash token for this particular proposal fee.
     * @param  amount     The amount of cash token of the proposal fee.
     */
    event ProposalFeeSentToVault(uint256 indexed proposalId, address indexed cashToken, uint256 amount);

    /**
     * @notice Emitted when the proposal fee is set to `proposalFee`.
     * @param  proposalFee The amount of cash token required onwards to create proposals.
     */
    event ProposalFeeSet(uint256 proposalFee);

    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when the proposal fee for a yet defeated or yet expired proposal is trying to be moved.
     * @param  state The current state of the proposal.
     */
    error FeeNotDestinedForVault(ProposalState state);

    /// @notice Revert message when the Cash Token specified in the constructor is address(0).
    error InvalidCashTokenAddress();

    /// @notice Revert message when the Emergency Governor specified in the constructor is address(0).
    error InvalidEmergencyGovernorAddress();

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the Zero Token specified in the constructor is address(0).
    error InvalidZeroTokenAddress();

    /// @notice Revert message when proposal fee trying to be moved to the vault is 0.
    error NoFeeToSend();

    /// @notice Revert message when the caller is not this contract itself nor the Emergency Governor.
    error NotSelfOrEmergencyGovernor();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /// @notice Revert message when a token transfer, from this contract, fails.
    error TransferFailed();

    /// @notice Revert message when a token transferFrom fails.
    error TransferFromFailed();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Sends the proposal fee for proposal `proposalId` to the vault, if it is Defeated or Expired.
     * @param  proposalId The unique identifier of the proposal.
     */
    function sendProposalFeeToVault(uint256 proposalId) external;

    /**
     * @notice Set the cash token and proposal fee to be used to create proposals going forward.
     * @param  newCashToken   The address of the new cash token.
     * @param  newProposalFee The amount of cash token required onwards to create proposals.
     */
    function setCashToken(address newCashToken, uint256 newProposalFee) external;

    /* ============ Proposal Functions ============ */

    /**
     * @notice One of the valid proposals. Adds `account` to `list` at the Registrar.
     * @param  list    The key for some list.
     * @param  account The address of some account to be added.
     */
    function addToList(bytes32 list, address account) external;

    /**
     * @notice One of the valid proposals. Removes `account` to `list` at the Registrar.
     * @param  list    The key for some list.
     * @param  account The address of some account to be removed.
     */
    function removeFromList(bytes32 list, address account) external;

    /**
     * @notice One of the valid proposals. Removes `accountToRemove` and adds `accountToAdd` to `list` at the Registrar.
     * @param  list            The key for some list.
     * @param  accountToRemove The address of some account to be removed.
     * @param  accountToAdd    The address of some account to be added.
     */
    function removeFromAndAddToList(bytes32 list, address accountToRemove, address accountToAdd) external;

    /**
     * @notice One of the valid proposals. Sets `key` to `value` at the Registrar.
     * @param  key   Some key.
     * @param  value Some value.
     */
    function setKey(bytes32 key, bytes32 value) external;

    /**
     * @notice One of the valid proposals. Sets the proposal fee of the Standard Governor.
     * @param  newProposalFee The new proposal fee.
     */
    function setProposalFee(uint256 newProposalFee) external;

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the required amount of cashToken it costs an account to create a proposal.
    function proposalFee() external view returns (uint256);

    /**
     * @notice Returns all the proposal details for a proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier of the proposal.
     * @return voteStart  The first clock value when voting on the proposal is allowed.
     * @return voteEnd    The last clock value when voting on the proposal is allowed.
     * @return state      The state of the proposal.
     * @return noVotes    The amount of votes cast against the proposal.
     * @return yesVotes   The amount of votes cast for the proposal.
     * @return proposer   The address of the account that created the proposal.
     * @return quorum     The number of votes required to meet quorum.
     */
    function getProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            uint48 voteStart,
            uint48 voteEnd,
            ProposalState state,
            uint256 noVotes,
            uint256 yesVotes,
            address proposer,
            uint256 quorum
        );

    /**
     * @notice Returns the proposal fee information.
     * @param  proposalId The unique identifier of the proposal.
     * @return cashToken  The address of the cash token for this particular proposal fee.
     * @return amount     The amount of cash token of the proposal fee.
     */
    function getProposalFee(uint256 proposalId) external view returns (address cashToken, uint256 amount);

    /// @notice Returns the maximum amount of Zero Token that can be rewarded to all vote casters per active epoch.
    function maxTotalZeroRewardPerActiveEpoch() external view returns (uint256);

    /**
     * @notice Returns the number of proposals at epoch `epoch`.
     * @param  epoch The epoch as a clock value.
     * @return The number of proposals at epoch `epoch`.
     */
    function numberOfProposalsAt(uint256 epoch) external view returns (uint256);

    /**
     * @notice Returns the number of proposals that were voted on at `epoch`.
     * @param  voter The address of some account.
     * @param  epoch The epoch as a clock value.
     * @return The number of proposals at `epoch`.
     */
    function numberOfProposalsVotedOnAt(address voter, uint256 epoch) external view returns (uint256);

    /**
     * @notice Returns whether `voter` has voted on all proposals in `epoch`.
     * @param  voter The address of some account.
     * @param  epoch The epoch as a clock value.
     * @return Whether `voter` has voted on all proposals in `epoch`.
     */
    function hasVotedOnAllProposals(address voter, uint256 epoch) external view returns (bool);

    /// @notice Returns the address of the Cash Token.
    function cashToken() external view returns (address);

    /// @notice Returns the address of the Emergency Governor.
    function emergencyGovernor() external view returns (address);

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);

    /// @notice Returns the address of the Zero Token.
    function zeroToken() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IStandardGovernorDeployer.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IDeployer } from "./IDeployer.sol";

/**
 * @title  A Deterministic deployer of Standard Governor contracts using CREATE.
 * @author M^0 Labs
 */
interface IStandardGovernorDeployer is IDeployer {
    /* ============ Custom Errors ============ */

    /// @notice Revert message when the Registrar specified in the constructor is address(0).
    error InvalidRegistrarAddress();

    /// @notice Revert message when the Vault specified in the constructor is address(0).
    error InvalidVaultAddress();

    /// @notice Revert message when the Zero Governor specified in the constructor is address(0).
    error InvalidZeroGovernorAddress();

    /// @notice Revert message when the Zero Token specified in the constructor is address(0).
    error InvalidZeroTokenAddress();

    /// @notice Revert message when the caller is not the Zero Governor.
    error NotZeroGovernor();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Deploys a new instance of a Standard Governor.
     * @param  powerToken                       The address of some Power Token that will be used by voters.
     * @param  emergencyGovernor                The address of some Emergency Governor.
     * @param  cashToken                        The address of some Cash Token.
     * @param  proposalFee                      The proposal fee required to create proposals.
     * @param  maxTotalZeroRewardPerActiveEpoch The maximum amount of Zero Token rewarded per active epoch.
     * @return The address of the deployed Standard Governor.
     */
    function deploy(
        address powerToken,
        address emergencyGovernor,
        address cashToken,
        uint256 proposalFee,
        uint256 maxTotalZeroRewardPerActiveEpoch
    ) external returns (address);

    /* ============ View/Pure Functions ============ */

    /// @notice Returns the address of the Registrar.
    function registrar() external view returns (address);

    /// @notice Returns the address of the Vault.
    function vault() external view returns (address);

    /// @notice Returns the address of the Zero Governor.
    function zeroGovernor() external view returns (address);

    /// @notice Returns the address of the Zero Token.
    function zeroToken() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IZeroGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IThresholdGovernor } from "../abstract/interfaces/IThresholdGovernor.sol";

/**
 * @title  An instance of a ThresholdGovernor with a unique and limited set of possible proposals.
 * @author M^0 Labs
 */
interface IZeroGovernor is IThresholdGovernor {
    /* ============ Events ============ */

    /**
     * @notice Emitted upon contract deployment, once the set of allowed cash tokens is finalized.
     * @param  allowedCashTokens An array of addressed that are allowed as cash tokens.
     */
    event AllowedCashTokensSet(address[] allowedCashTokens);

    /**
     * @notice Emitted upon a Reset, resulting in a new Standard Governor, Emergency Governor, and Power Token.
     * @param  bootstrapToken    The address of token (Zero Token or old Power Token), that bootstraps the reset.
     * @param  standardGovernor  The address of the new Standard Governor.
     * @param  emergencyGovernor The address of the new Emergency Governor.
     * @param  powerToken        The address of the new Power Token.
     */
    event ResetExecuted(
        address indexed bootstrapToken,
        address standardGovernor,
        address emergencyGovernor,
        address powerToken
    );

    /* ============ Custom Errors ============ */

    /// @notice Revert message when the Cash Token specified is not in the allowed set.
    error InvalidCashToken();

    /// @notice Revert message when the Cash Token specified in the constructor is address(0).
    error InvalidCashTokenAddress();

    /// @notice Revert message when the Emergency Governor Deployer specified in the constructor is address(0).
    error InvalidEmergencyGovernorDeployerAddress();

    /// @notice Revert message when the Power Token Deployer specified in the constructor is address(0).
    error InvalidPowerTokenDeployerAddress();

    /// @notice Revert message when the Standard Governor Deployer specified in the constructor is address(0).
    error InvalidStandardGovernorDeployerAddress();

    /// @notice Revert message when the set of allowed cash tokens specified in the constructor is empty.
    error NoAllowedCashTokens();

    /**
     * @notice Revert message when the address of the deployed Power Token differs fro what was expected.
     * @param  expected The expected address of the deployed Power Token.
     * @param  deployed The actual address of the deployed Power Token.
     */
    error UnexpectedPowerTokenDeployed(address expected, address deployed);

    /**
     * @notice Revert message when the address of the deployed Standard Governor differs fro what was expected.
     * @param  expected The expected address of the deployed Standard Governor.
     * @param  deployed The actual address of the deployed Standard Governor.
     */
    error UnexpectedStandardGovernorDeployed(address expected, address deployed);

    /* ============ Proposal Functions ============ */

    /**
     * @notice One of the valid proposals. Reset the Standard Governor, Emergency Governor, and Power Token to the
     *         Power Token holders. This would be used by Zero Token holders in the event that inflation is soon to
     *         result in Power Token overflowing, and/or there is a loss of faith in the state of either the Standard
     *         Governor or Emergency Governor.
     */
    function resetToPowerHolders() external;

    /**
     * @notice One of the valid proposals. Reset the Standard Governor, Emergency Governor, and Power Token to the
     *         ZeroToken holders. This would be used by Zero Token holders if they no longer have faith in the current
     *         set of PowerToken holders and/or the state of either the Standard Governor or Emergency Governor.
     */
    function resetToZeroHolders() external;

    /**
     * @notice One of the valid proposals. Sets the Cash Token of the system.
     * @param  newCashToken   The address of the new cash token.
     * @param  newProposalFee The amount of cash token required onwards to create Standard Governor proposals.
     */
    function setCashToken(address newCashToken, uint256 newProposalFee) external;

    /**
     * @notice One of the valid proposals. Sets the threshold ratio for Emergency Governor proposals.
     * @param  newThresholdRatio The new threshold ratio.
     */
    function setEmergencyProposalThresholdRatio(uint16 newThresholdRatio) external;

    /**
     * @notice One of the valid proposals. Sets the threshold ratio for this governor's proposals.
     * @param  newThresholdRatio The new threshold ratio.
     */
    function setZeroProposalThresholdRatio(uint16 newThresholdRatio) external;

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns whether `token` is an allowed Cash Token of the system, as a parameter in setCashToken proposal.
     * @param  token The address of some token.
     * @return Whether `token` is an allowed Cash Token.
     */
    function isAllowedCashToken(address token) external view returns (bool);

    /// @notice Returns the address of the Emergency Governor.
    function emergencyGovernor() external view returns (address);

    /// @notice Returns the address of the Emergency Governor Deployer.
    function emergencyGovernorDeployer() external view returns (address);

    /// @notice Returns the address of the Power Token Deployer.
    function powerTokenDeployer() external view returns (address);

    /// @notice Returns the address of the Standard Governor.
    function standardGovernor() external view returns (address);

    /// @notice Returns the address of the Standard Governor Deployer.
    function standardGovernorDeployer() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IERC712 } from "../../../lib/common/src/interfaces/IERC712.sol";

import { IERC6372 } from "./IERC6372.sol";

/**
 * @title  Minimal OpenZeppelin-style, Tally-compatible governor.
 * @author M^0 Labs
 */
interface IGovernor is IERC6372, IERC712 {
    /* ============ Enums ============ */

    /**
     * @notice Proposal state.
     * @param  Pending   The proposal has been created, but the vote has not started yet.
     * @param  Active    The proposal is currently in the voting period.
     * @param  Canceled  The proposal has been canceled.
     * @param  Defeated  The proposal has been defeated.
     * @param  Succeeded The proposal has succeeded.
     * @param  Queued    The proposal has been queued.
     * @param  Expired   The proposal has expired.
     * @param  Executed  The proposal has been executed.
     */
    enum ProposalState {
        Pending,
        Active,
        Canceled, // never used by TTG.
        Defeated,
        Succeeded,
        Queued, // never used by TTG.
        Expired,
        Executed
    }

    /* ============ Events ============ */

    /**
     * @notice Emitted when a proposal has been created.
     * @param  proposalId  The unique identifier for the proposal.
     * @param  proposer    The address of the account that created the proposal.
     * @param  targets     An array of addresses that will be called upon the execution.
     * @param  values      An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  signatures  Empty string array required to be compatible with OZ governor contract.
     * @param  callDatas   An array of call data used to call each respective target upon execution.
     * @param  voteStart   The first clock value when voting on the proposal is allowed.
     * @param  voteEnd     The last clock value when voting on the proposal is allowed.
     * @param  description The string of the description of the proposal.
     */
    event ProposalCreated(
        uint256 proposalId,
        address proposer,
        address[] targets,
        uint256[] values,
        string[] signatures,
        bytes[] callDatas,
        uint256 voteStart,
        uint256 voteEnd,
        string description
    );

    /**
     * @notice Emitted when a proposal has been executed.
     * @param  proposalId The unique identifier for the proposal.
     */
    event ProposalExecuted(uint256 proposalId);

    /**
     * @notice Emitted when a vote for a proposal with id `proposalId` has been cast by `voter`.
     * @param  voter      The address of the account that has casted their vote.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support that has been cast for the proposal.
     * @param  weight     The number of votes cast.
     * @param  reason     The string of the reason `voter` has cast their vote, if any.
     */
    event VoteCast(address indexed voter, uint256 proposalId, uint8 support, uint256 weight, string reason);

    /* ============ Interactive Functions ============ */

    /**
     * @notice Allows the caller to cast a vote on a proposal with id `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @return weight     The number of votes cast.
     */
    function castVote(uint256 proposalId, uint8 support) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast a vote on a proposal with id `proposalId` via an ECDSA secp256k1 signature.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  v          An ECDSA secp256k1 signature parameter.
     * @param  r          An ECDSA secp256k1 signature parameter.
     * @param  s          An ECDSA secp256k1 signature parameter.
     * @return weight     The number of votes cast.
     */
    function castVoteBySig(
        uint256 proposalId,
        uint8 support,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows `voter` to cast a vote on a proposal with id `proposalId` via an arbitrary signature.
     * @param  voter      The address of the account that casting their vote, and purported to have signed.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  signature  An arbitrary signature.
     * @return weight     The number of votes cast.
     */
    function castVoteBySig(
        address voter,
        uint256 proposalId,
        uint8 support,
        bytes memory signature
    ) external returns (uint256 weight);

    /**
     * @notice Allows the caller to cast a vote with reason on a proposal with id `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  reason     The reason for which the caller casts their vote, if any.
     * @return weight     The number of votes cast.
     */
    function castVoteWithReason(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast a vote with reason on a proposal with id `proposalId`
     *         via an ECDSA secp256k1 signature.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  reason     The reason for which the caller casts their vote, if any.
     * @param  v          An ECDSA secp256k1 signature parameter.
     * @param  r          An ECDSA secp256k1 signature parameter.
     * @param  s          An ECDSA secp256k1 signature parameter.
     * @return weight     The number of votes cast.
     */
    function castVoteWithReasonBySig(
        uint256 proposalId,
        uint8 support,
        string calldata reason,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows `voter` to cast a vote with reason on a proposal with id `proposalId` via an arbitrary signature.
     * @param  voter      The address of the account that casting their vote, and purported to have signed.
     * @param  proposalId The unique identifier for the proposal.
     * @param  support    The type of support to cast for the proposal.
     * @param  reason     The reason for which the caller casts their vote, if any.
     * @param  signature  An arbitrary signature.
     * @return weight     The number of votes cast.
     */
    function castVoteWithReasonBySig(
        address voter,
        uint256 proposalId,
        uint8 support,
        string calldata reason,
        bytes memory signature
    ) external returns (uint256 weight);

    /**
     * @notice Allows the caller to execute a proposal.
     * @param  targets         An array of addresses that will be called upon the execution.
     * @param  values          An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas       An array of call data used to call each respective target upon execution.
     * @param  descriptionHash The hash of the string of the description of the proposal.
     * @return proposalId      The unique identifier for the proposal.
     */
    function execute(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        bytes32 descriptionHash
    ) external payable returns (uint256 proposalId);

    /**
     * @notice Allows the caller to create a proposal.
     * @param  targets     An array of addresses that will be called upon the execution.
     * @param  values      An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas   An array of call data used to call each respective target upon execution.
     * @param  description The string of the description of the proposal.
     * @return proposalId  The unique identifier for the proposal.
     */
    function propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        string memory description
    ) external returns (uint256 proposalId);

    /* ============ View/Pure Functions ============ */

    /**
     * @notice module:voting
     * @dev    A description of the possible "support" values for castVote and the way these votes are counted, meant to
     *         be consumed by UIs to show correct vote options and interpret the results. The string is a URL-encoded
     *         sequence of key-value pairs that each describe one aspect, for example `support=for,against&quorum=for`.
     *         The string can be decoded by the standard URLSearchParams JavaScript class.
     */
    function COUNTING_MODE() external view returns (string memory);

    /**
     * @notice Returns the voting power of `account` at clock value `timepoint`.
     * @param  account   The address of the account with voting power.
     * @param  timepoint The point in time, according to the clock mode the contract is operating on.
     * @return The voting power of `account` at `timepoint`.
     */
    function getVotes(address account, uint256 timepoint) external view returns (uint256);

    /**
     * @notice Returns the unique identifier for the proposal if it were created at this exact moment.
     * @param  targets         An array of addresses that will be called upon the execution.
     * @param  values          An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas       An array of call data used to call each respective target upon execution.
     * @param  descriptionHash The hash of the string of the description of the proposal.
     * @return The unique identifier for the proposal.
     */
    function hashProposal(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory callDatas,
        bytes32 descriptionHash
    ) external view returns (uint256);

    /**
     * @notice Returns whether `account` has voted on the proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @param  account    The address of some account.
     * @return Whether `account` has already voted on the proposal.
     */
    function hasVoted(uint256 proposalId, address account) external view returns (bool);

    /// @notice Returns the name of the contract.
    function name() external view returns (string memory);

    /**
     * @notice Returns the last clock value when voting on the proposal with identifier `proposalId` is allowed.
     * @param  proposalId The unique identifier for the proposal.
     * @return The last clock value when voting on the proposal is allowed.
     */
    function proposalDeadline(uint256 proposalId) external view returns (uint256);

    /**
     * @notice Returns the account that created the proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The address of the account that created the proposal.
     */
    function proposalProposer(uint256 proposalId) external view returns (address);

    /**
     * @notice Returns the clock value used to retrieve voting power to vote on proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The clock value used to retrieve voting power.
     */
    function proposalSnapshot(uint256 proposalId) external view returns (uint256);

    /// @notice Returns the required voting power an account needs to create a proposal.
    function proposalThreshold() external view returns (uint256);

    /**
     * @notice Returns the vote support totals for the proposal with identifier `proposalId`.
     * @param  proposalId   The unique identifier for the proposal.
     * @return noVotes      The amount of votes cast against the proposal.
     * @return yesVotes     The amount of votes cast for the proposal.
     * @return abstainVotes The amount of votes cast in abstention the proposal.
     */
    function proposalVotes(
        uint256 proposalId
    ) external view returns (uint256 noVotes, uint256 yesVotes, uint256 abstainVotes);

    /// @notice Returns the minimum number of eligible (COUNTING_MODE) votes for a proposal to succeed.
    function quorum() external view returns (uint256);

    /**
     * @notice Returns the state of a proposal with identifier `proposalId`.
     * @param  proposalId The unique identifier for the proposal.
     * @return The state of the proposal.
     */
    function state(uint256 proposalId) external view returns (ProposalState);

    /// @notice Returns the EIP-5805 token contact used for determine voting power and total supplies.
    function token() external view returns (address);

    /// @notice Returns the number of clock values that must elapse before voting begins for a newly created proposal.
    function votingDelay() external view returns (uint256);

    /// @notice Returns the number of clock values between the vote start and vote end.
    function votingPeriod() external view returns (uint256);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for `castVoteBySig` function.
    function BALLOT_TYPEHASH() external pure returns (bytes32);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for `castVoteWithReasonBySig` function.
    function BALLOT_WITH_REASON_TYPEHASH() external pure returns (bytes32);
}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IThresholdGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IBatchGovernor } from "./IBatchGovernor.sol";

/**
 * @title  Extension for BatchGovernor with a threshold ratio used to determine quorum and yes-threshold requirements.
 * @author M^0 Labs
 */
interface IThresholdGovernor is IBatchGovernor {
    /* ============ Events ============ */

    /**
     * @notice Emitted when the threshold ratio is set.
     * @param  thresholdRatio The new threshold ratio.
     */
    event ThresholdRatioSet(uint16 thresholdRatio);

    /**
     * @notice Emitted when the quorum numerator is set.
     * @param  oldQuorumNumerator The old quorum numerator.
     * @param  newQuorumNumerator The new quorum numerator.
     */
    event QuorumNumeratorUpdated(uint256 oldQuorumNumerator, uint256 newQuorumNumerator);

    /* ============ Custom Errors ============ */

    /**
     * @notice Revert message when trying to set the threshold ratio above 100% or below 2.71%.
     * @param  thresholdRatio    The threshold ratio being set.
     * @param  minThresholdRatio The minimum allowed threshold ratio.
     * @param  maxThresholdRatio The maximum allowed threshold ratio.
     */
    error InvalidThresholdRatio(uint256 thresholdRatio, uint256 minThresholdRatio, uint256 maxThresholdRatio);

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns all data of a proposal with identifier `proposalId`.
     * @param  proposalId      The unique identifier for the proposal.
     * @return voteStart       The first clock value when voting on the proposal is allowed.
     * @return voteEnd         The last clock value when voting on the proposal is allowed.
     * @return state           The state of the proposal.
     * @return noVotes         The amount of votes cast against the proposal.
     * @return yesVotes        The amount of votes cast for the proposal.
     * @return proposer        The address of the account that created the proposal.
     * @return quorum          The threshold/quorum of yes votes required for the proposal to succeed.
     * @return quorumNumerator The threshold/quorum numerator used to calculate the quorum.
     */
    function getProposal(
        uint256 proposalId
    )
        external
        view
        returns (
            uint48 voteStart,
            uint48 voteEnd,
            ProposalState state,
            uint256 noVotes,
            uint256 yesVotes,
            address proposer,
            uint256 quorum,
            uint16 quorumNumerator
        );

    /**
     * @notice Returns the threshold ratio to be applied to determine the success threshold for a proposal.
     * @dev    For all intents and purposes, this is the same as `quorumNumerator`.
     */
    function thresholdRatio() external view returns (uint16);

    /**
     * @notice Returns the quorum of yes votes needed for a specific proposal to succeed.
     * @param  proposalId The unique identifier for the proposal.
     * @return The quorum of yes votes needed for the proposal to succeed.
     */
    function proposalQuorum(uint256 proposalId) external view returns (uint256);

    /**
     * @notice Returns the quorum numerator used to determine the quorum for a proposal.
     * @dev    For all intents and purposes, this is the same as `thresholdRatio`.
     */
    function quorumNumerator() external view returns (uint256);

    /// @notice Returns the quorum denominator used to determine the quorum for a proposal.
    function quorumDenominator() external view returns (uint256);

    /// @notice Returns the value used as 100%, to be used to correctly ascertain the threshold ratio.
    function ONE() external pure returns (uint256);
}


// ============================================================================
// FILE: lib/ttg/src/abstract/BatchGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { ERC712Extended } from "../../lib/common/src/ERC712Extended.sol";

import { PureEpochs } from "../libs/PureEpochs.sol";

import { IBatchGovernor } from "./interfaces/IBatchGovernor.sol";
import { IEpochBasedVoteToken } from "./interfaces/IEpochBasedVoteToken.sol";
import { IERC6372 } from "./interfaces/IERC6372.sol";
import { IGovernor } from "./interfaces/IGovernor.sol";

/**
 * @title  Extension for Governor with specialized strict proposal parameters, vote batching, and an epoch clock.
 * @author M^0 Labs
 */
abstract contract BatchGovernor is IBatchGovernor, ERC712Extended {
    /* ============ Structs ============ */

    /**
     * @notice Proposal struct for storing all relevant proposal information.
     * @param  voteStart      The epoch at which voting begins, inclusively.
     * @param  executed       Whether or not the proposal has been executed.
     * @param  proposer       The address of the proposer.
     * @param  thresholdRatio The ratio of yes votes required for a proposal to meet quorum and succeed.
     * @param  noWeight       The total number of votes against the proposal.
     * @param  yesWeight      The total number of votes for the proposal.
     */
    struct Proposal {
        // 1st slot
        uint16 voteStart;
        bool executed;
        address proposer;
        uint16 thresholdRatio;
        // 2nd slot
        uint256 noWeight;
        // 3rd slot
        uint256 yesWeight;
    }

    /* ============ Variables ============ */

    /// @dev Length constant for calldata with no argument.
    uint256 internal constant _SELECTOR_PLUS_0_ARGS = 4;

    /// @dev Length constant for calldata with one argument.
    uint256 internal constant _SELECTOR_PLUS_1_ARGS = 36;

    /// @dev Length constant for calldata with two arguments.
    uint256 internal constant _SELECTOR_PLUS_2_ARGS = 68;

    /// @dev Length constant for calldata with three arguments.
    uint256 internal constant _SELECTOR_PLUS_3_ARGS = 100;

    // keccak256("Ballot(uint256 proposalId,uint8 support)")
    /// @inheritdoc IGovernor
    bytes32 public constant BALLOT_TYPEHASH = 0x150214d74d59b7d1e90c73fc22ef3d991dd0a76b046543d4d80ab92d2a50328f;

    // keccak256("BallotWithReason(uint256 proposalId,uint8 support,string reason)")
    /// @inheritdoc IGovernor
    bytes32 public constant BALLOT_WITH_REASON_TYPEHASH =
        0x7949bd92105c02f48ca245aa185f4a7a4d7185641d59b186ac64abeb44964f0c;

    // keccak256("Ballots(uint256[] proposalIds,uint8[] supportList)")
    /// @inheritdoc IBatchGovernor
    bytes32 public constant BALLOTS_TYPEHASH = 0x9a121fc10d6025acfc09275f9709796b68831733b5bbac0d510d13f85b1b730f;

    // keccak256("BallotsWithReason(uint256[] proposalIds,uint8[] supportList,string[] reasonList)")
    /// @inheritdoc IBatchGovernor
    bytes32 public constant BALLOTS_WITH_REASON_TYPEHASH =
        0xa891f76027ef63a24501b9dd3b0c779b49ad26d2328e9d423640209d1ad4fcc4;

    /// @inheritdoc IBatchGovernor
    address public immutable voteToken;

    /// @dev The list of proposals per proposal ID.
    mapping(uint256 proposalId => Proposal proposal) internal _proposals;

    /// @inheritdoc IGovernor
    mapping(uint256 proposalId => mapping(address voter => bool hasVoted)) public hasVoted;

    /* ============ Modifiers ============ */

    /// @dev Reverts if the caller is not the contract itself.
    modifier onlySelf() {
        _revertIfNotSelf();
        _;
    }

    /* ============ Constructor ============ */

    /**
     * @notice Construct a new BatchGovernor contract.
     * @param  name_      The name of the contract. Used to compute EIP712 domain separator.
     * @param  voteToken_ The address of the token used to vote.
     */
    constructor(string memory name_, address voteToken_) ERC712Extended(name_) {
        if ((voteToken = voteToken_) == address(0)) revert InvalidVoteTokenAddress();
    }

    /* ============ Interactive Functions ============ */

    /// @inheritdoc IGovernor
    function castVote(uint256 proposalId_, uint8 support_) external returns (uint256 weight_) {
        return _castVote(msg.sender, proposalId_, support_, "");
    }

    /// @inheritdoc IBatchGovernor
    function castVotes(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_
    ) external returns (uint256 weight_) {
        return _castVotes(msg.sender, proposalIds_, supportList_, new string[](proposalIds_.length));
    }

    /// @inheritdoc IGovernor
    function castVoteWithReason(
        uint256 proposalId_,
        uint8 support_,
        string calldata reason_
    ) external returns (uint256 weight_) {
        return _castVote(msg.sender, proposalId_, support_, reason_);
    }

    /// @inheritdoc IBatchGovernor
    function castVotesWithReason(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        string[] calldata reasonList_
    ) external returns (uint256 weight_) {
        return _castVotes(msg.sender, proposalIds_, supportList_, reasonList_);
    }

    /// @inheritdoc IGovernor
    function castVoteBySig(
        uint256 proposalId_,
        uint8 support_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external returns (uint256 weight_) {
        return
            _castVote(
                _getSignerAndRevertIfInvalidSignature(_getBallotDigest(proposalId_, support_), v_, r_, s_),
                proposalId_,
                support_,
                ""
            );
    }

    /// @inheritdoc IGovernor
    function castVoteBySig(
        address voter_,
        uint256 proposalId_,
        uint8 support_,
        bytes memory signature_
    ) external returns (uint256 weight_) {
        _revertIfInvalidSignature(voter_, _getBallotDigest(proposalId_, support_), signature_);

        return _castVote(voter_, proposalId_, support_, "");
    }

    /// @inheritdoc IBatchGovernor
    function castVotesBySig(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external returns (uint256 weight_) {
        return
            _castVotes(
                _getSignerAndRevertIfInvalidSignature(
                    _getBallotsDigest(
                        keccak256(abi.encodePacked(proposalIds_)),
                        keccak256(abi.encodePacked(supportList_))
                    ),
                    v_,
                    r_,
                    s_
                ),
                proposalIds_,
                supportList_,
                new string[](proposalIds_.length)
            );
    }

    /// @inheritdoc IBatchGovernor
    function castVotesBySig(
        address voter_,
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        bytes memory signature_
    ) external returns (uint256 weight_) {
        _revertIfInvalidSignature(
            voter_,
            _getBallotsDigest(keccak256(abi.encodePacked(proposalIds_)), keccak256(abi.encodePacked(supportList_))),
            signature_
        );

        return _castVotes(voter_, proposalIds_, supportList_, new string[](proposalIds_.length));
    }

    /// @inheritdoc IGovernor
    function castVoteWithReasonBySig(
        uint256 proposalId_,
        uint8 support_,
        string calldata reason_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external returns (uint256 weight_) {
        return
            _castVote(
                _getSignerAndRevertIfInvalidSignature(
                    _getBallotWithReasonDigest(proposalId_, support_, reason_),
                    v_,
                    r_,
                    s_
                ),
                proposalId_,
                support_,
                reason_
            );
    }

    /// @inheritdoc IGovernor
    function castVoteWithReasonBySig(
        address voter_,
        uint256 proposalId_,
        uint8 support_,
        string calldata reason_,
        bytes memory signature_
    ) external returns (uint256 weight_) {
        _revertIfInvalidSignature(voter_, _getBallotWithReasonDigest(proposalId_, support_, reason_), signature_);

        return _castVote(voter_, proposalId_, support_, reason_);
    }

    /// @inheritdoc IBatchGovernor
    function castVotesWithReasonBySig(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        string[] calldata reasonList_,
        uint8 v_,
        bytes32 r_,
        bytes32 s_
    ) external returns (uint256 weight_) {
        return
            _castVotes(
                _getSignerAndRevertIfInvalidSignature(
                    _getBallotsWithReasonDigest(
                        keccak256(abi.encodePacked(proposalIds_)),
                        keccak256(abi.encodePacked(supportList_)),
                        _getReasonListHash(reasonList_)
                    ),
                    v_,
                    r_,
                    s_
                ),
                proposalIds_,
                supportList_,
                reasonList_
            );
    }

    /// @inheritdoc IBatchGovernor
    function castVotesWithReasonBySig(
        address voter_,
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        string[] calldata reasonList_,
        bytes memory signature_
    ) external returns (uint256 weight_) {
        _revertIfInvalidSignature(
            voter_,
            _getBallotsWithReasonDigest(
                keccak256(abi.encodePacked(proposalIds_)),
                keccak256(abi.encodePacked(supportList_)),
                _getReasonListHash(reasonList_)
            ),
            signature_
        );

        return _castVotes(voter_, proposalIds_, supportList_, reasonList_);
    }

    /* ============ View/Pure Functions ============ */

    /// @inheritdoc IGovernor
    function hashProposal(
        address[] memory,
        uint256[] memory,
        bytes[] memory callDatas_,
        bytes32
    ) external view returns (uint256) {
        return _hashProposal(callDatas_[0]);
    }

    /// @inheritdoc IBatchGovernor
    function hashProposal(bytes memory callData_) external view returns (uint256) {
        return _hashProposal(callData_);
    }

    /// @inheritdoc IGovernor
    function name() external view returns (string memory) {
        return _name;
    }

    /// @inheritdoc IGovernor
    function proposalDeadline(uint256 proposalId_) external view returns (uint256) {
        return _getVoteEnd(_proposals[proposalId_].voteStart);
    }

    /// @inheritdoc IGovernor
    function proposalProposer(uint256 proposalId_) external view returns (address) {
        return _proposals[proposalId_].proposer;
    }

    /// @inheritdoc IGovernor
    function proposalSnapshot(uint256 proposalId_) external view returns (uint256) {
        return _proposals[proposalId_].voteStart - 1;
    }

    /// @inheritdoc IGovernor
    function proposalVotes(uint256 proposalId_) external view returns (uint256, uint256, uint256) {
        Proposal storage proposal_ = _proposals[proposalId_];

        return (proposal_.noWeight, proposal_.yesWeight, 0);
    }

    /// @inheritdoc IGovernor
    function token() external view returns (address) {
        return voteToken;
    }

    /// @inheritdoc IERC6372
    function CLOCK_MODE() external pure returns (string memory) {
        return PureEpochs.clockMode();
    }

    /// @inheritdoc IGovernor
    function proposalThreshold() external pure returns (uint256) {
        return 0;
    }

    /// @inheritdoc IERC6372
    function clock() public view returns (uint48) {
        return _clock();
    }

    /// @inheritdoc IBatchGovernor
    function getBallotDigest(uint256 proposalId_, uint8 support_) external view returns (bytes32) {
        return _getBallotDigest(proposalId_, support_);
    }

    /// @inheritdoc IBatchGovernor
    function getBallotsDigest(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_
    ) external view returns (bytes32) {
        return _getBallotsDigest(keccak256(abi.encodePacked(proposalIds_)), keccak256(abi.encodePacked(supportList_)));
    }

    /// @inheritdoc IBatchGovernor
    function getBallotWithReasonDigest(
        uint256 proposalId_,
        uint8 support_,
        string calldata reason_
    ) external view returns (bytes32) {
        return _getBallotWithReasonDigest(proposalId_, support_, reason_);
    }

    /// @inheritdoc IBatchGovernor
    function getBallotsWithReasonDigest(
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        string[] calldata reasonList_
    ) external view returns (bytes32) {
        return
            _getBallotsWithReasonDigest(
                keccak256(abi.encodePacked(proposalIds_)),
                keccak256(abi.encodePacked(supportList_)),
                _getReasonListHash(reasonList_)
            );
    }

    /// @inheritdoc IGovernor
    function getVotes(address account_, uint256 timepoint_) public view returns (uint256) {
        return IEpochBasedVoteToken(voteToken).getPastVotes(account_, timepoint_);
    }

    /// @inheritdoc IGovernor
    function state(uint256 proposalId_) public view virtual returns (ProposalState);

    /// @inheritdoc IGovernor
    function votingDelay() public view returns (uint256) {
        return _votingDelay();
    }

    /// @inheritdoc IGovernor
    function votingPeriod() public view returns (uint256) {
        return _votingPeriod();
    }

    /* ============ Internal Interactive Functions ============ */

    /**
     * @dev    Cast votes on several proposals for `voter_`.
     * @param  voter_       The address of the voter.
     * @param  proposalIds_ The list of unique proposal IDs being voted on.
     * @param  supportList_ The list of support type per proposal IDs to cast.
     * @param  reasonList_  The list of reason per proposal IDs to cast.
     * @return weight_      The number of votes the voter cast on each proposal.
     */
    function _castVotes(
        address voter_,
        uint256[] calldata proposalIds_,
        uint8[] calldata supportList_,
        string[] memory reasonList_
    ) internal virtual returns (uint256 weight_) {
        uint256 length_ = proposalIds_.length;

        if (length_ == 0) revert EmptyProposalIdsArray();

        if (length_ != supportList_.length) revert ArrayLengthMismatch(length_, supportList_.length);

        if (length_ != reasonList_.length) revert ArrayLengthMismatch(length_, reasonList_.length);

        for (uint256 index_; index_ < length_; ++index_) {
            weight_ = _castVote(voter_, proposalIds_[index_], supportList_[index_], reasonList_[index_]);
        }
    }

    /**
     * @dev    Cast votes on proposal for `voter_`.
     * @param  voter_      The address of the voter.
     * @param  proposalId_ The unique identifier of the proposal.
     * @param  support_    The type of support to cast for the proposal.
     * @param  reason_     The reason for which the caller casts their vote, if any.
     * @return weight_     The number of votes cast.
     */
    function _castVote(
        address voter_,
        uint256 proposalId_,
        uint8 support_,
        string memory reason_
    ) internal returns (uint256 weight_) {
        ProposalState state_ = state(proposalId_);

        if (state_ != ProposalState.Active) revert ProposalInactive(state_);

        unchecked {
            // NOTE: Can be done unchecked since `voteStart` is always greater than 0.
            weight_ = getVotes(voter_, _proposals[proposalId_].voteStart - 1);
        }

        _castVote(voter_, weight_, proposalId_, support_, reason_);
    }

    /**
     * @dev   Cast `weight_` votes on a proposal with id `proposalId_` for `voter_`.
     * @param voter_      The address of the voter.
     * @param weight_     The number of votes the voter is casting.
     * @param proposalId_ The unique identifier of the proposal.
     * @param support_    The type of support to cast for the proposal.
     * @param reason_     The reason for which the caller casts their vote, if any.
     */
    function _castVote(
        address voter_,
        uint256 weight_,
        uint256 proposalId_,
        uint8 support_,
        string memory reason_
    ) internal virtual {
        if (weight_ == 0) revert ZeroVotingPower();
        if (hasVoted[proposalId_][voter_]) revert AlreadyVoted();

        hasVoted[proposalId_][voter_] = true;

        unchecked {
            // NOTE: Can be done unchecked since total supply is less than `type(uint256).max`.
            if (VoteType(support_) == VoteType.No) {
                _proposals[proposalId_].noWeight += weight_;
            } else {
                _proposals[proposalId_].yesWeight += weight_;
            }
        }

        emit VoteCast(voter_, proposalId_, support_, weight_, reason_);
    }

    /**
     * @dev   Creates a new proposal with the given parameters.
     * @param proposalId_ The unique identifier of the proposal.
     * @param voteStart_  The epoch at which the proposal will start collecting votes.
     */
    function _createProposal(uint256 proposalId_, uint16 voteStart_) internal virtual;

    /**
     * @dev    Executes a proposal given its call data and voteStart (which are unique to it).
     * @param  callData_   The call data to execute.
     * @param  voteStart_  The epoch at which the proposal started collecting votes.
     * @return proposalId_ The unique identifier of the proposal that matched the criteria.
     */
    function _execute(bytes memory callData_, uint16 voteStart_) internal virtual returns (uint256 proposalId_) {
        proposalId_ = _hashProposal(callData_, voteStart_);

        Proposal storage proposal_ = _proposals[proposalId_];

        if (proposal_.voteStart != voteStart_) return 0;

        if (state(proposalId_) != ProposalState.Succeeded) return 0;

        proposal_.executed = true;

        emit ProposalExecuted(proposalId_);

        // solhint-disable-next-line avoid-low-level-calls
        (bool success_, bytes memory data_) = address(this).call(callData_);

        if (!success_) revert ExecutionFailed(data_);
    }

    /**
     * @dev    Internal handler for making proposals.
     * @param  targets_     An array of addresses that will be called upon the execution.
     * @param  values_      An array of ETH amounts that will be sent to each respective target upon execution.
     * @param  callDatas_   An array of call data used to call each respective target upon execution.
     * @param  description_ The string of the description of the proposal.
     * @return proposalId_  The unique identifier of the proposal.
     * @return voteStart_   The timepoint at which voting on the proposal begins, inclusively.
     */
    function _propose(
        address[] memory targets_,
        uint256[] memory values_,
        bytes[] memory callDatas_,
        string memory description_
    ) internal returns (uint256 proposalId_, uint16 voteStart_) {
        _revertIfInvalidProposal(targets_, values_, callDatas_);

        voteStart_ = _voteStart();

        proposalId_ = _hashProposal(callDatas_[0], voteStart_);

        if (_proposals[proposalId_].voteStart != 0) revert ProposalExists();

        _createProposal(proposalId_, voteStart_);

        emit ProposalCreated(
            proposalId_,
            msg.sender,
            targets_,
            values_,
            new string[](targets_.length),
            callDatas_,
            voteStart_,
            _getVoteEnd(voteStart_),
            description_
        );
    }

    /**
     * @dev    This function tries to execute a proposal based on the call data and a range of possible vote starts.
     *         This is needed due to the fact that proposalId's are generated based on the call data and vote start
     *         time, and so an executed function will need this in order to attempt to find and execute a proposal given
     *         a known range of possible vote start times which depends on how the inheriting implementation
     *         determines the vote start time and expiry of proposals based on the time of the proposal creation.
     * @param  callData_          An array of call data used to call each respective target upon execution.
     * @param  latestVoteStart_   The most recent vote start to use in attempting to search for the proposal.
     * @param  earliestVoteStart_ The least recent vote start to use in attempting to search for the proposal.
     * @return proposalId_        The unique identifier of the most recent proposal that matched the criteria.
     */
    function _tryExecute(
        bytes memory callData_,
        uint16 latestVoteStart_,
        uint16 earliestVoteStart_
    ) internal returns (uint256 proposalId_) {
        if (msg.value != 0) revert InvalidValue();

        // Non-existent proposals have a default vote start of 0
        if (earliestVoteStart_ == 0) revert InvalidVoteStart();

        while (latestVoteStart_ >= earliestVoteStart_) {
            // `proposalId_` will be 0 if no proposal exists for `callData_` and `latestVoteStart_`, or if the proposal
            // is not in  a `Succeeded` state. It will be executed otherwise. (see `_execute`)
            unchecked {
                proposalId_ = _execute(callData_, latestVoteStart_--);
            }

            // If the `proposalId_` is not 0, then a proposal matching `callData_` and `latestVoteStart_` was found, in
            // a Succeeded state, and was executed, so return it.
            if (proposalId_ != 0) return proposalId_;
        }

        revert ProposalCannotBeExecuted(); // No proposal matching the criteria was found/executed.
    }

    /* ============ Internal View/Pure Functions ============ */

    /// @dev Returns the current timepoint according to the mode the contract is operating on.
    function _clock() internal view returns (uint16) {
        return PureEpochs.currentEpoch();
    }

    /**
     * @dev    Returns the vote token's total supply at `timepoint_`.
     * @param  timepoint_ The clock value at which to query the vote token's total supply.
     * @return The vote token's total supply at the `timepoint` clock value.
     */
    function _getTotalSupply(uint16 timepoint_) internal view returns (uint256) {
        return IEpochBasedVoteToken(voteToken).pastTotalSupply(timepoint_);
    }

    /// @dev Returns the timepoint at which voting would start for a proposal created in current timepoint.
    function _voteStart() internal view returns (uint16) {
        unchecked {
            return _clock() + _votingDelay();
        }
    }

    /**
     * @dev    Returns the timepoint at which voting would end given a timepoint at which voting would start.
     * @param  voteStart_ The clock value at which voting would start, inclusively.
     * @return The clock value at which voting would end, inclusively.
     */
    function _getVoteEnd(uint16 voteStart_) internal view returns (uint16) {
        unchecked {
            return voteStart_ + _votingPeriod();
        }
    }

    /**
     * @dev    Returns the ballot digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalId_ The unique proposal ID being voted on.
     * @param  support_    The type of support to cast for the proposal.
     * @return The digest to be signed.
     */
    function _getBallotDigest(uint256 proposalId_, uint8 support_) internal view returns (bytes32) {
        return _getDigest(keccak256(abi.encode(BALLOT_TYPEHASH, proposalId_, support_)));
    }

    /**
     * @dev    Returns the ballots digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalIdsHash_ The hash of the list of unique proposal IDs being voted on.
     * @param  supportListHash_ The hash of the list of support type per proposal IDs to cast.
     * @return The digest to be signed.
     */
    function _getBallotsDigest(bytes32 proposalIdsHash_, bytes32 supportListHash_) internal view returns (bytes32) {
        return _getDigest(keccak256(abi.encode(BALLOTS_TYPEHASH, proposalIdsHash_, supportListHash_)));
    }

    /**
     * @dev    Returns the ballot with reason digest to be signed, via EIP-712,
     *         given an internal digest (i.e. hash struct).
     * @param  proposalId_ The unique proposal ID being voted on.
     * @param  support_    The type of support to cast for the proposal.
     * @param  reason_     The reason for which the caller casts their vote, if any.
     * @return The digest to be signed.
     */
    function _getBallotWithReasonDigest(
        uint256 proposalId_,
        uint8 support_,
        string calldata reason_
    ) internal view returns (bytes32) {
        return
            _getDigest(
                keccak256(abi.encode(BALLOT_WITH_REASON_TYPEHASH, proposalId_, support_, keccak256(bytes(reason_))))
            );
    }

    /**
     * @dev    Returns the ballots digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalIdsHash_ The hash of the list of unique proposal IDs being voted on.
     * @param  supportListHash_ The hash of the list of support type per proposal IDs to cast.
     * @param  reasonListHash_  The hash of the list of reason per proposal IDs to cast.
     * @return The digest to be signed.
     */
    function _getBallotsWithReasonDigest(
        bytes32 proposalIdsHash_,
        bytes32 supportListHash_,
        bytes32 reasonListHash_
    ) internal view returns (bytes32) {
        return
            _getDigest(
                keccak256(abi.encode(BALLOTS_WITH_REASON_TYPEHASH, proposalIdsHash_, supportListHash_, reasonListHash_))
            );
    }

    /**
     * @dev    Returns the hash of the reason list to be used in the ballots digest.
     * @param  reasonList_ The list of reasons to hash.
     * @return The hash of the reason list.
     */
    function _getReasonListHash(string[] calldata reasonList_) internal pure returns (bytes32) {
        uint256 reasonListLength_ = reasonList_.length;
        bytes32[] memory reasonListBytes_ = new bytes32[](reasonListLength_);

        for (uint256 index_; index_ < reasonListLength_; ++index_) {
            reasonListBytes_[index_] = keccak256(bytes(reasonList_[index_]));
        }

        return keccak256(abi.encodePacked(reasonListBytes_));
    }

    /**
     * @dev    Returns the unique identifier for the proposal if it were created at this exact moment.
     * @param  callData_ The single call data used to call this governor upon execution of a proposal.
     * @return The unique identifier for the proposal.
     */
    function _hashProposal(bytes memory callData_) internal view returns (uint256) {
        return _hashProposal(callData_, _voteStart());
    }

    /**
     * @dev    Returns the unique identifier for the proposal if it were to have a given vote start timepoint.
     * @param  callData_  The single call data used to call this governor upon execution of a proposal.
     * @param  voteStart_ The clock value at which voting would start, inclusively.
     * @return The unique identifier for the proposal.
     */
    function _hashProposal(bytes memory callData_, uint16 voteStart_) internal view returns (uint256) {
        return uint256(keccak256(abi.encode(callData_, voteStart_, address(this))));
    }

    /// @dev Reverts if the caller is not the contract itself.
    function _revertIfNotSelf() internal view {
        if (msg.sender != address(this)) revert NotSelf();
    }

    /// @dev Returns the number of clock values that must elapse before voting begins for a newly created proposal.
    function _votingDelay() internal view virtual returns (uint16);

    /// @dev Returns the number of clock values between the vote start and vote end.
    function _votingPeriod() internal view virtual returns (uint16);

    /**
     * @dev   All proposals target this contract itself, and must call one of the listed functions to be valid.
     * @param callData_ The call data to check.
     */
    function _revertIfInvalidCalldata(bytes memory callData_) internal pure virtual;

    /**
     * @dev   Reverts if the proposal arguments are invalid.
     * @param targets_   An array of addresses that will be called upon the execution.
     * @param values_    An array of ETH amounts that will be sent to each respective target upon execution.
     * @param callDatas_ An array of call data used to call each respective target upon execution.
     */
    function _revertIfInvalidProposal(
        address[] memory targets_,
        uint256[] memory values_,
        bytes[] memory callDatas_
    ) internal view {
        if (targets_.length != 1) revert InvalidTargetsLength();
        if (targets_[0] != address(this)) revert InvalidTarget();

        if (values_.length != 1) revert InvalidValuesLength();
        if (values_[0] != 0) revert InvalidValue();

        if (callDatas_.length != 1) revert InvalidCallDatasLength();

        _revertIfInvalidCalldata(callDatas_[0]);
    }
}


// ============================================================================
// FILE: lib/ttg/src/interfaces/IDeployer.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

/**
 * @title  A Deterministic deployer of contracts using CREATE.
 * @author M^0 Labs
 */
interface IDeployer {
    /// @notice Returns the nonce used to pre deterministically compute the address of the next deployed contract.
    function nonce() external view returns (uint256);

    /// @notice Returns the address of the last contract deployed by this contract.
    function lastDeploy() external view returns (address);

    /// @notice Returns the address of the next contract this contract will deploy.
    function nextDeploy() external view returns (address);
}


// ============================================================================
// FILE: lib/ttg/src/abstract/interfaces/IBatchGovernor.sol
// ============================================================================

// SPDX-License-Identifier: GPL-3.0

pragma solidity 0.8.23;

import { IGovernor } from "./IGovernor.sol";

/**
 * @title  Extension for Governor with specialized strict proposal parameters, vote batching, and an epoch clock.
 * @author M^0 Labs
 */
interface IBatchGovernor is IGovernor {
    /* ============ Enums ============ */

    /**
     * @notice The type of support to cast for a proposal.
     * @param  No  The voter does not support the proposal.
     * @param  Yes The voter supports the proposal.
     */
    enum VoteType {
        No,
        Yes
    }

    /* ============ Custom Errors ============ */

    /// @notice Revert message when a voter is trying to vote on a proposal they already voted on.
    error AlreadyVoted();

    /// @notice Revert message when input arrays do not match in length.
    error ArrayLengthMismatch(uint256 length1, uint256 length2);

    /// @notice Revert message when the proposal IDs array is empty.
    error EmptyProposalIdsArray();

    /**
     * @notice Revert message when execution of a proposal fails.
     * @param  data The revert data returned due to the failed execution.
     */
    error ExecutionFailed(bytes data);

    /// @notice Revert message when a proposal's call data is not specifically supported.
    error InvalidCallData();

    /// @notice Revert message when a proposal's call data array is not of length 1.
    error InvalidCallDatasLength();

    /// @notice Revert message when a proposal target is not this governor itself.
    error InvalidTarget();

    /// @notice Revert message when a proposal's targets array is not of length 1.
    error InvalidTargetsLength();

    /// @notice Revert message when a proposal value is not 0 ETH.
    error InvalidValue();

    /// @notice Revert message when a proposal's values array is not of length 1.
    error InvalidValuesLength();

    /// @notice Revert message when a an invalid vote start is detected.
    error InvalidVoteStart();

    /// @notice Revert message when the vote token specified in the constructor is address(0).
    error InvalidVoteTokenAddress();

    /// @notice Revert message when the caller of a governance-controlled function is not this governor itself.
    error NotSelf();

    /// @notice Revert message when the proposal information provided cannot be executed.
    error ProposalCannotBeExecuted();

    /// @notice Revert message when the proposal does not exist.
    error ProposalDoesNotExist();

    /// @notice Revert message when the proposal already exists.
    error ProposalExists();

    /**
     * @notice Revert message when voting on a proposal that is not in an active state (i.e. not collecting votes).
     * @param  state The current state of the proposal.
     */
    error ProposalInactive(ProposalState state);

    /// @notice Revert message when voting on a proposal with a zero voting weight.
    error ZeroVotingPower();

    /* ============ Interactive Functions ============ */

    /**
     * @notice Allows the caller to cast votes on multiple proposals.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotes(uint256[] calldata proposalIds, uint8[] calldata supportList) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes on multiple proposals via an ECDSA secp256k1 signature.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  v           An ECDSA secp256k1 signature parameter.
     * @param  r           An ECDSA secp256k1 signature parameter.
     * @param  s           An ECDSA secp256k1 signature parameter.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesBySig(
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes on multiple proposals via an arbitrary signature.
     * @param  voter       The address of the account casting the votes.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  signature   An arbitrary signature
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesBySig(
        address voter,
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        bytes memory signature
    ) external returns (uint256 weight);

    /**
     * @notice Allows the caller to cast votes with reason on multiple proposals.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  reasonList  The list of reason per proposal IDs to cast.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesWithReason(
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        string[] calldata reasonList
    ) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes with reason on multiple proposals via an ECDSA secp256k1 signature.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  reasonList  The list of reason per proposal IDs to cast.
     * @param  v           An ECDSA secp256k1 signature parameter.
     * @param  r           An ECDSA secp256k1 signature parameter.
     * @param  s           An ECDSA secp256k1 signature parameter.
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesWithReasonBySig(
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        string[] calldata reasonList,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256 weight);

    /**
     * @notice Allows a signer to cast votes with reason on multiple proposals via an arbitrary signature.
     * @param  voter       The address of the account casting the votes.
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  reasonList  The list of reason per proposal IDs to cast.
     * @param  signature   An arbitrary signature
     * @return weight      The number of votes cast for each proposal (the same for all of them).
     */
    function castVotesWithReasonBySig(
        address voter,
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        string[] calldata reasonList,
        bytes memory signature
    ) external returns (uint256 weight);

    /* ============ View/Pure Functions ============ */

    /**
     * @notice Returns the ballot digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalId The unique proposal ID being voted on.
     * @param  support    The type of support to cast for the proposal.
     * @return The digest to be signed.
     */
    function getBallotDigest(uint256 proposalId, uint8 support) external view returns (bytes32);

    /**
     * @notice Returns the ballots digest to be signed, via EIP-712, given an internal digest (i.e. hash struct).
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @return The digest to be signed.
     */
    function getBallotsDigest(
        uint256[] calldata proposalIds,
        uint8[] calldata supportList
    ) external view returns (bytes32);

    /**
     * @notice Returns the ballot with reason digest to be signed, via EIP-712,
     *         given an internal digest (i.e. hash struct).
     * @param  proposalId The unique proposal ID being voted on.
     * @param  support    The type of support to cast for the proposal.
     * @param  reason     The reason for which the caller casts their vote, if any.
     * @return The digest to be signed.
     */
    function getBallotWithReasonDigest(
        uint256 proposalId,
        uint8 support,
        string calldata reason
    ) external view returns (bytes32);

    /**
     * @notice Returns the ballots with reason digest to be signed, via EIP-712,
     *         given an internal digest (i.e. hash struct).
     * @param  proposalIds The list of unique proposal IDs being voted on.
     * @param  supportList The list of support type per proposal IDs to cast.
     * @param  reasonList  The list of reason per proposal IDs to cast.
     * @return The digest to be signed.
     */
    function getBallotsWithReasonDigest(
        uint256[] calldata proposalIds,
        uint8[] calldata supportList,
        string[] calldata reasonList
    ) external view returns (bytes32);

    /**
     * @notice Returns the unique identifier for the proposal if it were created at this exact moment.
     * @param  callData The single call data used to call this governor upon execution of a proposal.
     * @return The unique identifier for the proposal.
     */
    function hashProposal(bytes memory callData) external view returns (uint256);

    /// @notice Returns the EIP-5805 token contact used for determine voting power and total supplies.
    function voteToken() external view returns (address);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for `castVotesBySig` function.
    function BALLOTS_TYPEHASH() external pure returns (bytes32);

    /// @notice Returns the EIP712 typehash used in the encoding of the digest for `castVotesWithReasonBySig` function.
    function BALLOTS_WITH_REASON_TYPEHASH() external pure returns (bytes32);
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
