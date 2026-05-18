// SPDX-License-Identifier: UNLICENSED
// Source: 0x8098af2b2066382b07d7f3959e414a2e414d7dfc
// Contract Name: Arbitrator
// Generated on: 2026-05-14 11:59:35


// ============================================================================
// FILE: src/tontine/Arbitrator.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Owned} from "solmate/auth/Owned.sol";
import {ERC20} from "solmate/tokens/ERC20.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";
import {EIP712} from "openzeppelin/utils/cryptography/EIP712.sol";

import {IArbitrator} from "../interfaces/IArbitrator.sol";

contract Arbitrator is Owned, IArbitrator, EIP712 {
    using ECDSA for bytes32;

    /// Minimum random value
    uint256 private constant RAND_MIN = 1;
    /// Maximum random value
    uint256 private constant RAND_MAX = 25;
    /// Ante percentage e.g 1000 / 10000 = .1 = 10%
    uint128 private constant ANTE = 1000;
    /// Denominator for percentage values e.g 1000 / 10000 = .1 = 10%
    uint128 private constant DENOMINATOR = 10000;
    /// Maximum allowed fee percentage
    uint128 private constant MAX_FEE = 1000;
    /// Number of blocks before a given game can begin
    uint64 private constant START_DELAY = 99 seconds;
    /// TODO ? Time between turns ?
    uint64 private constant DEFAULT_CADENCE = 99 seconds;
    /// Minimum number of players in a given game
    uint8 private constant MIN_SEATS = 2;
    /// Maximum number of players in a given game
    uint8 private constant MAX_SEATS = 100;
    /// Randomness function signature
    bytes32 private constant RANDOMNESS_TYPEHASH =
        keccak256("Randomness(uint256 randomness,uint64 counter,uint256 id)");

    /// Fee receiver address
    address public feeController;
    /// Current fee percentage
    uint128 public fee = 500;
    /// Latest created game (array index)
    uint256 public currentId;
    /// Randomness supplier/signer address
    address public rngSource;

    /// Bitmasked of allowed game modes
    uint256 private modeAllowlist;
    /// Current game balances
    mapping(address => uint256) private balances;
    /// Arrays of participants based on tontine ID
    mapping(uint256 => address[]) private participants;
    /// Assets allowed for game use
    mapping(address => bool) private assetAllowlist;
    /// Tontines
    mapping(uint256 => Tontine) private tontines;
    /// Activity tracking
    mapping(bytes32 => bool) private activityLog;

    constructor(
        address _admin,
        address _feeController,
        address _rngSource
    ) Owned(_admin) EIP712("Tontine", "1") {
        feeController = _feeController;
        rngSource = _rngSource;
    }

    /// @notice Create a new Tontine
    /// @param _asset Game currency to be used
    /// @param _bet Starting bet amount
    /// @param _seats Number of players
    /// @param _betMode Lobby betting mode
    /// @param _rngMode Lobby RNG mode
    function create(
        address _asset,
        uint128 _bet,
        uint8 _seats,
        BetMode _betMode,
        RNGMode _rngMode
    ) external payable {
        if (tx.origin != msg.sender) revert NotEOA();
        if (_seats < MIN_SEATS || _seats > MAX_SEATS) revert InvalidSeatCount();
        if (_bet == 0) revert InvalidBet();
        if (!getBetModeAllowed(_betMode) || !getRNGModeAllowed(_rngMode))
            revert InvalidMode();
        if (!assetAllowlist[_asset]) revert InvalidAsset();

        Tontine storage tontine = tontines[currentId];
        tontine.asset = _asset;
        tontine.seats = _seats;
        tontine.betMode = _betMode;
        tontine.rngMode = _rngMode;
        tontine.bet = _bet;
        tontine.balance = _bet;
        tontine.participantState = 1 << 127;

        participants[currentId].push(msg.sender);
        unchecked {
            balances[_asset] += _bet;
            currentId++;
        }

        activityLog[
            _getParticipantIdentifier(msg.sender, currentId - 1)
        ] = true;

        if (_asset == address(0)) {
            if (msg.value != _bet) revert InvalidBet();
        } else {
            if (msg.value > 0) revert InvalidBet();
            ERC20(_asset).transferFrom(msg.sender, address(this), _bet);
        }

        emit Created(currentId - 1, _bet, _asset);
        emit Joined(currentId - 1, msg.sender);
    }

    /// @notice Join an existing Tontine
    /// @param _id Tontine ID
    function join(uint256 _id) external payable {
        Tontine storage tontine = tontines[_id];
        address asset = tontine.asset;
        uint128 bet = tontine.bet;

        if (tx.origin != msg.sender) revert NotEOA();
        if (tontine.lastBetTime != 0) revert AlreadyStarted();
        // If the ID doesn't exist it will revert as "Ended"
        if (tontine.participantState == 0) revert Ended();

        bytes32 participantId = _getParticipantIdentifier(msg.sender, _id);
        if (activityLog[participantId]) revert AlreadyJoined();

        uint8 participantLength = uint8(participants[_id].length);

        unchecked {
            tontine.participantState |= uint128(1 << (127 - participantLength));
            tontine.balance += bet;
            balances[asset] += bet;
        }

        participants[_id].push(msg.sender);
        activityLog[participantId] = true;

        // Start round if full
        if (++participantLength == tontine.seats) {
            // Schedule start time
            tontine.lastBetTime = uint64(block.timestamp) + START_DELAY;
            // Scramble order to keep odds uniform
            tontine.lastIndex = _scramble(tontine.seats);

            // Deduct fee on start such that participants are not charged fees when leaving
            uint128 feeDelta = tontine.balance -
                _getBetAfterFee(tontine.balance);
            unchecked {
                tontine.balance -= feeDelta;
                balances[asset] -= feeDelta;
            }

            emit Started(_id);
        }

        if (asset == address(0)) {
            if (msg.value != bet) revert InvalidBet();
        } else {
            if (msg.value != 0) revert InvalidBet();
            ERC20(asset).transferFrom(msg.sender, address(this), bet);
        }

        emit Joined(currentId, msg.sender);
    }

    /// @notice Leave a tontine lobby (that hasn't started yet)
    /// @param _id Tontine ID
    /// @param _index Participant array ID
    function leave(uint256 _id, uint8 _index) external {
        Tontine storage tontine = tontines[_id];
        address[] storage participantArray = participants[_id];

        if (tx.origin != msg.sender) revert NotEOA();
        if (tontine.lastBetTime != 0) revert AlreadyStarted();
        if (participantArray[_index] != msg.sender) revert NotJoined();

        uint128 bet = tontine.bet;
        address asset = tontine.asset;
        unchecked {
            balances[tontine.asset] -= bet;
            tontine.balance -= bet;
        }

        // Clear state
        if (participantArray.length <= 1) {
            delete participants[_id];
            delete tontines[_id];
            emit Claimed(_id, address(0), address(0), 0);
        } else {
            participantArray[_index] = participantArray[
                participantArray.length - 1
            ];
            participantArray.pop();
            tontine.participantState ^= uint128(
                1 << (127 - participantArray.length)
            );
        }

        delete activityLog[_getParticipantIdentifier(msg.sender, _id)];

        // Return funds
        if (asset == address(0)) {
            payable(msg.sender).transfer(bet);
        } else {
            ERC20(asset).transfer(msg.sender, bet);
        }

        emit Left(_id, msg.sender);
    }

    /// @notice Leave an already started game - funds will NOT be returned
    /// @param _id Tontine ID
    /// @param _index Participant array ID
    function fold(uint256 _id, uint8 _index) external {
        Tontine storage tontine = tontines[_id];
        uint64 lastBetTime = tontine.lastBetTime;

        if (tx.origin != msg.sender) revert NotEOA();
        if (lastBetTime == 0 || lastBetTime > block.timestamp)
            revert NotStarted();
        if (participants[_id][_index] != msg.sender) revert NotJoined();

        (
            uint128 participantState,
            bool ended,
            uint256 currentIndex
        ) = _updateParticipantState(
                tontine.participantState,
                tontine.lastIndex,
                lastBetTime,
                tontine.seats
            );

        if (currentIndex != _index) revert NotTurn();
        if (ended || _isLastAlive(participantState, _index)) revert Ended();
        if (!_isAlive(participantState, _index)) revert PlayerNotAlive();

        tontine.participantState = _killPlayer(participantState, _index);
        tontine.lastIndex = _index;
        tontine.lastBetTime = uint64(block.timestamp);
        ++tontine.counter;

        emit Folded(_id, msg.sender);
    }

    /// Play your turn
    /// @param _id Tontine ID
    /// @param _index Participant array ID
    /// @param _bet Bet amount in  wei
    /// @param _rng Randomness data
    /// @param _sig Signed randomness data
    function play(
        uint256 _id,
        uint8 _index,
        uint128 _bet,
        Randomness calldata _rng,
        bytes calldata _sig
    ) external payable {
        Tontine storage tontine = tontines[_id];
        uint64 lastBetTime = tontine.lastBetTime;

        if (tx.origin != msg.sender) revert NotEOA();
        if (lastBetTime == 0 || lastBetTime > block.timestamp)
            revert NotStarted();
        if (participants[_id][_index] != msg.sender) revert NotJoined();

        if (tontine.counter > 0 && tontine.rngMode == RNGMode.RANDOM) {
            uint32 counter = tontine.counter;
            if (_rng.id != _id) revert InvalidID();
            if (_rng.counter != counter) revert InvalidCounter();
            _validateRandomness(_rng, _sig);

            if (
                _shouldKillLastPlayer(
                    _id,
                    counter,
                    tontine.rngMode,
                    _rng.randomness
                )
            ) {
                tontine.participantState = _killPlayer(
                    tontine.participantState,
                    tontine.lastIndex
                );
            }
        }

        (
            uint128 participantState,
            bool ended,
            uint256 currentIndex
        ) = _updateParticipantState(
                tontine.participantState,
                tontine.lastIndex,
                lastBetTime,
                tontine.seats
            );

        if (currentIndex != _index) revert NotTurn();
        if (ended || _isLastAlive(participantState, _index)) revert Ended();

        // Handling for alternate bet modes
        if (_bet >= tontine.bet && tontine.betMode == BetMode.VARIABLE) {
            tontine.bet = _bet;
        } else if (tontine.betMode == BetMode.ANTE) {
            tontine.bet = (tontine.bet * (DENOMINATOR + ANTE)) / DENOMINATOR;
        }

        uint128 betAfterFee = _getBetAfterFee(tontine.bet);
        tontine.balance += betAfterFee;
        balances[tontine.asset] += betAfterFee;
        tontine.lastBetTime = uint64(block.timestamp);
        tontine.lastIndex = _index;
        tontine.participantState = participantState;
        ++tontine.counter;

        if (tontine.asset == address(0)) {
            if (msg.value != tontine.bet) revert InvalidBet();
        } else {
            if (msg.value > 0) revert InvalidBet();
            ERC20(tontine.asset).transferFrom(
                msg.sender,
                address(this),
                tontine.bet
            );
        }

        emit Played(_id, msg.sender, tontine.bet);
    }

    /// @notice Claim winnings when you're the last person standing
    /// @param _id Tontine ID
    /// @param _index Participant array ID
    /// @param _rng Randomness data
    /// @param _sig Signed randomness data
    function claim(
        uint256 _id,
        uint8 _index,
        Randomness calldata _rng,
        bytes calldata _sig
    ) external {
        Tontine storage tontine = tontines[_id];
        uint64 lastBetTime = tontine.lastBetTime;

        if (tx.origin != msg.sender) revert NotEOA();
        if (tontine.participantState == 0) revert AlreadyClaimed();
        if (lastBetTime == 0 || lastBetTime > block.timestamp)
            revert NotStarted();
        if (participants[_id][_index] != msg.sender) revert NotJoined();

        if (tontine.counter > 0 && tontine.rngMode == RNGMode.RANDOM) {
            uint32 counter = tontine.counter;
            if (_rng.id != _id) revert InvalidID();
            if (_rng.counter != counter) revert InvalidCounter();
            _validateRandomness(_rng, _sig);

            if (
                _shouldKillLastPlayer(
                    _id,
                    counter,
                    tontine.rngMode,
                    _rng.randomness
                )
            ) {
                tontine.participantState = _killPlayer(
                    tontine.participantState,
                    tontine.lastIndex
                );
            }
        }

        (uint128 participantState, bool ended, ) = _updateParticipantState(
            tontine.participantState,
            tontine.lastIndex,
            lastBetTime,
            tontine.seats
        );

        if (!_isAlive(participantState, _index)) revert PlayerNotAlive();
        if (!ended && !_isLastAlive(participantState, _index)) revert Running();

        uint128 amount = tontine.balance;

        tontine.balance = 0;
        unchecked {
            balances[tontine.asset] -= amount;
        }
        address asset = tontine.asset;

        delete tontines[_id];
        delete participants[_id];

        // Return funds
        if (asset == address(0)) {
            payable(msg.sender).transfer(amount);
        } else {
            ERC20(asset).transfer(msg.sender, amount);
        }

        emit Claimed(_id, msg.sender, asset, amount);
    }

    /// @notice Collect and send held fees to controller
    /// @dev Use zero address for native currency
    /// @param _asset Asset to be collected
    function collectFees(address _asset) external {
        if (!assetAllowlist[_asset]) revert InvalidAsset();

        if (_asset == address(0)) {
            payable(feeController).transfer(
                address(this).balance - balances[_asset]
            );
        } else {
            ERC20(_asset).transfer(
                feeController,
                ERC20(_asset).balanceOf(address(this)) - balances[_asset]
            );
        }
    }

    /// @notice Sets a new controller address
    /// @param _feeController New controller address
    function setFeeController(address _feeController) external {
        if (msg.sender != feeController) revert InvalidCaller();
        feeController = _feeController;
    }

    /// @notice Sets a new fee
    /// @dev Fee is determined by division e.g 500 / 10000 = .05 = 5%
    /// @param _fee New fee percentage
    function setFee(uint128 _fee) external {
        if (msg.sender != feeController) revert InvalidCaller();
        if (_fee > MAX_FEE) revert MaxFeeExceeded();
        fee = _fee;
    }

    /// @notice White/blacklists a given asset
    /// @dev Use  zero address for native currency
    /// @param _asset Asset to be allowed/disallowed
    /// @param _allowed Is this asset allowed?
    function setAssetAllowlist(
        address _asset,
        bool _allowed
    ) external onlyOwner {
        assetAllowlist[_asset] = _allowed;
    }

    /// @notice Sets a new bitmask of allowed game modes
    /// @param _allowlist New mode allow list value
    function setModeAllowlist(uint256 _allowlist) external onlyOwner {
        modeAllowlist = _allowlist;
    }

    /// @notice Sets the signer that is in charge of supplying randomness
    /// @param _rngSource New signer address
    function setRNGSource(address _rngSource) external onlyOwner {
        rngSource = _rngSource;
    }

    /// @notice Helper to more easily determine if a bet mode is allowed as opposed to shifting bitmask
    /// @param _mode Betmode enum value
    /// @return Is the supplied mode allowed?
    function getBetModeAllowed(
        BetMode _mode
    ) public view override returns (bool) {
        return ((modeAllowlist >> uint8(_mode)) & 1) == 1;
    }

    /// @notice Helper to more easily determine if a bet mode is allowed as opposed to shifting bitmask
    /// @param _mode RNG enum value
    /// @return Is the supplied mode allowed?
    function getRNGModeAllowed(
        RNGMode _mode
    ) public view override returns (bool) {
        return ((modeAllowlist >> (uint8(_mode) + 128)) & 1) == 1;
    }

    /// TODO: Is this needed? Appears unused.  Document if needed
    function getRandomness(
        uint256 _id,
        uint64 _counter
    ) public pure override returns (uint256) {
        return (uint256(keccak256(abi.encodePacked(_id, _counter))) % RAND_MAX);
    }

    /// Participant state for a given lobby
    /// @param _id Tontine ID
    /// @param _rng Randomness data
    /// @return Participant state
    /// @return Last player index
    /// @return Seats in tontine
    function getParticipantState(
        uint256 _id,
        Randomness calldata _rng
    ) public view override returns (uint128, bool, uint256) {
        Tontine memory tontine = tontines[_id];
        uint64 lastBetTime = tontine.lastBetTime;

        if (lastBetTime == 0) {
            return (tontine.participantState, false, 0);
        }

        if (tontine.counter > 0 && tontine.rngMode == RNGMode.RANDOM) {
            if (
                _shouldKillLastPlayer(
                    _id,
                    tontine.counter,
                    tontine.rngMode,
                    _rng.randomness
                )
            ) {
                tontine.participantState = _killPlayer(
                    tontine.participantState,
                    tontine.lastIndex
                );
            }
        }

        return
            _updateParticipantState(
                tontine.participantState,
                tontine.lastIndex,
                lastBetTime,
                tontine.seats
            );
    }

    /// TODO: Duplicate function, not exactly necessary.  Change internal visibility on original (ln 600)
    function getParticipantIdentifier(
        address _participant,
        uint256 _id
    ) external pure override returns (bytes32) {
        return _getParticipantIdentifier(_participant, _id);
    }

    /// Gets amount after fees
    /// @dev Use WEI
    /// @param _amount Amount in
    /// @return Amount out
    function getAmountAfterFee(
        uint256 _amount
    ) external view override returns (uint256) {
        return (_amount * (DENOMINATOR - fee)) / DENOMINATOR;
    }

    /// Gets a tontine
    /// @param _id Tontine ID
    function getTontine(
        uint256 _id
    ) external view override returns (Tontine memory) {
        return (tontines[_id]);
    }

    /// Checks if a given address/participant is still active
    /// @param _participant Participant address
    /// @param _id Tontine ID
    /// @return Is participant active?
    function isActive(
        address _participant,
        uint256 _id
    ) external view override returns (bool) {
        return activityLog[_getParticipantIdentifier(_participant, _id)];
    }

    /// Gets balance of supplied token address (contract accounting)
    /// @dev Amount returned in WEI
    /// @dev Use zero address for base currency
    /// @param _token Token address
    function getBalance(
        address _token
    ) external view override returns (uint256) {
        return balances[_token];
    }

    /// Gets address for supplied IDs
    /// @param _id Tontine ID
    /// @param _index Participant array ID
    /// @return Participant address
    function getParticipant(
        uint256 _id,
        uint256 _index
    ) external view override returns (address) {
        return participants[_id][_index];
    }

    /// Gets all participants in a given lobby
    /// @param _id Tontine ID
    /// @return Array of participants
    function getParticipants(
        uint256 _id
    ) external view override returns (address[] memory) {
        return participants[_id];
    }

    /// Checks if an asset is allowed for game
    /// @dev Use zero address for base currency
    /// @param _asset Asset/token address
    /// @return Is asset allowed?
    function getAssetAllowed(
        address _asset
    ) external view override returns (bool) {
        return assetAllowlist[_asset];
    }

    /// Hashes randomness data
    /// @param _rng Randomness data
    /// @return Hashed randomness data
    function randomnessHash(
        Randomness memory _rng
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        RANDOMNESS_TYPEHASH,
                        _rng.randomness,
                        _rng.counter,
                        _rng.id
                    )
                )
            );
    }

    /// Validates signed randomness data
    /// @param _rng Randomness data
    /// @param _sig Signed randomness data
    function _validateRandomness(
        Randomness memory _rng,
        bytes memory _sig
    ) internal view {
        bytes32 hash = randomnessHash(_rng);
        address signer = ECDSA.recover(hash, _sig);
        if (signer != rngSource) revert InvalidSigner();
    }

    /// Shuffle index
    /// @param _range Number of seats/players
    /// @return Shuffled index within bounds
    function _scramble(uint8 _range) internal view returns (uint8) {
        return
            uint8(
                uint256(
                    keccak256(
                        abi.encodePacked(block.prevrandao, block.timestamp)
                    )
                )
            ) % _range;
    }

    /// TODO: Same as ln 432.  Remove?
    function _getBetAfterFee(uint128 _amount) internal view returns (uint128) {
        return (_amount * (DENOMINATOR - fee)) / DENOMINATOR;
    }

    /// Checks if player is alive
    /// @param _participantState Participant state bitmask
    /// @param _index Participant array ID
    /// @return Is player alive?
    function _isAlive(
        uint128 _participantState,
        uint8 _index
    ) internal pure returns (bool) {
        uint128 liveMask = uint128(1 << (127 - _index));

        return (liveMask & _participantState) != 0;
    }

    /// Checks if player is last alive
    /// @param _participantState Participant state bitmask
    /// @param _index Participant array ID
    function _isLastAlive(
        uint128 _participantState,
        uint8 _index
    ) internal pure returns (bool) {
        return (_killPlayer(_participantState, _index) == 0);
    }

    /// Kills a designated player
    /// @param _participantState Participant state bitmask
    /// @param _index Participant array ID
    /// @return Updated state with designated player killed
    function _killPlayer(
        uint128 _participantState,
        uint8 _index
    ) internal pure returns (uint128) {
        uint128 deadMask = ~uint128(1 << (127 - _index));

        return deadMask & _participantState;
    }

    /// Updates tontine participants state
    /// @param _participantState Participant state bitmask
    /// @param _lastIndex Last player index on participant state
    /// @param _lastBetTime Last time a bet was received, or when game started
    /// @param _seats Number of players/seats in lobby
    /// @return Participant state
    /// @return Is last alive?
    /// @return Next player index
    function _updateParticipantState(
        uint128 _participantState,
        uint64 _lastIndex,
        uint64 _lastBetTime,
        uint8 _seats
    ) internal view returns (uint128, bool, uint256) {
        if (_seats == 0) return (0, false, 0);
        if (_lastBetTime > block.timestamp)
            return (_participantState, false, (_lastIndex + 1) % _seats);

        uint256 iterations = (block.timestamp - _lastBetTime) / DEFAULT_CADENCE;

        for (uint256 i = 1; i <= iterations; i++) {
            uint8 index = uint8((_lastIndex + i) % _seats);

            if (_isAlive(_participantState, index)) {
                if (_isLastAlive(_participantState, index)) {
                    return (_participantState, true, index);
                } else {
                    _participantState = _killPlayer(_participantState, index);
                }
            } else {
                unchecked {
                    ++iterations;
                }
            }
        }

        uint256 newIndex = (_lastIndex + iterations + 1) % _seats;

        // Assign index to next living player
        for (uint256 i = 0; i < _seats - 1; i++) {
            if (_isAlive(_participantState, uint8((newIndex + i) % _seats))) {
                newIndex = uint8((newIndex + i) % _seats);
                break;
            }
        }

        return (
            _participantState,
            _isLastAlive(_participantState, uint8(newIndex)),
            newIndex
        );
    }

    /// Check if last player should be killed
    /// @param _id Participant array ID
    /// @param _counter RNG counter
    /// @param _rngMode RNG enum value
    /// @param randomness Randomness int
    /// @return Should last player be killed?
    function _shouldKillLastPlayer(
        uint256 _id,
        uint64 _counter,
        RNGMode _rngMode,
        uint256 randomness
    ) internal pure returns (bool) {
        if (_rngMode == RNGMode.RANDOM) {
            uint256 seed = uint256(keccak256(abi.encodePacked(randomness)));

            uint256 range = (uint256(
                keccak256(abi.encodePacked(_id, _counter))
            ) % RAND_MAX);

            return (seed % 100) <= range;
        }

        return false;
    }

    /// Get hashed identifier
    /// @param _participant Participant/player address
    /// @param _id Participant array ID
    /// @return Participant identifier
    function _getParticipantIdentifier(
        address _participant,
        uint256 _id
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(_participant, _id));
    }

    /// @dev Prevent direct sending of funds
    receive() external payable {
        revert();
    }

    /// @dev default
    fallback() external {
        revert();
    }
}


// ============================================================================
// FILE: lib/solmate/src/auth/Owned.sol
// ============================================================================

// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity >=0.8.0;

/// @notice Simple single owner authorization mixin.
/// @author Solmate (https://github.com/transmissions11/solmate/blob/main/src/auth/Owned.sol)
abstract contract Owned {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event OwnershipTransferred(address indexed user, address indexed newOwner);

    /*//////////////////////////////////////////////////////////////
                            OWNERSHIP STORAGE
    //////////////////////////////////////////////////////////////*/

    address public owner;

    modifier onlyOwner() virtual {
        require(msg.sender == owner, "UNAUTHORIZED");

        _;
    }

    /*//////////////////////////////////////////////////////////////
                               CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor(address _owner) {
        owner = _owner;

        emit OwnershipTransferred(address(0), _owner);
    }

    /*//////////////////////////////////////////////////////////////
                             OWNERSHIP LOGIC
    //////////////////////////////////////////////////////////////*/

    function transferOwnership(address newOwner) public virtual onlyOwner {
        owner = newOwner;

        emit OwnershipTransferred(msg.sender, newOwner);
    }
}


// ============================================================================
// FILE: lib/solmate/src/tokens/ERC20.sol
// ============================================================================

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


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol
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
// FILE: lib/openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/cryptography/EIP712.sol)

pragma solidity ^0.8.8;

import "./ECDSA.sol";
import "../ShortStrings.sol";
import "../../interfaces/IERC5267.sol";

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
 * @custom:oz-upgrades-unsafe-allow state-variable-immutable state-variable-assignment
 */
abstract contract EIP712 is IERC5267 {
    using ShortStrings for *;

    bytes32 private constant _TYPE_HASH =
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
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
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
        return keccak256(abi.encode(_TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
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
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
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
        return (
            hex"0f", // 01111
            _name.toStringWithFallback(_nameFallback),
            _version.toStringWithFallback(_versionFallback),
            block.chainid,
            address(this),
            bytes32(0),
            new uint256[](0)
        );
    }
}


// ============================================================================
// FILE: src/interfaces/IArbitrator.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IArbitratorErrors} from "./IArbitratorErrors.sol";
import {IArbitratorEvents} from "./IArbitratorEvents.sol";
import {IArbitratorData} from "./IArbitratorData.sol";

interface IArbitrator is IArbitratorErrors, IArbitratorEvents, IArbitratorData {
    /*////////////////////////////////////////////////////////////// 
                                  Core                          
    //////////////////////////////////////////////////////////////*/

    function create(
        address _asset,
        uint128 _bet,
        uint8 _seats,
        BetMode _betMode,
        RNGMode _rngMode
    ) external payable;

    function join(uint256 _id) external payable;

    function leave(uint256 _id, uint8 _index) external;

    function fold(uint256 _id, uint8 _index) external;

    function play(
        uint256 _id,
        uint8 _index,
        uint128 _bet,
        Randomness calldata _rng,
        bytes calldata _sig
    ) external payable;

    function claim(
        uint256 _id,
        uint8 _index,
        Randomness calldata _rng,
        bytes calldata _sig
    ) external;

    function collectFees(address _asset) external;

    /*//////////////////////////////////////////////////////////////
                                  Views
    //////////////////////////////////////////////////////////////*/

    function rngSource() external view returns (address);

    function fee() external view returns (uint128);

    function currentId() external view returns (uint256);

    function getBalance(address _token) external view returns (uint256);

    function getParticipant(
        uint256 _id,
        uint256 _index
    ) external view returns (address);

    function getParticipants(
        uint256 _id
    ) external view returns (address[] memory);

    function getAssetAllowed(address _asset) external view returns (bool);

    function getBetModeAllowed(BetMode _mode) external view returns (bool);

    function getRNGModeAllowed(RNGMode _mode) external view returns (bool);

    function getRandomness(
        uint256 _id,
        uint64 _counter
    ) external view returns (uint256);

    function getTontine(uint256 _id) external view returns (Tontine memory);

    function getAmountAfterFee(uint256 _amount) external view returns (uint256);

    function isActive(
        address _participant,
        uint256 _id
    ) external view returns (bool);

    function getParticipantState(
        uint256 _id,
        Randomness calldata _rng
    ) external view returns (uint128, bool, uint256);

    function getParticipantIdentifier(
        address _participant,
        uint256 _id
    ) external pure returns (bytes32);
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/Strings.sol
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
// FILE: lib/openzeppelin-contracts/contracts/utils/ShortStrings.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (utils/ShortStrings.sol)

pragma solidity ^0.8.8;

import "./StorageSlot.sol";

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
    bytes32 private constant _FALLBACK_SENTINEL = 0x00000000000000000000000000000000000000000000000000000000000000FF;

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
            return ShortString.wrap(_FALLBACK_SENTINEL);
        }
    }

    /**
     * @dev Decode a string that was encoded to `ShortString` or written to storage using {setWithFallback}.
     */
    function toStringWithFallback(ShortString value, string storage store) internal pure returns (string memory) {
        if (ShortString.unwrap(value) != _FALLBACK_SENTINEL) {
            return toString(value);
        } else {
            return store;
        }
    }

    /**
     * @dev Return the length of a string that was encoded to `ShortString` or written to storage using {setWithFallback}.
     *
     * WARNING: This will return the "byte length" of the string. This may not reflect the actual length in terms of
     * actual characters as the UTF-8 encoding of a single character can span over multiple bytes.
     */
    function byteLengthWithFallback(ShortString value, string storage store) internal view returns (uint256) {
        if (ShortString.unwrap(value) != _FALLBACK_SENTINEL) {
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
// OpenZeppelin Contracts (last updated v4.9.0) (interfaces/IERC5267.sol)

pragma solidity ^0.8.0;

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
// FILE: src/interfaces/IArbitratorErrors.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IArbitratorErrors {
    /*////////////////////////////////////////////////////////////// 
                                 Errors                              
    //////////////////////////////////////////////////////////////*/

    /// @notice caller not EOA.
    error NotEOA();

    /// @notice invalid asset.
    error InvalidAsset();

    /// @notice invalid caller.
    error InvalidCaller();

    /// @notice provided fee greater than maximum allowed.
    error MaxFeeExceeded();

    /// @notice number of seats are invalid.
    error InvalidSeatCount();

    /// @notice invalid bet size.
    error InvalidBet();

    /// @notice invalid mode.
    error InvalidMode();

    /// @notice game already started.
    error AlreadyStarted();

    /// @notice game not started.
    error NotStarted();

    /// @notice game already joined.
    error AlreadyJoined();

    /// @notice game not joined.
    error NotJoined();

    /// @notice not player's turn.
    error NotTurn();

    /// @notice game ended.
    error Ended();

    /// @notice game running.
    error Running();

    /// @notice player no longer participating.
    error PlayerNotAlive();

    /// @notice already claimed.
    error AlreadyClaimed();

    /// @notice invalid signer.
    error InvalidSigner();

    /// @notice invalid signer.
    error InvalidID();

    /// @notice invalid signer.
    error InvalidCounter();
}


// ============================================================================
// FILE: src/interfaces/IArbitratorEvents.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IArbitratorEvents {
    /*////////////////////////////////////////////////////////////// 
                                 Events                              
    //////////////////////////////////////////////////////////////*/

    event Created(
        uint256 indexed id,
        uint256 indexed bet,
        address indexed asset
    );

    event Joined(uint256 indexed id, address indexed participant);

    event Left(uint256 indexed id, address indexed participant);

    event Played(uint256 indexed id, address indexed participant, uint128 bet);

    event Folded(uint256 indexed id, address indexed participant);

    event Claimed(
        uint256 indexed id,
        address indexed participant,
        address indexed asset,
        uint128 amount
    );

    event Started(uint256 indexed id);
}


// ============================================================================
// FILE: src/interfaces/IArbitratorData.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IArbitratorData {
    /*//////////////////////////////////////////////////////////////
                             Data Structures
    //////////////////////////////////////////////////////////////*/

    enum BetMode {
        // Fixed bet size
        CLASSIC,
        // Bet size is strictly increasing and determined by the player
        VARIABLE,
        // Bet size is increasing linearly
        ANTE
    }

    enum RNGMode {
        // No odds of death
        ZERO,
        // Odds of death randomly selected between RAND_MIN and RAND_MAX
        RANDOM
    }

    struct Randomness {
        uint256 randomness;
        uint64 counter;
        uint256 id;
    }

    struct Tontine {
        // Asset used for Tontine
        address asset;
        // Available seats
        uint8 seats;
        // Bet Mode
        BetMode betMode;
        // RNG Mode
        RNGMode rngMode;
        // Balance
        uint128 balance;
        // Current bet amount
        uint128 bet;
        // State of all participants
        uint128 participantState;
        // Last time a bet was received, or game started
        uint64 lastBetTime;
        // Counter for rng
        uint32 counter;
        // Last player index on participant state
        uint8 lastIndex;
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/math/Math.sol
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
// FILE: lib/openzeppelin-contracts/contracts/utils/math/SignedMath.sol
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
// FILE: lib/openzeppelin-contracts/contracts/utils/StorageSlot.sol
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
