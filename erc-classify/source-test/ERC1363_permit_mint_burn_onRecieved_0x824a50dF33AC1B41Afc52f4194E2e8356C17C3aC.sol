// SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/draft-ERC20Permit.sol";
import "erc-payable-token/contracts/token/ERC1363/ERC1363.sol";

contract KickToken is ERC1363, ERC20Permit, Pausable, AccessControl {
    uint8 private _decimals;
    uint256 private _tTotal; // token total
    uint256 private _rTotal; // reflection total

    mapping(address => uint256) private _rOwned; // reflection balance

    // no burn and distribution if transfer to these addresses
    mapping(address => bool) private _isNoIncomeFee;
    uint256 private _distributionPercent;
    uint256 private _burnPercent;

    bytes32 public constant OWNER_ROLE = keccak256("OWNER_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant UNPAUSED_ROLE = keccak256("UNPAUSED_ROLE");

    event DistributionPercentChanged(uint256 value);
    event BurnPercentChanged(uint256 value);
    event NoIncomeFeeRoleGranted(address indexed account);
    event NoIncomeFeeRoleRevoked(address indexed account);
    event Distribution(address indexed account, uint256 value);

    modifier notPaused() {
        if (paused()) {
            require(
                hasRole(UNPAUSED_ROLE, _msgSender()),
                "can't perform an action"
            );
        }
        _;
    }

    constructor(
        string memory name,
        string memory ticker,
        uint8 decimal,
        uint256 tTotal,
        uint256 dPercent,
        uint256 bPercent
    ) ERC20(name, ticker) ERC20Permit(name) {
        // init supply
        _decimals = decimal;
        _tTotal = tTotal * 10**decimal;
        _rTotal = (type(uint256).max - (type(uint256).max % _tTotal));

        // set fee percents
        require(10 <= dPercent && dPercent <= 100 && 10 <= bPercent && bPercent <= 100, 
            "incorrect fee percent"
        );
        _distributionPercent = dPercent;
        emit DistributionPercentChanged(dPercent);
        _burnPercent = bPercent;
        emit BurnPercentChanged(bPercent);

        // set roles
        _setRoleAdmin(ADMIN_ROLE, OWNER_ROLE);
        _setRoleAdmin(UNPAUSED_ROLE, ADMIN_ROLE);

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(OWNER_ROLE, _msgSender());
        _setupRole(ADMIN_ROLE, _msgSender());
        _setupRole(UNPAUSED_ROLE, _msgSender());

        // mint inital supply
        _rOwned[_msgSender()] = _rTotal;
        emit Transfer(address(0), _msgSender(), _tTotal);
    }

    // base logic -------------------------------------------------------------
    // ------------------------------------------------------------------------

    function decimals() public view override returns (uint8) {
        return _decimals;
    }

    function totalSupply() public view override returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view override returns (uint256) {
        return tokenFromReflection(_rOwned[account]);
    }

    // transfer logic ---------------------------------------------------------
    // ------------------------------------------------------------------------

    function setDistributionPercent(uint256 percent) external onlyRole(OWNER_ROLE) {
        require(10 <= percent && percent <= 100, "incorrect fee percent"); // 1% <= percent <= 10%
        _distributionPercent = percent;
        emit DistributionPercentChanged(percent);
    }

    function setBurnPercent(uint256 percent) external onlyRole(OWNER_ROLE) {
        require(10 <= percent && percent <= 100, "incorrect fee percent"); // 1% <= percent <= 10%
        _burnPercent = percent;
        emit BurnPercentChanged(percent);
    }

    function distributionPercent() external view returns (uint256) {
        return _distributionPercent;
    }

    function burnPercent() external view returns (uint256) {
        return _burnPercent;
    }

    function reflectionFromToken(uint256 tAmount, bool deductTransferFee) external view returns(uint256) {
        require(tAmount <= _tTotal, "Amount must be less than supply");
        if (!deductTransferFee) {
            (uint256 rAmount, , , ) = _getValues(tAmount);
            return rAmount;
        } else {
            (, uint256 rBurnAmount) = _getBurnValues(tAmount);
            (, uint256 rTransferAmount, , ) = _getValues(tAmount);
            return rTransferAmount - rBurnAmount;
        }
    }

    function tokenFromReflection(uint256 rAmount) public view returns(uint256) {
        require(rAmount <= _rTotal, "Amount must be less than total reflections");
        uint256 currentRate = _getRate();
        return rAmount / currentRate;
    }

    function isNoIncomeFee(address account) external view returns (bool) {
        return _isNoIncomeFee[account];
    }

    function grantNoIncomeFee(address account) external onlyRole(ADMIN_ROLE) {
        require(!_isNoIncomeFee[account], "Account is already no income fee");
        _isNoIncomeFee[account] = true;
        emit NoIncomeFeeRoleGranted(account);
    }

    function revokeNoIncomeFee(address account) external onlyRole(ADMIN_ROLE) {
        require(_isNoIncomeFee[account], "Account is not no income fee");
        _isNoIncomeFee[account] = false;
        emit NoIncomeFeeRoleRevoked(account);
    }

    function _transfer(
        address sender,
        address recipient,
        uint256 amount
    ) internal override(ERC20) notPaused {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        if (_isNoIncomeFee[recipient]) {
            _transferWithoutFee(sender, recipient, amount);
        } else {
            _transferStandard(sender, recipient, amount);
        }
    }

    function _transferStandard(address sender, address recipient, uint256 tAmount) private {
        (uint256 tBurnAmount, uint256 rBurnAmount) = _getBurnValues(tAmount);
        _tTotal -= tBurnAmount;
        _rTotal -= rBurnAmount;

        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount) = _getValues(tAmount);
        _rOwned[sender] -= rAmount;
        _rOwned[recipient] += rTransferAmount - rBurnAmount;

        // distribute fee
        _rTotal -= rFee;

        emit Transfer(sender, recipient, tTransferAmount - tBurnAmount);
        emit Transfer(sender, address(0), tBurnAmount);
        emit Distribution(sender, tAmount - tTransferAmount);
    }

    function _transferWithoutFee(address sender, address recipient, uint256 tAmount) private {
        uint256 currentRate = _getRate();
        uint256 rAmount = tAmount * currentRate;
        _rOwned[sender] -= rAmount;
        _rOwned[recipient] += rAmount;
        emit Transfer(sender, recipient, tAmount);
    }

    function _getBurnValues(uint256 tAmount) private view returns (uint256, uint256) {
        uint256 tBurnAmount = (tAmount * _burnPercent) / 1000;
        uint256 currentRate = _getRate();
        uint256 rBurnAmount = tBurnAmount * currentRate;
        return (tBurnAmount, rBurnAmount);
    }

    function _getValues(uint256 tAmount) private view returns (uint256, uint256, uint256, uint256) {
        uint256 tFee = (tAmount * _distributionPercent) / 1000;
        uint256 tTransferAmount = tAmount - tFee;

        uint256 currentRate = _getRate();
        uint256 rAmount = tAmount * currentRate;
        uint256 rFee = tFee * currentRate;
        uint256 rTransferAmount = rAmount - rFee;

        return (rAmount, rTransferAmount, rFee, tTransferAmount);
    }

    function _getRate() private view returns (uint256) {
        return _rTotal / _tTotal;
    }

    function transferAll(address recipient) external returns (bool) {
        _transfer(_msgSender(), recipient, tokenFromReflection(_rOwned[_msgSender()]));
        return true;
    }

    function transferAllFrom(address account, address recipient) external returns (bool) {
        uint256 tAmount = tokenFromReflection(_rOwned[account]);
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= tAmount, "transfer amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - tAmount);
        _transfer(account, recipient, tAmount);
        return true;
    }

    // for initial token distribution (swap from old token)
    function multisend(
        address[] memory recipients,
        uint256[] memory tAmounts
    ) external onlyRole(OWNER_ROLE) {
        require(recipients.length <= 200, "More than 200 recipients");

        uint256 rTotal;
        uint256 rAmount;
        uint256 currentRate = _getRate();

        uint8 i = 0;
        for (i; i < recipients.length; i++) {
            rAmount = tAmounts[i] * currentRate;
            rTotal += rAmount;
            _rOwned[recipients[i]] += rAmount;
            emit Transfer(_msgSender(), recipients[i], tAmounts[i]);
        }

        _rOwned[_msgSender()] -= rTotal;
    }

    // burn logic -------------------------------------------------------------
    // ------------------------------------------------------------------------

    function _burn(address account, uint256 tAmount) internal notPaused override {
        require(account != address(0), "burn from the zero address");

        uint256 currentRate = _getRate();
        uint256 rAmount = tAmount * currentRate;
        _rOwned[account] -= rAmount;
        _rTotal -= rAmount;
        _tTotal -= tAmount;

        emit Transfer(account, address(0), tAmount);
    }

    function burn(uint256 tAmount) external {
        _burn(_msgSender(), tAmount);
    }

    function burnFrom(address account, uint256 tAmount) external {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= tAmount, "burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - tAmount);
        _burn(account, tAmount);
    }

    // distribute logic -------------------------------------------------------
    // ------------------------------------------------------------------------

    function _distribute(address account, uint256 tAmount) internal {
        (uint256 rAmount, , , ) = _getValues(tAmount);
        _rOwned[account] -= rAmount;
        _rTotal -= rAmount;
        emit Distribution(account, tAmount);
    }

    function distribute(uint256 tAmount) external {
        _distribute(_msgSender(), tAmount);
    }

    function distributeFrom(address account, uint256 tAmount) external {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= tAmount, "distribute amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - tAmount);
        _distribute(account, tAmount);
    }

    // denomination logic -----------------------------------------------------
    // ------------------------------------------------------------------------

    function denominate(uint256 rate) external onlyRole(OWNER_ROLE) {
        _tTotal /= rate;
    }

    // pause logic ------------------------------------------------------------
    // ------------------------------------------------------------------------

    function pauseTrigger() external onlyRole(OWNER_ROLE) {
        if (paused()) {
            _unpause();
        } else {
            _pause();
        }
    }

    // interface support ------------------------------------------------------
    // ------------------------------------------------------------------------

    function supportsInterface(
        bytes4 interfaceId
    ) public view override(AccessControl, ERC1363) returns (bool) {
        return AccessControl.supportsInterface(interfaceId) || ERC1363.supportsInterface(interfaceId);
    }

    // stuck funds ------------------------------------------------------------
    // ------------------------------------------------------------------------

    function stuckFundsTransfer(
        address token,
        address to,
        uint256 amount
    ) external onlyRole(OWNER_ROLE) returns (bool) {
        return IERC20(token).transfer(to, amount);
    }
}


// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./draft-IERC20Permit.sol";
import "../ERC20.sol";
import "../../../utils/cryptography/draft-EIP712.sol";
import "../../../utils/cryptography/ECDSA.sol";
import "../../../utils/Counters.sol";

/**
 * @dev Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * _Available since v3.4._
 */
abstract contract ERC20Permit is ERC20, IERC20Permit, EIP712 {
    using Counters for Counters.Counter;

    mapping (address => Counters.Counter) private _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private immutable _PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     * It's a good idea to use the same `name` that is defined as the ERC20 token name.
     */
    constructor(string memory name) EIP712(name, "1") {
    }

    /**
     * @dev See {IERC20Permit-permit}.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {
        // solhint-disable-next-line not-rely-on-time
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                _useNonce(owner),
                deadline
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");

        _approve(owner, spender, value);
    }

    /**
     * @dev See {IERC20Permit-nonces}.
     */
    function nonces(address owner) public view virtual override returns (uint256) {
        return _nonces[owner].current();
    }

    /**
     * @dev See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }

    /**
     * @dev "Consume a nonce": return the current value and increment.
     *
     * _Available since v4.1._
     */
    function _useNonce(address owner) internal virtual returns (uint256 current) {
        Counters.Counter storage nonce = _nonces[owner];
        current = nonce.current();
        nonce.increment();
    }
}


// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/utils/Address.sol";
import "@openzeppelin/contracts/utils/introspection/ERC165.sol";

import "./IERC1363.sol";
import "./IERC1363Receiver.sol";
import "./IERC1363Spender.sol";

/**
 * @title ERC1363
 * @author Vittorio Minacori (https://github.com/vittominacori)
 * @dev Implementation of an ERC1363 interface
 */
abstract contract ERC1363 is ERC20, IERC1363, ERC165 {
    using Address for address;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1363).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Transfer tokens to a specified address and then execute a callback on recipient.
     * @param recipient The address to transfer to.
     * @param amount The amount to be transferred.
     * @return A boolean that indicates if the operation was successful.
     */
    function transferAndCall(address recipient, uint256 amount) public virtual override returns (bool) {
        return transferAndCall(recipient, amount, "");
    }

    /**
     * @dev Transfer tokens to a specified address and then execute a callback on recipient.
     * @param recipient The address to transfer to
     * @param amount The amount to be transferred
     * @param data Additional data with no specified format
     * @return A boolean that indicates if the operation was successful.
     */
    function transferAndCall(address recipient, uint256 amount, bytes memory data) public virtual override returns (bool) {
        transfer(recipient, amount);
        require(_checkAndCallTransfer(_msgSender(), recipient, amount, data), "ERC1363: _checkAndCallTransfer reverts");
        return true;
    }

    /**
     * @dev Transfer tokens from one address to another and then execute a callback on recipient.
     * @param sender The address which you want to send tokens from
     * @param recipient The address which you want to transfer to
     * @param amount The amount of tokens to be transferred
     * @return A boolean that indicates if the operation was successful.
     */
    function transferFromAndCall(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        return transferFromAndCall(sender, recipient, amount, "");
    }

    /**
     * @dev Transfer tokens from one address to another and then execute a callback on recipient.
     * @param sender The address which you want to send tokens from
     * @param recipient The address which you want to transfer to
     * @param amount The amount of tokens to be transferred
     * @param data Additional data with no specified format
     * @return A boolean that indicates if the operation was successful.
     */
    function transferFromAndCall(address sender, address recipient, uint256 amount, bytes memory data) public virtual override returns (bool) {
        transferFrom(sender, recipient, amount);
        require(_checkAndCallTransfer(sender, recipient, amount, data), "ERC1363: _checkAndCallTransfer reverts");
        return true;
    }

    /**
     * @dev Approve spender to transfer tokens and then execute a callback on recipient.
     * @param spender The address allowed to transfer to
     * @param amount The amount allowed to be transferred
     * @return A boolean that indicates if the operation was successful.
     */
    function approveAndCall(address spender, uint256 amount) public virtual override returns (bool) {
        return approveAndCall(spender, amount, "");
    }

    /**
     * @dev Approve spender to transfer tokens and then execute a callback on recipient.
     * @param spender The address allowed to transfer to.
     * @param amount The amount allowed to be transferred.
     * @param data Additional data with no specified format.
     * @return A boolean that indicates if the operation was successful.
     */
    function approveAndCall(address spender, uint256 amount, bytes memory data) public virtual override returns (bool) {
        approve(spender, amount);
        require(_checkAndCallApprove(spender, amount, data), "ERC1363: _checkAndCallApprove reverts");
        return true;
    }

    /**
     * @dev Internal function to invoke `onTransferReceived` on a target address
     *  The call is not executed if the target address is not a contract
     * @param sender address Representing the previous owner of the given token value
     * @param recipient address Target address that will receive the tokens
     * @param amount uint256 The amount mount of tokens to be transferred
     * @param data bytes Optional data to send along with the call
     * @return whether the call correctly returned the expected magic value
     */
    function _checkAndCallTransfer(address sender, address recipient, uint256 amount, bytes memory data) internal virtual returns (bool) {
        if (!recipient.isContract()) {
            return false;
        }
        bytes4 retval = IERC1363Receiver(recipient).onTransferReceived(
            _msgSender(), sender, amount, data
        );
        return (retval == IERC1363Receiver(recipient).onTransferReceived.selector);
    }

    /**
     * @dev Internal function to invoke `onApprovalReceived` on a target address
     *  The call is not executed if the target address is not a contract
     * @param spender address The address which will spend the funds
     * @param amount uint256 The amount of tokens to be spent
     * @param data bytes Optional data to send along with the call
     * @return whether the call correctly returned the expected magic value
     */
    function _checkAndCallApprove(address spender, uint256 amount, bytes memory data) internal virtual returns (bool) {
        if (!spender.isContract()) {
            return false;
        }
        bytes4 retval = IERC1363Spender(spender).onApprovalReceived(
            _msgSender(), amount, data
        );
        return (retval == IERC1363Spender(spender).onApprovalReceived.selector);
    }
}