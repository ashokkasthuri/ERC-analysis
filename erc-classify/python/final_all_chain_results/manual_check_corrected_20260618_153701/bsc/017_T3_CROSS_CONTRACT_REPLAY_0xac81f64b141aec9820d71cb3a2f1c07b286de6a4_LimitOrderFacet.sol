// SPDX-License-Identifier: UNLICENSED
// Flattened source downloaded from Etherscan
// Address: 0xac81f64b141aec9820d71cb3a2f1c07b286de6a4
// Contract Name: LimitOrderFacet



// ============================================================
// FILE: @openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol
// ============================================================
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



// ============================================================
// FILE: @openzeppelin/contracts/token/ERC20/IERC20.sol
// ============================================================
// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/IERC20.sol)

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
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}



// ============================================================
// FILE: @uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol
// ============================================================
pragma solidity >=0.5.0;

interface IUniswapV2Factory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function allPairsLength() external view returns (uint);

    function createPair(address tokenA, address tokenB) external returns (address pair);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
}



// ============================================================
// FILE: @uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol
// ============================================================
pragma solidity >=0.5.0;

interface IUniswapV2Pair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}



// ============================================================
// FILE: @uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router01.sol
// ============================================================
pragma solidity >=0.6.2;

interface IUniswapV2Router01 {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}



// ============================================================
// FILE: contracts/facets/interfaces/ILimitOrderFacet.sol
// ============================================================
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

interface ILimitOrderFacet {
    error LimitOrderFacet__ValidateCallFailure();
    error LimitOrderFacet__InvalidChainId();
    error LimitOrderFacet__InvalidWallet();
    error LimitOrderFacet__InvalidTimestamp();
    error LimitOrderFacet__Signature();
    error LimitOrderFacet__InvalidCounter();
    error LimitOrderFacet__InvalidOrder();
    error LimitOrderFacet__ZeroAmount();
    error LimitOrderFacet__InsufficientBalance();
    error LimitOrderFacet__InvalidPrice();
    error LimitOrderFacet__NativeTokenTransferFailure();
    error LimitOrderFacet__InvalidMarketPrice();
    event OrderSettled(bytes32 indexed OrderHash, uint256 amountsOut);
}



// ============================================================
// FILE: contracts/facets/interfaces/Order.sol
// ============================================================
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

struct Order {
    address wallet;
    address tokenFrom;
    address tokenTo;
    uint256 amount;
    uint256 triggerPrice;
    uint128 maxFlexibility;
    uint128 maxSlippage;
    uint128 startTime;
    uint128 endTime;
    bytes32 salt;
    uint256 counter;
    uint256 chainId;
    uint256 fee;
    bytes signature;
}



// ============================================================
// FILE: contracts/facets/LimitOrderFacet.sol
// ============================================================
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {IUniswapV2Router01} from "@uniswap/v2-periphery/contracts/interfaces/IUniswapV2Router01.sol";
import {IUniswapV2Factory} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Pair} from "@uniswap/v2-core/contracts/interfaces/IUniswapV2Pair.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {LibLimitOrderStorage, LimitOrderStorage} from "../libraries/LibLimitOrderStorage.sol";
import {Order} from "./interfaces/Order.sol";
import {ILimitOrderFacet} from "./interfaces/ILimitOrderFacet.sol";

contract LimitOrderFacet is ILimitOrderFacet {
    // EIP-712 Domain
    bytes32 public constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    bytes32 public constant ORDER_TYPEHASH =
        keccak256(
            "Order(address wallet,address tokenFrom,address tokenTo,uint256 amount,uint256 triggerPrice,uint128 maxFlexibility,uint128 maxSlippage,uint128 startTime,uint128 endTime,bytes32 salt,uint256 counter,uint256 chainId,uint256 fee)"
        );

    IUniswapV2Router01 public immutable UNISWAP_ROUTER;
    IUniswapV2Factory public immutable UNISWAP_FACTORY;
    uint256 public constant basePoint = 10000; // e.g., 50 = 0.5%
    address public immutable WNativeToken;
    address public immutable Treasury;

    constructor(address _uniswapRouter, address _uniswapFactory, address _wnativeToken, address _treasury) {
        UNISWAP_ROUTER = IUniswapV2Router01(_uniswapRouter);
        UNISWAP_FACTORY = IUniswapV2Factory(_uniswapFactory);
        // 0x0d500b1d8e8ef31e21c99d1db9a6444d3adf1270 for Polygon
        WNativeToken = _wnativeToken;
        Treasury = _treasury;
    }

    function settleOrder(Order memory order) external {
        if (!validateOrder(order)) revert LimitOrderFacet__InvalidOrder();
        ++LibLimitOrderStorage.limitOrderStorage().counter;

        uint256 feeAmount = order.amount * order.fee / basePoint;
        uint256 orderAmount = order.amount - feeAmount;

        uint256 minAmount = order.triggerPrice -
            ((order.triggerPrice * order.maxSlippage) / basePoint);
        uint256[] memory amountsOut = new uint256[](2);
        if (order.tokenFrom != address(0)) {
            IERC20(order.tokenFrom).transfer(Treasury, feeAmount);
            IERC20(order.tokenFrom).approve(
                address(UNISWAP_ROUTER),
                orderAmount
            );
            address[] memory path = new address[](2);
            path[0] = order.tokenFrom;
            path[1] = order.tokenTo;
            validatePrice(
                order.triggerPrice,
                orderAmount,
                order.maxFlexibility,
                path
            );
            amountsOut = UNISWAP_ROUTER.getAmountsOut(orderAmount, path);

            UNISWAP_ROUTER.swapExactTokensForTokens(
                orderAmount,
                minAmount,
                path,
                address(this),
                block.timestamp
            );
        } else {
            _sendNativeToken(Treasury, feeAmount);
            address[] memory path = new address[](2);
            path[0] = WNativeToken;
            path[1] = order.tokenTo;
            validatePrice(
                order.triggerPrice,
                orderAmount,
                order.maxFlexibility,
                path
            );
            amountsOut = UNISWAP_ROUTER.getAmountsOut(orderAmount, path);

            UNISWAP_ROUTER.swapExactETHForTokens{value: orderAmount}(
                minAmount,
                path,
                address(this),
                block.timestamp
            );
        }
        emit OrderSettled(getOrderHash(order), amountsOut[1]);
    }

    function validatePrice(
        uint256 _orderPrice,
        uint256 _orderAmount,
        uint256 _maxFlexibility,
        address[] memory _path
    ) public view {
        IUniswapV2Pair pair = IUniswapV2Pair(
            UNISWAP_FACTORY.getPair(_path[0], _path[1])
        );

        uint256[] memory amountsOut = UNISWAP_ROUTER.getAmountsOut(_orderAmount, _path);
        uint256 marketPrice = amountsOut[1];
        if (marketPrice == 0) revert LimitOrderFacet__InvalidMarketPrice();

        uint256 flexibility = (_orderPrice * _maxFlexibility) / basePoint;

        if (
            marketPrice > _orderPrice + flexibility ||
            marketPrice < _orderPrice - flexibility
        ) revert LimitOrderFacet__InvalidPrice();
    }

    function getPrice(
        uint256 _orderPrice,
        uint256 _orderAmount,
        uint256 _maxFlexibility,
        address[] memory _path
    ) public view returns (uint256 res0, uint256 res1, uint256 price, uint256 flexibility, uint256[] memory amount, bool isTrue) {
        IUniswapV2Pair pair = IUniswapV2Pair(
            UNISWAP_FACTORY.getPair(_path[0], _path[1])
        );
        IERC20Metadata token1 = IERC20Metadata(pair.token1());
        (res0, res1, ) = pair.getReserves();
        amount = UNISWAP_ROUTER.getAmountsOut(_orderAmount, _path);
        flexibility = (_orderPrice * _maxFlexibility) / basePoint;

        isTrue = (
            amount[1] > _orderPrice + flexibility ||
            amount[1] < _orderPrice - flexibility
        );
    }

    function validateOrder(
        Order memory order
    ) public view returns (bool isOrderValid) {
        if (order.chainId != block.chainid)
            revert LimitOrderFacet__InvalidChainId();
        if (order.wallet != address(this))
            revert LimitOrderFacet__InvalidWallet();
        if (
            order.startTime > block.timestamp ||
            order.endTime <= block.timestamp
        ) revert LimitOrderFacet__InvalidTimestamp();
        if (
            !_validateSignature(
                getTypedDataHash(order, address(this), block.chainid),
                order.signature
            )
        ) revert LimitOrderFacet__Signature();
        if (order.counter != LibLimitOrderStorage.limitOrderStorage().counter)
            revert LimitOrderFacet__InvalidCounter();
        if (order.amount == 0) revert LimitOrderFacet__ZeroAmount();
        if (!validateBalance(order.tokenFrom, order.amount))
            revert LimitOrderFacet__InsufficientBalance();

        isOrderValid = true;
    }

    function validateBalance(
        address _tokenFrom,
        uint256 _amount
    ) public view returns (bool isValid) {
        if (_tokenFrom == address(0))
            isValid = address(this).balance >= _amount;
        else isValid = IERC20(_tokenFrom).balanceOf(address(this)) >= _amount;
    }

    function _validateSignature(
        bytes32 _orderHash,
        bytes memory _signature
    ) internal view returns (bool isSignatureValid) {
        bytes memory validateCall = abi.encodeWithSignature(
            "isValidSignature(bytes32,bytes)",
            _orderHash,
            _signature
        );
        (bool success, bytes memory result) = address(this).staticcall(
            validateCall
        );
        if (!success) {
            revert LimitOrderFacet__ValidateCallFailure();
        }
        bytes4 isValid = bytes4(result);
        isSignatureValid = (isValid == 0x1626ba7e) ? true : false;
    }

    function _sendNativeToken(address _to, uint256 _amount) internal {
        // Call returns a boolean value indicating success or failure.
        // This is the current recommended method to use.
        (bool sent, ) = _to.call{value: _amount}("");
        if (!sent)
            revert LimitOrderFacet__NativeTokenTransferFailure();
    }

    function getDomainSeparator(
        address _contractAddress,
        uint256 _chainId
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    DOMAIN_TYPEHASH,
                    keccak256("BarzLimitOrder"),
                    keccak256("1"),
                    _chainId,
                    _contractAddress
                )
            );
    }

    function getOrderHash(Order memory _order) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    ORDER_TYPEHASH,
                    _order.wallet,
                    _order.tokenFrom,
                    _order.tokenTo,
                    _order.amount,
                    _order.triggerPrice,
                    _order.maxFlexibility,
                    _order.maxSlippage,
                    _order.startTime,
                    _order.endTime,
                    _order.salt,
                    _order.counter,
                    _order.chainId,
                    _order.fee
                )
            );
    }

    function getTypedDataHash(
        Order memory _order,
        address _contractAddress,
        uint256 _chainId
    ) public pure returns (bytes32) {
        bytes32 domainSeparator = getDomainSeparator(_contractAddress, _chainId);
        bytes32 orderHash = getOrderHash(_order);

        return
            keccak256(abi.encodePacked("\x19\x01", domainSeparator, orderHash));
    }
}



// ============================================================
// FILE: contracts/libraries/LibLimitOrderStorage.sol
// ============================================================
// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

struct LimitOrderStorage {
    uint256 counter;
}

library LibLimitOrderStorage {
    function limitOrderStorage()
        internal
        pure
        returns (LimitOrderStorage storage ds)
    {
        bytes32 storagePosition = keccak256(
            "v0.trustwallet.diamond.storage.LimitOrderStorage"
        );
        assembly {
            ds.slot := storagePosition
        }
    }
}
