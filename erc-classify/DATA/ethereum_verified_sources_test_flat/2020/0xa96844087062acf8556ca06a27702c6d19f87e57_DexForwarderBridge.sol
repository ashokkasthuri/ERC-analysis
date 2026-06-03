// SPDX-License-Identifier: UNLICENSED
// Flattened source downloaded from Etherscan
// Address: 0xa96844087062acf8556ca06a27702c6d19f87e57
// Contract Name: DexForwarderBridge



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/ChaiBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "../interfaces/IERC20Bridge.sol";
import "../interfaces/IChai.sol";
import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";


// solhint-disable space-after-comma
contract ChaiBridge is
    IERC20Bridge,
    DeploymentConstants
{
    /// @dev Withdraws `amount` of `from` address's Dai from the Chai contract.
    ///      Transfers `amount` of Dai to `to` address.
    /// @param from Address to transfer asset from.
    /// @param to Address to transfer asset to.
    /// @param amount Amount of asset to transfer.
    /// @return success The magic bytes `0xdc1600f3` if successful.
    function bridgeTransferFrom(
        address /* tokenAddress */,
        address from,
        address to,
        uint256 amount,
        bytes calldata /* bridgeData */
    )
        external
        returns (bytes4 success)
    {
        // Ensure that only the `ERC20BridgeProxy` can call this function.
        require(
            msg.sender == _getERC20BridgeProxyAddress(),
            "ChaiBridge/ONLY_CALLABLE_BY_ERC20_BRIDGE_PROXY"
        );

        // Withdraw `from` address's Dai.
        // NOTE: This contract must be approved to spend Chai on behalf of `from`.
        bytes memory drawCalldata = abi.encodeWithSelector(
            IChai(address(0)).draw.selector,
            from,
            amount
        );

        (bool success,) = _getChaiAddress().call(drawCalldata);
        require(
            success,
            "ChaiBridge/DRAW_DAI_FAILED"
        );

        // Transfer Dai to `to`
        // This will never fail if the `draw` call was successful
        IERC20Token(_getDaiAddress()).transfer(to, amount);

        return BRIDGE_SUCCESS;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IERC20Bridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


contract IERC20Bridge {

    /// @dev Result of a successful bridge call.
    bytes4 constant internal BRIDGE_SUCCESS = 0xdc1600f3;

    /// @dev Emitted when a trade occurs.
    /// @param inputToken The token the bridge is converting from.
    /// @param outputToken The token the bridge is converting to.
    /// @param inputTokenAmount Amount of input token.
    /// @param outputTokenAmount Amount of output token.
    /// @param from The `from` address in `bridgeTransferFrom()`
    /// @param to The `to` address in `bridgeTransferFrom()`
    event ERC20BridgeTransfer(
        address inputToken,
        address outputToken,
        uint256 inputTokenAmount,
        uint256 outputTokenAmount,
        address from,
        address to
    );

    /// @dev Transfers `amount` of the ERC20 `tokenAddress` from `from` to `to`.
    /// @param tokenAddress The address of the ERC20 token to transfer.
    /// @param from Address to transfer asset from.
    /// @param to Address to transfer asset to.
    /// @param amount Amount of asset to transfer.
    /// @param bridgeData Arbitrary asset data needed by the bridge contract.
    /// @return success The magic bytes `0xdc1600f3` if successful.
    function bridgeTransferFrom(
        address tokenAddress,
        address from,
        address to,
        uint256 amount,
        bytes calldata bridgeData
    )
        external
        returns (bytes4 success);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IChai.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";


contract PotLike {
    function chi() external returns (uint256);
    function rho() external returns (uint256);
    function drip() external returns (uint256);
    function join(uint256) external;
    function exit(uint256) external;
}


// The actual Chai contract can be found here: https://github.com/dapphub/chai
contract IChai is
    IERC20Token
{
    /// @dev Withdraws Dai owned by `src`
    /// @param src Address that owns Dai.
    /// @param wad Amount of Dai to withdraw.
    function draw(
        address src,
        uint256 wad
    )
        external;

    /// @dev Queries Dai balance of Chai holder.
    /// @param usr Address of Chai holder.
    /// @return Dai balance.
    function dai(address usr)
        external
        returns (uint256);

    /// @dev Queries the Pot contract used by the Chai contract.
    function pot()
        external
        returns (PotLike);

    /// @dev Deposits Dai in exchange for Chai
    /// @param dst Address to receive Chai.
    /// @param wad Amount of Dai to deposit.
    function join(
        address dst,
        uint256 wad
    )
        external;
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


contract IERC20Token {

    // solhint-disable no-simple-event-func-name
    event Transfer(
        address indexed _from,
        address indexed _to,
        uint256 _value
    );

    event Approval(
        address indexed _owner,
        address indexed _spender,
        uint256 _value
    );

    /// @dev send `value` token to `to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return True if transfer was successful
    function transfer(address _to, uint256 _value)
        external
        returns (bool);

    /// @dev send `value` token to `to` from `from` on the condition it is approved by `from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return True if transfer was successful
    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    )
        external
        returns (bool);

    /// @dev `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of wei to be approved for transfer
    /// @return Always true if the call has enough gas to complete execution
    function approve(address _spender, uint256 _value)
        external
        returns (bool);

    /// @dev Query total supply of token
    /// @return Total supply of token
    function totalSupply()
        external
        view
        returns (uint256);

    /// @param _owner The address from which the balance will be retrieved
    /// @return Balance of owner
    function balanceOf(address _owner)
        external
        view
        returns (uint256);

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender)
        external
        view
        returns (uint256);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/DeploymentConstants.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


contract DeploymentConstants {
    /// @dev Mainnet address of the WETH contract.
    address constant private WETH_ADDRESS = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    // /// @dev Kovan address of the WETH contract.
    // address constant private WETH_ADDRESS = 0xd0A1E359811322d97991E03f863a0C30C2cF029C;
    /// @dev Mainnet address of the KyberNetworkProxy contract.
    address constant private KYBER_NETWORK_PROXY_ADDRESS = 0x818E6FECD516Ecc3849DAf6845e3EC868087B755;
    // /// @dev Kovan address of the KyberNetworkProxy contract.
    // address constant private KYBER_NETWORK_PROXY_ADDRESS = 0x692f391bCc85cefCe8C237C01e1f636BbD70EA4D;
    /// @dev Mainnet address of the `UniswapExchangeFactory` contract.
    address constant private UNISWAP_EXCHANGE_FACTORY_ADDRESS = 0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95;
    // /// @dev Kovan address of the `UniswapExchangeFactory` contract.
    // address constant private UNISWAP_EXCHANGE_FACTORY_ADDRESS = 0xD3E51Ef092B2845f10401a0159B2B96e8B6c3D30;
    /// @dev Mainnet address of the Eth2Dai `MatchingMarket` contract.
    address constant private ETH2DAI_ADDRESS = 0x794e6e91555438aFc3ccF1c5076A74F42133d08D;
    // /// @dev Kovan address of the Eth2Dai `MatchingMarket` contract.
    // address constant private ETH2DAI_ADDRESS = 0xe325acB9765b02b8b418199bf9650972299235F4;
    /// @dev Mainnet address of the `ERC20BridgeProxy` contract
    address constant private ERC20_BRIDGE_PROXY_ADDRESS = 0x8ED95d1746bf1E4dAb58d8ED4724f1Ef95B20Db0;
    // /// @dev Kovan address of the `ERC20BridgeProxy` contract
    // address constant private ERC20_BRIDGE_PROXY_ADDRESS = 0xFb2DD2A1366dE37f7241C83d47DA58fd503E2C64;
    ///@dev Mainnet address of the `Dai` (multi-collateral) contract
    address constant private DAI_ADDRESS = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    // ///@dev Kovan address of the `Dai` (multi-collateral) contract
    // address constant private DAI_ADDRESS = 0x4F96Fe3b7A6Cf9725f59d353F723c1bDb64CA6Aa;
    /// @dev Mainnet address of the `Chai` contract
    address constant private CHAI_ADDRESS = 0x06AF07097C9Eeb7fD685c692751D5C66dB49c215;
    /// @dev Mainnet address of the 0x DevUtils contract.
    address constant private DEV_UTILS_ADDRESS = 0x74134CF88b21383713E096a5ecF59e297dc7f547;
    // /// @dev Kovan address of the 0x DevUtils contract.
    // address constant private DEV_UTILS_ADDRESS = 0x9402639A828BdF4E9e4103ac3B69E1a6E522eB59;
    /// @dev Kyber ETH pseudo-address.
    address constant internal KYBER_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    /// @dev Mainnet address of the dYdX contract.
    address constant private DYDX_ADDRESS = 0x1E0447b19BB6EcFdAe1e4AE1694b0C3659614e4e;
    /// @dev Mainnet address of the GST2 contract
    address constant private GST_ADDRESS = 0x0000000000b3F879cb30FE243b4Dfee438691c04;
    /// @dev Mainnet address of the GST Collector
    address constant private GST_COLLECTOR_ADDRESS = address(0);
    // /// @dev Kovan address of the GST2 contract
    // address constant private GST_ADDRESS = address(0);
    // /// @dev Kovan address of the GST Collector
    // address constant private GST_COLLECTOR_ADDRESS = address(0);

    /// @dev Overridable way to get the `KyberNetworkProxy` address.
    /// @return kyberAddress The `IKyberNetworkProxy` address.
    function _getKyberNetworkProxyAddress()
        internal
        view
        returns (address kyberAddress)
    {
        return KYBER_NETWORK_PROXY_ADDRESS;
    }

    /// @dev Overridable way to get the WETH address.
    /// @return wethAddress The WETH address.
    function _getWethAddress()
        internal
        view
        returns (address wethAddress)
    {
        return WETH_ADDRESS;
    }

    /// @dev Overridable way to get the `UniswapExchangeFactory` address.
    /// @return uniswapAddress The `UniswapExchangeFactory` address.
    function _getUniswapExchangeFactoryAddress()
        internal
        view
        returns (address uniswapAddress)
    {
        return UNISWAP_EXCHANGE_FACTORY_ADDRESS;
    }

    /// @dev An overridable way to retrieve the Eth2Dai `MatchingMarket` contract.
    /// @return eth2daiAddress The Eth2Dai `MatchingMarket` contract.
    function _getEth2DaiAddress()
        internal
        view
        returns (address eth2daiAddress)
    {
        return ETH2DAI_ADDRESS;
    }

    /// @dev An overridable way to retrieve the `ERC20BridgeProxy` contract.
    /// @return erc20BridgeProxyAddress The `ERC20BridgeProxy` contract.
    function _getERC20BridgeProxyAddress()
        internal
        view
        returns (address erc20BridgeProxyAddress)
    {
        return ERC20_BRIDGE_PROXY_ADDRESS;
    }

    /// @dev An overridable way to retrieve the `Dai` contract.
    /// @return daiAddress The `Dai` contract.
    function _getDaiAddress()
        internal
        view
        returns (address daiAddress)
    {
        return DAI_ADDRESS;
    }

    /// @dev An overridable way to retrieve the `Chai` contract.
    /// @return chaiAddress The `Chai` contract.
    function _getChaiAddress()
        internal
        view
        returns (address chaiAddress)
    {
        return CHAI_ADDRESS;
    }

    /// @dev An overridable way to retrieve the 0x `DevUtils` contract address.
    /// @return devUtils The 0x `DevUtils` contract address.
    function _getDevUtilsAddress()
        internal
        view
        returns (address devUtils)
    {
        return DEV_UTILS_ADDRESS;
    }

    /// @dev Overridable way to get the DyDx contract.
    /// @return exchange The DyDx exchange contract.
    function _getDydxAddress()
        internal
        view
        returns (address dydxAddress)
    {
        return DYDX_ADDRESS;
    }

    /// @dev An overridable way to retrieve the GST2 contract address.
    /// @return gst The GST contract.
    function _getGstAddress()
        internal
        view
        returns (address gst)
    {
        return GST_ADDRESS;
    }

    /// @dev An overridable way to retrieve the GST Collector address.
    /// @return collector The GST collector address.
    function _getGstCollectorAddress()
        internal
        view
        returns (address collector)
    {
        return GST_COLLECTOR_ADDRESS;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/CurveBridge.sol
// ============================================================

/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-erc20/contracts/src/LibERC20Token.sol";
import "@0x/contracts-exchange-libs/contracts/src/IWallet.sol";
import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "../interfaces/IERC20Bridge.sol";
import "../interfaces/ICurve.sol";
import "./MixinGasToken.sol";


// solhint-disable not-rely-on-time
// solhint-disable space-after-comma
contract CurveBridge is
    IERC20Bridge,
    IWallet,
    DeploymentConstants,
    MixinGasToken
{
    struct CurveBridgeData {
        address curveAddress;
        int128 fromCoinIdx;
        int128 toCoinIdx;
        int128 version;
    }

    /// @dev Callback for `ICurve`. Tries to buy `amount` of
    ///      `toTokenAddress` tokens by selling the entirety of the opposing asset
    ///      (DAI, USDC) to the Curve contract, then transfers the bought
    ///      tokens to `to`.
    /// @param toTokenAddress The token to give to `to` (i.e DAI, USDC, USDT).
    /// @param from The maker (this contract).
    /// @param to The recipient of the bought tokens.
    /// @param amount Minimum amount of `toTokenAddress` tokens to buy.
    /// @param bridgeData The abi-encoeded "from" token address.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address toTokenAddress,
        address from,
        address to,
        uint256 amount,
        bytes calldata bridgeData
    )
        external
        freesGasTokensFromCollector
        returns (bytes4 success)
    {
        // Decode the bridge data to get the Curve metadata.
        CurveBridgeData memory data = abi.decode(bridgeData, (CurveBridgeData));

        address fromTokenAddress = ICurve(data.curveAddress).underlying_coins(data.fromCoinIdx);
        require(toTokenAddress != fromTokenAddress, "CurveBridge/INVALID_PAIR");
        uint256 fromTokenBalance = IERC20Token(fromTokenAddress).balanceOf(address(this));
        // Grant an allowance to the exchange to spend `fromTokenAddress` token.
        LibERC20Token.approveIfBelow(fromTokenAddress, data.curveAddress, fromTokenBalance);

        // Try to sell all of this contract's `fromTokenAddress` token balance.
        if (data.version == 0) {
            ICurve(data.curveAddress).exchange_underlying(
                data.fromCoinIdx,
                data.toCoinIdx,
                // dx
                fromTokenBalance,
                // min dy
                amount,
                // expires
                block.timestamp + 1
            );
        } else {
            ICurve(data.curveAddress).exchange_underlying(
                data.fromCoinIdx,
                data.toCoinIdx,
                // dx
                fromTokenBalance,
                // min dy
                amount
            );
        }

        uint256 toTokenBalance = IERC20Token(toTokenAddress).balanceOf(address(this));
        // Transfer the converted `toToken`s to `to`.
        LibERC20Token.transfer(toTokenAddress, to, toTokenBalance);

        emit ERC20BridgeTransfer(
            fromTokenAddress,
            toTokenAddress,
            fromTokenBalance,
            toTokenBalance,
            from,
            to
        );
        return BRIDGE_SUCCESS;
    }

    /// @dev `SignatureType.Wallet` callback, so that this bridge can be the maker
    ///      and sign for itself in orders. Always succeeds.
    /// @return magicValue Magic success bytes, always.
    function isValidSignature(
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bytes4 magicValue)
    {
        return LEGACY_WALLET_MAGIC_VALUE;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-erc20/contracts/src/LibERC20Token.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "@0x/contracts-utils/contracts/src/LibRichErrors.sol";
import "@0x/contracts-utils/contracts/src/LibBytes.sol";
import "../src/interfaces/IERC20Token.sol";


library LibERC20Token {
    bytes constant private DECIMALS_CALL_DATA = hex"313ce567";

    /// @dev Calls `IERC20Token(token).approve()`.
    ///      Reverts if `false` is returned or if the return
    ///      data length is nonzero and not 32 bytes.
    /// @param token The address of the token contract.
    /// @param spender The address that receives an allowance.
    /// @param allowance The allowance to set.
    function approve(
        address token,
        address spender,
        uint256 allowance
    )
        internal
    {
        bytes memory callData = abi.encodeWithSelector(
            IERC20Token(0).approve.selector,
            spender,
            allowance
        );
        _callWithOptionalBooleanResult(token, callData);
    }

    /// @dev Calls `IERC20Token(token).approve()` and sets the allowance to the
    ///      maximum if the current approval is not already >= an amount.
    ///      Reverts if `false` is returned or if the return
    ///      data length is nonzero and not 32 bytes.
    /// @param token The address of the token contract.
    /// @param spender The address that receives an allowance.
    /// @param amount The minimum allowance needed.
    function approveIfBelow(
        address token,
        address spender,
        uint256 amount
    )
        internal
    {
        if (IERC20Token(token).allowance(address(this), spender) < amount) {
            approve(token, spender, uint256(-1));
        }
    }

    /// @dev Calls `IERC20Token(token).transfer()`.
    ///      Reverts if `false` is returned or if the return
    ///      data length is nonzero and not 32 bytes.
    /// @param token The address of the token contract.
    /// @param to The address that receives the tokens
    /// @param amount Number of tokens to transfer.
    function transfer(
        address token,
        address to,
        uint256 amount
    )
        internal
    {
        bytes memory callData = abi.encodeWithSelector(
            IERC20Token(0).transfer.selector,
            to,
            amount
        );
        _callWithOptionalBooleanResult(token, callData);
    }

    /// @dev Calls `IERC20Token(token).transferFrom()`.
    ///      Reverts if `false` is returned or if the return
    ///      data length is nonzero and not 32 bytes.
    /// @param token The address of the token contract.
    /// @param from The owner of the tokens.
    /// @param to The address that receives the tokens
    /// @param amount Number of tokens to transfer.
    function transferFrom(
        address token,
        address from,
        address to,
        uint256 amount
    )
        internal
    {
        bytes memory callData = abi.encodeWithSelector(
            IERC20Token(0).transferFrom.selector,
            from,
            to,
            amount
        );
        _callWithOptionalBooleanResult(token, callData);
    }

    /// @dev Retrieves the number of decimals for a token.
    ///      Returns `18` if the call reverts.
    /// @param token The address of the token contract.
    /// @return tokenDecimals The number of decimals places for the token.
    function decimals(address token)
        internal
        view
        returns (uint8 tokenDecimals)
    {
        tokenDecimals = 18;
        (bool didSucceed, bytes memory resultData) = token.staticcall(DECIMALS_CALL_DATA);
        if (didSucceed && resultData.length == 32) {
            tokenDecimals = uint8(LibBytes.readUint256(resultData, 0));
        }
    }

    /// @dev Retrieves the allowance for a token, owner, and spender.
    ///      Returns `0` if the call reverts.
    /// @param token The address of the token contract.
    /// @param owner The owner of the tokens.
    /// @param spender The address the spender.
    /// @return allowance The allowance for a token, owner, and spender.
    function allowance(address token, address owner, address spender)
        internal
        view
        returns (uint256 allowance_)
    {
        (bool didSucceed, bytes memory resultData) = token.staticcall(
            abi.encodeWithSelector(
                IERC20Token(0).allowance.selector,
                owner,
                spender
            )
        );
        if (didSucceed && resultData.length == 32) {
            allowance_ = LibBytes.readUint256(resultData, 0);
        }
    }

    /// @dev Retrieves the balance for a token owner.
    ///      Returns `0` if the call reverts.
    /// @param token The address of the token contract.
    /// @param owner The owner of the tokens.
    /// @return balance The token balance of an owner.
    function balanceOf(address token, address owner)
        internal
        view
        returns (uint256 balance)
    {
        (bool didSucceed, bytes memory resultData) = token.staticcall(
            abi.encodeWithSelector(
                IERC20Token(0).balanceOf.selector,
                owner
            )
        );
        if (didSucceed && resultData.length == 32) {
            balance = LibBytes.readUint256(resultData, 0);
        }
    }

    /// @dev Executes a call on address `target` with calldata `callData`
    ///      and asserts that either nothing was returned or a single boolean
    ///      was returned equal to `true`.
    /// @param target The call target.
    /// @param callData The abi-encoded call data.
    function _callWithOptionalBooleanResult(
        address target,
        bytes memory callData
    )
        private
    {
        (bool didSucceed, bytes memory resultData) = target.call(callData);
        if (didSucceed) {
            if (resultData.length == 0) {
                return;
            }
            if (resultData.length == 32) {
                uint256 result = LibBytes.readUint256(resultData, 0);
                if (result == 1) {
                    return;
                }
            }
        }
        LibRichErrors.rrevert(resultData);
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/LibRichErrors.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


library LibRichErrors {

    // bytes4(keccak256("Error(string)"))
    bytes4 internal constant STANDARD_ERROR_SELECTOR =
        0x08c379a0;

    // solhint-disable func-name-mixedcase
    /// @dev ABI encode a standard, string revert error payload.
    ///      This is the same payload that would be included by a `revert(string)`
    ///      solidity statement. It has the function signature `Error(string)`.
    /// @param message The error string.
    /// @return The ABI encoded error.
    function StandardError(
        string memory message
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            STANDARD_ERROR_SELECTOR,
            bytes(message)
        );
    }
    // solhint-enable func-name-mixedcase

    /// @dev Reverts an encoded rich revert reason `errorData`.
    /// @param errorData ABI encoded error data.
    function rrevert(bytes memory errorData)
        internal
        pure
    {
        assembly {
            revert(add(errorData, 0x20), mload(errorData))
        }
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/LibBytes.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "./LibBytesRichErrors.sol";
import "./LibRichErrors.sol";


library LibBytes {

    using LibBytes for bytes;

    /// @dev Gets the memory address for a byte array.
    /// @param input Byte array to lookup.
    /// @return memoryAddress Memory address of byte array. This
    ///         points to the header of the byte array which contains
    ///         the length.
    function rawAddress(bytes memory input)
        internal
        pure
        returns (uint256 memoryAddress)
    {
        assembly {
            memoryAddress := input
        }
        return memoryAddress;
    }

    /// @dev Gets the memory address for the contents of a byte array.
    /// @param input Byte array to lookup.
    /// @return memoryAddress Memory address of the contents of the byte array.
    function contentAddress(bytes memory input)
        internal
        pure
        returns (uint256 memoryAddress)
    {
        assembly {
            memoryAddress := add(input, 32)
        }
        return memoryAddress;
    }

    /// @dev Copies `length` bytes from memory location `source` to `dest`.
    /// @param dest memory address to copy bytes to.
    /// @param source memory address to copy bytes from.
    /// @param length number of bytes to copy.
    function memCopy(
        uint256 dest,
        uint256 source,
        uint256 length
    )
        internal
        pure
    {
        if (length < 32) {
            // Handle a partial word by reading destination and masking
            // off the bits we are interested in.
            // This correctly handles overlap, zero lengths and source == dest
            assembly {
                let mask := sub(exp(256, sub(32, length)), 1)
                let s := and(mload(source), not(mask))
                let d := and(mload(dest), mask)
                mstore(dest, or(s, d))
            }
        } else {
            // Skip the O(length) loop when source == dest.
            if (source == dest) {
                return;
            }

            // For large copies we copy whole words at a time. The final
            // word is aligned to the end of the range (instead of after the
            // previous) to handle partial words. So a copy will look like this:
            //
            //  ####
            //      ####
            //          ####
            //            ####
            //
            // We handle overlap in the source and destination range by
            // changing the copying direction. This prevents us from
            // overwriting parts of source that we still need to copy.
            //
            // This correctly handles source == dest
            //
            if (source > dest) {
                assembly {
                    // We subtract 32 from `sEnd` and `dEnd` because it
                    // is easier to compare with in the loop, and these
                    // are also the addresses we need for copying the
                    // last bytes.
                    length := sub(length, 32)
                    let sEnd := add(source, length)
                    let dEnd := add(dest, length)

                    // Remember the last 32 bytes of source
                    // This needs to be done here and not after the loop
                    // because we may have overwritten the last bytes in
                    // source already due to overlap.
                    let last := mload(sEnd)

                    // Copy whole words front to back
                    // Note: the first check is always true,
                    // this could have been a do-while loop.
                    // solhint-disable-next-line no-empty-blocks
                    for {} lt(source, sEnd) {} {
                        mstore(dest, mload(source))
                        source := add(source, 32)
                        dest := add(dest, 32)
                    }

                    // Write the last 32 bytes
                    mstore(dEnd, last)
                }
            } else {
                assembly {
                    // We subtract 32 from `sEnd` and `dEnd` because those
                    // are the starting points when copying a word at the end.
                    length := sub(length, 32)
                    let sEnd := add(source, length)
                    let dEnd := add(dest, length)

                    // Remember the first 32 bytes of source
                    // This needs to be done here and not after the loop
                    // because we may have overwritten the first bytes in
                    // source already due to overlap.
                    let first := mload(source)

                    // Copy whole words back to front
                    // We use a signed comparisson here to allow dEnd to become
                    // negative (happens when source and dest < 32). Valid
                    // addresses in local memory will never be larger than
                    // 2**255, so they can be safely re-interpreted as signed.
                    // Note: the first check is always true,
                    // this could have been a do-while loop.
                    // solhint-disable-next-line no-empty-blocks
                    for {} slt(dest, dEnd) {} {
                        mstore(dEnd, mload(sEnd))
                        sEnd := sub(sEnd, 32)
                        dEnd := sub(dEnd, 32)
                    }

                    // Write the first 32 bytes
                    mstore(dest, first)
                }
            }
        }
    }

    /// @dev Returns a slices from a byte array.
    /// @param b The byte array to take a slice from.
    /// @param from The starting index for the slice (inclusive).
    /// @param to The final index for the slice (exclusive).
    /// @return result The slice containing bytes at indices [from, to)
    function slice(
        bytes memory b,
        uint256 from,
        uint256 to
    )
        internal
        pure
        returns (bytes memory result)
    {
        // Ensure that the from and to positions are valid positions for a slice within
        // the byte array that is being used.
        if (from > to) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.FromLessThanOrEqualsToRequired,
                from,
                to
            ));
        }
        if (to > b.length) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.ToLessThanOrEqualsLengthRequired,
                to,
                b.length
            ));
        }

        // Create a new bytes structure and copy contents
        result = new bytes(to - from);
        memCopy(
            result.contentAddress(),
            b.contentAddress() + from,
            result.length
        );
        return result;
    }

    /// @dev Returns a slice from a byte array without preserving the input.
    /// @param b The byte array to take a slice from. Will be destroyed in the process.
    /// @param from The starting index for the slice (inclusive).
    /// @param to The final index for the slice (exclusive).
    /// @return result The slice containing bytes at indices [from, to)
    /// @dev When `from == 0`, the original array will match the slice. In other cases its state will be corrupted.
    function sliceDestructive(
        bytes memory b,
        uint256 from,
        uint256 to
    )
        internal
        pure
        returns (bytes memory result)
    {
        // Ensure that the from and to positions are valid positions for a slice within
        // the byte array that is being used.
        if (from > to) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.FromLessThanOrEqualsToRequired,
                from,
                to
            ));
        }
        if (to > b.length) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.ToLessThanOrEqualsLengthRequired,
                to,
                b.length
            ));
        }

        // Create a new bytes structure around [from, to) in-place.
        assembly {
            result := add(b, from)
            mstore(result, sub(to, from))
        }
        return result;
    }

    /// @dev Pops the last byte off of a byte array by modifying its length.
    /// @param b Byte array that will be modified.
    /// @return The byte that was popped off.
    function popLastByte(bytes memory b)
        internal
        pure
        returns (bytes1 result)
    {
        if (b.length == 0) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanZeroRequired,
                b.length,
                0
            ));
        }

        // Store last byte.
        result = b[b.length - 1];

        assembly {
            // Decrement length of byte array.
            let newLen := sub(mload(b), 1)
            mstore(b, newLen)
        }
        return result;
    }

    /// @dev Tests equality of two byte arrays.
    /// @param lhs First byte array to compare.
    /// @param rhs Second byte array to compare.
    /// @return True if arrays are the same. False otherwise.
    function equals(
        bytes memory lhs,
        bytes memory rhs
    )
        internal
        pure
        returns (bool equal)
    {
        // Keccak gas cost is 30 + numWords * 6. This is a cheap way to compare.
        // We early exit on unequal lengths, but keccak would also correctly
        // handle this.
        return lhs.length == rhs.length && keccak256(lhs) == keccak256(rhs);
    }

    /// @dev Reads an address from a position in a byte array.
    /// @param b Byte array containing an address.
    /// @param index Index in byte array of address.
    /// @return address from byte array.
    function readAddress(
        bytes memory b,
        uint256 index
    )
        internal
        pure
        returns (address result)
    {
        if (b.length < index + 20) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanOrEqualsTwentyRequired,
                b.length,
                index + 20 // 20 is length of address
            ));
        }

        // Add offset to index:
        // 1. Arrays are prefixed by 32-byte length parameter (add 32 to index)
        // 2. Account for size difference between address length and 32-byte storage word (subtract 12 from index)
        index += 20;

        // Read address from array memory
        assembly {
            // 1. Add index to address of bytes array
            // 2. Load 32-byte word from memory
            // 3. Apply 20-byte mask to obtain address
            result := and(mload(add(b, index)), 0xffffffffffffffffffffffffffffffffffffffff)
        }
        return result;
    }

    /// @dev Writes an address into a specific position in a byte array.
    /// @param b Byte array to insert address into.
    /// @param index Index in byte array of address.
    /// @param input Address to put into byte array.
    function writeAddress(
        bytes memory b,
        uint256 index,
        address input
    )
        internal
        pure
    {
        if (b.length < index + 20) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanOrEqualsTwentyRequired,
                b.length,
                index + 20 // 20 is length of address
            ));
        }

        // Add offset to index:
        // 1. Arrays are prefixed by 32-byte length parameter (add 32 to index)
        // 2. Account for size difference between address length and 32-byte storage word (subtract 12 from index)
        index += 20;

        // Store address into array memory
        assembly {
            // The address occupies 20 bytes and mstore stores 32 bytes.
            // First fetch the 32-byte word where we'll be storing the address, then
            // apply a mask so we have only the bytes in the word that the address will not occupy.
            // Then combine these bytes with the address and store the 32 bytes back to memory with mstore.

            // 1. Add index to address of bytes array
            // 2. Load 32-byte word from memory
            // 3. Apply 12-byte mask to obtain extra bytes occupying word of memory where we'll store the address
            let neighbors := and(
                mload(add(b, index)),
                0xffffffffffffffffffffffff0000000000000000000000000000000000000000
            )

            // Make sure input address is clean.
            // (Solidity does not guarantee this)
            input := and(input, 0xffffffffffffffffffffffffffffffffffffffff)

            // Store the neighbors and address into memory
            mstore(add(b, index), xor(input, neighbors))
        }
    }

    /// @dev Reads a bytes32 value from a position in a byte array.
    /// @param b Byte array containing a bytes32 value.
    /// @param index Index in byte array of bytes32 value.
    /// @return bytes32 value from byte array.
    function readBytes32(
        bytes memory b,
        uint256 index
    )
        internal
        pure
        returns (bytes32 result)
    {
        if (b.length < index + 32) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanOrEqualsThirtyTwoRequired,
                b.length,
                index + 32
            ));
        }

        // Arrays are prefixed by a 256 bit length parameter
        index += 32;

        // Read the bytes32 from array memory
        assembly {
            result := mload(add(b, index))
        }
        return result;
    }

    /// @dev Writes a bytes32 into a specific position in a byte array.
    /// @param b Byte array to insert <input> into.
    /// @param index Index in byte array of <input>.
    /// @param input bytes32 to put into byte array.
    function writeBytes32(
        bytes memory b,
        uint256 index,
        bytes32 input
    )
        internal
        pure
    {
        if (b.length < index + 32) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanOrEqualsThirtyTwoRequired,
                b.length,
                index + 32
            ));
        }

        // Arrays are prefixed by a 256 bit length parameter
        index += 32;

        // Read the bytes32 from array memory
        assembly {
            mstore(add(b, index), input)
        }
    }

    /// @dev Reads a uint256 value from a position in a byte array.
    /// @param b Byte array containing a uint256 value.
    /// @param index Index in byte array of uint256 value.
    /// @return uint256 value from byte array.
    function readUint256(
        bytes memory b,
        uint256 index
    )
        internal
        pure
        returns (uint256 result)
    {
        result = uint256(readBytes32(b, index));
        return result;
    }

    /// @dev Writes a uint256 into a specific position in a byte array.
    /// @param b Byte array to insert <input> into.
    /// @param index Index in byte array of <input>.
    /// @param input uint256 to put into byte array.
    function writeUint256(
        bytes memory b,
        uint256 index,
        uint256 input
    )
        internal
        pure
    {
        writeBytes32(b, index, bytes32(input));
    }

    /// @dev Reads an unpadded bytes4 value from a position in a byte array.
    /// @param b Byte array containing a bytes4 value.
    /// @param index Index in byte array of bytes4 value.
    /// @return bytes4 value from byte array.
    function readBytes4(
        bytes memory b,
        uint256 index
    )
        internal
        pure
        returns (bytes4 result)
    {
        if (b.length < index + 4) {
            LibRichErrors.rrevert(LibBytesRichErrors.InvalidByteOperationError(
                LibBytesRichErrors.InvalidByteOperationErrorCodes.LengthGreaterThanOrEqualsFourRequired,
                b.length,
                index + 4
            ));
        }

        // Arrays are prefixed by a 32 byte length field
        index += 32;

        // Read the bytes4 from array memory
        assembly {
            result := mload(add(b, index))
            // Solidity does not require us to clean the trailing bytes.
            // We do it anyway
            result := and(result, 0xFFFFFFFF00000000000000000000000000000000000000000000000000000000)
        }
        return result;
    }

    /// @dev Writes a new length to a byte array.
    ///      Decreasing length will lead to removing the corresponding lower order bytes from the byte array.
    ///      Increasing length may lead to appending adjacent in-memory bytes to the end of the byte array.
    /// @param b Bytes array to write new length to.
    /// @param length New length of byte array.
    function writeLength(bytes memory b, uint256 length)
        internal
        pure
    {
        assembly {
            mstore(b, length)
        }
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/LibBytesRichErrors.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


library LibBytesRichErrors {

    enum InvalidByteOperationErrorCodes {
        FromLessThanOrEqualsToRequired,
        ToLessThanOrEqualsLengthRequired,
        LengthGreaterThanZeroRequired,
        LengthGreaterThanOrEqualsFourRequired,
        LengthGreaterThanOrEqualsTwentyRequired,
        LengthGreaterThanOrEqualsThirtyTwoRequired,
        LengthGreaterThanOrEqualsNestedBytesLengthRequired,
        DestinationLengthGreaterThanOrEqualSourceLengthRequired
    }

    // bytes4(keccak256("InvalidByteOperationError(uint8,uint256,uint256)"))
    bytes4 internal constant INVALID_BYTE_OPERATION_ERROR_SELECTOR =
        0x28006595;

    // solhint-disable func-name-mixedcase
    function InvalidByteOperationError(
        InvalidByteOperationErrorCodes errorCode,
        uint256 offset,
        uint256 required
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            INVALID_BYTE_OPERATION_ERROR_SELECTOR,
            errorCode,
            offset,
            required
        );
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-exchange-libs/contracts/src/IWallet.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;


contract IWallet {

    bytes4 internal constant LEGACY_WALLET_MAGIC_VALUE = 0xb0671381;

    /// @dev Validates a hash with the `Wallet` signature type.
    /// @param hash Message hash that is signed.
    /// @param signature Proof of signing.
    /// @return magicValue `bytes4(0xb0671381)` if the signature check succeeds.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bytes4 magicValue);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/ICurve.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


// solhint-disable func-name-mixedcase
interface ICurve {

    /// @dev Sell `sellAmount` of `fromToken` token and receive `toToken` token.
    ///      This function exists on early versions of Curve (USDC/DAI)
    /// @param i The token index being sold.
    /// @param j The token index being bought.
    /// @param sellAmount The amount of token being bought.
    /// @param minBuyAmount The minimum buy amount of the token being bought.
    /// @param deadline The time in seconds when this operation should expire.
    function exchange_underlying(
        int128 i,
        int128 j,
        uint256 sellAmount,
        uint256 minBuyAmount,
        uint256 deadline
    )
        external;

    /// @dev Sell `sellAmount` of `fromToken` token and receive `toToken` token.
    ///      This function exists on later versions of Curve (USDC/DAI/USDT)
    /// @param i The token index being sold.
    /// @param j The token index being bought.
    /// @param sellAmount The amount of token being bought.
    /// @param minBuyAmount The minimum buy amount of the token being bought.
    function exchange_underlying(
        int128 i,
        int128 j,
        uint256 sellAmount,
        uint256 minBuyAmount
    )
        external;

    /// @dev Get the amount of `toToken` by selling `sellAmount` of `fromToken`
    /// @param i The token index being sold.
    /// @param j The token index being bought.
    /// @param sellAmount The amount of token being bought.
    function get_dy_underlying(
        int128 i,
        int128 j,
        uint256 sellAmount
    )
        external
        returns (uint256 dy);

    /// @dev Get the amount of `fromToken` by buying `buyAmount` of `toToken`
    ///      This function exists on later versions of Curve (USDC/DAI/USDT)
    /// @param i The token index being sold.
    /// @param j The token index being bought.
    /// @param buyAmount The amount of token being bought.
    function get_dx_underlying(
        int128 i,
        int128 j,
        uint256 buyAmount
    )
        external
        returns (uint256 dx);

    /// @dev Get the underlying token address from the token index
    /// @param i The token index.
    function underlying_coins(
        int128 i
    )
        external
        returns (address tokenAddress);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/MixinGasToken.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.16;

import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "../interfaces/IGasToken.sol";


contract MixinGasToken is
    DeploymentConstants
{

    /// @dev Frees gas tokens based on the amount of gas consumed in the function
    modifier freesGasTokens {
        uint256 gasBefore = gasleft();
        _;
        IGasToken gst = IGasToken(_getGstAddress());
        if (address(gst) != address(0)) {
            // (gasUsed + FREE_BASE) / (2 * REIMBURSE - FREE_TOKEN)
            //            14154             24000        6870
            uint256 value = (gasBefore - gasleft() + 14154) / 41130;
            gst.freeUpTo(value);
        }
    }

    /// @dev Frees gas tokens using the balance of `from`. Amount freed is based
    ///     on the gas consumed in the function
    modifier freesGasTokensFromCollector() {
        uint256 gasBefore = gasleft();
        _;
        IGasToken gst = IGasToken(_getGstAddress());
        if (address(gst) != address(0)) {
            // (gasUsed + FREE_BASE) / (2 * REIMBURSE - FREE_TOKEN)
            //            14154             24000        6870
            uint256 value = (gasBefore - gasleft() + 14154) / 41130;
            gst.freeFromUpTo(_getGstCollectorAddress(), value);
        }
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IGasToken.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.15;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";


contract IGasToken is IERC20Token {

    /// @dev Frees up to `value` sub-tokens
    /// @param value The amount of tokens to free
    /// @return How many tokens were freed
    function freeUpTo(uint256 value) external returns (uint256 freed);

    /// @dev Frees up to `value` sub-tokens owned by `from`
    /// @param from The owner of tokens to spend
    /// @param value The amount of tokens to free
    /// @return How many tokens were freed
    function freeFromUpTo(address from, uint256 value) external returns (uint256 freed);

    /// @dev Mints `value` amount of tokens
    /// @param value The amount of tokens to mint
    function mint(uint256 value) external;
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/DexForwarderBridge.sol
// ============================================================
/*

  Copyright 2020 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-erc20/contracts/src/LibERC20Token.sol";
import "@0x/contracts-exchange-libs/contracts/src/IWallet.sol";
import "@0x/contracts-exchange-libs/contracts/src/LibMath.sol";
import "@0x/contracts-utils/contracts/src/LibBytes.sol";
import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";
import "../interfaces/IERC20Bridge.sol";


// solhint-disable space-after-comma, indent
contract DexForwarderBridge is
    IERC20Bridge,
    IWallet
{
    using LibSafeMath for uint256;

    /// @dev Data needed to reconstruct a bridge call.
    struct BridgeCall {
        address target;
        uint256 inputTokenAmount;
        uint256 outputTokenAmount;
        bytes bridgeData;
    }

    /// @dev Intermediate state variables used by `bridgeTransferFrom()`, in
    ///      struct form to get around stack limits.
    struct TransferFromState {
        address inputToken;
        uint256 initialInputTokenBalance;
        uint256 callInputTokenAmount;
        uint256 callOutputTokenAmount;
        uint256 totalInputTokenSold;
        BridgeCall[] calls;
    }

    /// @dev Spends this contract's entire balance of input tokens by forwarding
    /// them to other bridges. Reverts if the entire balance is not spent.
    /// @param outputToken The token being bought.
    /// @param to The recipient of the bought tokens.
    /// @param bridgeData The abi-encoded input token address.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address outputToken,
        address /* from */,
        address to,
        uint256 /* amount */,
        bytes calldata bridgeData
    )
        external
        returns (bytes4 success)
    {
        TransferFromState memory state;
        (
            state.inputToken,
            state.calls
        ) = abi.decode(bridgeData, (address, BridgeCall[]));

        state.initialInputTokenBalance = IERC20Token(state.inputToken).balanceOf(address(this));

        for (uint256 i = 0; i < state.calls.length; ++i) {
            // Stop if the we've sold all our input tokens.
            if (state.totalInputTokenSold >= state.initialInputTokenBalance) {
                break;
            }

            BridgeCall memory call = state.calls[i];
            // Compute token amounts.
            state.callInputTokenAmount = LibSafeMath.min256(
                call.inputTokenAmount,
                state.initialInputTokenBalance.safeSub(state.totalInputTokenSold)
            );
            state.callOutputTokenAmount = LibMath.getPartialAmountFloor(
                state.callInputTokenAmount,
                call.inputTokenAmount,
                call.outputTokenAmount
            );

            // Execute the call in a new context so we can recoup transferred
            // funds by reverting.
            (bool didSucceed, ) = address(this)
                .call(abi.encodeWithSelector(
                    this.executeBridgeCall.selector,
                    call.target,
                    to,
                    state.inputToken,
                    outputToken,
                    state.callInputTokenAmount,
                    state.callOutputTokenAmount,
                    call.bridgeData
                ));

            if (didSucceed) {
                // Increase the amount of tokens sold.
                state.totalInputTokenSold = state.totalInputTokenSold.safeAdd(
                    state.callInputTokenAmount
                );
            }
        }
        // Revert if we were not able to sell our entire input token balance.
        require(
            state.totalInputTokenSold >= state.initialInputTokenBalance,
            "DexForwarderBridge/INCOMPLETE_FILL"
        );
        // Always succeed.
        return BRIDGE_SUCCESS;
    }

    /// @dev Transfers `inputToken` token to a bridge contract then calls
    ///      its `bridgeTransferFrom()`. This is executed in separate context
    ///      so we can revert the transfer on error. This can only be called
    //       by this contract itself.
    /// @param bridge The bridge contract.
    /// @param to The recipient of `outputToken` tokens.
    /// @param inputToken The input token.
    /// @param outputToken The output token.
    /// @param inputTokenAmount The amount of input tokens to transfer to `bridge`.
    /// @param outputTokenAmount The amount of expected output tokens to be sent
    ///        to `to` by `bridge`.
    function executeBridgeCall(
        address bridge,
        address to,
        address inputToken,
        address outputToken,
        uint256 inputTokenAmount,
        uint256 outputTokenAmount,
        bytes calldata bridgeData
    )
        external
    {
        // Must be called through `bridgeTransferFrom()`.
        require(msg.sender == address(this), "DexForwarderBridge/ONLY_SELF");
        // `bridge` must not be this contract.
        require(bridge != address(this));

        // Get the starting balance of output tokens for `to`.
        uint256 initialRecipientBalance = IERC20Token(outputToken).balanceOf(to);

        // Transfer input tokens to the bridge.
        LibERC20Token.transfer(inputToken, bridge, inputTokenAmount);

        // Call the bridge.
        (bool didSucceed, bytes memory resultData) =
            bridge.call(abi.encodeWithSelector(
                IERC20Bridge(0).bridgeTransferFrom.selector,
                outputToken,
                bridge,
                to,
                outputTokenAmount,
                bridgeData
            ));

        // Revert if the call failed or not enough tokens were bought.
        // This will also undo the token transfer.
        require(
            didSucceed
            && resultData.length == 32
            && LibBytes.readBytes32(resultData, 0) == bytes32(BRIDGE_SUCCESS)
            && IERC20Token(outputToken).balanceOf(to).safeSub(initialRecipientBalance) >= outputTokenAmount
        );
    }

    /// @dev `SignatureType.Wallet` callback, so that this bridge can be the maker
    ///      and sign for itself in orders. Always succeeds.
    /// @return magicValue Magic success bytes, always.
    function isValidSignature(
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bytes4 magicValue)
    {
        return LEGACY_WALLET_MAGIC_VALUE;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-exchange-libs/contracts/src/LibMath.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";
import "@0x/contracts-utils/contracts/src/LibRichErrors.sol";
import "./LibMathRichErrors.sol";


library LibMath {

    using LibSafeMath for uint256;

    /// @dev Calculates partial value given a numerator and denominator rounded down.
    ///      Reverts if rounding error is >= 0.1%
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to calculate partial of.
    /// @return Partial value of target rounded down.
    function safeGetPartialAmountFloor(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (uint256 partialAmount)
    {
        if (isRoundingErrorFloor(
                numerator,
                denominator,
                target
        )) {
            LibRichErrors.rrevert(LibMathRichErrors.RoundingError(
                numerator,
                denominator,
                target
            ));
        }

        partialAmount = numerator.safeMul(target).safeDiv(denominator);
        return partialAmount;
    }

    /// @dev Calculates partial value given a numerator and denominator rounded down.
    ///      Reverts if rounding error is >= 0.1%
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to calculate partial of.
    /// @return Partial value of target rounded up.
    function safeGetPartialAmountCeil(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (uint256 partialAmount)
    {
        if (isRoundingErrorCeil(
                numerator,
                denominator,
                target
        )) {
            LibRichErrors.rrevert(LibMathRichErrors.RoundingError(
                numerator,
                denominator,
                target
            ));
        }

        // safeDiv computes `floor(a / b)`. We use the identity (a, b integer):
        //       ceil(a / b) = floor((a + b - 1) / b)
        // To implement `ceil(a / b)` using safeDiv.
        partialAmount = numerator.safeMul(target)
            .safeAdd(denominator.safeSub(1))
            .safeDiv(denominator);

        return partialAmount;
    }

    /// @dev Calculates partial value given a numerator and denominator rounded down.
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to calculate partial of.
    /// @return Partial value of target rounded down.
    function getPartialAmountFloor(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (uint256 partialAmount)
    {
        partialAmount = numerator.safeMul(target).safeDiv(denominator);
        return partialAmount;
    }

    /// @dev Calculates partial value given a numerator and denominator rounded down.
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to calculate partial of.
    /// @return Partial value of target rounded up.
    function getPartialAmountCeil(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (uint256 partialAmount)
    {
        // safeDiv computes `floor(a / b)`. We use the identity (a, b integer):
        //       ceil(a / b) = floor((a + b - 1) / b)
        // To implement `ceil(a / b)` using safeDiv.
        partialAmount = numerator.safeMul(target)
            .safeAdd(denominator.safeSub(1))
            .safeDiv(denominator);

        return partialAmount;
    }

    /// @dev Checks if rounding error >= 0.1% when rounding down.
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to multiply with numerator/denominator.
    /// @return Rounding error is present.
    function isRoundingErrorFloor(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (bool isError)
    {
        if (denominator == 0) {
            LibRichErrors.rrevert(LibMathRichErrors.DivisionByZeroError());
        }

        // The absolute rounding error is the difference between the rounded
        // value and the ideal value. The relative rounding error is the
        // absolute rounding error divided by the absolute value of the
        // ideal value. This is undefined when the ideal value is zero.
        //
        // The ideal value is `numerator * target / denominator`.
        // Let's call `numerator * target % denominator` the remainder.
        // The absolute error is `remainder / denominator`.
        //
        // When the ideal value is zero, we require the absolute error to
        // be zero. Fortunately, this is always the case. The ideal value is
        // zero iff `numerator == 0` and/or `target == 0`. In this case the
        // remainder and absolute error are also zero.
        if (target == 0 || numerator == 0) {
            return false;
        }

        // Otherwise, we want the relative rounding error to be strictly
        // less than 0.1%.
        // The relative error is `remainder / (numerator * target)`.
        // We want the relative error less than 1 / 1000:
        //        remainder / (numerator * denominator)  <  1 / 1000
        // or equivalently:
        //        1000 * remainder  <  numerator * target
        // so we have a rounding error iff:
        //        1000 * remainder  >=  numerator * target
        uint256 remainder = mulmod(
            target,
            numerator,
            denominator
        );
        isError = remainder.safeMul(1000) >= numerator.safeMul(target);
        return isError;
    }

    /// @dev Checks if rounding error >= 0.1% when rounding up.
    /// @param numerator Numerator.
    /// @param denominator Denominator.
    /// @param target Value to multiply with numerator/denominator.
    /// @return Rounding error is present.
    function isRoundingErrorCeil(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (bool isError)
    {
        if (denominator == 0) {
            LibRichErrors.rrevert(LibMathRichErrors.DivisionByZeroError());
        }

        // See the comments in `isRoundingError`.
        if (target == 0 || numerator == 0) {
            // When either is zero, the ideal value and rounded value are zero
            // and there is no rounding error. (Although the relative error
            // is undefined.)
            return false;
        }
        // Compute remainder as before
        uint256 remainder = mulmod(
            target,
            numerator,
            denominator
        );
        remainder = denominator.safeSub(remainder) % denominator;
        isError = remainder.safeMul(1000) >= numerator.safeMul(target);
        return isError;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/LibSafeMath.sol
// ============================================================
pragma solidity ^0.5.9;

import "./LibRichErrors.sol";
import "./LibSafeMathRichErrors.sol";


library LibSafeMath {

    function safeMul(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        if (a == 0) {
            return 0;
        }
        uint256 c = a * b;
        if (c / a != b) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.MULTIPLICATION_OVERFLOW,
                a,
                b
            ));
        }
        return c;
    }

    function safeDiv(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        if (b == 0) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.DIVISION_BY_ZERO,
                a,
                b
            ));
        }
        uint256 c = a / b;
        return c;
    }

    function safeSub(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        if (b > a) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.SUBTRACTION_UNDERFLOW,
                a,
                b
            ));
        }
        return a - b;
    }

    function safeAdd(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        uint256 c = a + b;
        if (c < a) {
            LibRichErrors.rrevert(LibSafeMathRichErrors.Uint256BinOpError(
                LibSafeMathRichErrors.BinOpErrorCodes.ADDITION_OVERFLOW,
                a,
                b
            ));
        }
        return c;
    }

    function max256(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        return a >= b ? a : b;
    }

    function min256(uint256 a, uint256 b)
        internal
        pure
        returns (uint256)
    {
        return a < b ? a : b;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-utils/contracts/src/LibSafeMathRichErrors.sol
// ============================================================
pragma solidity ^0.5.9;


library LibSafeMathRichErrors {

    // bytes4(keccak256("Uint256BinOpError(uint8,uint256,uint256)"))
    bytes4 internal constant UINT256_BINOP_ERROR_SELECTOR =
        0xe946c1bb;

    // bytes4(keccak256("Uint256DowncastError(uint8,uint256)"))
    bytes4 internal constant UINT256_DOWNCAST_ERROR_SELECTOR =
        0xc996af7b;

    enum BinOpErrorCodes {
        ADDITION_OVERFLOW,
        MULTIPLICATION_OVERFLOW,
        SUBTRACTION_UNDERFLOW,
        DIVISION_BY_ZERO
    }

    enum DowncastErrorCodes {
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT32,
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT64,
        VALUE_TOO_LARGE_TO_DOWNCAST_TO_UINT96
    }

    // solhint-disable func-name-mixedcase
    function Uint256BinOpError(
        BinOpErrorCodes errorCode,
        uint256 a,
        uint256 b
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            UINT256_BINOP_ERROR_SELECTOR,
            errorCode,
            a,
            b
        );
    }

    function Uint256DowncastError(
        DowncastErrorCodes errorCode,
        uint256 a
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            UINT256_DOWNCAST_ERROR_SELECTOR,
            errorCode,
            a
        );
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-exchange-libs/contracts/src/LibMathRichErrors.sol
// ============================================================
pragma solidity ^0.5.9;


library LibMathRichErrors {

    // bytes4(keccak256("DivisionByZeroError()"))
    bytes internal constant DIVISION_BY_ZERO_ERROR =
        hex"a791837c";

    // bytes4(keccak256("RoundingError(uint256,uint256,uint256)"))
    bytes4 internal constant ROUNDING_ERROR_SELECTOR =
        0x339f3de2;

    // solhint-disable func-name-mixedcase
    function DivisionByZeroError()
        internal
        pure
        returns (bytes memory)
    {
        return DIVISION_BY_ZERO_ERROR;
    }

    function RoundingError(
        uint256 numerator,
        uint256 denominator,
        uint256 target
    )
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodeWithSelector(
            ROUNDING_ERROR_SELECTOR,
            numerator,
            denominator,
            target
        );
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/DydxBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";
import "@0x/contracts-exchange-libs/contracts/src/LibMath.sol";
import "../interfaces/IERC20Bridge.sol";
import "../interfaces/IDydxBridge.sol";
import "../interfaces/IDydx.sol";


contract DydxBridge is
    IERC20Bridge,
    IDydxBridge,
    DeploymentConstants
{

    using LibSafeMath for uint256;

    /// @dev Callback for `IERC20Bridge`. Deposits or withdraws tokens from a dydx account.
    ///      Notes:
    ///         1. This bridge must be set as an operator of the input dydx account.
    ///         2. This function may only be called in the context of the 0x Exchange.
    ///         3. The maker or taker of the 0x order must be the dydx account owner.
    ///         4. Deposits into dydx are made from the `from` address.
    ///         5. Withdrawals from dydx are made to the `to` address.
    ///         6. Calling this function must always withdraw at least `amount`,
    ///            otherwise the `ERC20Bridge` will revert.
    /// @param from The sender of the tokens and owner of the dydx account.
    /// @param to The recipient of the tokens.
    /// @param amount Minimum amount of `toTokenAddress` tokens to deposit or withdraw.
    /// @param encodedBridgeData An abi-encoded `BridgeData` struct.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address, /* toTokenAddress */
        address from,
        address to,
        uint256 amount,
        bytes calldata encodedBridgeData
    )
        external
        returns (bytes4 success)
    {
        // Ensure that only the `ERC20BridgeProxy` can call this function.
        require(
            msg.sender == _getERC20BridgeProxyAddress(),
            "DydxBridge/ONLY_CALLABLE_BY_ERC20_BRIDGE_PROXY"
        );

        // Decode bridge data.
        (BridgeData memory bridgeData) = abi.decode(encodedBridgeData, (BridgeData));

        // The dydx accounts are owned by the `from` address.
        IDydx.AccountInfo[] memory accounts = _createAccounts(from, bridgeData);

        // Create dydx actions to run on the dydx accounts.
        IDydx.ActionArgs[] memory actions = _createActions(
            from,
            to,
            amount,
            bridgeData
        );

        // Run operation. This will revert on failure.
        IDydx(_getDydxAddress()).operate(accounts, actions);

        return BRIDGE_SUCCESS;
    }

    /// @dev Creates an array of accounts for dydx to operate on.
    ///      All accounts must belong to the same owner.
    /// @param accountOwner Owner of the dydx account.
    /// @param bridgeData A `BridgeData` struct.
    function _createAccounts(
        address accountOwner,
        BridgeData memory bridgeData
    )
        internal
        returns (IDydx.AccountInfo[] memory accounts)
    {
        uint256[] memory accountNumbers = bridgeData.accountNumbers;
        uint256 nAccounts = accountNumbers.length;
        accounts = new IDydx.AccountInfo[](nAccounts);
        for (uint256 i = 0; i < nAccounts; ++i) {
            accounts[i] = IDydx.AccountInfo({
                owner: accountOwner,
                number: accountNumbers[i]
            });
        }
    }

    /// @dev Creates an array of actions to carry out on dydx.
    /// @param depositFrom Deposit value from this address (owner of the dydx account).
    /// @param withdrawTo Withdraw value to this address.
    /// @param amount The amount of value available to operate on.
    /// @param bridgeData A `BridgeData` struct.
    function _createActions(
        address depositFrom,
        address withdrawTo,
        uint256 amount,
        BridgeData memory bridgeData
    )
        internal
        returns (IDydx.ActionArgs[] memory actions)
    {
        BridgeAction[] memory bridgeActions = bridgeData.actions;
        uint256 nBridgeActions = bridgeActions.length;
        actions = new IDydx.ActionArgs[](nBridgeActions);
        for (uint256 i = 0; i < nBridgeActions; ++i) {
            // Cache current bridge action.
            BridgeAction memory bridgeAction = bridgeActions[i];

            // Scale amount, if conversion rate is set.
            uint256 scaledAmount;
            if (bridgeAction.conversionRateDenominator > 0) {
                scaledAmount = LibMath.safeGetPartialAmountFloor(
                    bridgeAction.conversionRateNumerator,
                    bridgeAction.conversionRateDenominator,
                    amount
                );
            } else {
                scaledAmount = amount;
            }

            // Construct dydx action.
            if (bridgeAction.actionType == BridgeActionType.Deposit) {
                // Deposit tokens from the account owner into their dydx account.
                actions[i] = _createDepositAction(
                    depositFrom,
                    scaledAmount,
                    bridgeAction
                );
            } else if (bridgeAction.actionType == BridgeActionType.Withdraw) {
                // Withdraw tokens from dydx to the `otherAccount`.
                actions[i] = _createWithdrawAction(
                    withdrawTo,
                    scaledAmount,
                    bridgeAction
                );
            } else {
                // If all values in the `Action` enum are handled then this
                // revert is unreachable: Solidity will revert when casting
                // from `uint8` to `Action`.
                revert("DydxBridge/UNRECOGNIZED_BRIDGE_ACTION");
            }
        }
    }

    /// @dev Returns a dydx `DepositAction`.
    /// @param depositFrom Deposit tokens from this address who is also the account owner.
    /// @param amount of tokens to deposit.
    /// @param bridgeAction A `BridgeAction` struct.
    /// @return depositAction The encoded dydx action.
    function _createDepositAction(
        address depositFrom,
        uint256 amount,
        BridgeAction memory bridgeAction
    )
        internal
        pure
        returns (
            IDydx.ActionArgs memory depositAction
        )
    {
        // Create dydx amount.
        IDydx.AssetAmount memory dydxAmount = IDydx.AssetAmount({
            sign: true,                                 // true if positive.
            denomination: IDydx.AssetDenomination.Wei,  // Wei => actual token amount held in account.
            ref: IDydx.AssetReference.Delta,                // Delta => a relative amount.
            value: amount                               // amount to deposit.
        });

        // Create dydx deposit action.
        depositAction = IDydx.ActionArgs({
            actionType: IDydx.ActionType.Deposit,           // deposit tokens.
            amount: dydxAmount,                             // amount to deposit.
            accountIdx: bridgeAction.accountIdx,             // index in the `accounts` when calling `operate`.
            primaryMarketId: bridgeAction.marketId,         // indicates which token to deposit.
            otherAddress: depositFrom,                      // deposit from the account owner.
            // unused parameters
            secondaryMarketId: 0,
            otherAccountIdx: 0,
            data: hex''
        });
    }

    /// @dev Returns a dydx `WithdrawAction`.
    /// @param withdrawTo Withdraw tokens to this address.
    /// @param amount of tokens to withdraw.
    /// @param bridgeAction A `BridgeAction` struct.
    /// @return withdrawAction The encoded dydx action.
    function _createWithdrawAction(
        address withdrawTo,
        uint256 amount,
        BridgeAction memory bridgeAction
    )
        internal
        pure
        returns (
            IDydx.ActionArgs memory withdrawAction
        )
    {
        // Create dydx amount.
        IDydx.AssetAmount memory amountToWithdraw = IDydx.AssetAmount({
            sign: false,                                    // false if negative.
            denomination: IDydx.AssetDenomination.Wei,      // Wei => actual token amount held in account.
            ref: IDydx.AssetReference.Delta,                // Delta => a relative amount.
            value: amount                                   // amount to withdraw.
        });

        // Create withdraw action.
        withdrawAction = IDydx.ActionArgs({
            actionType: IDydx.ActionType.Withdraw,          // withdraw tokens.
            amount: amountToWithdraw,                       // amount to withdraw.
            accountIdx: bridgeAction.accountIdx,            // index in the `accounts` when calling `operate`.
            primaryMarketId: bridgeAction.marketId,         // indicates which token to withdraw.
            otherAddress: withdrawTo,                       // withdraw tokens to this address.
            // unused parameters
            secondaryMarketId: 0,
            otherAccountIdx: 0,
            data: hex''
        });
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IDydxBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


interface IDydxBridge {

    /// @dev This is the subset of `IDydx.ActionType` that are supported by the bridge.
    enum BridgeActionType {
        Deposit,                    // Deposit tokens into dydx account.
        Withdraw                    // Withdraw tokens from dydx account.
    }

    struct BridgeAction {
        BridgeActionType actionType;            // Action to run on dydx account.
        uint256 accountIdx;                     // Index in `BridgeData.accountNumbers` for this action.
        uint256 marketId;                       // Market to operate on.
        uint256 conversionRateNumerator;        // Optional. If set, transfer amount is scaled by (conversionRateNumerator/conversionRateDenominator).
        uint256 conversionRateDenominator;      // Optional. If set, transfer amount is scaled by (conversionRateNumerator/conversionRateDenominator).
    }

    struct BridgeData {
        uint256[] accountNumbers;               // Account number used to identify the owner's specific account.
        BridgeAction[] actions;                 // Actions to carry out on the owner's accounts.
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IDydx.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;


interface IDydx {

    /// @dev Represents the unique key that specifies an account
    struct AccountInfo {
        address owner;  // The address that owns the account
        uint256 number; // A nonce that allows a single address to control many accounts
    }

    enum ActionType {
        Deposit,   // supply tokens
        Withdraw,  // borrow tokens
        Transfer,  // transfer balance between accounts
        Buy,       // buy an amount of some token (externally)
        Sell,      // sell an amount of some token (externally)
        Trade,     // trade tokens against another account
        Liquidate, // liquidate an undercollateralized or expiring account
        Vaporize,  // use excess tokens to zero-out a completely negative account
        Call       // send arbitrary data to an address
    }

    /// @dev Arguments that are passed to Solo in an ordered list as part of a single operation.
    /// Each ActionArgs has an actionType which specifies which action struct that this data will be
    /// parsed into before being processed.
    struct ActionArgs {
        ActionType actionType;
        uint256 accountIdx;
        AssetAmount amount;
        uint256 primaryMarketId;
        uint256 secondaryMarketId;
        address otherAddress;
        uint256 otherAccountIdx;
        bytes data;
    }

    enum AssetDenomination {
        Wei, // the amount is denominated in wei
        Par  // the amount is denominated in par
    }

    enum AssetReference {
        Delta, // the amount is given as a delta from the current value
        Target // the amount is given as an exact number to end up at
    }

    struct AssetAmount {
        bool sign; // true if positive
        AssetDenomination denomination;
        AssetReference ref;
        uint256 value;
    }

    struct D256 {
        uint256 value;
    }

    struct Value {
        uint256 value;
    }

    struct Price {
        uint256 value;
    }

    struct OperatorArg {
        address operator;
        bool trusted;
    }

    /// @dev The global risk parameters that govern the health and security of the system
    struct RiskParams {
        // Required ratio of over-collateralization
        D256 marginRatio;
        // Percentage penalty incurred by liquidated accounts
        D256 liquidationSpread;
        // Percentage of the borrower's interest fee that gets passed to the suppliers
        D256 earningsRate;
        // The minimum absolute borrow value of an account
        // There must be sufficient incentivize to liquidate undercollateralized accounts
        Value minBorrowedValue;
    }

    /// @dev The main entry-point to Solo that allows users and contracts to manage accounts.
    ///      Take one or more actions on one or more accounts. The msg.sender must be the owner or
    ///      operator of all accounts except for those being liquidated, vaporized, or traded with.
    ///      One call to operate() is considered a singular "operation". Account collateralization is
    ///      ensured only after the completion of the entire operation.
    /// @param  accounts  A list of all accounts that will be used in this operation. Cannot contain
    ///                   duplicates. In each action, the relevant account will be referred-to by its
    ///                   index in the list.
    /// @param  actions   An ordered list of all actions that will be taken in this operation. The
    ///                   actions will be processed in order.
    function operate(
        AccountInfo[] calldata accounts,
        ActionArgs[] calldata actions
    )
        external;

    // @dev Approves/disapproves any number of operators. An operator is an external address that has the
    //      same permissions to manipulate an account as the owner of the account. Operators are simply
    //      addresses and therefore may either be externally-owned Ethereum accounts OR smart contracts.
    //      Operators are also able to act as AutoTrader contracts on behalf of the account owner if the
    //      operator is a smart contract and implements the IAutoTrader interface.
    // @param args A list of OperatorArgs which have an address and a boolean. The boolean value
    //        denotes whether to approve (true) or revoke approval (false) for that address.
    function setOperators(OperatorArg[] calldata args) external;

    /// @dev Return true if a particular address is approved as an operator for an owner's accounts.
    ///      Approved operators can act on the accounts of the owner as if it were the operator's own.
    /// @param owner The owner of the accounts
    /// @param operator The possible operator
    /// @return isLocalOperator True if operator is approved for owner's accounts
    function getIsLocalOperator(
        address owner,
        address operator
    )
        external
        view
        returns (bool isLocalOperator);

    /// @dev Get the ERC20 token address for a market.
    /// @param marketId The market to query
    /// @return tokenAddress The token address
    function getMarketTokenAddress(
        uint256 marketId
    )
        external
        view
        returns (address tokenAddress);

    /// @dev Get all risk parameters in a single struct.
    /// @return riskParams All global risk parameters
    function getRiskParams()
        external
        view
        returns (RiskParams memory riskParams);

    /// @dev Get the price of the token for a market.
    /// @param marketId The market to query
    /// @return price The price of each atomic unit of the token
    function getMarketPrice(
        uint256 marketId
    )
        external
        view
        returns (Price memory price);

    /// @dev Get the margin premium for a market. A margin premium makes it so that any positions that
    ///      include the market require a higher collateralization to avoid being liquidated.
    /// @param  marketId  The market to query
    /// @return premium The market's margin premium
    function getMarketMarginPremium(uint256 marketId)
        external
        view
        returns (D256 memory premium);

    /// @dev Get the total supplied and total borrowed values of an account adjusted by the marginPremium
    ///      of each market. Supplied values are divided by (1 + marginPremium) for each market and
    ///      borrowed values are multiplied by (1 + marginPremium) for each market. Comparing these
    ///      adjusted values gives the margin-ratio of the account which will be compared to the global
    ///      margin-ratio when determining if the account can be liquidated.
    /// @param account The account to query
    /// @return supplyValue The supplied value of the account (adjusted for marginPremium)
    /// @return borrowValue The borrowed value of the account (adjusted for marginPremium)
    function getAdjustedAccountValues(
        AccountInfo calldata account
    )
        external
        view
        returns (Value memory supplyValue, Value memory borrowValue);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/Eth2DaiBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-erc20/contracts/src/LibERC20Token.sol";
import "@0x/contracts-exchange-libs/contracts/src/IWallet.sol";
import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "../interfaces/IERC20Bridge.sol";
import "../interfaces/IEth2Dai.sol";


// solhint-disable space-after-comma
contract Eth2DaiBridge is
    IERC20Bridge,
    IWallet,
    DeploymentConstants
{
    /// @dev Callback for `IERC20Bridge`. Tries to buy `amount` of
    ///      `toTokenAddress` tokens by selling the entirety of the opposing asset
    ///      (DAI or WETH) to the Eth2Dai contract, then transfers the bought
    ///      tokens to `to`.
    /// @param toTokenAddress The token to give to `to` (either DAI or WETH).
    /// @param from The maker (this contract).
    /// @param to The recipient of the bought tokens.
    /// @param amount Minimum amount of `toTokenAddress` tokens to buy.
    /// @param bridgeData The abi-encoeded "from" token address.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address toTokenAddress,
        address from,
        address to,
        uint256 amount,
        bytes calldata bridgeData
    )
        external
        returns (bytes4 success)
    {
        // Decode the bridge data to get the `fromTokenAddress`.
        (address fromTokenAddress) = abi.decode(bridgeData, (address));

        IEth2Dai exchange = IEth2Dai(_getEth2DaiAddress());
        uint256 fromTokenBalance = IERC20Token(fromTokenAddress).balanceOf(address(this));
        // Grant an allowance to the exchange to spend `fromTokenAddress` token.
        LibERC20Token.approveIfBelow(fromTokenAddress, address(exchange), fromTokenBalance);

        // Try to sell all of this contract's `fromTokenAddress` token balance.
        uint256 boughtAmount = exchange.sellAllAmount(
            fromTokenAddress,
            fromTokenBalance,
            toTokenAddress,
            amount
        );
        // Transfer the converted `toToken`s to `to`.
        LibERC20Token.transfer(toTokenAddress, to, boughtAmount);

        emit ERC20BridgeTransfer(
            fromTokenAddress,
            toTokenAddress,
            fromTokenBalance,
            boughtAmount,
            from,
            to
        );
        return BRIDGE_SUCCESS;
    }

    /// @dev `SignatureType.Wallet` callback, so that this bridge can be the maker
    ///      and sign for itself in orders. Always succeeds.
    /// @return magicValue Magic success bytes, always.
    function isValidSignature(
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bytes4 magicValue)
    {
        return LEGACY_WALLET_MAGIC_VALUE;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IEth2Dai.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


interface IEth2Dai {

    /// @dev Sell `sellAmount` of `fromToken` token and receive `toToken` token.
    /// @param fromToken The token being sold.
    /// @param sellAmount The amount of `fromToken` token being sold.
    /// @param toToken The token being bought.
    /// @param minFillAmount Minimum amount of `toToken` token to buy.
    /// @return fillAmount Amount of `toToken` bought.
    function sellAllAmount(
        address fromToken,
        uint256 sellAmount,
        address toToken,
        uint256 minFillAmount
    )
        external
        returns (uint256 fillAmount);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/KyberBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-erc20/contracts/src/interfaces/IEtherToken.sol";
import "@0x/contracts-erc20/contracts/src/LibERC20Token.sol";
import "@0x/contracts-exchange-libs/contracts/src/IWallet.sol";
import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";
import "../interfaces/IERC20Bridge.sol";
import "../interfaces/IKyberNetworkProxy.sol";


// solhint-disable space-after-comma
contract KyberBridge is
    IERC20Bridge,
    IWallet,
    DeploymentConstants
{
    using LibSafeMath for uint256;

    // @dev Structure used internally to get around stack limits.
    struct TradeState {
        IKyberNetworkProxy kyber;
        IEtherToken weth;
        address fromTokenAddress;
        uint256 fromTokenBalance;
        uint256 payableAmount;
        uint256 conversionRate;
    }

    /// @dev Kyber ETH pseudo-address.
    address constant public KYBER_ETH_ADDRESS = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;
    /// @dev `bridgeTransferFrom()` failure result.
    bytes4 constant private BRIDGE_FAILED = 0x0;
    /// @dev Precision of Kyber rates.
    uint256 constant private KYBER_RATE_BASE = 10 ** 18;

    // solhint-disable no-empty-blocks
    /// @dev Payable fallback to receive ETH from Kyber.
    function ()
        external
        payable
    {}

    /// @dev Callback for `IKyberBridge`. Tries to buy `amount` of
    ///      `toTokenAddress` tokens by selling the entirety of the opposing asset
    ///      to the `KyberNetworkProxy` contract, then transfers the bought
    ///      tokens to `to`.
    /// @param toTokenAddress The token to give to `to`.
    /// @param from The maker (this contract).
    /// @param to The recipient of the bought tokens.
    /// @param amount Minimum amount of `toTokenAddress` tokens to buy.
    /// @param bridgeData The abi-encoeded "from" token address.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address toTokenAddress,
        address from,
        address to,
        uint256 amount,
        bytes calldata bridgeData
    )
        external
        returns (bytes4 success)
    {
        TradeState memory state;
        state.kyber = IKyberNetworkProxy(_getKyberNetworkProxyAddress());
        state.weth = IEtherToken(_getWethAddress());
        // Decode the bridge data to get the `fromTokenAddress`.
        (state.fromTokenAddress) = abi.decode(bridgeData, (address));
        // Query the balance of "from" tokens.
        state.fromTokenBalance = IERC20Token(state.fromTokenAddress).balanceOf(address(this));
        if (state.fromTokenBalance == 0) {
            // Return failure if no input tokens.
            return BRIDGE_FAILED;
        }
        // Compute the conversion rate, expressed in 18 decimals.
        // The sequential notation is to get around stack limits.
        state.conversionRate = KYBER_RATE_BASE;
        state.conversionRate = state.conversionRate.safeMul(amount);
        state.conversionRate = state.conversionRate.safeMul(
            10 ** uint256(LibERC20Token.decimals(state.fromTokenAddress))
        );
        state.conversionRate = state.conversionRate.safeDiv(state.fromTokenBalance);
        state.conversionRate = state.conversionRate.safeDiv(
            10 ** uint256(LibERC20Token.decimals(toTokenAddress))
        );
        if (state.fromTokenAddress == toTokenAddress) {
            // Just transfer the tokens if they're the same.
            LibERC20Token.transfer(state.fromTokenAddress, to, state.fromTokenBalance);
            return BRIDGE_SUCCESS;
        } else if (state.fromTokenAddress != address(state.weth)) {
            // If the input token is not WETH, grant an allowance to the exchange
            // to spend them.
            LibERC20Token.approveIfBelow(
                state.fromTokenAddress,
                address(state.kyber),
                state.fromTokenBalance
            );
        } else {
            // If the input token is WETH, unwrap it and attach it to the call.
            state.fromTokenAddress = KYBER_ETH_ADDRESS;
            state.payableAmount = state.fromTokenBalance;
            state.weth.withdraw(state.fromTokenBalance);
        }
        bool isToTokenWeth = toTokenAddress == address(state.weth);

        // Try to sell all of this contract's input token balance through
        // `KyberNetworkProxy.trade()`.
        uint256 boughtAmount = state.kyber.trade.value(state.payableAmount)(
            // Input token.
            state.fromTokenAddress,
            // Sell amount.
            state.fromTokenBalance,
            // Output token.
            isToTokenWeth ? KYBER_ETH_ADDRESS : toTokenAddress,
            // Transfer to this contract if converting to ETH, otherwise
            // transfer directly to the recipient.
            isToTokenWeth ? address(uint160(address(this))) : address(uint160(to)),
            // Buy as much as possible.
            uint256(-1),
            // Compute the minimum conversion rate, which is expressed in units with
            // 18 decimal places.
            state.conversionRate,
            // No affiliate address.
            address(0)
        );
        // Wrap ETH output and transfer to recipient.
        if (isToTokenWeth) {
            state.weth.deposit.value(boughtAmount)();
            state.weth.transfer(to, boughtAmount);
        }

        emit ERC20BridgeTransfer(
            state.fromTokenAddress == KYBER_ETH_ADDRESS ? address(state.weth) : state.fromTokenAddress,
            toTokenAddress,
            state.fromTokenBalance,
            boughtAmount,
            from,
            to
        );
        return BRIDGE_SUCCESS;
    }

    /// @dev `SignatureType.Wallet` callback, so that this bridge can be the maker
    ///      and sign for itself in orders. Always succeeds.
    /// @return magicValue Magic success bytes, always.
    function isValidSignature(
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bytes4 magicValue)
    {
        return LEGACY_WALLET_MAGIC_VALUE;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-erc20/contracts/src/interfaces/IEtherToken.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "./IERC20Token.sol";


contract IEtherToken is
    IERC20Token
{
    function deposit()
        public
        payable;
    
    function withdraw(uint256 amount)
        public;
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IKyberNetworkProxy.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


interface IKyberNetworkProxy {

    /// @dev Sells `sellTokenAddress` tokens for `buyTokenAddress` tokens.
    /// @param sellTokenAddress Token to sell.
    /// @param sellAmount Amount of tokens to sell.
    /// @param buyTokenAddress Token to buy.
    /// @param recipientAddress Address to send bought tokens to.
    /// @param maxBuyTokenAmount A limit on the amount of tokens to buy.
    /// @param minConversionRate The minimal conversion rate. If actual rate
    ///        is lower, trade is canceled.
    /// @param walletId The wallet ID to send part of the fees
    /// @return boughtAmount Amount of tokens bought.
    function trade(
        address sellTokenAddress,
        uint256 sellAmount,
        address buyTokenAddress,
        address payable recipientAddress,
        uint256 maxBuyTokenAmount,
        uint256 minConversionRate,
        address walletId
    )
        external
        payable
        returns(uint256 boughtAmount);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/bridges/UniswapBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-erc20/contracts/src/interfaces/IEtherToken.sol";
import "@0x/contracts-erc20/contracts/src/LibERC20Token.sol";
import "@0x/contracts-exchange-libs/contracts/src/IWallet.sol";
import "@0x/contracts-utils/contracts/src/DeploymentConstants.sol";
import "../interfaces/IUniswapExchangeFactory.sol";
import "../interfaces/IUniswapExchange.sol";
import "../interfaces/IERC20Bridge.sol";


// solhint-disable space-after-comma
// solhint-disable not-rely-on-time
contract UniswapBridge is
    IERC20Bridge,
    IWallet,
    DeploymentConstants
{
    // Struct to hold `bridgeTransferFrom()` local variables in memory and to avoid
    // stack overflows.
    struct TransferState {
        IUniswapExchange exchange;
        uint256 fromTokenBalance;
        IEtherToken weth;
        uint256 boughtAmount;
    }

    // solhint-disable no-empty-blocks
    /// @dev Payable fallback to receive ETH from uniswap.
    function ()
        external
        payable
    {}

    /// @dev Callback for `IERC20Bridge`. Tries to buy `amount` of
    ///      `toTokenAddress` tokens by selling the entirety of the `fromTokenAddress`
    ///      token encoded in the bridge data.
    /// @param toTokenAddress The token to buy and transfer to `to`.
    /// @param from The maker (this contract).
    /// @param to The recipient of the bought tokens.
    /// @param amount Minimum amount of `toTokenAddress` tokens to buy.
    /// @param bridgeData The abi-encoded "from" token address.
    /// @return success The magic bytes if successful.
    function bridgeTransferFrom(
        address toTokenAddress,
        address from,
        address to,
        uint256 amount,
        bytes calldata bridgeData
    )
        external
        returns (bytes4 success)
    {
        // State memory object to avoid stack overflows.
        TransferState memory state;
        // Decode the bridge data to get the `fromTokenAddress`.
        (address fromTokenAddress) = abi.decode(bridgeData, (address));

        // Just transfer the tokens if they're the same.
        if (fromTokenAddress == toTokenAddress) {
            LibERC20Token.transfer(fromTokenAddress, to, amount);
            return BRIDGE_SUCCESS;
        }

        // Get the exchange for the token pair.
        state.exchange = _getUniswapExchangeForTokenPair(
            fromTokenAddress,
            toTokenAddress
        );
        // Get our balance of `fromTokenAddress` token.
        state.fromTokenBalance = IERC20Token(fromTokenAddress).balanceOf(address(this));
        // Get the weth contract.
        state.weth = IEtherToken(_getWethAddress());

        // Convert from WETH to a token.
        if (fromTokenAddress == address(state.weth)) {
            // Unwrap the WETH.
            state.weth.withdraw(state.fromTokenBalance);
            // Buy as much of `toTokenAddress` token with ETH as possible and
            // transfer it to `to`.
            state.boughtAmount = state.exchange.ethToTokenTransferInput.value(state.fromTokenBalance)(
                // Minimum buy amount.
                amount,
                // Expires after this block.
                block.timestamp,
                // Recipient is `to`.
                to
            );

        // Convert from a token to WETH.
        } else if (toTokenAddress == address(state.weth)) {
            // Grant the exchange an allowance.
            _grantExchangeAllowance(state.exchange, fromTokenAddress, state.fromTokenBalance);
            // Buy as much ETH with `fromTokenAddress` token as possible.
            state.boughtAmount = state.exchange.tokenToEthSwapInput(
                // Sell all tokens we hold.
                state.fromTokenBalance,
                // Minimum buy amount.
                amount,
                // Expires after this block.
                block.timestamp
            );
            // Wrap the ETH.
            state.weth.deposit.value(state.boughtAmount)();
            // Transfer the WETH to `to`.
            IEtherToken(toTokenAddress).transfer(to, state.boughtAmount);

        // Convert from one token to another.
        } else {
            // Grant the exchange an allowance.
            _grantExchangeAllowance(state.exchange, fromTokenAddress, state.fromTokenBalance);
            // Buy as much `toTokenAddress` token with `fromTokenAddress` token
            // and transfer it to `to`.
            state.boughtAmount = state.exchange.tokenToTokenTransferInput(
                // Sell all tokens we hold.
                state.fromTokenBalance,
                // Minimum buy amount.
                amount,
                // Must buy at least 1 intermediate ETH.
                1,
                // Expires after this block.
                block.timestamp,
                // Recipient is `to`.
                to,
                // Convert to `toTokenAddress`.
                toTokenAddress
            );
        }

        emit ERC20BridgeTransfer(
            fromTokenAddress,
            toTokenAddress,
            state.fromTokenBalance,
            state.boughtAmount,
            from,
            to
        );
        return BRIDGE_SUCCESS;
    }

    /// @dev `SignatureType.Wallet` callback, so that this bridge can be the maker
    ///      and sign for itself in orders. Always succeeds.
    /// @return magicValue Success bytes, always.
    function isValidSignature(
        bytes32,
        bytes calldata
    )
        external
        view
        returns (bytes4 magicValue)
    {
        return LEGACY_WALLET_MAGIC_VALUE;
    }

    /// @dev Grants an unlimited allowance to the exchange for its token
    ///      on behalf of this contract.
    /// @param exchange The Uniswap token exchange.
    /// @param tokenAddress The token address for the exchange.
    /// @param minimumAllowance The minimum necessary allowance.
    function _grantExchangeAllowance(
        IUniswapExchange exchange,
        address tokenAddress,
        uint256 minimumAllowance
    )
        private
    {
        LibERC20Token.approveIfBelow(
            tokenAddress,
            address(exchange),
            minimumAllowance
        );
    }

    /// @dev Retrieves the uniswap exchange for a given token pair.
    ///      In the case of a WETH-token exchange, this will be the non-WETH token.
    ///      In th ecase of a token-token exchange, this will be the first token.
    /// @param fromTokenAddress The address of the token we are converting from.
    /// @param toTokenAddress The address of the token we are converting to.
    /// @return exchange The uniswap exchange.
    function _getUniswapExchangeForTokenPair(
        address fromTokenAddress,
        address toTokenAddress
    )
        private
        view
        returns (IUniswapExchange exchange)
    {
        address exchangeTokenAddress = fromTokenAddress;
        // Whichever isn't WETH is the exchange token.
        if (fromTokenAddress == _getWethAddress()) {
            exchangeTokenAddress = toTokenAddress;
        }
        exchange = IUniswapExchange(
            IUniswapExchangeFactory(_getUniswapExchangeFactoryAddress())
            .getExchange(exchangeTokenAddress)
        );
        require(address(exchange) != address(0), "NO_UNISWAP_EXCHANGE_FOR_TOKEN");
        return exchange;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IUniswapExchangeFactory.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "./IUniswapExchange.sol";


interface IUniswapExchangeFactory {

    /// @dev Get the exchange for a token.
    /// @param tokenAddress The address of the token contract.
    function getExchange(address tokenAddress)
        external
        view
        returns (address);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/src/interfaces/IUniswapExchange.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;


interface IUniswapExchange {

    /// @dev Buys at least `minTokensBought` tokens with ETH and transfer them
    ///      to `recipient`.
    /// @param minTokensBought The minimum number of tokens to buy.
    /// @param deadline Time when this order expires.
    /// @param recipient Who to transfer the tokens to.
    /// @return tokensBought Amount of tokens bought.
    function ethToTokenTransferInput(
        uint256 minTokensBought,
        uint256 deadline,
        address recipient
    )
        external
        payable
        returns (uint256 tokensBought);

    /// @dev Buys at least `minEthBought` ETH with tokens.
    /// @param tokensSold Amount of tokens to sell.
    /// @param minEthBought The minimum amount of ETH to buy.
    /// @param deadline Time when this order expires.
    /// @return ethBought Amount of tokens bought.
    function tokenToEthSwapInput(
        uint256 tokensSold,
        uint256 minEthBought,
        uint256 deadline
    )
        external
        returns (uint256 ethBought);

    /// @dev Buys at least `minTokensBought` tokens with the exchange token
    ///      and transfer them to `recipient`.
    /// @param minTokensBought The minimum number of tokens to buy.
    /// @param minEthBought The minimum amount of intermediate ETH to buy.
    /// @param deadline Time when this order expires.
    /// @param recipient Who to transfer the tokens to.
    /// @param toTokenAddress The token being bought.
    /// @return tokensBought Amount of tokens bought.
    function tokenToTokenTransferInput(
        uint256 tokensSold,
        uint256 minTokensBought,
        uint256 minEthBought,
        uint256 deadline,
        address recipient,
        address toTokenAddress
    )
        external
        returns (uint256 tokensBought);
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestChaiBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "../src/bridges/ChaiBridge.sol";
import "@0x/contracts-erc20/contracts/src/ERC20Token.sol";


contract TestChaiDai is
    ERC20Token
{
    address private constant ALWAYS_REVERT_ADDRESS = address(1);

    function draw(
        address from,
        uint256 amount
    )
        external
    {
        if (from == ALWAYS_REVERT_ADDRESS) {
            revert();
        }
        balances[msg.sender] += amount;
    }
}


contract TestChaiBridge is
    ChaiBridge
{
    address public testChaiDai;
    address private constant ALWAYS_REVERT_ADDRESS = address(1);

    constructor()
        public
    {
        testChaiDai = address(new TestChaiDai());
    }

    function _getDaiAddress()
        internal
        view
        returns (address)
    {
        return testChaiDai;
    }

    function _getChaiAddress()
        internal
        view
        returns (address)
    {
        return testChaiDai;
    }

    function _getERC20BridgeProxyAddress()
        internal
        view
        returns (address)
    {
        return msg.sender == ALWAYS_REVERT_ADDRESS ? address(0) : msg.sender;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/node_modules/@0x/contracts-erc20/contracts/src/ERC20Token.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;

import "./interfaces/IERC20Token.sol";


contract ERC20Token is
    IERC20Token
{
    mapping (address => uint256) internal balances;
    mapping (address => mapping (address => uint256)) internal allowed;

    uint256 internal _totalSupply;

    /// @dev send `value` token to `to` from `msg.sender`
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return True if transfer was successful
    function transfer(address _to, uint256 _value)
        external
        returns (bool)
    {
        require(
            balances[msg.sender] >= _value,
            "ERC20_INSUFFICIENT_BALANCE"
        );
        require(
            balances[_to] + _value >= balances[_to],
            "UINT256_OVERFLOW"
        );

        balances[msg.sender] -= _value;
        balances[_to] += _value;

        emit Transfer(
            msg.sender,
            _to,
            _value
        );

        return true;
    }

    /// @dev send `value` token to `to` from `from` on the condition it is approved by `from`
    /// @param _from The address of the sender
    /// @param _to The address of the recipient
    /// @param _value The amount of token to be transferred
    /// @return True if transfer was successful
    function transferFrom(
        address _from,
        address _to,
        uint256 _value
    )
        external
        returns (bool)
    {
        require(
            balances[_from] >= _value,
            "ERC20_INSUFFICIENT_BALANCE"
        );
        require(
            allowed[_from][msg.sender] >= _value,
            "ERC20_INSUFFICIENT_ALLOWANCE"
        );
        require(
            balances[_to] + _value >= balances[_to],
            "UINT256_OVERFLOW"
        );

        balances[_to] += _value;
        balances[_from] -= _value;
        allowed[_from][msg.sender] -= _value;

        emit Transfer(
            _from,
            _to,
            _value
        );

        return true;
    }

    /// @dev `msg.sender` approves `_spender` to spend `_value` tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @param _value The amount of wei to be approved for transfer
    /// @return Always true if the call has enough gas to complete execution
    function approve(address _spender, uint256 _value)
        external
        returns (bool)
    {
        allowed[msg.sender][_spender] = _value;
        emit Approval(
            msg.sender,
            _spender,
            _value
        );
        return true;
    }

    /// @dev Query total supply of token
    /// @return Total supply of token
    function totalSupply()
        external
        view
        returns (uint256)
    {
        return _totalSupply;
    }

    /// @dev Query the balance of owner
    /// @param _owner The address from which the balance will be retrieved
    /// @return Balance of owner
    function balanceOf(address _owner)
        external
        view
        returns (uint256)
    {
        return balances[_owner];
    }

    /// @param _owner The address of the account owning tokens
    /// @param _spender The address of the account able to transfer the tokens
    /// @return Amount of remaining tokens allowed to spent
    function allowance(address _owner, address _spender)
        external
        view
        returns (uint256)
    {
        return allowed[_owner][_spender];
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestDexForwarderBridge.sol
// ============================================================
/*

  Copyright 2020 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "../src/bridges/DexForwarderBridge.sol";
import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";


interface ITestDexForwarderBridge {
    event BridgeTransferFromCalled(
        address caller,
        uint256 inputTokenBalance,
        address inputToken,
        address outputToken,
        address from,
        address to,
        uint256 amount
    );

    event TokenTransferCalled(
        address from,
        address to,
        uint256 amount
    );

    function emitBridgeTransferFromCalled(
        address caller,
        uint256 inputTokenBalance,
        address inputToken,
        address outputToken,
        address from,
        address to,
        uint256 amount
    ) external;

    function emitTokenTransferCalled(
        address from,
        address to,
        uint256 amount
    ) external;
}


interface ITestDexForwarderBridgeTestToken {

    function transfer(address to, uint256 amount)
        external
        returns (bool);

    function mint(address to, uint256 amount)
        external;

    function balanceOf(address owner) external view returns (uint256);
}


contract TestDexForwarderBridgeTestBridge {

    bytes4 private _returnCode;
    string private _revertError;
    uint256 private _transferAmount;
    ITestDexForwarderBridge private _testContract;

    constructor(bytes4 returnCode, string memory revertError) public {
        _testContract = ITestDexForwarderBridge(msg.sender);
        _returnCode = returnCode;
        _revertError = revertError;
    }

    function setTransferAmount(uint256 amount) external {
        _transferAmount = amount;
    }

    function bridgeTransferFrom(
        address outputToken,
        address from,
        address to,
        uint256 amount,
        bytes memory bridgeData
    )
        public
        returns (bytes4 success)
    {
        if (bytes(_revertError).length != 0) {
            revert(_revertError);
        }
        address inputToken = abi.decode(bridgeData, (address));
        _testContract.emitBridgeTransferFromCalled(
            msg.sender,
            ITestDexForwarderBridgeTestToken(inputToken).balanceOf(address(this)),
            inputToken,
            outputToken,
            from,
            to,
            amount
        );
        ITestDexForwarderBridgeTestToken(outputToken).mint(to, _transferAmount);
        return _returnCode;
    }
}


contract TestDexForwarderBridgeTestToken {

    using LibSafeMath for uint256;

    mapping(address => uint256) public balanceOf;
    ITestDexForwarderBridge private _testContract;

    constructor() public {
        _testContract = ITestDexForwarderBridge(msg.sender);
    }

    function transfer(address to, uint256 amount)
        external
        returns (bool)
    {
        balanceOf[msg.sender] = balanceOf[msg.sender].safeSub(amount);
        balanceOf[to] = balanceOf[to].safeAdd(amount);
        _testContract.emitTokenTransferCalled(msg.sender, to, amount);
        return true;
    }

    function mint(address owner, uint256 amount)
        external
    {
        balanceOf[owner] = balanceOf[owner].safeAdd(amount);
    }

    function setBalance(address owner, uint256 amount)
        external
    {
        balanceOf[owner] = amount;
    }
}


contract TestDexForwarderBridge is
    ITestDexForwarderBridge,
    DexForwarderBridge
{
    function createBridge(
        bytes4 returnCode,
        string memory revertError
    )
        public
        returns (address bridge)
    {
        return address(new TestDexForwarderBridgeTestBridge(returnCode, revertError));
    }

    function createToken() public returns (address token) {
        return address(new TestDexForwarderBridgeTestToken());
    }

    function setTokenBalance(address token, address owner, uint256 amount) public {
        TestDexForwarderBridgeTestToken(token).setBalance(owner, amount);
    }

    function setBridgeTransferAmount(address bridge, uint256 amount) public {
        TestDexForwarderBridgeTestBridge(bridge).setTransferAmount(amount);
    }

    function emitBridgeTransferFromCalled(
        address caller,
        uint256 inputTokenBalance,
        address inputToken,
        address outputToken,
        address from,
        address to,
        uint256 amount
    )
        public
    {
        emit BridgeTransferFromCalled(
            caller,
            inputTokenBalance,
            inputToken,
            outputToken,
            from,
            to,
            amount
        );
    }

    function emitTokenTransferCalled(
        address from,
        address to,
        uint256 amount
    )
        public
    {
        emit TokenTransferCalled(
            from,
            to,
            amount
        );
    }

    function balanceOf(address token, address owner) public view returns (uint256) {
        return TestDexForwarderBridgeTestToken(token).balanceOf(owner);
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestDydxBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "../src/bridges/DydxBridge.sol";


// solhint-disable no-empty-blocks
contract TestDydxBridgeToken {

    uint256 private constant INIT_HOLDER_BALANCE = 10 * 10**18; // 10 tokens
    mapping (address => uint256) private _balances;

    /// @dev Sets initial balance of token holders.
    constructor(address[] memory holders)
        public
    {
        for (uint256 i = 0; i != holders.length; ++i) {
            _balances[holders[i]] = INIT_HOLDER_BALANCE;
        }
        _balances[msg.sender] = INIT_HOLDER_BALANCE;
    }

    /// @dev Basic transferFrom implementation.
    function transferFrom(address from, address to, uint256 amount)
        external
        returns (bool)
    {
        if (_balances[from] < amount || _balances[to] + amount < _balances[to]) {
            return false;
        }
        _balances[from] -= amount;
        _balances[to] += amount;
        return true;
    }

    /// @dev Returns balance of `holder`.
    function balanceOf(address holder)
        external
        view
        returns (uint256)
    {
        return _balances[holder];
    }
}


// solhint-disable space-after-comma
contract TestDydxBridge is
    IDydx,
    DydxBridge
{

    address private constant ALWAYS_REVERT_ADDRESS = address(1);
    address private _testTokenAddress;
    bool private _shouldRevertOnOperate;

    event OperateAccount(
        address owner,
        uint256 number
    );

    event OperateAction(
        ActionType actionType,
        uint256 accountIdx,
        bool amountSign,
        AssetDenomination amountDenomination,
        AssetReference amountRef,
        uint256 amountValue,
        uint256 primaryMarketId,
        uint256 secondaryMarketId,
        address otherAddress,
        uint256 otherAccountId,
        bytes data
    );

    constructor(address[] memory holders)
        public
    {
        // Deploy a test token. This represents the asset being deposited/withdrawn from dydx.
        _testTokenAddress = address(new TestDydxBridgeToken(holders));
    }

    /// @dev Simulates `operate` in dydx contract.
    ///      Emits events so that arguments can be validated client-side.
    function operate(
        AccountInfo[] calldata accounts,
        ActionArgs[] calldata actions
    )
        external
    {
        if (_shouldRevertOnOperate) {
            revert("TestDydxBridge/SHOULD_REVERT_ON_OPERATE");
        }

        for (uint i = 0; i < accounts.length; ++i) {
            emit OperateAccount(
                accounts[i].owner,
                accounts[i].number
            );
        }

        for (uint i = 0; i < actions.length; ++i) {
            emit OperateAction(
                actions[i].actionType,
                actions[i].accountIdx,
                actions[i].amount.sign,
                actions[i].amount.denomination,
                actions[i].amount.ref,
                actions[i].amount.value,
                actions[i].primaryMarketId,
                actions[i].secondaryMarketId,
                actions[i].otherAddress,
                actions[i].otherAccountIdx,
                actions[i].data
            );

            if (actions[i].actionType == IDydx.ActionType.Withdraw) {
                require(
                    IERC20Token(_testTokenAddress).transferFrom(
                        address(this),
                        actions[i].otherAddress,
                        actions[i].amount.value
                    ),
                    "TestDydxBridge/WITHDRAW_FAILED"
                );
            } else if (actions[i].actionType == IDydx.ActionType.Deposit) {
                require(
                    IERC20Token(_testTokenAddress).transferFrom(
                        actions[i].otherAddress,
                        address(this),
                        actions[i].amount.value
                    ),
                    "TestDydxBridge/DEPOSIT_FAILED"
                );
            } else {
                revert("TestDydxBridge/UNSUPPORTED_ACTION");
            }
        }
    }

    /// @dev If `true` then subsequent calls to `operate` will revert.
    function setRevertOnOperate(bool shouldRevert)
        external
    {
        _shouldRevertOnOperate = shouldRevert;
    }

    /// @dev Returns test token.
    function getTestToken()
        external
        returns (address)
    {
        return _testTokenAddress;
    }

    /// @dev Unused.
    function setOperators(OperatorArg[] calldata args) external {}

    /// @dev Unused.
    function getIsLocalOperator(
        address owner,
        address operator
    )
        external
        view
        returns (bool isLocalOperator)
    {}

    /// @dev Unused.
    function getMarketTokenAddress(
        uint256 marketId
    )
        external
        view
        returns (address tokenAddress)
    {}

    /// @dev Unused.
    function getRiskParams()
        external
        view
        returns (RiskParams memory riskParams)
    {}

    /// @dev Unsused.
    function getMarketPrice(
        uint256 marketId
    )
        external
        view
        returns (Price memory price)
    {}

    /// @dev Unsused
    function getMarketMarginPremium(uint256 marketId)
        external
        view
        returns (IDydx.D256 memory premium)
    {}

    /// @dev Unused.
    function getAdjustedAccountValues(
        AccountInfo calldata account
    )
        external
        view
        returns (Value memory supplyValue, Value memory borrowValue)
    {}

    /// @dev overrides `_getDydxAddress()` from `DeploymentConstants` to return this address.
    function _getDydxAddress()
        internal
        view
        returns (address)
    {
        return address(this);
    }

    /// @dev overrides `_getERC20BridgeProxyAddress()` from `DeploymentConstants` for testing.
    function _getERC20BridgeProxyAddress()
        internal
        view
        returns (address)
    {
        return msg.sender == ALWAYS_REVERT_ADDRESS ? address(0) : msg.sender;
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestEth2DaiBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "../src/bridges/Eth2DaiBridge.sol";
import "../src/interfaces/IEth2Dai.sol";


// solhint-disable no-simple-event-func-name
contract TestEvents {

    event TokenTransfer(
        address token,
        address from,
        address to,
        uint256 amount
    );

    event TokenApprove(
        address token,
        address spender,
        uint256 allowance
    );

    function raiseTokenTransfer(
        address from,
        address to,
        uint256 amount
    )
        external
    {
        emit TokenTransfer(
            msg.sender,
            from,
            to,
            amount
        );
    }

    function raiseTokenApprove(address spender, uint256 allowance)
        external
    {
        emit TokenApprove(msg.sender, spender, allowance);
    }
}


/// @dev A minimalist ERC20 token.
contract TestToken {

    mapping (address => uint256) public balances;
    string private _nextTransferRevertReason;
    bytes private _nextTransferReturnData;

    /// @dev Just calls `raiseTokenTransfer()` on the caller.
    function transfer(address to, uint256 amount)
        external
        returns (bool)
    {
        TestEvents(msg.sender).raiseTokenTransfer(msg.sender, to, amount);
        if (bytes(_nextTransferRevertReason).length != 0) {
            revert(_nextTransferRevertReason);
        }
        bytes memory returnData = _nextTransferReturnData;
        assembly { return(add(returnData, 0x20), mload(returnData)) }
    }

    /// @dev Set the balance for `owner`.
    function setBalance(address owner, uint256 balance)
        external
    {
        balances[owner] = balance;
    }

    /// @dev Set the behavior of the `transfer()` call.
    function setTransferBehavior(
        string calldata revertReason,
        bytes calldata returnData
    )
        external
    {
        _nextTransferRevertReason = revertReason;
        _nextTransferReturnData = returnData;
    }

    /// @dev Just calls `raiseTokenApprove()` on the caller.
    function approve(address spender, uint256 allowance)
        external
        returns (bool)
    {
        TestEvents(msg.sender).raiseTokenApprove(spender, allowance);
        return true;
    }

    function allowance(address, address) external view returns (uint256) {
        return 0;
    }

    /// @dev Retrieve the balance for `owner`.
    function balanceOf(address owner)
        external
        view
        returns (uint256)
    {
        return balances[owner];
    }
}


/// @dev Eth2DaiBridge overridden to mock tokens and
///      implement IEth2Dai.
contract TestEth2DaiBridge is
    TestEvents,
    IEth2Dai,
    Eth2DaiBridge
{
    event SellAllAmount(
        address sellToken,
        uint256 sellTokenAmount,
        address buyToken,
        uint256 minimumFillAmount
    );

    mapping (address => TestToken)  public testTokens;
    string private _nextRevertReason;
    uint256 private _nextFillAmount;

    /// @dev Create a token and set this contract's balance.
    function createToken(uint256 balance)
        external
        returns (address tokenAddress)
    {
        TestToken token = new TestToken();
        testTokens[address(token)] = token;
        token.setBalance(address(this), balance);
        return address(token);
    }

    /// @dev Set the behavior for `IEth2Dai.sellAllAmount()`.
    function setFillBehavior(string calldata revertReason, uint256 fillAmount)
        external
    {
        _nextRevertReason = revertReason;
        _nextFillAmount = fillAmount;
    }

    /// @dev Set the behavior of a token's `transfer()`.
    function setTransferBehavior(
        address tokenAddress,
        string calldata revertReason,
        bytes calldata returnData
    )
        external
    {
        testTokens[tokenAddress].setTransferBehavior(revertReason, returnData);
    }

    /// @dev Implementation of `IEth2Dai.sellAllAmount()`
    function sellAllAmount(
        address sellTokenAddress,
        uint256 sellTokenAmount,
        address buyTokenAddress,
        uint256 minimumFillAmount
    )
        external
        returns (uint256 fillAmount)
    {
        emit SellAllAmount(
            sellTokenAddress,
            sellTokenAmount,
            buyTokenAddress,
            minimumFillAmount
        );
        if (bytes(_nextRevertReason).length != 0) {
            revert(_nextRevertReason);
        }
        return _nextFillAmount;
    }

    // @dev This contract will double as the Eth2Dai contract.
    function _getEth2DaiAddress()
        internal
        view
        returns (address)
    {
        return address(this);
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestKyberBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "../src/bridges/KyberBridge.sol";
import "../src/interfaces/IKyberNetworkProxy.sol";


// solhint-disable no-simple-event-func-name
interface ITestContract {

    function wethWithdraw(
        address payable ownerAddress,
        uint256 amount
    )
        external;

    function wethDeposit(
        address ownerAddress
    )
        external
        payable;

    function tokenTransfer(
        address ownerAddress,
        address recipientAddress,
        uint256 amount
    )
        external
        returns (bool success);

    function tokenApprove(
        address ownerAddress,
        address spenderAddress,
        uint256 allowance
    )
        external
        returns (bool success);

    function tokenBalanceOf(
        address ownerAddress
    )
        external
        view
        returns (uint256 balance);
}


/// @dev A minimalist ERC20/WETH token.
contract TestToken {

    uint8 public decimals;
    ITestContract private _testContract;

    constructor(uint8 decimals_) public {
        decimals = decimals_;
        _testContract = ITestContract(msg.sender);
    }

    function approve(address spender, uint256 allowance)
        external
        returns (bool)
    {
        return _testContract.tokenApprove(
            msg.sender,
            spender,
            allowance
        );
    }

    function transfer(address recipient, uint256 amount)
        external
        returns (bool)
    {
        return _testContract.tokenTransfer(
            msg.sender,
            recipient,
            amount
        );
    }

    function withdraw(uint256 amount)
        external
    {
        return _testContract.wethWithdraw(msg.sender, amount);
    }

    function deposit()
        external
        payable
    {
        return _testContract.wethDeposit.value(msg.value)(msg.sender);
    }

    function allowance(address, address) external view returns (uint256) {
        return 0;
    }

    function balanceOf(address owner)
        external
        view
        returns (uint256)
    {
        return _testContract.tokenBalanceOf(owner);
    }
}


/// @dev KyberBridge overridden to mock tokens and implement IKyberBridge.
contract TestKyberBridge is
    KyberBridge,
    ITestContract,
    IKyberNetworkProxy
{
    event KyberBridgeTrade(
        uint256 msgValue,
        address sellTokenAddress,
        uint256 sellAmount,
        address buyTokenAddress,
        address payable recipientAddress,
        uint256 maxBuyTokenAmount,
        uint256 minConversionRate,
        address walletId
    );

    event KyberBridgeWethWithdraw(
        address ownerAddress,
        uint256 amount
    );

    event KyberBridgeWethDeposit(
        uint256 msgValue,
        address ownerAddress,
        uint256 amount
    );

    event KyberBridgeTokenApprove(
        address tokenAddress,
        address ownerAddress,
        address spenderAddress,
        uint256 allowance
    );

    event KyberBridgeTokenTransfer(
        address tokenAddress,
        address ownerAddress,
        address recipientAddress,
        uint256 amount
    );

    IEtherToken public weth;
    mapping (address => mapping (address => uint256)) private _tokenBalances;
    uint256 private _nextFillAmount;

    constructor() public {
        weth = IEtherToken(address(new TestToken(18)));
    }

    /// @dev Implementation of `IKyberNetworkProxy.trade()`
    function trade(
        address sellTokenAddress,
        uint256 sellAmount,
        address buyTokenAddress,
        address payable recipientAddress,
        uint256 maxBuyTokenAmount,
        uint256 minConversionRate,
        address walletId
    )
        external
        payable
        returns(uint256 boughtAmount)
    {
        emit KyberBridgeTrade(
            msg.value,
            sellTokenAddress,
            sellAmount,
            buyTokenAddress,
            recipientAddress,
            maxBuyTokenAmount,
            minConversionRate,
            walletId
        );
        return _nextFillAmount;
    }

    function createToken(uint8 decimals)
        external
        returns (address tokenAddress)
    {
        return address(new TestToken(decimals));
    }

    function setNextFillAmount(uint256 amount)
        external
        payable
    {
        if (msg.value != 0) {
            require(amount == msg.value, "VALUE_AMOUNT_MISMATCH");
            grantTokensTo(address(weth), address(this), msg.value);
        }
        _nextFillAmount = amount;
    }

    function wethDeposit(
        address ownerAddress
    )
        external
        payable
    {
        require(msg.sender == address(weth), "ONLY_WETH");
        grantTokensTo(address(weth), ownerAddress, msg.value);
        emit KyberBridgeWethDeposit(
            msg.value,
            ownerAddress,
            msg.value
        );
    }

    function wethWithdraw(
        address payable ownerAddress,
        uint256 amount
    )
        external
    {
        require(msg.sender == address(weth), "ONLY_WETH");
        _tokenBalances[address(weth)][ownerAddress] -= amount;
        ownerAddress.transfer(amount);
        emit KyberBridgeWethWithdraw(
            ownerAddress,
            amount
        );
    }

    function tokenApprove(
        address ownerAddress,
        address spenderAddress,
        uint256 allowance
    )
        external
        returns (bool success)
    {
        emit KyberBridgeTokenApprove(
            msg.sender,
            ownerAddress,
            spenderAddress,
            allowance
        );
        return true;
    }

    function tokenTransfer(
        address ownerAddress,
        address recipientAddress,
        uint256 amount
    )
        external
        returns (bool success)
    {
        _tokenBalances[msg.sender][ownerAddress] -= amount;
        _tokenBalances[msg.sender][recipientAddress] += amount;
        emit KyberBridgeTokenTransfer(
            msg.sender,
            ownerAddress,
            recipientAddress,
            amount
        );
        return true;
    }

    function tokenBalanceOf(
        address ownerAddress
    )
        external
        view
        returns (uint256 balance)
    {
        return _tokenBalances[msg.sender][ownerAddress];
    }

    function grantTokensTo(address tokenAddress, address ownerAddress, uint256 amount)
        public
        payable
    {
        _tokenBalances[tokenAddress][ownerAddress] += amount;
        if (tokenAddress != address(weth)) {
            // Send back ether if not WETH.
            msg.sender.transfer(msg.value);
        } else {
            require(msg.value == amount, "VALUE_AMOUNT_MISMATCH");
        }
    }

    // @dev overridden to point to this contract.
    function _getKyberNetworkProxyAddress()
        internal
        view
        returns (address)
    {
        return address(this);
    }

    // @dev overridden to point to test WETH.
    function _getWethAddress()
        internal
        view
        returns (address)
    {
        return address(weth);
    }
}



// ============================================================
// FILE: /home/cluracan/code/0x-monorepo/contracts/asset-proxy/contracts/test/TestUniswapBridge.sol
// ============================================================
/*

  Copyright 2019 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.9;
pragma experimental ABIEncoderV2;

import "@0x/contracts-erc20/contracts/src/interfaces/IERC20Token.sol";
import "@0x/contracts-utils/contracts/src/LibSafeMath.sol";
import "../src/bridges/UniswapBridge.sol";
import "../src/interfaces/IUniswapExchangeFactory.sol";
import "../src/interfaces/IUniswapExchange.sol";


// solhint-disable no-simple-event-func-name
contract TestEventsRaiser {

    event TokenTransfer(
        address token,
        address from,
        address to,
        uint256 amount
    );

    event TokenApprove(
        address spender,
        uint256 allowance
    );

    event WethDeposit(
        uint256 amount
    );

    event WethWithdraw(
        uint256 amount
    );

    event EthToTokenTransferInput(
        address exchange,
        uint256 minTokensBought,
        uint256 deadline,
        address recipient
    );

    event TokenToEthSwapInput(
        address exchange,
        uint256 tokensSold,
        uint256 minEthBought,
        uint256 deadline
    );

    event TokenToTokenTransferInput(
        address exchange,
        uint256 tokensSold,
        uint256 minTokensBought,
        uint256 minEthBought,
        uint256 deadline,
        address recipient,
        address toTokenAddress
    );

    function raiseEthToTokenTransferInput(
        uint256 minTokensBought,
        uint256 deadline,
        address recipient
    )
        external
    {
        emit EthToTokenTransferInput(
            msg.sender,
            minTokensBought,
            deadline,
            recipient
        );
    }

    function raiseTokenToEthSwapInput(
        uint256 tokensSold,
        uint256 minEthBought,
        uint256 deadline
    )
        external
    {
        emit TokenToEthSwapInput(
            msg.sender,
            tokensSold,
            minEthBought,
            deadline
        );
    }

    function raiseTokenToTokenTransferInput(
        uint256 tokensSold,
        uint256 minTokensBought,
        uint256 minEthBought,
        uint256 deadline,
        address recipient,
        address toTokenAddress
    )
        external
    {
        emit TokenToTokenTransferInput(
            msg.sender,
            tokensSold,
            minTokensBought,
            minEthBought,
            deadline,
            recipient,
            toTokenAddress
        );
    }

    function raiseTokenTransfer(
        address from,
        address to,
        uint256 amount
    )
        external
    {
        emit TokenTransfer(
            msg.sender,
            from,
            to,
            amount
        );
    }

    function raiseTokenApprove(address spender, uint256 allowance)
        external
    {
        emit TokenApprove(spender, allowance);
    }

    function raiseWethDeposit(uint256 amount)
        external
    {
        emit WethDeposit(amount);
    }

    function raiseWethWithdraw(uint256 amount)
        external
    {
        emit WethWithdraw(amount);
    }
}


/// @dev A minimalist ERC20/WETH token.
contract TestToken {

    using LibSafeMath for uint256;

    mapping (address => uint256) public balances;
    string private _nextRevertReason;

    /// @dev Set the balance for `owner`.
    function setBalance(address owner)
        external
        payable
    {
        balances[owner] = msg.value;
    }

    /// @dev Set the revert reason for `transfer()`,
    ///      `deposit()`, and `withdraw()`.
    function setRevertReason(string calldata reason)
        external
    {
        _nextRevertReason = reason;
    }

    /// @dev Just calls `raiseTokenTransfer()` on the caller.
    function transfer(address to, uint256 amount)
        external
        returns (bool)
    {
        _revertIfReasonExists();
        TestEventsRaiser(msg.sender).raiseTokenTransfer(msg.sender, to, amount);
        return true;
    }

    /// @dev Just calls `raiseTokenApprove()` on the caller.
    function approve(address spender, uint256 allowance)
        external
        returns (bool)
    {
        TestEventsRaiser(msg.sender).raiseTokenApprove(spender, allowance);
        return true;
    }

    /// @dev `IWETH.deposit()` that increases balances and calls
    ///     `raiseWethDeposit()` on the caller.
    function deposit()
        external
        payable
    {
        _revertIfReasonExists();
        balances[msg.sender] += balances[msg.sender].safeAdd(msg.value);
        TestEventsRaiser(msg.sender).raiseWethDeposit(msg.value);
    }

    /// @dev `IWETH.withdraw()` that just reduces balances and calls
    ///       `raiseWethWithdraw()` on the caller.
    function withdraw(uint256 amount)
        external
    {
        _revertIfReasonExists();
        balances[msg.sender] = balances[msg.sender].safeSub(amount);
        msg.sender.transfer(amount);
        TestEventsRaiser(msg.sender).raiseWethWithdraw(amount);
    }

    function allowance(address, address) external view returns (uint256) {
        return 0;
    }

    /// @dev Retrieve the balance for `owner`.
    function balanceOf(address owner)
        external
        view
        returns (uint256)
    {
        return balances[owner];
    }

    function _revertIfReasonExists()
        private
        view
    {
        if (bytes(_nextRevertReason).length != 0) {
            revert(_nextRevertReason);
        }
    }
}


contract TestExchange is
    IUniswapExchange
{
    address public tokenAddress;
    string private _nextRevertReason;

    constructor(address _tokenAddress) public {
        tokenAddress = _tokenAddress;
    }

    function setFillBehavior(
        string calldata revertReason
    )
        external
        payable
    {
        _nextRevertReason = revertReason;
    }

    function ethToTokenTransferInput(
        uint256 minTokensBought,
        uint256 deadline,
        address recipient
    )
        external
        payable
        returns (uint256 tokensBought)
    {
        TestEventsRaiser(msg.sender).raiseEthToTokenTransferInput(
            minTokensBought,
            deadline,
            recipient
        );
        _revertIfReasonExists();
        return address(this).balance;
    }

    function tokenToEthSwapInput(
        uint256 tokensSold,
        uint256 minEthBought,
        uint256 deadline
    )
        external
        returns (uint256 ethBought)
    {
        TestEventsRaiser(msg.sender).raiseTokenToEthSwapInput(
            tokensSold,
            minEthBought,
            deadline
        );
        _revertIfReasonExists();
        uint256 fillAmount = address(this).balance;
        msg.sender.transfer(fillAmount);
        return fillAmount;
    }

    function tokenToTokenTransferInput(
        uint256 tokensSold,
        uint256 minTokensBought,
        uint256 minEthBought,
        uint256 deadline,
        address recipient,
        address toTokenAddress
    )
        external
        returns (uint256 tokensBought)
    {
        TestEventsRaiser(msg.sender).raiseTokenToTokenTransferInput(
            tokensSold,
            minTokensBought,
            minEthBought,
            deadline,
            recipient,
            toTokenAddress
        );
        _revertIfReasonExists();
        return address(this).balance;
    }

    function toTokenAddress()
        external
        view
        returns (address _tokenAddress)
    {
        return tokenAddress;
    }

    function _revertIfReasonExists()
        private
        view
    {
        if (bytes(_nextRevertReason).length != 0) {
            revert(_nextRevertReason);
        }
    }
}


/// @dev UniswapBridge overridden to mock tokens and implement IUniswapExchangeFactory.
contract TestUniswapBridge is
    IUniswapExchangeFactory,
    TestEventsRaiser,
    UniswapBridge
{
    TestToken public wethToken;
    // Token address to TestToken instance.
    mapping (address => TestToken) private _testTokens;
    // Token address to TestExchange instance.
    mapping (address => TestExchange) private _testExchanges;

    constructor() public {
        wethToken = new TestToken();
        _testTokens[address(wethToken)] = wethToken;
    }

    /// @dev Sets the balance of this contract for an existing token.
    ///      The wei attached will be the balance.
    function setTokenBalance(address tokenAddress)
        external
        payable
    {
        TestToken token = _testTokens[tokenAddress];
        token.deposit.value(msg.value)();
    }

    /// @dev Sets the revert reason for an existing token.
    function setTokenRevertReason(address tokenAddress, string calldata revertReason)
        external
    {
        TestToken token = _testTokens[tokenAddress];
        token.setRevertReason(revertReason);
    }

    /// @dev Create a token and exchange (if they don't exist) for a new token
    ///      and sets the exchange revert and fill behavior. The wei attached
    ///      will be the fill amount for the exchange.
    /// @param tokenAddress The token address. If zero, one will be created.
    /// @param revertReason The revert reason for exchange operations.
    function createTokenAndExchange(
        address tokenAddress,
        string calldata revertReason
    )
        external
        payable
        returns (TestToken token, TestExchange exchange)
    {
        token = TestToken(tokenAddress);
        if (tokenAddress == address(0)) {
            token = new TestToken();
        }
        _testTokens[address(token)] = token;
        exchange = _testExchanges[address(token)];
        if (address(exchange) == address(0)) {
            _testExchanges[address(token)] = exchange = new TestExchange(address(token));
        }
        exchange.setFillBehavior.value(msg.value)(revertReason);
        return (token, exchange);
    }

    /// @dev `IUniswapExchangeFactory.getExchange`
    function getExchange(address tokenAddress)
        external
        view
        returns (address)
    {
        return address(_testExchanges[tokenAddress]);
    }

    // @dev Use `wethToken`.
    function _getWethAddress()
        internal
        view
        returns (address)
    {
        return address(wethToken);
    }

    // @dev This contract will double as the Uniswap contract.
    function _getUniswapExchangeFactoryAddress()
        internal
        view
        returns (address)
    {
        return address(this);
    }
}
