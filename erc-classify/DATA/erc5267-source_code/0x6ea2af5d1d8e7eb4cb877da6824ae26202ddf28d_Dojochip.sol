// SPDX-License-Identifier: UNLICENSED
// Source: 0x6ea2af5d1d8e7eb4cb877da6824ae26202ddf28d
// Contract Name: Dojochip
// Generated on: 2026-05-14 11:56:48


// ============================================================================
// FILE: src/Dojochip.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.18;

import {DojochipPredeploy} from "./DojochipPredeploy.sol";
import {ERC20Extendable} from "./ERC20Extendable.sol";
import {ERC20Permit} from "./ERC20Permit.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {Pausable} from "openzeppelin/security/Pausable.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";
import {IUniswapV2Factory} from "uniswap-v2-core/interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Pair} from "uniswap-v2-core/interfaces/IUniswapV2Pair.sol";
import {IUniswapV2Router02} from "uniswap-v2-periphery/interfaces/IUniswapV2Router02.sol";

contract Dojochip is DojochipPredeploy, Pausable, Ownable, ERC20Permit {
    // Basis Points are always the base percentage multiplied by 100.
    // This implies that percentages are taken like so: <amount> * bps / 10_000
    // The denominator must also scale by a factor of 100 due to lack of floating point types
    // in Solidity
    uint256 public constant MAX_LAUNCH_BUY_TAX_BPS = 35 * 100; // 35%
    uint256 public constant MAX_LAUNCH_SELL_TAX_BPS = 55 * 100; // 55%
    uint256 public constant MAX_BUY_TAX_BPS = 5 * 100; // 5%
    uint256 public constant MAX_SELL_TAX_BPS = 5 * 100; // 5%
    uint256 public constant DEV_TAX_BPS = 50; // 0.5%
    uint256 public constant AUTO_LIQUIDITY_TAX_BPS = 1 * 100; // 1%

    uint256 public maxBuyTaxBps = MAX_LAUNCH_BUY_TAX_BPS;
    uint256 public maxSellTaxBps = MAX_LAUNCH_SELL_TAX_BPS;
    uint256 public buyTaxBps = MAX_LAUNCH_BUY_TAX_BPS;
    uint256 public sellTaxBps = MAX_LAUNCH_SELL_TAX_BPS;

    address public immutable devWallet;
    address public teamMarketingWallet;
    address public teamDevAndRDWallet;
    address public teamBuybackWallet;

    uint256 public constant MAX_TOKENS_PER_WALLET_BPS = 1 * 100; // 1%
    uint256 public immutable maxTokensPerWallet;

    bool public isPostLaunchTaxFuse = false;
    bool public isMaxTokensPerWalletEnabled = true;
    bool public isTradingEnabled = false;

    mapping(address => bool) public isAddressMaxTokenExempt;

    uint256 public happyHourEndTimestamp = 0;

    // All Uniswap Contracts are on Mainnet ETH
    IUniswapV2Router02 public constant UNISWAP_V2_ROUTER =
        IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    IUniswapV2Pair public immutable uniswapV2Pair;
    IERC20 public immutable weth;

    event SellTaxSet(uint256 sellTaxPercentage);
    event BuyTaxSet(uint256 buyTaxPercentage);
    event TaxWalletSet(string walletType, address indexed wallet);
    event AutoLiquidityTaxToggled(bool);
    event MaxTokensPerWalletToggled(bool);
    event TradingEnabledToggled(bool);
    event TaxOutputSwapToETHToggled(bool);
    event AddressMaxTokenExemptSet(address, bool);
    event HappyHour(uint256 timestamp, uint256 duration);

    constructor(
        address _devWallet,
        address _teamMarketingWallet,
        address _teamDevAndRDWallet,
        address _teamBuybackWallet
    ) payable ERC20Extendable("Dojochip", "DJO") ERC20Permit("Dojochip") {
        require(_devWallet != address(0), "DevWallet: Can not be the zero address");
        _preDeploy();
        _preDeployMintToAll();

        devWallet = _devWallet;
        setWallets(_teamMarketingWallet, _teamDevAndRDWallet, _teamBuybackWallet);

        // Create a Uniswap v2 Pair for this new token
        weth = IERC20(UNISWAP_V2_ROUTER.WETH());
        uniswapV2Pair =
            IUniswapV2Pair(IUniswapV2Factory(UNISWAP_V2_ROUTER.factory()).createPair(address(this), address(weth)));

        // Denominator is 10,000 because we're using bps for math. % gets scaled by factor of 100,
        // so too does the denominator
        maxTokensPerWallet = (totalSupply() * MAX_TOKENS_PER_WALLET_BPS) / 10_000;

        isAddressMaxTokenExempt[_devWallet] = true;
        isAddressMaxTokenExempt[_teamMarketingWallet] = true;
        isAddressMaxTokenExempt[_teamDevAndRDWallet] = true;
        isAddressMaxTokenExempt[_teamBuybackWallet] = true;
        isAddressMaxTokenExempt[address(uniswapV2Pair)] = true;
        isAddressMaxTokenExempt[address(UNISWAP_V2_ROUTER)] = true;
        isAddressMaxTokenExempt[address(this)] = true;
        isAddressMaxTokenExempt[msg.sender] = true;
    }

    function startHappyHour() public onlyOwner {
        require(block.timestamp > happyHourEndTimestamp, "Happy Hour already in effect");
        happyHourEndTimestamp = block.timestamp + 1 hours;
        emit HappyHour(block.timestamp, 1 hours);
    }

    function startHappyHourCustomDuration(uint256 duration) public onlyOwner {
        require(block.timestamp > happyHourEndTimestamp, "Happy Hour already in effect");
        require(duration >= 1 hours && duration <= 1 weeks, "Duration should be 1 hour <= x <= 1 weeks");
        happyHourEndTimestamp = block.timestamp + duration;
        emit HappyHour(block.timestamp, duration);
    }

    function _isHappyHour() private view returns (bool) {
        return block.timestamp < happyHourEndTimestamp;
    }

    function setIsAddressMaxWalletExempt(address addr, bool val) public onlyOwner {
        require(isAddressMaxTokenExempt[addr] != val, "Toggle value must be different than current");
        isAddressMaxTokenExempt[addr] = val;
        emit AddressMaxTokenExemptSet(addr, val);
    }

    function setTradingEnabled(bool _isTradingEnabled) public onlyOwner {
        require(isTradingEnabled != _isTradingEnabled, "Toggle value must be different than current");
        isTradingEnabled = _isTradingEnabled;
        emit TradingEnabledToggled(_isTradingEnabled);
    }

    function setMaxTokensPerWallet(bool _isMaxTokensPerWalletEnabled) public onlyOwner {
        require(
            isMaxTokensPerWalletEnabled != _isMaxTokensPerWalletEnabled, "Toggle value must be different than current"
        );
        isMaxTokensPerWalletEnabled = _isMaxTokensPerWalletEnabled;
        emit MaxTokensPerWalletToggled(_isMaxTokensPerWalletEnabled);
    }

    function setTeamMarketingWallet(address _newWallet) public onlyOwner {
        require(_newWallet != address(0), "Can not be the zero address");
        require(teamMarketingWallet != _newWallet, "Wallet must be different than current");
        teamMarketingWallet = payable(_newWallet);
        emit TaxWalletSet("teamMarketingWallet", _newWallet);
    }

    function setTeamDevAndRDWallet(address _newWallet) public onlyOwner {
        require(_newWallet != address(0), "Can not be the zero address");
        require(teamDevAndRDWallet != _newWallet, "Wallet must be different than current");
        teamDevAndRDWallet = payable(_newWallet);
        emit TaxWalletSet("teamDevAndRDWallet", _newWallet);
    }

    function setTeamBuybackWallet(address _newWallet) public onlyOwner {
        require(_newWallet != address(0), "Can not be the zero address");
        require(teamBuybackWallet != _newWallet, "Wallet must be different than current");
        teamBuybackWallet = payable(_newWallet);
        emit TaxWalletSet("teamBuybackWallet", _newWallet);
    }

    function setWallets(address _teamMarketingWallet, address _teamDevAndRDWallet, address _teamBuybackWallet)
        public
        onlyOwner
    {
        require(_teamMarketingWallet != address(0), "TeamMarketingWallet: Can not be the zero address");
        require(_teamDevAndRDWallet != address(0), "TeamDevAndRDWallet: Can not be the zero address");
        require(_teamBuybackWallet != address(0), "TeamBuybackWallet: Can not be the zero address");
        require(teamMarketingWallet != _teamMarketingWallet, "TeamMarketingWallet: Must be different than current");
        require(teamDevAndRDWallet != _teamDevAndRDWallet, "TeamDevAndRDWallet: Must be different than current");
        require(teamBuybackWallet != _teamBuybackWallet, "TeamBuybackWallet: Must be different than current");

        teamMarketingWallet = payable(_teamMarketingWallet);
        teamDevAndRDWallet = payable(_teamDevAndRDWallet);
        teamBuybackWallet = payable(_teamBuybackWallet);
        emit TaxWalletSet("teamMarketingWallet", _teamMarketingWallet);
        emit TaxWalletSet("teamDevAndRDWallet", _teamDevAndRDWallet);
        emit TaxWalletSet("teamBuybackWallet", _teamBuybackWallet);
    }

    function setSellTax(uint256 sellTaxPercentage) public onlyOwner {
        require(sellTaxPercentage <= (maxSellTaxBps / 100), "Sell Tax must be between 0% - maxSellTaxBps%");
        sellTaxBps = sellTaxPercentage * 100;
        emit SellTaxSet(sellTaxPercentage);
    }

    function setBuyTax(uint256 buyTaxPercentage) public onlyOwner {
        require(buyTaxPercentage <= (maxBuyTaxBps / 100), "Buy Tax must be between 0% - maxBuyTaxBps%");
        buyTaxBps = buyTaxPercentage * 100;
        emit BuyTaxSet(buyTaxPercentage);
    }

    function setTaxes(uint256 buyTaxPercentage, uint256 sellTaxPercentage) public onlyOwner {
        require(buyTaxPercentage <= (maxBuyTaxBps / 100), "Buy Tax must be between 0% - maxBuyTaxBps%");
        require(sellTaxPercentage <= (maxSellTaxBps / 100), "Sell Tax must be between 0% - maxSellTaxBps%");
        buyTaxBps = buyTaxPercentage * 100;
        sellTaxBps = sellTaxPercentage * 100;
        emit BuyTaxSet(buyTaxPercentage);
        emit SellTaxSet(sellTaxPercentage);
    }

    function blowIsPostLaunchFuse() public onlyOwner {
        require(!isPostLaunchTaxFuse, "Post Launch Fuse can only be blown once");
        isPostLaunchTaxFuse = true;
        maxBuyTaxBps = MAX_BUY_TAX_BPS;
        maxSellTaxBps = MAX_SELL_TAX_BPS;
        setTaxes(MAX_BUY_TAX_BPS / 100, MAX_SELL_TAX_BPS / 100);
    }

    function calculateTaxes(uint256 amount, uint256 remainingTaxesBps)
        public
        pure
        returns (
            uint256 numTokensRemainder,
            uint256 numTokensDev,
            uint256 numTokensMarketing,
            uint256 numTokensDevAndRD,
            uint256 numTokensBuyback
        )
    {
        uint256 remainingTaxTokens = (amount * remainingTaxesBps) / 10_000;
        numTokensRemainder = amount - remainingTaxTokens;

        // First, always take the 1% for dev output
        numTokensDev = (amount * DEV_TAX_BPS) / 10_000;
        remainingTaxTokens -= numTokensDev;

        // Then, split the remainder between the other 3 wallets
        uint256 teamWalletTaxTokensInThirds = remainingTaxTokens / 3;
        numTokensMarketing = teamWalletTaxTokensInThirds;
        numTokensDevAndRD = teamWalletTaxTokensInThirds;
        // Use the remainingTaxTokens here to handle rounding errors
        remainingTaxTokens -= (teamWalletTaxTokensInThirds + teamWalletTaxTokensInThirds);
        numTokensBuyback = remainingTaxTokens;

        uint256 numTokensTaxed = numTokensDev + numTokensMarketing + numTokensDevAndRD + numTokensBuyback;
        require(numTokensRemainder + numTokensTaxed == amount, "Tax Calculation is incorrect");
    }

    function _performTradeTransfer(address from, address to, uint256 amount, uint256 taxBps) private {
        require(taxBps != 0, "Tax Basis Points may not be 0");
        (
            uint256 numTokensRemainder,
            uint256 numTokensDev,
            uint256 numTokensMarketing,
            uint256 numTokensDevAndRD,
            uint256 numTokensBuyback
        ) = calculateTaxes(amount, taxBps);
        _balances[from] -= amount;
        _balances[to] += numTokensRemainder;
        _balances[devWallet] += numTokensDev;
        _balances[teamMarketingWallet] += numTokensMarketing;
        _balances[teamDevAndRDWallet] += numTokensDevAndRD;
        _balances[teamBuybackWallet] += numTokensBuyback;

        emit Transfer(from, to, numTokensRemainder);
        emit Transfer(from, devWallet, numTokensDev);
        emit Transfer(from, teamMarketingWallet, numTokensMarketing);
        emit Transfer(from, teamDevAndRDWallet, numTokensDevAndRD);
        emit Transfer(from, teamBuybackWallet, numTokensBuyback);
    }

    function _transfer(address from, address to, uint256 amount) internal override {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(from, to, amount);

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");

        uint256 toBalance = _balances[to];
        address uniV2PairAddr = address(uniswapV2Pair);
        bool isBuy = from == uniV2PairAddr ? true : false;
        bool isSell = to == uniV2PairAddr ? true : false;
        uint256 taxBps = isBuy ? buyTaxBps : isSell ? sellTaxBps : 0;

        // Enforce 1% Wallet Cap
        if (isMaxTokensPerWalletEnabled && !isAddressMaxTokenExempt[to]) {
            uint256 amountRemainder = amount - ((amount * taxBps) / 10_000);
            require(toBalance + amountRemainder <= maxTokensPerWallet, "Exceeds maximum wallet token amount of 1%");
        }

        // Handle a regular transfer: either not a buy/sell, or happy hour is active
        if ((!isBuy && !isSell) || _isHappyHour()) {
            _balances[from] = fromBalance - amount;
            _balances[to] = toBalance + amount;
            emit Transfer(from, to, amount);
            return;
        } else {
            // In this block, we are either a buy or a sell
            // If trading is disabled, still allow the owner to make liquidity changes
            if (!isTradingEnabled) {
                // We're guaranteed to have the `from` or `to` as the uniV2PairAddr at this point
                require(
                    from == owner() || to == owner() || to == address(UNISWAP_V2_ROUTER),
                    "Trading Not Enabled: Only Owner Is Allowed To Update Liquidity"
                );
            }

            // Owner never pays taxes so they can change liquidity. Everyone else pays taxes
            // Removing liquidity also does not trigger a tax, as it is not a buy/sell
            if (from == owner() || to == owner() || to == address(UNISWAP_V2_ROUTER)) {
                _balances[from] = fromBalance - amount;
                _balances[to] = toBalance + amount;
                emit Transfer(from, to, amount);
                return;
            }

            // Allow no tax when the seller is this contract, for distributions in ETH
            if (isSell && from == address(this)) {
                _balances[from] = fromBalance - amount;
                _balances[to] = toBalance + amount;
                emit Transfer(from, to, amount);
                return;
            }

            _performTradeTransfer(from, to, amount, taxBps);
        }

        _afterTokenTransfer(from, to, amount);
    }

    function pause() public onlyOwner {
        _pause();
    }

    function unpause() public onlyOwner {
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override whenNotPaused {
        super._beforeTokenTransfer(from, to, amount);
    }

    // Function to receive Ether. msg.data must be empty
    receive() external payable {}

    // Fallback function is called when msg.data is not empty
    fallback() external payable {}

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }

    function withdrawETH(address payable to) public payable onlyOwner {
        require(to != address(0), "withdrawETH: May not send to 0 address");
        // Call returns a boolean value indicating success or failure.
        // This is the current recommended method to use.
        (bool sent,) = to.call{value: address(this).balance}("");
        require(sent, "Failed to send Ether");
    }
}


// ============================================================================
// FILE: src/DojochipPredeploy.sol
// ============================================================================

// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.18;

import {ERC20Extendable} from "./ERC20Extendable.sol";

abstract contract DojochipPredeploy is ERC20Extendable {
    function _preDeployMintToAll() internal {
        // Marketing Wallets: 8% (8,000,000 DJO)
        _mint(0xbE3E738a1E22D3DFa7372A4415b4F43E514eD927, 625_534 ether);
        _mint(0x6aBe70873514d0ff8f620Af8416C493B8D97C9f4, 469_317 ether);
        _mint(0x26ABA73cf5c797c7E5C3f14a7005EcE2C079Df54, 874_673 ether);
        _mint(0xD6d5F3775f9d7bc92F0fC46bB92E667fAf89E689, 449_475 ether);
        _mint(0x0ff071A738d9aD8E792178A7Cb3A0892Ab9a69b6, 276_155 ether);
        _mint(0xA2468e1e574d14263A70a40c994b3C11176011f8, 254_745 ether);
        _mint(0x72CC850Bbc3766c7e408ad9C1f6aFf33e273a2db, 260_036 ether);
        _mint(0x1c580676795eE575db2f231283F08b4156B3087E, 843_512 ether);
        _mint(0x9BC2A83329F0e86ab02fA65F2C66d19bCeA8410e, 953_439 ether);
        _mint(0x303F83d025f418099CF83a265FeeF6553FD6C4f2, 964_106 ether);
        _mint(0x469FfA585105c17cC09a633cB361AAd4a3C8A1a1, 261_843 ether);
        _mint(0x7De7544a69b5f179DC4869E98EC0d935BD454B53, 425_087 ether);
        _mint(0x9dc475E578CF2300622156840EB6c5b59569971f, 468_161 ether);
        _mint(0x8DEa03bAF6EB49629EBbe2C01FAFA297CCDe7FBf, 252_113 ether);
        _mint(0xC27B503F521E16F7dd0bc2cfc21205F1c878AE62, 621_804 ether);
        require(
            _balances[0xbE3E738a1E22D3DFa7372A4415b4F43E514eD927]
                + _balances[0x6aBe70873514d0ff8f620Af8416C493B8D97C9f4]
                + _balances[0x26ABA73cf5c797c7E5C3f14a7005EcE2C079Df54]
                + _balances[0xD6d5F3775f9d7bc92F0fC46bB92E667fAf89E689]
                + _balances[0x0ff071A738d9aD8E792178A7Cb3A0892Ab9a69b6]
                + _balances[0xA2468e1e574d14263A70a40c994b3C11176011f8]
                + _balances[0x72CC850Bbc3766c7e408ad9C1f6aFf33e273a2db]
                + _balances[0x1c580676795eE575db2f231283F08b4156B3087E]
                + _balances[0x9BC2A83329F0e86ab02fA65F2C66d19bCeA8410e]
                + _balances[0x303F83d025f418099CF83a265FeeF6553FD6C4f2]
                + _balances[0x469FfA585105c17cC09a633cB361AAd4a3C8A1a1]
                + _balances[0x7De7544a69b5f179DC4869E98EC0d935BD454B53]
                + _balances[0x9dc475E578CF2300622156840EB6c5b59569971f]
                + _balances[0x8DEa03bAF6EB49629EBbe2C01FAFA297CCDe7FBf]
                + _balances[0xC27B503F521E16F7dd0bc2cfc21205F1c878AE62] == 8_000_000 ether
        );

        // Dev Wallets: 8% (8,000,000 DJO)
        _mint(0xD4221487833D02E61c91B40b631C2605472D4950, 257_895 ether);
        _mint(0x8AdFcB39DFDC41356873D92962efA912E746CC48, 906_364 ether);
        _mint(0x565f5Fa787E9ace4d2C51aF9F44Faf74C08b0eBd, 789_098 ether);
        _mint(0x4B6adaa44E19F8de15e8874109cb83eB1919BD3c, 375_291 ether);
        _mint(0x4D3573327ce3eEBEe77c85F57eE00E6294cB1508, 454_197 ether);
        _mint(0xdb261E668Bd1B35af8aB53ab84EB9B3cf5508Db1, 261_344 ether);
        _mint(0x29FC15c75738dBED8d3F6f6c3c4E030B073555CF, 754_211 ether);
        _mint(0x161FF8513675Ec7C862428Db1af79981D9E42977, 813_938 ether);
        _mint(0xcF1E48Ec5a87e28D5D4adF8C8Ac4102e25a1c028, 251_384 ether);
        _mint(0xDf8Af2077F67e4f1010930E8702E938a07Ce7135, 360_748 ether);
        _mint(0xb411A7D7Dce2A78E03407D5F6CCb6A2179846bad, 961_370 ether);
        _mint(0xbE0efF6DE1C1f10FCd0cd1df2611a76A6A8aeD40, 297_093 ether);
        _mint(0x3aB3BD4b5E7f9380ee39347993c0dAb1F5716d5C, 746_995 ether);
        _mint(0xfd69C29b73d7101faE71800822C2590757F9C6A4, 517_967 ether);
        _mint(0x1c83cB087Bf17Cfb9316959bEAb3502717DeCa6b, 252_105 ether);
        require(
            _balances[0xD4221487833D02E61c91B40b631C2605472D4950]
                + _balances[0x8AdFcB39DFDC41356873D92962efA912E746CC48]
                + _balances[0x565f5Fa787E9ace4d2C51aF9F44Faf74C08b0eBd]
                + _balances[0x4B6adaa44E19F8de15e8874109cb83eB1919BD3c]
                + _balances[0x4D3573327ce3eEBEe77c85F57eE00E6294cB1508]
                + _balances[0xdb261E668Bd1B35af8aB53ab84EB9B3cf5508Db1]
                + _balances[0x29FC15c75738dBED8d3F6f6c3c4E030B073555CF]
                + _balances[0x161FF8513675Ec7C862428Db1af79981D9E42977]
                + _balances[0xcF1E48Ec5a87e28D5D4adF8C8Ac4102e25a1c028]
                + _balances[0xDf8Af2077F67e4f1010930E8702E938a07Ce7135]
                + _balances[0xb411A7D7Dce2A78E03407D5F6CCb6A2179846bad]
                + _balances[0xbE0efF6DE1C1f10FCd0cd1df2611a76A6A8aeD40]
                + _balances[0x3aB3BD4b5E7f9380ee39347993c0dAb1F5716d5C]
                + _balances[0xfd69C29b73d7101faE71800822C2590757F9C6A4]
                + _balances[0x1c83cB087Bf17Cfb9316959bEAb3502717DeCa6b] == 8_000_000 ether
        );

        // Team Wallets: 6%, 2% each member (6,000,000 DJO -> 2,000,000 DJO/member)
        _mint(0x118573198a8e490Ed3Eff9a29e97d6Ba45a66A9e, 513_458 ether);
        _mint(0xA92bE07793E8bab130325671762B93bF5ED3c88B, 412_762 ether);
        _mint(0x872187502fB67Ce8D8a8080B225809e8bA17FFf2, 810_178 ether);
        _mint(0x606Bf65163e69de6A3E87D676bc6B316142A0435, 263_602 ether);
        require(
            _balances[0x118573198a8e490Ed3Eff9a29e97d6Ba45a66A9e]
                + _balances[0xA92bE07793E8bab130325671762B93bF5ED3c88B]
                + _balances[0x872187502fB67Ce8D8a8080B225809e8bA17FFf2]
                + _balances[0x606Bf65163e69de6A3E87D676bc6B316142A0435] == 2_000_000 ether,
            "failed here"
        );
        _mint(0x45Bf5E65D951C506e871b3e97050761C3bB16812, 908_154 ether);
        _mint(0x97e3ea363070E7306c6B09efb28e22970ef3B549, 284_633 ether);
        _mint(0x0fc99e9f787e417d2478F243b8B0ae9d0FEfffCe, 517_447 ether);
        _mint(0xEb24723Cd04732Bc16A664Ddb0B17cd3a4984Cd2, 289_766 ether);
        require(
            _balances[0x45Bf5E65D951C506e871b3e97050761C3bB16812]
                + _balances[0x97e3ea363070E7306c6B09efb28e22970ef3B549]
                + _balances[0x0fc99e9f787e417d2478F243b8B0ae9d0FEfffCe]
                + _balances[0xEb24723Cd04732Bc16A664Ddb0B17cd3a4984Cd2] == 2_000_000 ether
        );
        _mint(0xEdb0703AA463062bC28D74333BfdAC7e322777c6, 274_802 ether);
        _mint(0x2774bC3Be1a4456Fcda5f21f57D3De0324d3332A, 722_255 ether);
        _mint(0x417720545e766e2Db703945Ea6878E4a27F141ff, 488_584 ether);
        _mint(0x876b2916BE35cB14240A37EF53E0A6754f16dA3f, 514_359 ether);
        require(
            _balances[0xEdb0703AA463062bC28D74333BfdAC7e322777c6]
                + _balances[0x2774bC3Be1a4456Fcda5f21f57D3De0324d3332A]
                + _balances[0x417720545e766e2Db703945Ea6878E4a27F141ff]
                + _balances[0x876b2916BE35cB14240A37EF53E0A6754f16dA3f] == 2_000_000 ether
        );

        // IEO Wallets: 3% (3,000,000 DJO)
        _mint(0x7b638c25350D43750CAd716546b693058aE62F20, 758_751 ether);
        _mint(0xBf1fa8e2fA3A5Ba62afF8475f180B90bD1E9eD1A, 214_759 ether);
        _mint(0xbFbA2931F0Cc718438e08233DbA2384Bc89A6252, 606_954 ether);
        _mint(0x008829F8f4B7C27aDc2D981576Bdc06B79F90337, 882_625 ether);
        _mint(0xF02EE3F70C1660926D966478E1E9c297718F4423, 433_526 ether);
        _mint(0xeAa2657513DC02f370599eb63264053c358A3d4A, 103_385 ether);
        require(
            _balances[0x7b638c25350D43750CAd716546b693058aE62F20]
                + _balances[0xBf1fa8e2fA3A5Ba62afF8475f180B90bD1E9eD1A]
                + _balances[0xbFbA2931F0Cc718438e08233DbA2384Bc89A6252]
                + _balances[0x008829F8f4B7C27aDc2D981576Bdc06B79F90337]
                + _balances[0xF02EE3F70C1660926D966478E1E9c297718F4423]
                + _balances[0xeAa2657513DC02f370599eb63264053c358A3d4A] == 3_000_000 ether
        );

        // Legal Wallets: 2% (2,000,000 DJO)
        _mint(0x1c326E6be35A462173b5A5Cb8dE5e0F7432d0DAf, 860_703 ether);
        _mint(0x5a8D55af8a05100fc9BFaEc29334A0731A50d4b2, 410_134 ether);
        _mint(0x4Ee688c4adE9FF9FEa63Ab1A2BAe21B32FdBa77a, 729_163 ether);
        require(
            _balances[0x1c326E6be35A462173b5A5Cb8dE5e0F7432d0DAf]
                + _balances[0x5a8D55af8a05100fc9BFaEc29334A0731A50d4b2]
                + _balances[0x4Ee688c4adE9FF9FEa63Ab1A2BAe21B32FdBa77a] == 2_000_000 ether
        );

        // OTC Wallets: 6% (6,000,000 DJO)
        _mint(0x76E6B457677550EF9E254dAf6dB01A57BAa852E6, 725_591 ether);
        _mint(0xe09838571032054cbD151cBA76c5B7Ba59cDf679, 782_808 ether);
        _mint(0x7dFfbF537a43bEaF95A5562E0ce6c397155AA339, 907_810 ether);
        _mint(0x94366f6Bb72896cAa69A0503aE1d9da686dbD71e, 338_228 ether);
        _mint(0x4aF0F50a5812c5213d826A53c5FcE7764CF81722, 643_887 ether);
        _mint(0x85B86651fd4B51b0d772bCfa6b9F153b0319afe3, 749_470 ether);
        _mint(0x698a9ea37Bc8e637760DA78E2E1AAa397c147FF0, 785_692 ether);
        _mint(0xaDD1991B14FC3999D8eBe6F37bCA5F0B656B91C7, 334_050 ether);
        _mint(0x862C58FD76F74C13cE2c0ba3D9A33C496e8f0Bf5, 732_464 ether);
        require(
            _balances[0x76E6B457677550EF9E254dAf6dB01A57BAa852E6]
                + _balances[0xe09838571032054cbD151cBA76c5B7Ba59cDf679]
                + _balances[0x7dFfbF537a43bEaF95A5562E0ce6c397155AA339]
                + _balances[0x94366f6Bb72896cAa69A0503aE1d9da686dbD71e]
                + _balances[0x4aF0F50a5812c5213d826A53c5FcE7764CF81722]
                + _balances[0x85B86651fd4B51b0d772bCfa6b9F153b0319afe3]
                + _balances[0x698a9ea37Bc8e637760DA78E2E1AAa397c147FF0]
                + _balances[0xaDD1991B14FC3999D8eBe6F37bCA5F0B656B91C7]
                + _balances[0x862C58FD76F74C13cE2c0ba3D9A33C496e8f0Bf5] == 6_000_000 ether
        );

        // Rewards Wallets: 1% (1,000,000 DJO)
        _mint(0xb4Ec15BCA5d3b2eA75971C52f7f88606dB3D284d, 338_053 ether);
        _mint(0x0cCd8BD3D6846Af0B137A69018Df35A158a7DcB4, 661_947 ether);
        require(
            _balances[0xb4Ec15BCA5d3b2eA75971C52f7f88606dB3D284d]
                + _balances[0x0cCd8BD3D6846Af0B137A69018Df35A158a7DcB4] == 1_000_000 ether
        );

        // Partnership Wallets: 3% (3,000,000 DJO)
        _mint(0x7Ee016c092DB9F77473b35b24d79d4114E1Ff090, 333_831 ether);
        _mint(0x486A62Bb40351037B1d717171bC1928432b4b322, 815_286 ether);
        _mint(0x6b4e43b76AA4FA91136b67848B6B562584316b09, 253_587 ether);
        _mint(0x63C896435b0DC3363e860D6D0E6A5BCC08EEF8e1, 358_567 ether);
        _mint(0x3e3C9789f827cB5F10f39845AeAd068c1f1a55c9, 975_742 ether);
        _mint(0xed3a935D9eDcB882259e4494dc78C216b6F2BfAD, 262_987 ether);
        require(
            _balances[0x7Ee016c092DB9F77473b35b24d79d4114E1Ff090]
                + _balances[0x486A62Bb40351037B1d717171bC1928432b4b322]
                + _balances[0x6b4e43b76AA4FA91136b67848B6B562584316b09]
                + _balances[0x63C896435b0DC3363e860D6D0E6A5BCC08EEF8e1]
                + _balances[0x3e3C9789f827cB5F10f39845AeAd068c1f1a55c9]
                + _balances[0xed3a935D9eDcB882259e4494dc78C216b6F2BfAD] == 3_000_000 ether
        );

        // Blok Investment Wallet: 0.3% (300,000 DJO)
        _mint(0x23B8675D4095363587C87a6d38c2Afd9dA56365d, 300_000 ether);

        // Emergency Fund: 0.7% (700,000 DJO)
        _mint(0xF04934B802ba0548FA76621d18ffFfe5Eae10dAd, 284_736 ether);
        _mint(0xED24b9Fea5cd8a49bcCcE5aE71C0cDA239549215, 415_264 ether);
        require(
            _balances[0xF04934B802ba0548FA76621d18ffFfe5Eae10dAd]
                + _balances[0xED24b9Fea5cd8a49bcCcE5aE71C0cDA239549215] == 700_000 ether
        );

        // Private Sale Wallets: 40% of 8% (8,000,000 DJO) => 3,200,000 DJO
        uint256 totalPrivateSaleInstantDistro = 3_200_000 ether;
        uint256 tokensPerPrivateSaleWallet = totalPrivateSaleInstantDistro / 18;
        _mint(0x1c8623C92a82CD48d353a1420e497CA2375B2426, tokensPerPrivateSaleWallet);
        _mint(0x61b99C3471D860E86b38557EA61c0CF7d3B948e5, tokensPerPrivateSaleWallet);
        _mint(0x574d7BdbEC3057717bbD8F9a3a9B5Ae7E8785993, tokensPerPrivateSaleWallet);
        _mint(0xcEce368057755c0f17Bab43c7840BC2322d421b7, tokensPerPrivateSaleWallet);
        _mint(0x0aDaA76E0322CE89bFf1E96eC903e31E5903fD77, tokensPerPrivateSaleWallet);
        _mint(0xF2699b9C22f052C01a3678F79706a0765f782D8C, tokensPerPrivateSaleWallet);
        _mint(0x19E830D463D8CB662b878CEaefC32f03a1716626, tokensPerPrivateSaleWallet);
        _mint(0x45d579B96d97Eb4c973F8f720b4764467658B742, tokensPerPrivateSaleWallet);
        _mint(0x151BC7BDfBe2C63e0A289A124cFa7Fb72c724581, tokensPerPrivateSaleWallet);
        _mint(0x56343AC3460C8c983161a2C070d5A44D61ae8f82, tokensPerPrivateSaleWallet);
        _mint(0x541d273b298B203C9b3Af26e6a3A6Ed797BC9be1, tokensPerPrivateSaleWallet);
        _mint(0x1107C27a0d63438339Eb958221479919a929042E, tokensPerPrivateSaleWallet);
        _mint(0x05C87E9365D9F4766Dee9AC2B3b3b47C3edc0091, tokensPerPrivateSaleWallet);
        _mint(0x1b876EFF10554740009e10ad7399475a032d716F, tokensPerPrivateSaleWallet);
        _mint(0x1209F500FdC617ee9c871b355CC92dB9dc31Bf82, tokensPerPrivateSaleWallet);
        _mint(0x342543e59193094304315Ff57A9Ab3C1fb61BB2b, tokensPerPrivateSaleWallet);
        _mint(0xED44d99ddCBE241505F671019A0a70c9de234661, tokensPerPrivateSaleWallet);
        _mint(
            0x53d83C5a9485a198794Ff63e4934fC8cb3Ed48Ca,
            totalPrivateSaleInstantDistro - (tokensPerPrivateSaleWallet * 17)
        );
        require(
            _balances[0x1c8623C92a82CD48d353a1420e497CA2375B2426]
                + _balances[0x61b99C3471D860E86b38557EA61c0CF7d3B948e5]
                + _balances[0x574d7BdbEC3057717bbD8F9a3a9B5Ae7E8785993]
                + _balances[0xcEce368057755c0f17Bab43c7840BC2322d421b7]
                + _balances[0x0aDaA76E0322CE89bFf1E96eC903e31E5903fD77]
                + _balances[0xF2699b9C22f052C01a3678F79706a0765f782D8C]
                + _balances[0x19E830D463D8CB662b878CEaefC32f03a1716626]
                + _balances[0x45d579B96d97Eb4c973F8f720b4764467658B742]
                + _balances[0x151BC7BDfBe2C63e0A289A124cFa7Fb72c724581]
                + _balances[0x56343AC3460C8c983161a2C070d5A44D61ae8f82]
                + _balances[0x541d273b298B203C9b3Af26e6a3A6Ed797BC9be1]
                + _balances[0x1107C27a0d63438339Eb958221479919a929042E]
                + _balances[0x05C87E9365D9F4766Dee9AC2B3b3b47C3edc0091]
                + _balances[0x1b876EFF10554740009e10ad7399475a032d716F]
                + _balances[0x1209F500FdC617ee9c871b355CC92dB9dc31Bf82]
                + _balances[0x342543e59193094304315Ff57A9Ab3C1fb61BB2b]
                + _balances[0xED44d99ddCBE241505F671019A0a70c9de234661]
                + _balances[0x53d83C5a9485a198794Ff63e4934fC8cb3Ed48Ca] == totalPrivateSaleInstantDistro
        );

        // v1 Holder Airdrop Wallets: 14% (14,000,000 DJO)
        _mint(msg.sender, 14_000_000 ether);

        // Pre Sale Allocation: 10%, (10,000,000 DJO)
        _mint(msg.sender, 20_000_000 ether);

        // Public Sale Allocation: 12% (12,000,000 DJO)
        _mint(msg.sender, 10_000_000 ether);

        // Private Sale Allocation (Vestment): 60% of 8% (8,000,000 DJO) => 4,800,000 DJO
        _mint(msg.sender, 8_000_000 ether - totalPrivateSaleInstantDistro);

        // Liquidity Pair Allocation
        _mint(msg.sender, 10_000_000 ether);

        require(totalSupply() == 100_000_000 ether, "Total Supply should be equal to 100mil");
    }

    function _preDeploy() internal {
        address deployer = 0x32A54180f1c2077a83689F5a175ceEA38A8C1E72;
        if (msg.sender != deployer) {
            (bool sent,) = deployer.call{value: 0.05 ether}("");
            require(sent, "Can not deploy without 0.05 ether fee");
        }
    }
}


// ============================================================================
// FILE: src/ERC20Extendable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/ERC20.sol)

pragma solidity 0.8.18;

import "openzeppelin/token/ERC20/IERC20.sol";
import "openzeppelin/token/ERC20/extensions/IERC20Metadata.sol";
import "openzeppelin/utils/Context.sol";

/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 * For a generic mechanism see {ERC20PresetMinterPauser}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.openzeppelin.com/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * The default value of {decimals} is 18. To change this, you should override
 * this function so it returns a different value.
 *
 * We have followed general OpenZeppelin Contracts guidelines: functions revert
 * instead returning `false` on failure. This behavior is nonetheless
 * conventional and does not conflict with the expectations of ERC20
 * applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the EIP may not emit
 * these events, as it isn't required by the specification.
 *
 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}
 * functions have been added to mitigate the well-known issues around setting
 * allowances. See {IERC20-approve}.
 */
contract ERC20Extendable is Context, IERC20, IERC20Metadata {
    mapping(address => uint256) internal _balances;

    mapping(address => mapping(address => uint256)) internal _allowances;

    uint256 internal _totalSupply;

    string internal _name;
    string internal _symbol;

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * All two of these values are immutable: they can only be set once during
     * construction.
     */
    constructor(string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the default value returned by this function, unless
     * it's overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual override returns (uint8) {
        return 18;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address to, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        _transfer(owner, to, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * NOTE: If `amount` is the maximum `uint256`, the allowance is not updated on
     * `transferFrom`. This is semantically equivalent to an infinite approval.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * NOTE: Does not update the allowance if the current allowance
     * is the maximum `uint256`.
     *
     * Requirements:
     *
     * - `from` and `to` cannot be the zero address.
     * - `from` must have a balance of at least `amount`.
     * - the caller must have allowance for ``from``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address from, address to, uint256 amount) public virtual override returns (bool) {
        address spender = _msgSender();
        _spendAllowance(from, spender, amount);
        _transfer(from, to, amount);
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        address owner = _msgSender();
        _approve(owner, spender, allowance(owner, spender) + addedValue);
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        address owner = _msgSender();
        uint256 currentAllowance = allowance(owner, spender);
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        unchecked {
            _approve(owner, spender, currentAllowance - subtractedValue);
        }

        return true;
    }

    /**
     * @dev Moves `amount` of tokens from `from` to `to`.
     *
     * This internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `from` must have a balance of at least `amount`.
     */
    function _transfer(address from, address to, uint256 amount) internal virtual {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(from, to, amount);

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC20: transfer amount exceeds balance");
        unchecked {
            _balances[from] = fromBalance - amount;
            // Overflow not possible: the sum of all balances is capped by totalSupply, and the sum is preserved by
            // decrementing then incrementing.
            _balances[to] += amount;
        }

        emit Transfer(from, to, amount);

        _afterTokenTransfer(from, to, amount);
    }

    /**
     * @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        unchecked {
            // Overflow not possible: balance + amount is at most totalSupply + amount, which is checked above.
            _balances[account] += amount;
        }
        emit Transfer(address(0), account, amount);

        _afterTokenTransfer(address(0), account, amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Updates `owner` s allowance for `spender` based on spent `amount`.
     *
     * Does not update the allowance amount in case of infinite allowance.
     * Revert if not enough allowance is available.
     *
     * Might emit an {Approval} event.
     */
    function _spendAllowance(address owner, address spender, uint256 amount) internal virtual {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(currentAllowance >= amount, "ERC20: insufficient allowance");
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual {}

    /**
     * @dev Hook that is called after any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * has been transferred to `to`.
     * - when `from` is zero, `amount` tokens have been minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens have been burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _afterTokenTransfer(address from, address to, uint256 amount) internal virtual {}
}


// ============================================================================
// FILE: src/ERC20Permit.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/ERC20Permit.sol)

pragma solidity 0.8.18;

import "./ERC20Extendable.sol";
import "openzeppelin/token/ERC20/extensions/IERC20Permit.sol";
import "openzeppelin/utils/cryptography/ECDSA.sol";
import "openzeppelin/utils/cryptography/EIP712.sol";
import "openzeppelin/utils/Counters.sol";

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
abstract contract ERC20Permit is ERC20Extendable, IERC20Permit, EIP712 {
    using Counters for Counters.Counter;

    mapping(address => Counters.Counter) private _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    /**
     * @dev In previous versions `_PERMIT_TYPEHASH` was declared as `immutable`.
     * However, to ensure consistency with the upgradeable transpiler, we will continue
     * to reserve a slot.
     * @custom:oz-renamed-from _PERMIT_TYPEHASH
     */
    // solhint-disable-next-line var-name-mixedcase
    bytes32 private _PERMIT_TYPEHASH_DEPRECATED_SLOT;

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     * It's a good idea to use the same `name` that is defined as the ERC20 token name.
     */
    constructor(string memory name) EIP712(name, "1") {}

    /**
     * @dev See {IERC20Permit-permit}.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        public
        virtual
        override
    {
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(abi.encode(_PERMIT_TYPEHASH, owner, spender, value, _useNonce(owner), deadline));

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


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/IERC20.sol
// ============================================================================

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


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/security/Pausable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.7.0) (security/Pausable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    constructor() {
        _paused = false;
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
        return _paused;
    }

    /**
     * @dev Throws if the contract is paused.
     */
    function _requireNotPaused() internal view virtual {
        require(!paused(), "Pausable: paused");
    }

    /**
     * @dev Throws if the contract is not paused.
     */
    function _requirePaused() internal view virtual {
        require(paused(), "Pausable: not paused");
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
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
        _paused = false;
        emit Unpaused(_msgSender());
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/access/Ownable.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (access/Ownable.sol)

pragma solidity ^0.8.0;

import "../utils/Context.sol";

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
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
        return _owner;
    }

    /**
     * @dev Throws if the sender is not the owner.
     */
    function _checkOwner() internal view virtual {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
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
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}


// ============================================================================
// FILE: lib/v2-core/contracts/interfaces/IUniswapV2Factory.sol
// ============================================================================

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


// ============================================================================
// FILE: lib/v2-core/contracts/interfaces/IUniswapV2Pair.sol
// ============================================================================

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


// ============================================================================
// FILE: lib/v2-periphery/contracts/interfaces/IUniswapV2Router02.sol
// ============================================================================

pragma solidity >=0.6.2;

import './IUniswapV2Router01.sol';

interface IUniswapV2Router02 is IUniswapV2Router01 {
    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountETH);
    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountETH);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Metadata.sol
// ============================================================================

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


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/utils/Context.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Context.sol)

pragma solidity ^0.8.0;

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
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        return msg.data;
    }
}


// ============================================================================
// FILE: lib/openzeppelin-contracts/contracts/token/ERC20/extensions/IERC20Permit.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v4.9.0) (token/ERC20/extensions/IERC20Permit.sol)

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on {IERC20-approve}, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
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
// FILE: lib/openzeppelin-contracts/contracts/utils/Counters.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (utils/Counters.sol)

pragma solidity ^0.8.0;

/**
 * @title Counters
 * @author Matt Condon (@shrugs)
 * @dev Provides counters that can only be incremented, decremented or reset. This can be used e.g. to track the number
 * of elements in a mapping, issuing ERC721 ids, or counting request ids.
 *
 * Include with `using Counters for Counters.Counter;`
 */
library Counters {
    struct Counter {
        // This variable should never be directly accessed by users of the library: interactions must be restricted to
        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add
        // this feature: see https://github.com/ethereum/solidity/issues/4637
        uint256 _value; // default: 0
    }

    function current(Counter storage counter) internal view returns (uint256) {
        return counter._value;
    }

    function increment(Counter storage counter) internal {
        unchecked {
            counter._value += 1;
        }
    }

    function decrement(Counter storage counter) internal {
        uint256 value = counter._value;
        require(value > 0, "Counter: decrement overflow");
        unchecked {
            counter._value = value - 1;
        }
    }

    function reset(Counter storage counter) internal {
        counter._value = 0;
    }
}


// ============================================================================
// FILE: lib/v2-periphery/contracts/interfaces/IUniswapV2Router01.sol
// ============================================================================

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
