/*
 * @Author: ashokkasthuri ashokk@smu.edu.sg
 * @Date: 2025-02-10 11:27:43
 * @LastEditors: ashokkasthuri ashokk@smu.edu.sg
 * @LastEditTime: 2025-02-10 11:33:56
 * @FilePath: /ERC-analysis-master/sepolia-testnet-deployment/hardhat.config.js
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
require('dotenv').config();
require("@nomiclabs/hardhat-ethers");

const { API_URL, PRIVATE_KEY } = process.env;

module.exports = {
  solidity: "0.7.3",
  defaultNetwork: "sepolia",
  networks: {
    hardhat: {},
    sepolia: {
      url: API_URL,
      accounts: [`0x${PRIVATE_KEY}`]
    }
  },
}