/*
 * @Author: ashokkasthuri ashokk@smu.edu.sg
 * @Date: 2025-02-10 11:34:50
 * @LastEditors: ashokkasthuri ashokk@smu.edu.sg
 * @LastEditTime: 2025-02-10 11:40:31
 * @FilePath: /ERC-analysis-master/sepolia-testnet-deployment/deployments/deploy.js
 * @Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
 */
// async function main() {
//     const HelloWorld = await ethers.getContractFactory("HelloWorld");
//     const hello_world = await HelloWorld.deploy("Hello World!");
//     console.log("Contract Deployed to Address:", hello_world.address);
//   }
//   main()
//     .then(() => process.exit(0))
//     .catch(error => {
//       console.error(error);
//       process.exit(1);
//     });


    async function main() {
        // Get the deployer account from ethers
        const [deployer] = await ethers.getSigners();
        console.log("Deploying contracts with account:", deployer.address);
      
        // Get the contract factory and deploy the contract.
        const MyContract = await ethers.getContractFactory("HelloWorld");
        const myContract = await MyContract.deploy("Hello, Sepolia!");
        
        // Wait until deployment is complete.
        await myContract.deployed();
        
        console.log("Contract deployed at address:", myContract.address);
        
        // Optionally, get and print the runtime bytecode.
        const runtimeBytecode = await ethers.provider.getCode(myContract.address);
        console.log("Deployed runtime bytecode:", runtimeBytecode);
      }
      
      main()
        .then(() => process.exit(0))
        .catch((error) => {
          console.error("Deployment error:", error);
          process.exit(1);
        });
      