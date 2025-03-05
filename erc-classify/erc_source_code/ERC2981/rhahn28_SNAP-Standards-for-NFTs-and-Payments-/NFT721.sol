// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract NFT721 is Ownable, ERC2981, ERC721("EIP2981Nft", "EIP2981NFTEXAMPLE"){
  bytes4 private constant _INTERFACE_ID_ERC721 = 0x80ac58cd;
  bytes4 private constant _INTERFACE_ID_ERC2981 = 0x2a55205a;

  uint tokenId;
  mapping(address=>tokenMetaData[]) public ownershipRecord;
  struct tokenMetaData{
    uint tokenId;
    uint timeStamp;
    string tokenURI;
  }

  function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, ERC2981) returns (bool) {
      return interfaceId == _INTERFACE_ID_ERC2981
        || interfaceId == _INTERFACE_ID_ERC721;
  }

  function mintToken(address recipient) onlyOwner public {
    require(owner()!=recipient, "Recipient cannot be the owner of the contract");
    _safeMint(recipient, tokenId);
    ownershipRecord[recipient].push(tokenMetaData(tokenId, block.timestamp, "https://miro.medium.com/max/1120/1*k_EY7dcLYB5Z5k8zhMcv6g.png"));
    tokenId = tokenId + 1;
  }
}
