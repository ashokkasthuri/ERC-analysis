// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "@openzeppelin/contracts/token/common/ERC2981.sol";
import "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/Strings.sol";

contract NFT1155 is Ownable, ERC2981, ERC1155 {
    bytes4 private constant _INTERFACE_ID_ERC1155 = 0xd9b67a26;
    bytes4 private constant _INTERFACE_ID_ERC2981 = 0x2a55205a;

    uint256 public constant Rock = 1;
    uint256 public constant Paper = 2;
    uint256 public constant Scissors = 3;

    constructor() ERC1155("https://ipfs.io/ipfs/bafybeihjjkwdrxxjnuwevlqtqmh3iegcadc32sio4wmo7bv2gbf34qs34a/{id}.json") {
        _mint(msg.sender, Rock, 1, "");
        _mint(msg.sender, Paper, 1, "");
        _mint(msg.sender, Scissors, 1, "");
    }

    function uri(uint256 _tokenid) override public pure returns (string memory) {
        return string(
            abi.encodePacked(
                "https://ipfs.io/ipfs/bafybeihjjkwdrxxjnuwevlqtqmh3iegcadc32sio4wmo7bv2gbf34qs34a/",
                Strings.toString(_tokenid),".json"
            )
        );
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC1155, ERC2981) returns (bool) {
      return interfaceId == _INTERFACE_ID_ERC2981
        || interfaceId == _INTERFACE_ID_ERC1155;
    }

    function mint(address account, uint256 id, uint256 amount, bytes memory data) onlyOwner public {
        _mint(account, id, amount, data);
    }
}
