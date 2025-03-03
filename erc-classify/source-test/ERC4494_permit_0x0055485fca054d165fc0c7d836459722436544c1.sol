//SPDX-License-Identifier: Unlicense
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import { ERC721Permit } from "./erc721/ERC721Permit.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

contract TRIS is ERC721Permit, Ownable {
  address constant treasury = 0xEC3de41D5eAD4cebFfD656f7FC9d1a8d8Ff0f8c0;
  bytes32 immutable public merkleRoot;
  uint256 public nextTokenId;
  string public __baseURI;

  mapping(address => bool) public claimed;
  mapping (uint256 => uint256) public nonces;

  bool public isMintingEnabled = false;
  bool public isPublicMint = false;
  uint16 constant MAX_SUPPLY = 1000; 
  uint256 private PRICE = 0.27 ether; 

  constructor(bytes32 _merkleRoot) ERC721Permit("TRIS", "TRIS", "1") Ownable() {
    merkleRoot = _merkleRoot;
    _setBaseURI("ipfs://bafybeienialkdrppvdfdanzuiwnt45m4hhckayxrvvhktrrvmowwkwr45a/");
  }

  function version() public pure returns (string memory) { return "1"; }

  // URI
  function setBaseURI(string memory _uri) public onlyOwner {
    _setBaseURI(_uri);
  }
  function _setBaseURI(string memory _uri) internal {
    __baseURI = _uri;
  }
  function _baseURI() internal override view returns (string memory _uri) {
    _uri = __baseURI;
  }

  // Admin
  function startPublicMint() public onlyOwner {
    require(isPublicMint == false, "Public mint is already enabled");
    isPublicMint = true;
  }

  function startMinting() public onlyOwner {
    require(isMintingEnabled == false, "Minting is already enabled");
    isMintingEnabled = true;
  }

  // Mint
  function mintingEnabled() public view returns (bool) { return isMintingEnabled; }

  function publicMint() public view returns (bool) { return isPublicMint; }

  function mint(bytes32[] calldata merkleProof) public payable {
    require(isMintingEnabled, "Minting is not enabled");
    require(msg.value >= PRICE, "Not enough ETH sent");
    require(nextTokenId < MAX_SUPPLY, "Exceeds token supply");
    require(claimed[msg.sender] == false, "User already claimed");
    if(!isPublicMint) {
      require(MerkleProof.verify(merkleProof, merkleRoot, toBytes32(msg.sender)) == true, "Invalid merkle proof");
    }
    claimed[msg.sender] = true;
    nextTokenId++;
    _mint(msg.sender, nextTokenId);
    (bool success, ) = treasury.call{ value: msg.value, gas: gasleft() }("");
    require(success, "Failed to forward ETH");
  }

  function adminMint(address _to, uint256 _tokenId) public onlyOwner {
    _mint(_to, _tokenId);
  }

  // Helpers
  function toBytes32(address addr) pure internal returns (bytes32) {
    return bytes32(uint256(uint160(addr)));
  }

  function _getAndIncrementNonce(uint256 _tokenId) internal override virtual returns (uint256) {
    uint256 nonce = nonces[_tokenId];
    nonces[_tokenId]++;
    return nonce;
  }
}





// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity >=0.8.0;

import '@openzeppelin/contracts/token/ERC721/extensions/ERC721Enumerable.sol';
import '@openzeppelin/contracts/utils/Address.sol';

import './libraries/ChainId.sol';
import './interfaces/external/IERC1271.sol';
import './interfaces/IERC721Permit.sol';
import './BlockTimestamp.sol';

/// @title ERC721 with permit
/// @notice Nonfungible tokens that support an approve via signature, i.e. permit
abstract contract ERC721Permit is BlockTimestamp, ERC721Enumerable, IERC721Permit {
    /// @dev Gets the current nonce for a token ID and then increments it, returning the original value
    function _getAndIncrementNonce(uint256 tokenId) internal virtual returns (uint256);

    /// @dev The hash of the name used in the permit signature verification
    bytes32 private immutable nameHash;

    /// @dev The hash of the version string used in the permit signature verification
    bytes32 private immutable versionHash;

    /// @notice Computes the nameHash and versionHash
    constructor(
        string memory name_,
        string memory symbol_,
        string memory version_
    ) ERC721(name_, symbol_) {
        nameHash = keccak256(bytes(name_));
        versionHash = keccak256(bytes(version_));
    }

    /// @inheritdoc IERC721Permit
    function DOMAIN_SEPARATOR() public view override returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    // keccak256('EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    nameHash,
                    versionHash,
                    ChainId.get(),
                    address(this)
                )
            );
    }

    /// @inheritdoc IERC721Permit
    /// @dev Value is equal to keccak256("Permit(address spender,uint256 tokenId,uint256 nonce,uint256 deadline)");
    bytes32 public constant override PERMIT_TYPEHASH =
        0x49ecf333e5b8c95c40fdafc95c1ad136e8914a8fb55e9dc8bb01eaa83a2df9ad;

    /// @inheritdoc IERC721Permit
    function permit(
        address spender,
        uint256 tokenId,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable override {
        require(_blockTimestamp() <= deadline, 'Permit expired');

        bytes32 digest =
            keccak256(
                abi.encodePacked(
                    '\x19\x01',
                    DOMAIN_SEPARATOR(),
                    keccak256(abi.encode(PERMIT_TYPEHASH, spender, tokenId, _getAndIncrementNonce(tokenId), deadline))
                )
            );
        address owner = ownerOf(tokenId);
        require(spender != owner, 'ERC721Permit: approval to current owner');

        if (Address.isContract(owner)) {
            require(IERC1271(owner).isValidSignature(digest, abi.encodePacked(r, s, v)) == 0x1626ba7e, 'Unauthorized');
        } else {
            address recoveredAddress = ecrecover(digest, v, r, s);
            require(recoveredAddress != address(0), 'Invalid signature');
            require(recoveredAddress == owner, 'Unauthorized');
        }

        _approve(spender, tokenId);
    }
}