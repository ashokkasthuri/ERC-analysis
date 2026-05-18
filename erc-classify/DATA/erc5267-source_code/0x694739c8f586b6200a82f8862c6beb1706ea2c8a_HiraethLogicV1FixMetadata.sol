// SPDX-License-Identifier: UNLICENSED
// Source: 0x694739c8f586b6200a82f8862c6beb1706ea2c8a
// Contract Name: HiraethLogicV1FixMetadata
// Generated on: 2026-05-14 11:57:42


// ============================================================================
// FILE: @openzeppelin/contracts/interfaces/IERC1271.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC1271.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC1271 standard signature validation method for
 * contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
 */
interface IERC1271 {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param hash      Hash of the data to be signed
     * @param signature Signature byte array associated with _data
     */
    function isValidSignature(bytes32 hash, bytes memory signature) external view returns (bytes4 magicValue);
}


// ============================================================================
// FILE: @openzeppelin/contracts/interfaces/IERC5267.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (interfaces/IERC5267.sol)

pragma solidity ^0.8.20;

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
// FILE: @openzeppelin/contracts/token/ERC721/IERC721.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (token/ERC721/IERC721.sol)

pragma solidity ^0.8.20;

import {IERC165} from "../../utils/introspection/IERC165.sol";

/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon
     *   a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external;

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must have been allowed to move this token by either {approve} or
     *   {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon
     *   a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Note that the caller is responsible to confirm that the recipient is capable of receiving ERC721
     * or else they may be permanently lost. Usage of {safeTransferFrom} prevents loss, though the caller must
     * understand this adds an external call which potentially creates a reentrancy vulnerability.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the address zero.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/Base64.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.2) (utils/Base64.sol)

pragma solidity ^0.8.20;

/**
 * @dev Provides a set of functions to operate with Base64 strings.
 */
library Base64 {
    /**
     * @dev Base64 Encoding/Decoding Table
     */
    string internal constant _TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    /**
     * @dev Converts a `bytes` to its Bytes64 `string` representation.
     */
    function encode(bytes memory data) internal pure returns (string memory) {
        /**
         * Inspired by Brecht Devos (Brechtpd) implementation - MIT licence
         * https://github.com/Brechtpd/base64/blob/e78d9fd951e7b0977ddca77d92dc85183770daf4/base64.sol
         */
        if (data.length == 0) return "";

        // Loads the table into memory
        string memory table = _TABLE;

        // Encoding takes 3 bytes chunks of binary data from `bytes` data parameter
        // and split into 4 numbers of 6 bits.
        // The final Base64 length should be `bytes` data length multiplied by 4/3 rounded up
        // - `data.length + 2`  -> Round up
        // - `/ 3`              -> Number of 3-bytes chunks
        // - `4 *`              -> 4 characters for each chunk
        string memory result = new string(4 * ((data.length + 2) / 3));

        /// @solidity memory-safe-assembly
        assembly {
            // Prepare the lookup table (skip the first "length" byte)
            let tablePtr := add(table, 1)

            // Prepare result pointer, jump over length
            let resultPtr := add(result, 0x20)
            let dataPtr := data
            let endPtr := add(data, mload(data))

            // In some cases, the last iteration will read bytes after the end of the data. We cache the value, and
            // set it to zero to make sure no dirty bytes are read in that section.
            let afterPtr := add(endPtr, 0x20)
            let afterCache := mload(afterPtr)
            mstore(afterPtr, 0x00)

            // Run over the input, 3 bytes at a time
            for {

            } lt(dataPtr, endPtr) {

            } {
                // Advance 3 bytes
                dataPtr := add(dataPtr, 3)
                let input := mload(dataPtr)

                // To write each character, shift the 3 byte (24 bits) chunk
                // 4 times in blocks of 6 bits for each character (18, 12, 6, 0)
                // and apply logical AND with 0x3F to bitmask the least significant 6 bits.
                // Use this as an index into the lookup table, mload an entire word
                // so the desired character is in the least significant byte, and
                // mstore8 this least significant byte into the result and continue.

                mstore8(resultPtr, mload(add(tablePtr, and(shr(18, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(shr(12, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(shr(6, input), 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance

                mstore8(resultPtr, mload(add(tablePtr, and(input, 0x3F))))
                resultPtr := add(resultPtr, 1) // Advance
            }

            // Reset the value that was cached
            mstore(afterPtr, afterCache)

            // When data `bytes` is not exactly 3 bytes long
            // it is padded with `=` characters at the end
            switch mod(mload(data), 3)
            case 1 {
                mstore8(sub(resultPtr, 1), 0x3d)
                mstore8(sub(resultPtr, 2), 0x3d)
            }
            case 2 {
                mstore8(sub(resultPtr, 1), 0x3d)
            }
        }

        return result;
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/Context.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.1) (utils/Context.sol)

pragma solidity ^0.8.20;

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

    function _contextSuffixLength() internal view virtual returns (uint256) {
        return 0;
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/cryptography/ECDSA.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/ECDSA.sol)

pragma solidity ^0.8.20;

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
        InvalidSignatureS
    }

    /**
     * @dev The signature derives the `address(0)`.
     */
    error ECDSAInvalidSignature();

    /**
     * @dev The signature has an invalid length.
     */
    error ECDSAInvalidSignatureLength(uint256 length);

    /**
     * @dev The signature has an S value that is in the upper half order.
     */
    error ECDSAInvalidSignatureS(bytes32 s);

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with `signature` or an error. This will not
     * return address(0) without also returning an error description. Errors are documented using an enum (error type)
     * and a bytes32 providing additional information about the error.
     *
     * If no error is returned, then the address can be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     *
     * Documentation for signature generation:
     * - with https://web3js.readthedocs.io/en/v1.3.4/web3-eth-accounts.html#sign[Web3.js]
     * - with https://docs.ethers.io/v5/api/signer/#Signer-signMessage[ethers]
     */
    function tryRecover(bytes32 hash, bytes memory signature) internal pure returns (address, RecoverError, bytes32) {
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
            return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
        }
    }

    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM precompile allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {MessageHashUtils-toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `r` and `vs` short-signature fields separately.
     *
     * See https://eips.ethereum.org/EIPS/eip-2098[EIP-2098 short signatures]
     */
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address, RecoverError, bytes32) {
        unchecked {
            bytes32 s = vs & bytes32(0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            // We do not check for an overflow here since the shift operation results in 0 or 1.
            uint8 v = uint8((uint256(vs) >> 255) + 27);
            return tryRecover(hash, v, r, s);
        }
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `r and `vs` short-signature fields separately.
     */
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, r, vs);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function tryRecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address, RecoverError, bytes32) {
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
            return (address(0), RecoverError.InvalidSignatureS, s);
        }

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) {
            return (address(0), RecoverError.InvalidSignature, bytes32(0));
        }

        return (signer, RecoverError.NoError, bytes32(0));
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, v, r, s);
        _throwError(error, errorArg);
        return recovered;
    }

    /**
     * @dev Optionally reverts with the corresponding custom error according to the `error` argument provided.
     */
    function _throwError(RecoverError error, bytes32 errorArg) private pure {
        if (error == RecoverError.NoError) {
            return; // no error: do nothing
        } else if (error == RecoverError.InvalidSignature) {
            revert ECDSAInvalidSignature();
        } else if (error == RecoverError.InvalidSignatureLength) {
            revert ECDSAInvalidSignatureLength(uint256(errorArg));
        } else if (error == RecoverError.InvalidSignatureS) {
            revert ECDSAInvalidSignatureS(errorArg);
        }
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/MessageHashUtils.sol)

pragma solidity ^0.8.20;

import {Strings} from "../Strings.sol";

/**
 * @dev Signature message hash utilities for producing digests to be consumed by {ECDSA} recovery or signing.
 *
 * The library provides methods for generating a hash of a message that conforms to the
 * https://eips.ethereum.org/EIPS/eip-191[EIP 191] and https://eips.ethereum.org/EIPS/eip-712[EIP 712]
 * specifications.
 */
library MessageHashUtils {
    /**
     * @dev Returns the keccak256 digest of an EIP-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing a bytes32 `messageHash` with
     * `"\x19Ethereum Signed Message:\n32"` and hashing the result. It corresponds with the
     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * NOTE: The `messageHash` parameter is intended to be the result of hashing a raw message with
     * keccak256, although any bytes32 value can be safely used because the final digest will
     * be re-hashed.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes32 messageHash) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, "\x19Ethereum Signed Message:\n32") // 32 is the bytes-length of messageHash
            mstore(0x1c, messageHash) // 0x1c (28) is the length of the prefix
            digest := keccak256(0x00, 0x3c) // 0x3c is the length of the prefix (0x1c) + messageHash (0x20)
        }
    }

    /**
     * @dev Returns the keccak256 digest of an EIP-191 signed data with version
     * `0x45` (`personal_sign` messages).
     *
     * The digest is calculated by prefixing an arbitrary `message` with
     * `"\x19Ethereum Signed Message:\n" + len(message)` and hashing the result. It corresponds with the
     * hash signed when using the https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`] JSON-RPC method.
     *
     * See {ECDSA-recover}.
     */
    function toEthSignedMessageHash(bytes memory message) internal pure returns (bytes32) {
        return
            keccak256(bytes.concat("\x19Ethereum Signed Message:\n", bytes(Strings.toString(message.length)), message));
    }

    /**
     * @dev Returns the keccak256 digest of an EIP-191 signed data with version
     * `0x00` (data with intended validator).
     *
     * The digest is calculated by prefixing an arbitrary `data` with `"\x19\x00"` and the intended
     * `validator` address. Then hashing the result.
     *
     * See {ECDSA-recover}.
     */
    function toDataWithIntendedValidatorHash(address validator, bytes memory data) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"19_00", validator, data));
    }

    /**
     * @dev Returns the keccak256 digest of an EIP-712 typed data (EIP-191 version `0x01`).
     *
     * The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them with
     * `\x19\x01` and hashing the result. It corresponds to the hash signed by the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of EIP-712.
     *
     * See {ECDSA-recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32 digest) {
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, hex"19_01")
            mstore(add(ptr, 0x02), domainSeparator)
            mstore(add(ptr, 0x22), structHash)
            digest := keccak256(ptr, 0x42)
        }
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/cryptography/SignatureChecker.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/SignatureChecker.sol)

pragma solidity ^0.8.20;

import {ECDSA} from "./ECDSA.sol";
import {IERC1271} from "../../interfaces/IERC1271.sol";

/**
 * @dev Signature verification helper that can be used instead of `ECDSA.recover` to seamlessly support both ECDSA
 * signatures from externally owned accounts (EOAs) as well as ERC1271 signatures from smart contract wallets like
 * Argent and Safe Wallet (previously Gnosis Safe).
 */
library SignatureChecker {
    /**
     * @dev Checks if a signature is valid for a given signer and data hash. If the signer is a smart contract, the
     * signature is validated against that smart contract using ERC1271, otherwise it's validated using `ECDSA.recover`.
     *
     * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * change through time. It could return true at block N and false at block N+1 (or the opposite).
     */
    function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature) internal view returns (bool) {
        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(hash, signature);
        return
            (error == ECDSA.RecoverError.NoError && recovered == signer) ||
            isValidERC1271SignatureNow(signer, hash, signature);
    }

    /**
     * @dev Checks if a signature is valid for a given signer and data hash. The signature is validated
     * against the signer smart contract using ERC1271.
     *
     * NOTE: Unlike ECDSA signatures, contract signatures are revocable, and the outcome of this function can thus
     * change through time. It could return true at block N and false at block N+1 (or the opposite).
     */
    function isValidERC1271SignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    ) internal view returns (bool) {
        (bool success, bytes memory result) = signer.staticcall(
            abi.encodeCall(IERC1271.isValidSignature, (hash, signature))
        );
        return (success &&
            result.length >= 32 &&
            abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector));
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/introspection/ERC165.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/ERC165.sol)

pragma solidity ^0.8.20;

import {IERC165} from "./IERC165.sol";

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/introspection/IERC165.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/introspection/IERC165.sol)

pragma solidity ^0.8.20;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/math/Math.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/Math.sol)

pragma solidity ^0.8.20;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Muldiv operation overflow.
     */
    error MathOverflowedMulDiv();

    enum Rounding {
        Floor, // Toward negative infinity
        Ceil, // Toward positive infinity
        Trunc, // Toward zero
        Expand // Away from zero
    }

    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, with an overflow flag.
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
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
     * This differs from standard division with `/` in that it rounds towards infinity instead
     * of rounding towards zero.
     */
    function ceilDiv(uint256 a, uint256 b) internal pure returns (uint256) {
        if (b == 0) {
            // Guarantee the same behavior as in a regular Solidity division.
            return a / b;
        }

        // (a + b - 1) / b can overflow on addition, so we distribute.
        return a == 0 ? 0 : (a - 1) / b + 1;
    }

    /**
     * @notice Calculates floor(x * y / denominator) with full precision. Throws if result overflows a uint256 or
     * denominator == 0.
     * @dev Original credit to Remco Bloemen under MIT license (https://xn--2-umb.com/21/muldiv) with further edits by
     * Uniswap Labs also under MIT license.
     */
    function mulDiv(uint256 x, uint256 y, uint256 denominator) internal pure returns (uint256 result) {
        unchecked {
            // 512-bit multiply [prod1 prod0] = x * y. Compute the product mod 2^256 and mod 2^256 - 1, then use
            // use the Chinese Remainder Theorem to reconstruct the 512 bit result. The result is stored in two 256
            // variables such that product = prod1 * 2^256 + prod0.
            uint256 prod0 = x * y; // Least significant 256 bits of the product
            uint256 prod1; // Most significant 256 bits of the product
            assembly {
                let mm := mulmod(x, y, not(0))
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
            if (denominator <= prod1) {
                revert MathOverflowedMulDiv();
            }

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

            // Factor powers of two out of denominator and compute largest power of two divisor of denominator.
            // Always >= 1. See https://cs.stackexchange.com/q/138556/92363.

            uint256 twos = denominator & (0 - denominator);
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

            // Use the Newton-Raphson iteration to improve the precision. Thanks to Hensel's lifting lemma, this also
            // works in modular arithmetic, doubling the correct bits in each step.
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
        if (unsignedRoundsUp(rounding) && mulmod(x, y, denominator) > 0) {
            result += 1;
        }
        return result;
    }

    /**
     * @dev Returns the square root of a number. If the number is not a perfect square, the value is rounded
     * towards zero.
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
            return result + (unsignedRoundsUp(rounding) && result * result < a ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 2 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 1 << result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 10 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 10 ** result < value ? 1 : 0);
        }
    }

    /**
     * @dev Return the log in base 256 of a positive value rounded towards zero.
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
            return result + (unsignedRoundsUp(rounding) && 1 << (result << 3) < value ? 1 : 0);
        }
    }

    /**
     * @dev Returns whether a provided rounding mode is considered rounding up for unsigned integers.
     */
    function unsignedRoundsUp(Rounding rounding) internal pure returns (bool) {
        return uint8(rounding) % 2 == 1;
    }
}


// ============================================================================
// FILE: @openzeppelin/contracts/utils/math/SignedMath.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/math/SignedMath.sol)

pragma solidity ^0.8.20;

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
// FILE: @openzeppelin/contracts/utils/Strings.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/Strings.sol)

pragma solidity ^0.8.20;

import {Math} from "./math/Math.sol";
import {SignedMath} from "./math/SignedMath.sol";

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant HEX_DIGITS = "0123456789abcdef";
    uint8 private constant ADDRESS_LENGTH = 20;

    /**
     * @dev The `value` string doesn't fit in the specified `length`.
     */
    error StringsInsufficientHexLength(uint256 value, uint256 length);

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
                    mstore8(ptr, byte(mod(value, 10), HEX_DIGITS))
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
    function toStringSigned(int256 value) internal pure returns (string memory) {
        return string.concat(value < 0 ? "-" : "", toString(SignedMath.abs(value)));
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
        uint256 localValue = value;
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = HEX_DIGITS[localValue & 0xf];
            localValue >>= 4;
        }
        if (localValue != 0) {
            revert StringsInsufficientHexLength(value, length);
        }
        return string(buffer);
    }

    /**
     * @dev Converts an `address` with fixed length of 20 bytes to its not checksummed ASCII `string` hexadecimal
     * representation.
     */
    function toHexString(address addr) internal pure returns (string memory) {
        return toHexString(uint256(uint160(addr)), ADDRESS_LENGTH);
    }

    /**
     * @dev Returns true if the two strings are equal.
     */
    function equal(string memory a, string memory b) internal pure returns (bool) {
        return bytes(a).length == bytes(b).length && keccak256(bytes(a)) == keccak256(bytes(b));
    }
}


// ============================================================================
// FILE: @protocol/core/contracts/interfaces/IComponent.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@openzeppelin/contracts/utils/introspection/IERC165.sol';

interface IComponent is IERC165 {
  function render(bytes calldata props) external view returns (bytes memory);
}


// ============================================================================
// FILE: @protocol/core/contracts/libraries/bytes/Bytecode.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

library Bytecode {
  error InvalidCodeAtRange(uint256 _size, uint256 _start, uint256 _end);

  /**
    @notice Generate a creation code that results on a contract with `_code` as bytecode
    @param _code The returning value of the resulting `creationCode`
    @return creationCode (constructor) for new contract
  */
  function creationCodeFor(
    bytes memory _code
  ) internal pure returns (bytes memory) {
    /*
      0x00    0x63         0x63XXXXXX  PUSH4 _code.length  size
      0x01    0x80         0x80        DUP1                size size
      0x02    0x60         0x600e      PUSH1 14            14 size size
      0x03    0x60         0x6000      PUSH1 00            0 14 size size
      0x04    0x39         0x39        CODECOPY            size
      0x05    0x60         0x6000      PUSH1 00            0 size
      0x06    0xf3         0xf3        RETURN
      <CODE>
    */

    return
      abi.encodePacked(
        hex'63',
        uint32(_code.length),
        hex'80_60_0E_60_00_39_60_00_F3',
        _code
      );
  }

  /**
    @notice Returns the size of the code on a given address
    @param _addr Address that may or may not contain code
    @return size of the code on the given `_addr`
  */
  function codeSize(address _addr) internal view returns (uint256 size) {
    assembly {
      size := extcodesize(_addr)
    }
  }

  /**
    @notice Returns the code of a given address
    @dev It will fail if `_end < _start`
    @param _addr Address that may or may not contain code
    @param _start number of bytes of code to skip on read
    @param _end index before which to end extraction
    @return oCode read from `_addr` deployed bytecode
    Forked from: https://gist.github.com/KardanovIR/fe98661df9338c842b4a30306d507fbd
  */
  function codeAt(
    address _addr,
    uint256 _start,
    uint256 _end
  ) internal view returns (bytes memory oCode) {
    uint256 csize = codeSize(_addr);
    if (csize == 0) return bytes('');

    if (_start > csize) return bytes('');
    if (_end < _start) revert InvalidCodeAtRange(csize, _start, _end);

    unchecked {
      uint256 reqSize = _end - _start;
      uint256 maxSize = csize - _start;

      uint256 size = maxSize < reqSize ? maxSize : reqSize;

      assembly {
        // allocate output byte array - this could also be done without assembly
        // by using o_code = new bytes(size)
        oCode := mload(0x40)
        // new "memory end" including padding
        mstore(0x40, add(oCode, and(add(add(size, 0x20), 0x1f), not(0x1f))))
        // store length in memory
        mstore(oCode, size)
        // actually retrieve the code, this needs assembly
        extcodecopy(_addr, add(oCode, 0x20), _start, size)
      }
    }
  }
}


// ============================================================================
// FILE: @protocol/core/contracts/libraries/bytes/BytesUtils.sol
// ============================================================================

// SPDX-License-Identifier: MIT
/*
 * @title Solidity Bytes Arrays Utils
 * @author Gonçalo Sá <goncalo.sa@consensys.net>
 *
 * @dev Bytes tightly packed arrays utility library for ethereum contracts written in Solidity.
 *      The library lets you concatenate, slice and type cast bytes arrays both in memory and storage.
 */
pragma solidity ^0.8.4;

library BytesUtils {
  function concat(
    bytes memory _preBytes,
    bytes memory _postBytes
  ) internal pure returns (bytes memory) {
    bytes memory tempBytes;

    assembly {
      // Get a location of some free memory and store it in tempBytes as
      // Solidity does for memory variables.
      tempBytes := mload(0x40)

      // Store the length of the first bytes array at the beginning of
      // the memory for tempBytes.
      let length := mload(_preBytes)
      mstore(tempBytes, length)

      // Maintain a memory counter for the current write location in the
      // temp bytes array by adding the 32 bytes for the array length to
      // the starting location.
      let mc := add(tempBytes, 0x20)
      // Stop copying when the memory counter reaches the length of the
      // first bytes array.
      let end := add(mc, length)

      for {
        // Initialize a copy counter to the start of the _preBytes data,
        // 32 bytes into its memory.
        let cc := add(_preBytes, 0x20)
      } lt(mc, end) {
        // Increase both counters by 32 bytes each iteration.
        mc := add(mc, 0x20)
        cc := add(cc, 0x20)
      } {
        // Write the _preBytes data into the tempBytes memory 32 bytes
        // at a time.
        mstore(mc, mload(cc))
      }

      // Add the length of _postBytes to the current length of tempBytes
      // and store it as the new length in the first 32 bytes of the
      // tempBytes memory.
      length := mload(_postBytes)
      mstore(tempBytes, add(length, mload(tempBytes)))

      // Move the memory counter back from a multiple of 0x20 to the
      // actual end of the _preBytes data.
      mc := end
      // Stop copying when the memory counter reaches the new combined
      // length of the arrays.
      end := add(mc, length)

      for {
        let cc := add(_postBytes, 0x20)
      } lt(mc, end) {
        mc := add(mc, 0x20)
        cc := add(cc, 0x20)
      } {
        mstore(mc, mload(cc))
      }

      // Update the free-memory pointer by padding our last write location
      // to 32 bytes: add 31 bytes to the end of tempBytes to move to the
      // next 32 byte block, then round down to the nearest multiple of
      // 32. If the sum of the length of the two arrays is zero then add
      // one before rounding down to leave a blank 32 bytes (the length block with 0).
      mstore(
        0x40,
        and(
          add(add(end, iszero(add(length, mload(_preBytes)))), 31),
          not(31) // Round down to the nearest 32 bytes.
        )
      )
    }

    return tempBytes;
  }

  function concatStorage(
    bytes storage _preBytes,
    bytes memory _postBytes
  ) internal {
    assembly {
      // Read the first 32 bytes of _preBytes storage, which is the length
      // of the array. (We don't need to use the offset into the slot
      // because arrays use the entire slot.)
      let fslot := sload(_preBytes.slot)
      // Arrays of 31 bytes or less have an even value in their slot,
      // while longer arrays have an odd value. The actual length is
      // the slot divided by two for odd values, and the lowest order
      // byte divided by two for even values.
      // If the slot is even, bitwise and the slot with 255 and divide by
      // two to get the length. If the slot is odd, bitwise and the slot
      // with -1 and divide by two.
      let slength := div(
        and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)),
        2
      )
      let mlength := mload(_postBytes)
      let newlength := add(slength, mlength)
      // slength can contain both the length and contents of the array
      // if length < 32 bytes so let's prepare for that
      // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
      switch add(lt(slength, 32), lt(newlength, 32))
      case 2 {
        // Since the new array still fits in the slot, we just need to
        // update the contents of the slot.
        // uint256(bytes_storage) = uint256(bytes_storage) + uint256(bytes_memory) + new_length
        sstore(
          _preBytes.slot,
          // all the modifications to the slot are inside this
          // next block
          add(
            // we can just add to the slot contents because the
            // bytes we want to change are the LSBs
            fslot,
            add(
              mul(
                div(
                  // load the bytes from memory
                  mload(add(_postBytes, 0x20)),
                  // zero all bytes to the right
                  exp(0x100, sub(32, mlength))
                ),
                // and now shift left the number of bytes to
                // leave space for the length in the slot
                exp(0x100, sub(32, newlength))
              ),
              // increase length by the double of the memory
              // bytes length
              mul(mlength, 2)
            )
          )
        )
      }
      case 1 {
        // The stored value fits in the slot, but the combined value
        // will exceed it.
        // get the keccak hash to get the contents of the array
        mstore(0x0, _preBytes.slot)
        let sc := add(keccak256(0x0, 0x20), div(slength, 32))

        // save new length
        sstore(_preBytes.slot, add(mul(newlength, 2), 1))

        // The contents of the _postBytes array start 32 bytes into
        // the structure. Our first read should obtain the `submod`
        // bytes that can fit into the unused space in the last word
        // of the stored array. To get this, we read 32 bytes starting
        // from `submod`, so the data we read overlaps with the array
        // contents by `submod` bytes. Masking the lowest-order
        // `submod` bytes allows us to add that value directly to the
        // stored value.

        let submod := sub(32, slength)
        let mc := add(_postBytes, submod)
        let end := add(_postBytes, mlength)
        let mask := sub(exp(0x100, submod), 1)

        sstore(
          sc,
          add(
            and(
              fslot,
              0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00
            ),
            and(mload(mc), mask)
          )
        )

        for {
          mc := add(mc, 0x20)
          sc := add(sc, 1)
        } lt(mc, end) {
          sc := add(sc, 1)
          mc := add(mc, 0x20)
        } {
          sstore(sc, mload(mc))
        }

        mask := exp(0x100, sub(mc, end))

        sstore(sc, mul(div(mload(mc), mask), mask))
      }
      default {
        // get the keccak hash to get the contents of the array
        mstore(0x0, _preBytes.slot)
        // Start copying to the last used word of the stored array.
        let sc := add(keccak256(0x0, 0x20), div(slength, 32))

        // save new length
        sstore(_preBytes.slot, add(mul(newlength, 2), 1))

        // Copy over the first `submod` bytes of the new data as in
        // case 1 above.
        let slengthmod := mod(slength, 32)
        let mlengthmod := mod(mlength, 32)
        let submod := sub(32, slengthmod)
        let mc := add(_postBytes, submod)
        let end := add(_postBytes, mlength)
        let mask := sub(exp(0x100, submod), 1)

        sstore(sc, add(sload(sc), and(mload(mc), mask)))

        for {
          sc := add(sc, 1)
          mc := add(mc, 0x20)
        } lt(mc, end) {
          sc := add(sc, 1)
          mc := add(mc, 0x20)
        } {
          sstore(sc, mload(mc))
        }

        mask := exp(0x100, sub(mc, end))

        sstore(sc, mul(div(mload(mc), mask), mask))
      }
    }
  }

  function slice(
    bytes memory _bytes,
    uint256 _start,
    uint256 _length
  ) internal pure returns (bytes memory) {
    require(_length + 31 >= _length, 'slice_overflow');
    require(_bytes.length >= _start + _length, 'slice_outOfBounds');

    bytes memory tempBytes;

    assembly {
      switch iszero(_length)
      case 0 {
        // Get a location of some free memory and store it in tempBytes as
        // Solidity does for memory variables.
        tempBytes := mload(0x40)

        // The first word of the slice result is potentially a partial
        // word read from the original array. To read it, we calculate
        // the length of that partial word and start copying that many
        // bytes into the array. The first word we copy will start with
        // data we don't care about, but the last `lengthmod` bytes will
        // land at the beginning of the contents of the new array. When
        // we're done copying, we overwrite the full first word with
        // the actual length of the slice.
        let lengthmod := and(_length, 31)

        // The multiplication in the next line is necessary
        // because when slicing multiples of 32 bytes (lengthmod == 0)
        // the following copy loop was copying the origin's length
        // and then ending prematurely not copying everything it should.
        let mc := add(add(tempBytes, lengthmod), mul(0x20, iszero(lengthmod)))
        let end := add(mc, _length)

        for {
          // The multiplication in the next line has the same exact purpose
          // as the one above.
          let cc := add(
            add(add(_bytes, lengthmod), mul(0x20, iszero(lengthmod))),
            _start
          )
        } lt(mc, end) {
          mc := add(mc, 0x20)
          cc := add(cc, 0x20)
        } {
          mstore(mc, mload(cc))
        }

        mstore(tempBytes, _length)

        //update free-memory pointer
        //allocating the array padded to 32 bytes like the compiler does now
        mstore(0x40, and(add(mc, 31), not(31)))
      }
      //if we want a zero-length slice let's just return a zero-length array
      default {
        tempBytes := mload(0x40)
        //zero out the 32 bytes slice we are about to return
        //we need to do it because Solidity does not garbage collect
        mstore(tempBytes, 0)

        mstore(0x40, add(tempBytes, 0x20))
      }
    }

    return tempBytes;
  }

  function toAddress(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (address) {
    require(_bytes.length >= _start + 20, 'toAddress_outOfBounds');
    address tempAddress;

    assembly {
      tempAddress := div(
        mload(add(add(_bytes, 0x20), _start)),
        0x1000000000000000000000000
      )
    }

    return tempAddress;
  }

  function toUint8(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint8) {
    require(_bytes.length >= _start + 1, 'toUint8_outOfBounds');
    uint8 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x1), _start))
    }

    return tempUint;
  }

  function toUint16(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint16) {
    require(_bytes.length >= _start + 2, 'toUint16_outOfBounds');
    uint16 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x2), _start))
    }

    return tempUint;
  }

  function toUint32(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint32) {
    require(_bytes.length >= _start + 4, 'toUint32_outOfBounds');
    uint32 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x4), _start))
    }

    return tempUint;
  }

  function toUint64(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint64) {
    require(_bytes.length >= _start + 8, 'toUint64_outOfBounds');
    uint64 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x8), _start))
    }

    return tempUint;
  }

  function toUint96(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint96) {
    require(_bytes.length >= _start + 12, 'toUint96_outOfBounds');
    uint96 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0xc), _start))
    }

    return tempUint;
  }

  function toUint128(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint128) {
    require(_bytes.length >= _start + 16, 'toUint128_outOfBounds');
    uint128 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x10), _start))
    }

    return tempUint;
  }

  function toUint256(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (uint256) {
    require(_bytes.length >= _start + 32, 'toUint256_outOfBounds');
    uint256 tempUint;

    assembly {
      tempUint := mload(add(add(_bytes, 0x20), _start))
    }

    return tempUint;
  }

  function toBytes32(
    bytes memory _bytes,
    uint256 _start
  ) internal pure returns (bytes32) {
    require(_bytes.length >= _start + 32, 'toBytes32_outOfBounds');
    bytes32 tempBytes32;

    assembly {
      tempBytes32 := mload(add(add(_bytes, 0x20), _start))
    }

    return tempBytes32;
  }

  function equal(
    bytes memory _preBytes,
    bytes memory _postBytes
  ) internal pure returns (bool) {
    bool success = true;

    assembly {
      let length := mload(_preBytes)

      // if lengths don't match the arrays are not equal
      switch eq(length, mload(_postBytes))
      case 1 {
        // cb is a circuit breaker in the for loop since there's
        //  no said feature for inline assembly loops
        // cb = 1 - don't breaker
        // cb = 0 - break
        let cb := 1

        let mc := add(_preBytes, 0x20)
        let end := add(mc, length)

        for {
          let cc := add(_postBytes, 0x20)
          // the next line is the loop condition:
          // while(uint256(mc < end) + cb == 2)
        } eq(add(lt(mc, end), cb), 2) {
          mc := add(mc, 0x20)
          cc := add(cc, 0x20)
        } {
          // if any of these checks fails then arrays are not equal
          if iszero(eq(mload(mc), mload(cc))) {
            // unsuccess:
            success := 0
            cb := 0
          }
        }
      }
      default {
        // unsuccess:
        success := 0
      }
    }

    return success;
  }

  function equalStorage(
    bytes storage _preBytes,
    bytes memory _postBytes
  ) internal view returns (bool) {
    bool success = true;

    assembly {
      // we know _preBytes_offset is 0
      let fslot := sload(_preBytes.slot)
      // Decode the length of the stored array like in concatStorage().
      let slength := div(
        and(fslot, sub(mul(0x100, iszero(and(fslot, 1))), 1)),
        2
      )
      let mlength := mload(_postBytes)

      // if lengths don't match the arrays are not equal
      switch eq(slength, mlength)
      case 1 {
        // slength can contain both the length and contents of the array
        // if length < 32 bytes so let's prepare for that
        // v. http://solidity.readthedocs.io/en/latest/miscellaneous.html#layout-of-state-variables-in-storage
        if iszero(iszero(slength)) {
          switch lt(slength, 32)
          case 1 {
            // blank the last byte which is the length
            fslot := mul(div(fslot, 0x100), 0x100)

            if iszero(eq(fslot, mload(add(_postBytes, 0x20)))) {
              // unsuccess:
              success := 0
            }
          }
          default {
            // cb is a circuit breaker in the for loop since there's
            //  no said feature for inline assembly loops
            // cb = 1 - don't breaker
            // cb = 0 - break
            let cb := 1

            // get the keccak hash to get the contents of the array
            mstore(0x0, _preBytes.slot)
            let sc := keccak256(0x0, 0x20)

            let mc := add(_postBytes, 0x20)
            let end := add(mc, mlength)

            // the next line is the loop condition:
            // while(uint256(mc < end) + cb == 2)
            for {

            } eq(add(lt(mc, end), cb), 2) {
              sc := add(sc, 1)
              mc := add(mc, 0x20)
            } {
              if iszero(eq(sload(sc), mload(mc))) {
                // unsuccess:
                success := 0
                cb := 0
              }
            }
          }
        }
      }
      default {
        // unsuccess:
        success := 0
      }
    }

    return success;
  }
}


// ============================================================================
// FILE: @protocol/core/contracts/libraries/sstore2/SSTORE2.sol
// ============================================================================

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import '../bytes/Bytecode.sol';

/**
  @title A key-value storage with auto-generated keys for storing chunks of data with a lower write & read cost.
  @author Agustin Aguilar <aa@horizon.io>

  Readme: https://github.com/0xsequence/sstore2#readme
*/
library SSTORE2 {
  error WriteError();

  /**
    @notice Stores `_data` and returns `pointer` as key for later retrieval
    @dev The pointer is a contract address with `_data` as code
    @param _data to be written
    @return pointer Pointer to the written `_data`
  */
  function write(bytes memory _data) internal returns (address pointer) {
    // Append 00 to _data so contract can't be called
    // Build init code
    bytes memory code = Bytecode.creationCodeFor(
      abi.encodePacked(hex'00', _data)
    );

    // Deploy contract using create
    assembly {
      pointer := create(0, add(code, 32), mload(code))
    }

    // Address MUST be non-zero
    if (pointer == address(0)) revert WriteError();
  }

  /**
    @notice Reads the contents of the `_pointer` code as data, skips the first byte 
    @dev The function is intended for reading pointers generated by `write`
    @param _pointer to be read
    @return data read from `_pointer` contract
  */
  function read(address _pointer) internal view returns (bytes memory) {
    return Bytecode.codeAt(_pointer, 1, type(uint256).max);
  }

  /**
    @notice Reads the contents of the `_pointer` code as data, skips the first byte 
    @dev The function is intended for reading pointers generated by `write`
    @param _pointer to be read
    @param _start number of bytes to skip
    @return data read from `_pointer` contract
  */
  function read(
    address _pointer,
    uint256 _start
  ) internal view returns (bytes memory) {
    return Bytecode.codeAt(_pointer, _start + 1, type(uint256).max);
  }

  /**
    @notice Reads the contents of the `_pointer` code as data, skips the first byte 
    @dev The function is intended for reading pointers generated by `write`
    @param _pointer to be read
    @param _start number of bytes to skip
    @param _end index before which to end extraction
    @return data read from `_pointer` contract
  */
  function read(
    address _pointer,
    uint256 _start,
    uint256 _end
  ) internal view returns (bytes memory) {
    return Bytecode.codeAt(_pointer, _start + 1, _end + 1);
  }
}


// ============================================================================
// FILE: @protocol/core/contracts/utils/EIP712.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (utils/cryptography/EIP712.sol)

pragma solidity ^0.8.20;

import {MessageHashUtils} from '@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol';
import {IERC5267} from '@openzeppelin/contracts/interfaces/IERC5267.sol';

/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP-712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding scheme specified in the EIP requires a domain separator and a hash of the typed structured data, whose
 * encoding is very generic and therefore its implementation in Solidity is not feasible, thus this contract
 * does not implement the encoding itself. Protocols need to implement the type-specific encoding they need in order to
 * produce the hash of their typed data using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP-712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
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
 * separator of the implementation contract. This will cause the {_domainSeparatorV4} function to always rebuild the
 * separator from the immutable values, which is cheaper than accessing a cached version in cold storage.
 */
abstract contract EIP712Upgradeable is IERC5267 {
  bytes32 private constant TYPE_HASH =
    keccak256(
      'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)'
    );

  /// @custom:storage-location erc7201:openzeppelin.storage.EIP712
  struct EIP712Storage {
    /// @custom:oz-renamed-from _HASHED_NAME
    bytes32 _hashedName;
    /// @custom:oz-renamed-from _HASHED_VERSION
    bytes32 _hashedVersion;
    string _name;
    string _version;
  }

  // keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.EIP712")) - 1)) & ~bytes32(uint256(0xff))
  bytes32 private constant EIP712StorageLocation =
    0xa16a46d94261c7517cc8ff89f61c0ce93598e3c849801011dee649a6a557d100;

  function _getEIP712Storage() private pure returns (EIP712Storage storage $) {
    assembly {
      $.slot := EIP712StorageLocation
    }
  }

  /**
   * @dev Initializes the domain separator and parameter caches.
   *
   * The meaning of `name` and `version` is specified in
   * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP-712]:
   *
   * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
   * - `version`: the current major version of the signing domain.
   *
   * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
   * contract upgrade].
   */
  function __EIP712_init(string memory name, string memory version) internal {
    __EIP712_init_unchained(name, version);
  }

  function __EIP712_init_unchained(
    string memory name,
    string memory version
  ) internal {
    EIP712Storage storage $ = _getEIP712Storage();
    $._name = name;
    $._version = version;

    // Reset prior values in storage if upgrading
    $._hashedName = 0;
    $._hashedVersion = 0;
  }

  /**
   * @dev Returns the domain separator for the current chain.
   */
  function _domainSeparatorV4() internal view returns (bytes32) {
    return _buildDomainSeparator();
  }

  function _buildDomainSeparator() private view returns (bytes32) {
    return
      keccak256(
        abi.encode(
          TYPE_HASH,
          _EIP712NameHash(),
          _EIP712VersionHash(),
          block.chainid,
          address(this)
        )
      );
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
  function _hashTypedDataV4(
    bytes32 structHash
  ) internal view virtual returns (bytes32) {
    return MessageHashUtils.toTypedDataHash(_domainSeparatorV4(), structHash);
  }

  /**
   * @dev See {IERC-5267}.
   */
  function eip712Domain()
    public
    view
    virtual
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
    EIP712Storage storage $ = _getEIP712Storage();
    // If the hashed name and version in storage are non-zero, the contract hasn't been properly initialized
    // and the EIP712 domain is not reliable, as it will be missing name and version.
    require(
      $._hashedName == 0 && $._hashedVersion == 0,
      'EIP712: Uninitialized'
    );

    return (
      hex'0f', // 01111
      _EIP712Name(),
      _EIP712Version(),
      block.chainid,
      address(this),
      bytes32(0),
      new uint256[](0)
    );
  }

  /**
   * @dev The name parameter for the EIP712 domain.
   *
   * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
   * are a concern.
   */
  function _EIP712Name() internal view virtual returns (string memory) {
    EIP712Storage storage $ = _getEIP712Storage();
    return $._name;
  }

  /**
   * @dev The version parameter for the EIP712 domain.
   *
   * NOTE: This function reads from storage by default, but can be redefined to return a constant value if gas costs
   * are a concern.
   */
  function _EIP712Version() internal view virtual returns (string memory) {
    EIP712Storage storage $ = _getEIP712Storage();
    return $._version;
  }

  /**
   * @dev The hash of the name parameter for the EIP712 domain.
   *
   * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Name` instead.
   */
  function _EIP712NameHash() internal view returns (bytes32) {
    EIP712Storage storage $ = _getEIP712Storage();
    string memory name = _EIP712Name();
    if (bytes(name).length > 0) {
      return keccak256(bytes(name));
    } else {
      // If the name is empty, the contract may have been upgraded without initializing the new storage.
      // We return the name hash in storage if non-zero, otherwise we assume the name is empty by design.
      bytes32 hashedName = $._hashedName;
      if (hashedName != 0) {
        return hashedName;
      } else {
        return keccak256('');
      }
    }
  }

  /**
   * @dev The hash of the version parameter for the EIP712 domain.
   *
   * NOTE: In previous versions this function was virtual. In this version you should override `_EIP712Version` instead.
   */
  function _EIP712VersionHash() internal view returns (bytes32) {
    EIP712Storage storage $ = _getEIP712Storage();
    string memory version = _EIP712Version();
    if (bytes(version).length > 0) {
      return keccak256(bytes(version));
    } else {
      // If the version is empty, the contract may have been upgraded without initializing the new storage.
      // We return the version hash in storage if non-zero, otherwise we assume the version is empty by design.
      bytes32 hashedVersion = $._hashedVersion;
      if (hashedVersion != 0) {
        return hashedVersion;
      } else {
        return keccak256('');
      }
    }
  }
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/interfaces/IERC4906.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@openzeppelin/contracts/utils/introspection/IERC165.sol';
import '@openzeppelin/contracts/token/ERC721/IERC721.sol';

interface IERC4906 {
  /// @dev This event emits when the metadata of a token is changed.
  /// So that the third-party platforms such as NFT market could
  /// timely update the images and related attributes of the NFT.
  event MetadataUpdate(uint256 _tokenId);

  /// @dev This event emits when the metadata of a range of tokens is changed.
  /// So that the third-party platforms such as NFT market could
  /// timely update the images and related attributes of the NFTs.
  event BatchMetadataUpdate(uint256 _fromTokenId, uint256 _toTokenId);
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/interfaces/IERC721CLogic.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

interface IERC721CLogic {
  function supportsInterface(bytes4 interfaceId) external view returns (bool);

  function contractURI() external view returns (string memory);

  function tokenURI(uint256 tokenId) external view returns (string memory);
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/ownable/MultiRoleAuthority.sol
// ============================================================================

// SPDX-License-Identifier: CC0-1.0
// Source: https://github.com/tubby-cats/dual-ownership-nft
pragma solidity ^0.8.4;

import '@openzeppelin/contracts/utils/Context.sol';

error CallerNotAdmin();
error CallerNotOwner();

abstract contract MultiRoleAuthorityBase is Context {
  bytes32 public constant MULTI_ROLE_AUTHORITY =
    keccak256('com.pob.MultiRoleAuthority');

  event OwnershipTransferred(
    address indexed previousOwner,
    address indexed newOwner
  );
  event AdminTransferred(
    address indexed previousAdmin,
    address indexed newAdmin
  );

  struct MultiRoleAuthorityStorage {
    address owner;
    address admin;
  }

  function _multiRoleAuthorityStorage()
    internal
    pure
    returns (MultiRoleAuthorityStorage storage state)
  {
    bytes32 position = MULTI_ROLE_AUTHORITY;
    assembly {
      state.slot := position
    }
  }

  constructor() {}

  modifier onlyOwner() {
    if (_multiRoleAuthorityStorage().owner != _msgSender()) {
      revert CallerNotOwner();
    }
    _;
  }

  modifier onlyAdmin() {
    if (_multiRoleAuthorityStorage().admin != _msgSender()) {
      revert CallerNotAdmin();
    }
    _;
  }
}

abstract contract MultiRoleAuthority is Context, MultiRoleAuthorityBase {
  constructor(address admin_) {
    _transferOwnership(admin_);
    _transferAdmin(admin_);
  }

  function owner() public view virtual returns (address) {
    return _multiRoleAuthorityStorage().owner;
  }

  function _transferOwnership(address newOwner) internal virtual {
    MultiRoleAuthorityStorage storage state = _multiRoleAuthorityStorage();
    address oldOwner = state.owner;
    state.owner = newOwner;
    emit OwnershipTransferred(oldOwner, newOwner);
  }

  function admin() public view returns (address) {
    return _multiRoleAuthorityStorage().admin;
  }

  function transferAdmin(address newAdmin) public onlyAdmin {
    _transferAdmin(newAdmin);
  }

  function _transferAdmin(address newAdmin) internal virtual {
    MultiRoleAuthorityStorage storage state = _multiRoleAuthorityStorage();
    address oldAdmin = state.admin;
    state.admin = newAdmin;
    emit AdminTransferred(oldAdmin, newAdmin);
  }

  function transferLowerOwnership(address newOwner) public onlyAdmin {
    _transferOwnership(newOwner);
  }
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/tokens/ERC721A.sol
// ============================================================================

// SPDX-License-Identifier: MIT
// Creator: Chiru Labs

pragma solidity ^0.8.4;

library ERC721AStorage {
  // Bypass for a `--via-ir` bug (https://github.com/chiru-labs/ERC721A/pull/364).
  struct TokenApprovalRef {
    address value;
  }

  struct Layout {
    // =============================================================
    //                            STORAGE
    // =============================================================

    // The next token ID to be minted.
    uint256 _currentIndex;
    // The number of tokens burned.
    uint256 _burnCounter;
    // Token name
    string _name;
    // Token symbol
    string _symbol;
    // Mapping from token ID to ownership details
    // An empty struct value does not necessarily mean the token is unowned.
    // See {_packedOwnershipOf} implementation for details.
    //
    // Bits Layout:
    // - [0..159]   `addr`
    // - [160..223] `startTimestamp`
    // - [224]      `burned`
    // - [225]      `nextInitialized`
    // - [232..255] `extraData`
    mapping(uint256 => uint256) _packedOwnerships;
    // Mapping owner address to address data.
    //
    // Bits Layout:
    // - [0..63]    `balance`
    // - [64..127]  `numberMinted`
    // - [128..191] `numberBurned`
    // - [192..255] `aux`
    mapping(address => uint256) _packedAddressData;
    // Mapping from token ID to approved address.
    mapping(uint256 => ERC721AStorage.TokenApprovalRef) _tokenApprovals;
    // Mapping from owner to operator approvals
    mapping(address => mapping(address => bool)) _operatorApprovals;
  }

  bytes32 internal constant STORAGE_SLOT =
    keccak256('ERC721A.contracts.storage.ERC721A');

  function layout() internal pure returns (Layout storage l) {
    bytes32 slot = STORAGE_SLOT;
    assembly {
      l.slot := slot
    }
  }
}

/**
 * @dev Interface of ERC721A.
 */
interface IERC721A {
  /**
   * The caller must own the token or be an approved operator.
   */
  error ApprovalCallerNotOwnerNorApproved();

  /**
   * The token does not exist.
   */
  error ApprovalQueryForNonexistentToken();

  /**
   * Cannot query the balance for the zero address.
   */
  error BalanceQueryForZeroAddress();

  /**
   * Cannot mint to the zero address.
   */
  error MintToZeroAddress();

  /**
   * The quantity of tokens minted must be more than zero.
   */
  error MintZeroQuantity();

  /**
   * The token does not exist.
   */
  error OwnerQueryForNonexistentToken();

  /**
   * The caller must own the token or be an approved operator.
   */
  error TransferCallerNotOwnerNorApproved();

  /**
   * The token must be owned by `from`.
   */
  error TransferFromIncorrectOwner();

  /**
   * Cannot safely transfer to a contract that does not implement the
   * ERC721Receiver interface.
   */
  error TransferToNonERC721ReceiverImplementer();

  /**
   * Cannot transfer to the zero address.
   */
  error TransferToZeroAddress();

  /**
   * The token does not exist.
   */
  error URIQueryForNonexistentToken();

  /**
   * The `quantity` minted with ERC2309 exceeds the safety limit.
   */
  error MintERC2309QuantityExceedsLimit();

  /**
   * The `extraData` cannot be set on an unintialized ownership slot.
   */
  error OwnershipNotInitializedForExtraData();

  // =============================================================
  //                            STRUCTS
  // =============================================================

  struct TokenOwnership {
    // The address of the owner.
    address addr;
    // Stores the start time of ownership with minimal overhead for tokenomics.
    uint64 startTimestamp;
    // Whether the token has been burned.
    bool burned;
    // Arbitrary data similar to `startTimestamp` that can be set via {_extraData}.
    uint24 extraData;
  }

  // =============================================================
  //                         TOKEN COUNTERS
  // =============================================================

  /**
   * @dev Returns the total number of tokens in existence.
   * Burned tokens will reduce the count.
   * To get the total number of tokens minted, please see {_totalMinted}.
   */
  function totalSupply() external view returns (uint256);

  // =============================================================
  //                            IERC165
  // =============================================================

  /**
   * @dev Returns true if this contract implements the interface defined by
   * `interfaceId`. See the corresponding
   * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)
   * to learn more about how these ids are created.
   *
   * This function call must use less than 30000 gas.
   */
  function supportsInterface(bytes4 interfaceId) external view returns (bool);

  // =============================================================
  //                            IERC721
  // =============================================================

  /**
   * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
   */
  event Transfer(
    address indexed from,
    address indexed to,
    uint256 indexed tokenId
  );

  /**
   * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
   */
  event Approval(
    address indexed owner,
    address indexed approved,
    uint256 indexed tokenId
  );

  /**
   * @dev Emitted when `owner` enables or disables
   * (`approved`) `operator` to manage all of its assets.
   */
  event ApprovalForAll(
    address indexed owner,
    address indexed operator,
    bool approved
  );

  /**
   * @dev Returns the number of tokens in `owner`'s account.
   */
  function balanceOf(address owner) external view returns (uint256 balance);

  /**
   * @dev Returns the owner of the `tokenId` token.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   */
  function ownerOf(uint256 tokenId) external view returns (address owner);

  /**
   * @dev Safely transfers `tokenId` token from `from` to `to`,
   * checking first that contract recipients are aware of the ERC721 protocol
   * to prevent tokens from being forever locked.
   *
   * Requirements:
   *
   * - `from` cannot be the zero address.
   * - `to` cannot be the zero address.
   * - `tokenId` token must exist and be owned by `from`.
   * - If the caller is not `from`, it must be have been allowed to move
   * this token by either {approve} or {setApprovalForAll}.
   * - If `to` refers to a smart contract, it must implement
   * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
   *
   * Emits a {Transfer} event.
   */
  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId,
    bytes calldata data
  ) external payable;

  /**
   * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.
   */
  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId
  ) external payable;

  /**
   * @dev Transfers `tokenId` from `from` to `to`.
   *
   * WARNING: Usage of this method is discouraged, use {safeTransferFrom}
   * whenever possible.
   *
   * Requirements:
   *
   * - `from` cannot be the zero address.
   * - `to` cannot be the zero address.
   * - `tokenId` token must be owned by `from`.
   * - If the caller is not `from`, it must be approved to move this token
   * by either {approve} or {setApprovalForAll}.
   *
   * Emits a {Transfer} event.
   */
  function transferFrom(
    address from,
    address to,
    uint256 tokenId
  ) external payable;

  /**
   * @dev Gives permission to `to` to transfer `tokenId` token to another account.
   * The approval is cleared when the token is transferred.
   *
   * Only a single account can be approved at a time, so approving the
   * zero address clears previous approvals.
   *
   * Requirements:
   *
   * - The caller must own the token or be an approved operator.
   * - `tokenId` must exist.
   *
   * Emits an {Approval} event.
   */
  function approve(address to, uint256 tokenId) external payable;

  /**
   * @dev Approve or remove `operator` as an operator for the caller.
   * Operators can call {transferFrom} or {safeTransferFrom}
   * for any token owned by the caller.
   *
   * Requirements:
   *
   * - The `operator` cannot be the caller.
   *
   * Emits an {ApprovalForAll} event.
   */
  function setApprovalForAll(address operator, bool _approved) external;

  /**
   * @dev Returns the account approved for `tokenId` token.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   */
  function getApproved(
    uint256 tokenId
  ) external view returns (address operator);

  /**
   * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
   *
   * See {setApprovalForAll}.
   */
  function isApprovedForAll(
    address owner,
    address operator
  ) external view returns (bool);

  // =============================================================
  //                        IERC721Metadata
  // =============================================================

  /**
   * @dev Returns the token collection name.
   */
  function name() external view returns (string memory);

  /**
   * @dev Returns the token collection symbol.
   */
  function symbol() external view returns (string memory);

  /**
   * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
   */
  function tokenURI(uint256 tokenId) external view returns (string memory);

  // =============================================================
  //                           IERC2309
  // =============================================================

  /**
   * @dev Emitted when tokens in `fromTokenId` to `toTokenId`
   * (inclusive) is transferred from `from` to `to`, as defined in the
   * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309) standard.
   *
   * See {_mintERC2309} for more details.
   */
  event ConsecutiveTransfer(
    uint256 indexed fromTokenId,
    uint256 toTokenId,
    address indexed from,
    address indexed to
  );
}

/**
 * @dev Interface of ERC721 token receiver.
 */
interface ERC721A__IERC721Receiver {
  function onERC721Received(
    address operator,
    address from,
    uint256 tokenId,
    bytes calldata data
  ) external returns (bytes4);
}

/**
 * @title ERC721A
 *
 * @dev Implementation of the [ERC721](https://eips.ethereum.org/EIPS/eip-721)
 * Non-Fungible Token Standard, including the Metadata extension.
 * Optimized for lower gas during batch mints.
 *
 * Token IDs are minted in sequential order (e.g. 0, 1, 2, 3, ...)
 * starting from `_startTokenId()`.
 *
 * Assumptions:
 *
 * - An owner cannot have more than 2**64 - 1 (max value of uint64) of supply.
 * - The maximum token ID cannot exceed 2**256 - 1 (max value of uint256).
 */
contract ERC721A is IERC721A {
  using ERC721AStorage for ERC721AStorage.Layout;

  // =============================================================
  //                           CONSTANTS
  // =============================================================

  // Mask of an entry in packed address data.
  uint256 private constant _BITMASK_ADDRESS_DATA_ENTRY = (1 << 64) - 1;

  // The bit position of `numberMinted` in packed address data.
  uint256 private constant _BITPOS_NUMBER_MINTED = 64;

  // The bit position of `numberBurned` in packed address data.
  uint256 private constant _BITPOS_NUMBER_BURNED = 128;

  // The bit position of `aux` in packed address data.
  uint256 private constant _BITPOS_AUX = 192;

  // Mask of all 256 bits in packed address data except the 64 bits for `aux`.
  uint256 private constant _BITMASK_AUX_COMPLEMENT = (1 << 192) - 1;

  // The bit position of `startTimestamp` in packed ownership.
  uint256 private constant _BITPOS_START_TIMESTAMP = 160;

  // The bit mask of the `burned` bit in packed ownership.
  uint256 private constant _BITMASK_BURNED = 1 << 224;

  // The bit position of the `nextInitialized` bit in packed ownership.
  uint256 private constant _BITPOS_NEXT_INITIALIZED = 225;

  // The bit mask of the `nextInitialized` bit in packed ownership.
  uint256 private constant _BITMASK_NEXT_INITIALIZED = 1 << 225;

  // The bit position of `extraData` in packed ownership.
  uint256 private constant _BITPOS_EXTRA_DATA = 232;

  // Mask of all 256 bits in a packed ownership except the 24 bits for `extraData`.
  uint256 private constant _BITMASK_EXTRA_DATA_COMPLEMENT = (1 << 232) - 1;

  // The mask of the lower 160 bits for addresses.
  uint256 private constant _BITMASK_ADDRESS = (1 << 160) - 1;

  // The maximum `quantity` that can be minted with {_mintERC2309}.
  // This limit is to prevent overflows on the address data entries.
  // For a limit of 5000, a total of 3.689e15 calls to {_mintERC2309}
  // is required to cause an overflow, which is unrealistic.
  uint256 private constant _MAX_MINT_ERC2309_QUANTITY_LIMIT = 5000;

  // The `Transfer` event signature is given by:
  // `keccak256(bytes("Transfer(address,address,uint256)"))`.
  bytes32 private constant _TRANSFER_EVENT_SIGNATURE =
    0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef;

  // =============================================================
  //                          CONSTRUCTOR
  // =============================================================

  constructor(string memory name_, string memory symbol_) {
    ERC721AStorage.layout()._name = name_;
    ERC721AStorage.layout()._symbol = symbol_;
    ERC721AStorage.layout()._currentIndex = _startTokenId();
  }

  // =============================================================
  //                   TOKEN COUNTING OPERATIONS
  // =============================================================

  /**
   * @dev Returns the starting token ID.
   * To change the starting token ID, please override this function.
   */
  function _startTokenId() internal view virtual returns (uint256) {
    return 0;
  }

  /**
   * @dev Returns the next token ID to be minted.
   */
  function _nextTokenId() internal view virtual returns (uint256) {
    return ERC721AStorage.layout()._currentIndex;
  }

  /**
   * @dev Returns the total number of tokens in existence.
   * Burned tokens will reduce the count.
   * To get the total number of tokens minted, please see {_totalMinted}.
   */
  function totalSupply() public view virtual override returns (uint256) {
    // Counter underflow is impossible as _burnCounter cannot be incremented
    // more than `_currentIndex - _startTokenId()` times.
    unchecked {
      return
        ERC721AStorage.layout()._currentIndex -
        ERC721AStorage.layout()._burnCounter -
        _startTokenId();
    }
  }

  /**
   * @dev Returns the total amount of tokens minted in the contract.
   */
  function _totalMinted() internal view virtual returns (uint256) {
    // Counter underflow is impossible as `_currentIndex` does not decrement,
    // and it is initialized to `_startTokenId()`.
    unchecked {
      return ERC721AStorage.layout()._currentIndex - _startTokenId();
    }
  }

  /**
   * @dev Returns the total number of tokens burned.
   */
  function _totalBurned() internal view virtual returns (uint256) {
    return ERC721AStorage.layout()._burnCounter;
  }

  // =============================================================
  //                    ADDRESS DATA OPERATIONS
  // =============================================================

  /**
   * @dev Returns the number of tokens in `owner`'s account.
   */
  function balanceOf(
    address owner
  ) public view virtual override returns (uint256) {
    if (owner == address(0)) _revert(BalanceQueryForZeroAddress.selector);
    return
      ERC721AStorage.layout()._packedAddressData[owner] &
      _BITMASK_ADDRESS_DATA_ENTRY;
  }

  /**
   * Returns the number of tokens minted by `owner`.
   */
  function _numberMinted(address owner) internal view returns (uint256) {
    return
      (ERC721AStorage.layout()._packedAddressData[owner] >>
        _BITPOS_NUMBER_MINTED) & _BITMASK_ADDRESS_DATA_ENTRY;
  }

  /**
   * Returns the number of tokens burned by or on behalf of `owner`.
   */
  function _numberBurned(address owner) internal view returns (uint256) {
    return
      (ERC721AStorage.layout()._packedAddressData[owner] >>
        _BITPOS_NUMBER_BURNED) & _BITMASK_ADDRESS_DATA_ENTRY;
  }

  /**
   * Returns the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).
   */
  function _getAux(address owner) internal view returns (uint64) {
    return
      uint64(ERC721AStorage.layout()._packedAddressData[owner] >> _BITPOS_AUX);
  }

  /**
   * Sets the auxiliary data for `owner`. (e.g. number of whitelist mint slots used).
   * If there are multiple variables, please pack them into a uint64.
   */
  function _setAux(address owner, uint64 aux) internal virtual {
    uint256 packed = ERC721AStorage.layout()._packedAddressData[owner];
    uint256 auxCasted;
    // Cast `aux` with assembly to avoid redundant masking.
    assembly {
      auxCasted := aux
    }
    packed = (packed & _BITMASK_AUX_COMPLEMENT) | (auxCasted << _BITPOS_AUX);
    ERC721AStorage.layout()._packedAddressData[owner] = packed;
  }

  // =============================================================
  //                            IERC165
  // =============================================================

  /**
   * @dev Returns true if this contract implements the interface defined by
   * `interfaceId`. See the corresponding
   * [EIP section](https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified)
   * to learn more about how these ids are created.
   *
   * This function call must use less than 30000 gas.
   */
  function supportsInterface(
    bytes4 interfaceId
  ) public view virtual override returns (bool) {
    // The interface IDs are constants representing the first 4 bytes
    // of the XOR of all function selectors in the interface.
    // See: [ERC165](https://eips.ethereum.org/EIPS/eip-165)
    // (e.g. `bytes4(i.functionA.selector ^ i.functionB.selector ^ ...)`)
    return
      interfaceId == 0x01ffc9a7 || // ERC165 interface ID for ERC165.
      interfaceId == 0x80ac58cd || // ERC165 interface ID for ERC721.
      interfaceId == 0x5b5e139f; // ERC165 interface ID for ERC721Metadata.
  }

  // =============================================================
  //                        IERC721Metadata
  // =============================================================

  /**
   * @dev Returns the token collection name.
   */
  function name() public view virtual override returns (string memory) {
    return ERC721AStorage.layout()._name;
  }

  /**
   * @dev Returns the token collection symbol.
   */
  function symbol() public view virtual override returns (string memory) {
    return ERC721AStorage.layout()._symbol;
  }

  /**
   * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
   */
  function tokenURI(
    uint256 tokenId
  ) public view virtual override returns (string memory) {
    if (!_exists(tokenId)) _revert(URIQueryForNonexistentToken.selector);
    return '';
  }

  // =============================================================
  //                     OWNERSHIPS OPERATIONS
  // =============================================================

  /**
   * @dev Returns the owner of the `tokenId` token.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   */
  function ownerOf(
    uint256 tokenId
  ) public view virtual override returns (address) {
    return address(uint160(_packedOwnershipOf(tokenId)));
  }

  /**
   * @dev Gas spent here starts off proportional to the maximum mint batch size.
   * It gradually moves to O(1) as tokens get transferred around over time.
   */
  function _ownershipOf(
    uint256 tokenId
  ) internal view virtual returns (TokenOwnership memory) {
    return _unpackedOwnership(_packedOwnershipOf(tokenId));
  }

  /**
   * @dev Returns the unpacked `TokenOwnership` struct at `index`.
   */
  function _ownershipAt(
    uint256 index
  ) internal view virtual returns (TokenOwnership memory) {
    return _unpackedOwnership(ERC721AStorage.layout()._packedOwnerships[index]);
  }

  /**
   * @dev Returns whether the ownership slot at `index` is initialized.
   * An uninitialized slot does not necessarily mean that the slot has no owner.
   */
  function _ownershipIsInitialized(
    uint256 index
  ) internal view virtual returns (bool) {
    return ERC721AStorage.layout()._packedOwnerships[index] != 0;
  }

  /**
   * @dev Initializes the ownership slot minted at `index` for efficiency purposes.
   */
  function _initializeOwnershipAt(uint256 index) internal virtual {
    if (ERC721AStorage.layout()._packedOwnerships[index] == 0) {
      ERC721AStorage.layout()._packedOwnerships[index] = _packedOwnershipOf(
        index
      );
    }
  }

  /**
   * Returns the packed ownership data of `tokenId`.
   */
  function _packedOwnershipOf(
    uint256 tokenId
  ) private view returns (uint256 packed) {
    if (_startTokenId() <= tokenId) {
      packed = ERC721AStorage.layout()._packedOwnerships[tokenId];
      // If the data at the starting slot does not exist, start the scan.
      if (packed == 0) {
        if (tokenId >= ERC721AStorage.layout()._currentIndex)
          _revert(OwnerQueryForNonexistentToken.selector);
        // Invariant:
        // There will always be an initialized ownership slot
        // (i.e. `ownership.addr != address(0) && ownership.burned == false`)
        // before an unintialized ownership slot
        // (i.e. `ownership.addr == address(0) && ownership.burned == false`)
        // Hence, `tokenId` will not underflow.
        //
        // We can directly compare the packed value.
        // If the address is zero, packed will be zero.
        for (;;) {
          unchecked {
            packed = ERC721AStorage.layout()._packedOwnerships[--tokenId];
          }
          if (packed == 0) continue;
          if (packed & _BITMASK_BURNED == 0) return packed;
          // Otherwise, the token is burned, and we must revert.
          // This handles the case of batch burned tokens, where only the burned bit
          // of the starting slot is set, and remaining slots are left uninitialized.
          _revert(OwnerQueryForNonexistentToken.selector);
        }
      }
      // Otherwise, the data exists and we can skip the scan.
      // This is possible because we have already achieved the target condition.
      // This saves 2143 gas on transfers of initialized tokens.
      // If the token is not burned, return `packed`. Otherwise, revert.
      if (packed & _BITMASK_BURNED == 0) return packed;
    }
    _revert(OwnerQueryForNonexistentToken.selector);
  }

  /**
   * @dev Returns the unpacked `TokenOwnership` struct from `packed`.
   */
  function _unpackedOwnership(
    uint256 packed
  ) private pure returns (TokenOwnership memory ownership) {
    ownership.addr = address(uint160(packed));
    ownership.startTimestamp = uint64(packed >> _BITPOS_START_TIMESTAMP);
    ownership.burned = packed & _BITMASK_BURNED != 0;
    ownership.extraData = uint24(packed >> _BITPOS_EXTRA_DATA);
  }

  /**
   * @dev Packs ownership data into a single uint256.
   */
  function _packOwnershipData(
    address owner,
    uint256 flags
  ) private view returns (uint256 result) {
    assembly {
      // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.
      owner := and(owner, _BITMASK_ADDRESS)
      // `owner | (block.timestamp << _BITPOS_START_TIMESTAMP) | flags`.
      result := or(owner, or(shl(_BITPOS_START_TIMESTAMP, timestamp()), flags))
    }
  }

  /**
   * @dev Returns the `nextInitialized` flag set if `quantity` equals 1.
   */
  function _nextInitializedFlag(
    uint256 quantity
  ) private pure returns (uint256 result) {
    // For branchless setting of the `nextInitialized` flag.
    assembly {
      // `(quantity == 1) << _BITPOS_NEXT_INITIALIZED`.
      result := shl(_BITPOS_NEXT_INITIALIZED, eq(quantity, 1))
    }
  }

  // =============================================================
  //                      APPROVAL OPERATIONS
  // =============================================================

  /**
   * @dev Gives permission to `to` to transfer `tokenId` token to another account. See {ERC721A-_approve}.
   *
   * Requirements:
   *
   * - The caller must own the token or be an approved operator.
   */
  function approve(
    address to,
    uint256 tokenId
  ) public payable virtual override {
    _approve(to, tokenId, true);
  }

  /**
   * @dev Returns the account approved for `tokenId` token.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   */
  function getApproved(
    uint256 tokenId
  ) public view virtual override returns (address) {
    if (!_exists(tokenId)) _revert(ApprovalQueryForNonexistentToken.selector);

    return ERC721AStorage.layout()._tokenApprovals[tokenId].value;
  }

  /**
   * @dev Approve or remove `operator` as an operator for the caller.
   * Operators can call {transferFrom} or {safeTransferFrom}
   * for any token owned by the caller.
   *
   * Requirements:
   *
   * - The `operator` cannot be the caller.
   *
   * Emits an {ApprovalForAll} event.
   */
  function setApprovalForAll(
    address operator,
    bool approved
  ) public virtual override {
    ERC721AStorage.layout()._operatorApprovals[_msgSenderERC721A()][
      operator
    ] = approved;
    emit ApprovalForAll(_msgSenderERC721A(), operator, approved);
  }

  /**
   * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
   *
   * See {setApprovalForAll}.
   */
  function isApprovedForAll(
    address owner,
    address operator
  ) public view virtual override returns (bool) {
    return ERC721AStorage.layout()._operatorApprovals[owner][operator];
  }

  /**
   * @dev Returns whether `tokenId` exists.
   *
   * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
   *
   * Tokens start existing when they are minted. See {_mint}.
   */
  function _exists(
    uint256 tokenId
  ) internal view virtual returns (bool result) {
    if (_startTokenId() <= tokenId) {
      if (tokenId < ERC721AStorage.layout()._currentIndex) {
        uint256 packed;
        while (
          (packed = ERC721AStorage.layout()._packedOwnerships[tokenId]) == 0
        ) --tokenId;
        result = packed & _BITMASK_BURNED == 0;
      }
    }
  }

  /**
   * @dev Returns whether `msgSender` is equal to `approvedAddress` or `owner`.
   */
  function _isSenderApprovedOrOwner(
    address approvedAddress,
    address owner,
    address msgSender
  ) private pure returns (bool result) {
    assembly {
      // Mask `owner` to the lower 160 bits, in case the upper bits somehow aren't clean.
      owner := and(owner, _BITMASK_ADDRESS)
      // Mask `msgSender` to the lower 160 bits, in case the upper bits somehow aren't clean.
      msgSender := and(msgSender, _BITMASK_ADDRESS)
      // `msgSender == owner || msgSender == approvedAddress`.
      result := or(eq(msgSender, owner), eq(msgSender, approvedAddress))
    }
  }

  /**
   * @dev Returns the storage slot and value for the approved address of `tokenId`.
   */
  function _getApprovedSlotAndAddress(
    uint256 tokenId
  )
    private
    view
    returns (uint256 approvedAddressSlot, address approvedAddress)
  {
    ERC721AStorage.TokenApprovalRef storage tokenApproval = ERC721AStorage
      .layout()
      ._tokenApprovals[tokenId];
    // The following is equivalent to `approvedAddress = _tokenApprovals[tokenId].value`.
    assembly {
      approvedAddressSlot := tokenApproval.slot
      approvedAddress := sload(approvedAddressSlot)
    }
  }

  // =============================================================
  //                      TRANSFER OPERATIONS
  // =============================================================

  /**
   * @dev Transfers `tokenId` from `from` to `to`.
   *
   * Requirements:
   *
   * - `from` cannot be the zero address.
   * - `to` cannot be the zero address.
   * - `tokenId` token must be owned by `from`.
   * - If the caller is not `from`, it must be approved to move this token
   * by either {approve} or {setApprovalForAll}.
   *
   * Emits a {Transfer} event.
   */
  function transferFrom(
    address from,
    address to,
    uint256 tokenId
  ) public payable virtual override {
    uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);

    // Mask `from` to the lower 160 bits, in case the upper bits somehow aren't clean.
    from = address(uint160(uint256(uint160(from)) & _BITMASK_ADDRESS));

    if (address(uint160(prevOwnershipPacked)) != from)
      _revert(TransferFromIncorrectOwner.selector);

    (
      uint256 approvedAddressSlot,
      address approvedAddress
    ) = _getApprovedSlotAndAddress(tokenId);

    // The nested ifs save around 20+ gas over a compound boolean condition.
    if (!_isSenderApprovedOrOwner(approvedAddress, from, _msgSenderERC721A()))
      if (!isApprovedForAll(from, _msgSenderERC721A()))
        _revert(TransferCallerNotOwnerNorApproved.selector);

    _beforeTokenTransfers(from, to, tokenId, 1);

    // Clear approvals from the previous owner.
    assembly {
      if approvedAddress {
        // This is equivalent to `delete _tokenApprovals[tokenId]`.
        sstore(approvedAddressSlot, 0)
      }
    }

    // Underflow of the sender's balance is impossible because we check for
    // ownership above and the recipient's balance can't realistically overflow.
    // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.
    unchecked {
      // We can directly increment and decrement the balances.
      --ERC721AStorage.layout()._packedAddressData[from]; // Updates: `balance -= 1`.
      ++ERC721AStorage.layout()._packedAddressData[to]; // Updates: `balance += 1`.

      // Updates:
      // - `address` to the next owner.
      // - `startTimestamp` to the timestamp of transfering.
      // - `burned` to `false`.
      // - `nextInitialized` to `true`.
      ERC721AStorage.layout()._packedOwnerships[tokenId] = _packOwnershipData(
        to,
        _BITMASK_NEXT_INITIALIZED |
          _nextExtraData(from, to, prevOwnershipPacked)
      );

      // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .
      if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {
        uint256 nextTokenId = tokenId + 1;
        // If the next slot's address is zero and not burned (i.e. packed value is zero).
        if (ERC721AStorage.layout()._packedOwnerships[nextTokenId] == 0) {
          // If the next slot is within bounds.
          if (nextTokenId != ERC721AStorage.layout()._currentIndex) {
            // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.
            ERC721AStorage.layout()._packedOwnerships[
              nextTokenId
            ] = prevOwnershipPacked;
          }
        }
      }
    }

    // Mask `to` to the lower 160 bits, in case the upper bits somehow aren't clean.
    uint256 toMasked = uint256(uint160(to)) & _BITMASK_ADDRESS;
    assembly {
      // Emit the `Transfer` event.
      log4(
        0, // Start of data (0, since no data).
        0, // End of data (0, since no data).
        _TRANSFER_EVENT_SIGNATURE, // Signature.
        from, // `from`.
        toMasked, // `to`.
        tokenId // `tokenId`.
      )
    }
    if (toMasked == 0) _revert(TransferToZeroAddress.selector);

    _afterTokenTransfers(from, to, tokenId, 1);
  }

  /**
   * @dev Equivalent to `safeTransferFrom(from, to, tokenId, '')`.
   */
  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId
  ) public payable virtual override {
    safeTransferFrom(from, to, tokenId, '');
  }

  /**
   * @dev Safely transfers `tokenId` token from `from` to `to`.
   *
   * Requirements:
   *
   * - `from` cannot be the zero address.
   * - `to` cannot be the zero address.
   * - `tokenId` token must exist and be owned by `from`.
   * - If the caller is not `from`, it must be approved to move this token
   * by either {approve} or {setApprovalForAll}.
   * - If `to` refers to a smart contract, it must implement
   * {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
   *
   * Emits a {Transfer} event.
   */
  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId,
    bytes memory _data
  ) public payable virtual override {
    transferFrom(from, to, tokenId);
    if (to.code.length != 0)
      if (!_checkContractOnERC721Received(from, to, tokenId, _data)) {
        _revert(TransferToNonERC721ReceiverImplementer.selector);
      }
  }

  /**
   * @dev Hook that is called before a set of serially-ordered token IDs
   * are about to be transferred. This includes minting.
   * And also called before burning one token.
   *
   * `startTokenId` - the first token ID to be transferred.
   * `quantity` - the amount to be transferred.
   *
   * Calling conditions:
   *
   * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be
   * transferred to `to`.
   * - When `from` is zero, `tokenId` will be minted for `to`.
   * - When `to` is zero, `tokenId` will be burned by `from`.
   * - `from` and `to` are never both zero.
   */
  function _beforeTokenTransfers(
    address from,
    address to,
    uint256 startTokenId,
    uint256 quantity
  ) internal virtual {}

  /**
   * @dev Hook that is called after a set of serially-ordered token IDs
   * have been transferred. This includes minting.
   * And also called after one token has been burned.
   *
   * `startTokenId` - the first token ID to be transferred.
   * `quantity` - the amount to be transferred.
   *
   * Calling conditions:
   *
   * - When `from` and `to` are both non-zero, `from`'s `tokenId` has been
   * transferred to `to`.
   * - When `from` is zero, `tokenId` has been minted for `to`.
   * - When `to` is zero, `tokenId` has been burned by `from`.
   * - `from` and `to` are never both zero.
   */
  function _afterTokenTransfers(
    address from,
    address to,
    uint256 startTokenId,
    uint256 quantity
  ) internal virtual {}

  /**
   * @dev Private function to invoke {IERC721Receiver-onERC721Received} on a target contract.
   *
   * `from` - Previous owner of the given token ID.
   * `to` - Target address that will receive the token.
   * `tokenId` - Token ID to be transferred.
   * `_data` - Optional data to send along with the call.
   *
   * Returns whether the call correctly returned the expected magic value.
   */
  function _checkContractOnERC721Received(
    address from,
    address to,
    uint256 tokenId,
    bytes memory _data
  ) private returns (bool) {
    try
      ERC721A__IERC721Receiver(to).onERC721Received(
        _msgSenderERC721A(),
        from,
        tokenId,
        _data
      )
    returns (bytes4 retval) {
      return retval == ERC721A__IERC721Receiver(to).onERC721Received.selector;
    } catch (bytes memory reason) {
      if (reason.length == 0) {
        _revert(TransferToNonERC721ReceiverImplementer.selector);
      }
      assembly {
        revert(add(32, reason), mload(reason))
      }
    }
  }

  // =============================================================
  //                        MINT OPERATIONS
  // =============================================================

  /**
   * @dev Mints `quantity` tokens and transfers them to `to`.
   *
   * Requirements:
   *
   * - `to` cannot be the zero address.
   * - `quantity` must be greater than 0.
   *
   * Emits a {Transfer} event for each mint.
   */
  function _mint(address to, uint256 quantity) internal virtual {
    uint256 startTokenId = ERC721AStorage.layout()._currentIndex;
    if (quantity == 0) _revert(MintZeroQuantity.selector);

    _beforeTokenTransfers(address(0), to, startTokenId, quantity);

    // Overflows are incredibly unrealistic.
    // `balance` and `numberMinted` have a maximum limit of 2**64.
    // `tokenId` has a maximum limit of 2**256.
    unchecked {
      // Updates:
      // - `address` to the owner.
      // - `startTimestamp` to the timestamp of minting.
      // - `burned` to `false`.
      // - `nextInitialized` to `quantity == 1`.
      ERC721AStorage.layout()._packedOwnerships[
        startTokenId
      ] = _packOwnershipData(
        to,
        _nextInitializedFlag(quantity) | _nextExtraData(address(0), to, 0)
      );

      // Updates:
      // - `balance += quantity`.
      // - `numberMinted += quantity`.
      //
      // We can directly add to the `balance` and `numberMinted`.
      ERC721AStorage.layout()._packedAddressData[to] +=
        quantity *
        ((1 << _BITPOS_NUMBER_MINTED) | 1);

      // Mask `to` to the lower 160 bits, in case the upper bits somehow aren't clean.
      uint256 toMasked = uint256(uint160(to)) & _BITMASK_ADDRESS;

      if (toMasked == 0) _revert(MintToZeroAddress.selector);

      uint256 end = startTokenId + quantity;
      uint256 tokenId = startTokenId;

      do {
        assembly {
          // Emit the `Transfer` event.
          log4(
            0, // Start of data (0, since no data).
            0, // End of data (0, since no data).
            _TRANSFER_EVENT_SIGNATURE, // Signature.
            0, // `address(0)`.
            toMasked, // `to`.
            tokenId // `tokenId`.
          )
        }
        // The `!=` check ensures that large values of `quantity`
        // that overflows uint256 will make the loop run out of gas.
      } while (++tokenId != end);

      ERC721AStorage.layout()._currentIndex = end;
    }
    _afterTokenTransfers(address(0), to, startTokenId, quantity);
  }

  /**
   * @dev Mints `quantity` tokens and transfers them to `to`.
   *
   * This function is intended for efficient minting only during contract creation.
   *
   * It emits only one {ConsecutiveTransfer} as defined in
   * [ERC2309](https://eips.ethereum.org/EIPS/eip-2309),
   * instead of a sequence of {Transfer} event(s).
   *
   * Calling this function outside of contract creation WILL make your contract
   * non-compliant with the ERC721 standard.
   * For full ERC721 compliance, substituting ERC721 {Transfer} event(s) with the ERC2309
   * {ConsecutiveTransfer} event is only permissible during contract creation.
   *
   * Requirements:
   *
   * - `to` cannot be the zero address.
   * - `quantity` must be greater than 0.
   *
   * Emits a {ConsecutiveTransfer} event.
   */
  function _mintERC2309(address to, uint256 quantity) internal virtual {
    uint256 startTokenId = ERC721AStorage.layout()._currentIndex;
    if (to == address(0)) _revert(MintToZeroAddress.selector);
    if (quantity == 0) _revert(MintZeroQuantity.selector);
    if (quantity > _MAX_MINT_ERC2309_QUANTITY_LIMIT)
      _revert(MintERC2309QuantityExceedsLimit.selector);

    _beforeTokenTransfers(address(0), to, startTokenId, quantity);

    // Overflows are unrealistic due to the above check for `quantity` to be below the limit.
    unchecked {
      // Updates:
      // - `balance += quantity`.
      // - `numberMinted += quantity`.
      //
      // We can directly add to the `balance` and `numberMinted`.
      ERC721AStorage.layout()._packedAddressData[to] +=
        quantity *
        ((1 << _BITPOS_NUMBER_MINTED) | 1);

      // Updates:
      // - `address` to the owner.
      // - `startTimestamp` to the timestamp of minting.
      // - `burned` to `false`.
      // - `nextInitialized` to `quantity == 1`.
      ERC721AStorage.layout()._packedOwnerships[
        startTokenId
      ] = _packOwnershipData(
        to,
        _nextInitializedFlag(quantity) | _nextExtraData(address(0), to, 0)
      );

      emit ConsecutiveTransfer(
        startTokenId,
        startTokenId + quantity - 1,
        address(0),
        to
      );

      ERC721AStorage.layout()._currentIndex = startTokenId + quantity;
    }
    _afterTokenTransfers(address(0), to, startTokenId, quantity);
  }

  /**
   * @dev Safely mints `quantity` tokens and transfers them to `to`.
   *
   * Requirements:
   *
   * - If `to` refers to a smart contract, it must implement
   * {IERC721Receiver-onERC721Received}, which is called for each safe transfer.
   * - `quantity` must be greater than 0.
   *
   * See {_mint}.
   *
   * Emits a {Transfer} event for each mint.
   */
  function _safeMint(
    address to,
    uint256 quantity,
    bytes memory _data
  ) internal virtual {
    _mint(to, quantity);

    unchecked {
      if (to.code.length != 0) {
        uint256 end = ERC721AStorage.layout()._currentIndex;
        uint256 index = end - quantity;
        do {
          if (!_checkContractOnERC721Received(address(0), to, index++, _data)) {
            _revert(TransferToNonERC721ReceiverImplementer.selector);
          }
        } while (index < end);
        // Reentrancy protection.
        if (ERC721AStorage.layout()._currentIndex != end) _revert(bytes4(0));
      }
    }
  }

  /**
   * @dev Equivalent to `_safeMint(to, quantity, '')`.
   */
  function _safeMint(address to, uint256 quantity) internal virtual {
    _safeMint(to, quantity, '');
  }

  // =============================================================
  //                       APPROVAL OPERATIONS
  // =============================================================

  /**
   * @dev Equivalent to `_approve(to, tokenId, false)`.
   */
  function _approve(address to, uint256 tokenId) internal virtual {
    _approve(to, tokenId, false);
  }

  /**
   * @dev Gives permission to `to` to transfer `tokenId` token to another account.
   * The approval is cleared when the token is transferred.
   *
   * Only a single account can be approved at a time, so approving the
   * zero address clears previous approvals.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   *
   * Emits an {Approval} event.
   */
  function _approve(
    address to,
    uint256 tokenId,
    bool approvalCheck
  ) internal virtual {
    address owner = ownerOf(tokenId);

    if (approvalCheck && _msgSenderERC721A() != owner)
      if (!isApprovedForAll(owner, _msgSenderERC721A())) {
        _revert(ApprovalCallerNotOwnerNorApproved.selector);
      }

    ERC721AStorage.layout()._tokenApprovals[tokenId].value = to;
    emit Approval(owner, to, tokenId);
  }

  // =============================================================
  //                        BURN OPERATIONS
  // =============================================================

  /**
   * @dev Equivalent to `_burn(tokenId, false)`.
   */
  function _burn(uint256 tokenId) internal virtual {
    _burn(tokenId, false);
  }

  /**
   * @dev Destroys `tokenId`.
   * The approval is cleared when the token is burned.
   *
   * Requirements:
   *
   * - `tokenId` must exist.
   *
   * Emits a {Transfer} event.
   */
  function _burn(uint256 tokenId, bool approvalCheck) internal virtual {
    uint256 prevOwnershipPacked = _packedOwnershipOf(tokenId);

    address from = address(uint160(prevOwnershipPacked));

    (
      uint256 approvedAddressSlot,
      address approvedAddress
    ) = _getApprovedSlotAndAddress(tokenId);

    if (approvalCheck) {
      // The nested ifs save around 20+ gas over a compound boolean condition.
      if (!_isSenderApprovedOrOwner(approvedAddress, from, _msgSenderERC721A()))
        if (!isApprovedForAll(from, _msgSenderERC721A()))
          _revert(TransferCallerNotOwnerNorApproved.selector);
    }

    _beforeTokenTransfers(from, address(0), tokenId, 1);

    // Clear approvals from the previous owner.
    assembly {
      if approvedAddress {
        // This is equivalent to `delete _tokenApprovals[tokenId]`.
        sstore(approvedAddressSlot, 0)
      }
    }

    // Underflow of the sender's balance is impossible because we check for
    // ownership above and the recipient's balance can't realistically overflow.
    // Counter overflow is incredibly unrealistic as `tokenId` would have to be 2**256.
    unchecked {
      // Updates:
      // - `balance -= 1`.
      // - `numberBurned += 1`.
      //
      // We can directly decrement the balance, and increment the number burned.
      // This is equivalent to `packed -= 1; packed += 1 << _BITPOS_NUMBER_BURNED;`.
      ERC721AStorage.layout()._packedAddressData[from] +=
        (1 << _BITPOS_NUMBER_BURNED) -
        1;

      // Updates:
      // - `address` to the last owner.
      // - `startTimestamp` to the timestamp of burning.
      // - `burned` to `true`.
      // - `nextInitialized` to `true`.
      ERC721AStorage.layout()._packedOwnerships[tokenId] = _packOwnershipData(
        from,
        (_BITMASK_BURNED | _BITMASK_NEXT_INITIALIZED) |
          _nextExtraData(from, address(0), prevOwnershipPacked)
      );

      // If the next slot may not have been initialized (i.e. `nextInitialized == false`) .
      if (prevOwnershipPacked & _BITMASK_NEXT_INITIALIZED == 0) {
        uint256 nextTokenId = tokenId + 1;
        // If the next slot's address is zero and not burned (i.e. packed value is zero).
        if (ERC721AStorage.layout()._packedOwnerships[nextTokenId] == 0) {
          // If the next slot is within bounds.
          if (nextTokenId != ERC721AStorage.layout()._currentIndex) {
            // Initialize the next slot to maintain correctness for `ownerOf(tokenId + 1)`.
            ERC721AStorage.layout()._packedOwnerships[
              nextTokenId
            ] = prevOwnershipPacked;
          }
        }
      }
    }

    emit Transfer(from, address(0), tokenId);
    _afterTokenTransfers(from, address(0), tokenId, 1);

    // Overflow not possible, as _burnCounter cannot be exceed _currentIndex times.
    unchecked {
      ERC721AStorage.layout()._burnCounter++;
    }
  }

  // =============================================================
  //                     EXTRA DATA OPERATIONS
  // =============================================================

  /**
   * @dev Directly sets the extra data for the ownership data `index`.
   */
  function _setExtraDataAt(uint256 index, uint24 extraData) internal virtual {
    uint256 packed = ERC721AStorage.layout()._packedOwnerships[index];
    if (packed == 0) _revert(OwnershipNotInitializedForExtraData.selector);
    uint256 extraDataCasted;
    // Cast `extraData` with assembly to avoid redundant masking.
    assembly {
      extraDataCasted := extraData
    }
    packed =
      (packed & _BITMASK_EXTRA_DATA_COMPLEMENT) |
      (extraDataCasted << _BITPOS_EXTRA_DATA);
    ERC721AStorage.layout()._packedOwnerships[index] = packed;
  }

  /**
   * @dev Called during each token transfer to set the 24bit `extraData` field.
   * Intended to be overridden by the cosumer contract.
   *
   * `previousExtraData` - the value of `extraData` before transfer.
   *
   * Calling conditions:
   *
   * - When `from` and `to` are both non-zero, `from`'s `tokenId` will be
   * transferred to `to`.
   * - When `from` is zero, `tokenId` will be minted for `to`.
   * - When `to` is zero, `tokenId` will be burned by `from`.
   * - `from` and `to` are never both zero.
   */
  function _extraData(
    address from,
    address to,
    uint24 previousExtraData
  ) internal view virtual returns (uint24) {}

  /**
   * @dev Returns the next extra data for the packed ownership data.
   * The returned result is shifted into position.
   */
  function _nextExtraData(
    address from,
    address to,
    uint256 prevOwnershipPacked
  ) private view returns (uint256) {
    uint24 extraData = uint24(prevOwnershipPacked >> _BITPOS_EXTRA_DATA);
    return uint256(_extraData(from, to, extraData)) << _BITPOS_EXTRA_DATA;
  }

  // =============================================================
  //                       OTHER OPERATIONS
  // =============================================================

  /**
   * @dev Returns the message sender (defaults to `msg.sender`).
   *
   * If you are writing GSN compatible contracts, you need to override this function.
   */
  function _msgSenderERC721A() internal view virtual returns (address) {
    return msg.sender;
  }

  /**
   * @dev Converts a uint256 to its ASCII string decimal representation.
   */
  function _toString(
    uint256 value
  ) internal pure virtual returns (string memory str) {
    assembly {
      // The maximum value of a uint256 contains 78 digits (1 byte per digit), but
      // we allocate 0xa0 bytes to keep the free memory pointer 32-byte word aligned.
      // We will need 1 word for the trailing zeros padding, 1 word for the length,
      // and 3 words for a maximum of 78 digits. Total: 5 * 0x20 = 0xa0.
      let m := add(mload(0x40), 0xa0)
      // Update the free memory pointer to allocate.
      mstore(0x40, m)
      // Assign the `str` to the end.
      str := sub(m, 0x20)
      // Zeroize the slot after the string.
      mstore(str, 0)

      // Cache the end of the memory to calculate the length later.
      let end := str

      // We write the string from rightmost digit to leftmost digit.
      // The following is essentially a do-while loop that also handles the zero case.
      // prettier-ignore
      for { let temp := value } 1 {} {
                str := sub(str, 1)
                // Write the character to the pointer.
                // The ASCII index of the '0' character is 48.
                mstore8(str, add(48, mod(temp, 10)))
                // Keep dividing `temp` until zero.
                temp := div(temp, 10)
                // prettier-ignore
                if iszero(temp) { break }
            }

      let length := sub(end, str)
      // Move the pointer 32 bytes leftwards to make room for the length.
      str := sub(str, 0x20)
      // Store the length.
      mstore(str, length)
    }
  }

  /**
   * @dev For more efficient reverts.
   */
  function _revert(bytes4 errorSelector) internal pure {
    assembly {
      mstore(0x00, errorSelector)
      revert(0x00, 0x04)
    }
  }
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/tokens/ERC721C.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import './ERC721A.sol';
import '../ownable/MultiRoleAuthority.sol';
import '../interfaces/IERC721CLogic.sol';

error SettingLogicThatIsImmutable();
error FunctionDoesNotExist();

interface IERC721CDelegatedMetadata {
  function delegatedTokenURI(
    uint256 tokenId
  ) external view returns (string memory);
}

abstract contract ERC721C is ERC721A, MultiRoleAuthority {
  uint256 internal constant EIP1967_LOGIC_SLOT =
    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

  bytes32 internal constant ERC721C_LOGIC = keccak256('com.erc721c.ERC721C');

  event Upgraded(address indexed logic);

  struct ERC721CStorage {
    bool isLogicImmutable;
  }

  constructor(address logic) {
    _setLogic(logic);
  }

  function _erc721cStorage()
    internal
    pure
    returns (ERC721CStorage storage state)
  {
    bytes32 position = ERC721C_LOGIC;
    assembly {
      state.slot := position
    }
  }

  function _setLogic(address logic) internal {
    if (_erc721cStorage().isLogicImmutable)
      revert SettingLogicThatIsImmutable();
    emit Upgraded(logic);
    assembly {
      sstore(EIP1967_LOGIC_SLOT, logic)
    }
  }

  function setLogic(address logic) public onlyAdmin {
    _setLogic(logic);
  }

  function isLogicImmutable() public view returns (bool) {
    return _erc721cStorage().isLogicImmutable;
  }

  function setLogicImmutable() public onlyAdmin {
    _erc721cStorage().isLogicImmutable = true;
  }

  function logicContract() public view returns (address logic_) {
    assembly {
      logic_ := sload(EIP1967_LOGIC_SLOT)
    }
  }

  function supportsInterface(
    bytes4 interfaceId
  ) public view virtual override returns (bool) {
    return
      // no need to delegatecall, basically pure
      IERC721CLogic(logicContract()).supportsInterface(interfaceId) ||
      super.supportsInterface(interfaceId);
  }

  function tokenURI(
    uint256 tokenId
  ) public view virtual override returns (string memory) {
    if (!_exists(tokenId)) revert URIQueryForNonexistentToken();
    return IERC721CDelegatedMetadata(address(this)).delegatedTokenURI(tokenId);
  }

  function delegatedTokenURI(
    // is view but not declared as such - psudo implementation of IERC721CMetadata
    uint256 tokenId
  ) external returns (string memory) {
    (bool success, bytes memory returndata) = logicContract().delegatecall(
      abi.encodeWithSelector(IERC721CLogic.tokenURI.selector, tokenId)
    );
    if (!success) {
      assembly {
        revert(add(returndata, 0x20), mload(returndata))
      }
    }
    return abi.decode(returndata, (string));
  }

  fallback(bytes calldata callData) external returns (bytes memory resultData) {
    bool success;
    (success, resultData) = logicContract().delegatecall(callData);
    if (!success) {
      if (resultData.length > 0) {
        assembly {
          revert(add(resultData, 0x20), mload(resultData))
        }
      } else {
        revert FunctionDoesNotExist();
      }
    }
  }
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/tokens/ERC721CLogicBase.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@protocol/core/contracts/interfaces/IComponent.sol';
import '../ownable/MultiRoleAuthority.sol';
import '../interfaces/IERC721CLogic.sol';
import '../interfaces/IERC4906.sol'; //metadata interface

error CallerNotMetadataOperator();
error AlreadyInitialized();

abstract contract ERC721CLogicBase is
  MultiRoleAuthorityBase,
  IERC721CLogic,
  IERC4906
{
  bytes32 internal constant ERC721C_METADATA_LOGIC =
    keccak256('com.erc721c.ERC721CLogicBase');

  event UpdatedContractMetadataComponent(address component);
  event UpdatedMetadataComponent(address component);

  struct ERC721CMetadataLogicStorage {
    address contractMetadataComponent;
    address metadataComponent;
    address metadataOperator;
    bool isInitialized;
  }

  function _metadataLogicStorage()
    internal
    pure
    returns (ERC721CMetadataLogicStorage storage state)
  {
    bytes32 position = ERC721C_METADATA_LOGIC;
    assembly {
      state.slot := position
    }
  }

  function contractMetadataComponent() external view returns (address) {
    return _metadataLogicStorage().contractMetadataComponent;
  }

  function metadataComponent() external view returns (address) {
    return _metadataLogicStorage().metadataComponent;
  }

  function metadataOperator() external view returns (address) {
    return _metadataLogicStorage().metadataOperator;
  }

  function isInitialized() external view returns (bool) {
    return _metadataLogicStorage().isInitialized;
  }

  function _initializeLogic(
    address contractMetadataComponent_,
    address metadataComponent_,
    address metadataOperator_
  ) internal {
    ERC721CMetadataLogicStorage storage state = _metadataLogicStorage();
    if (state.isInitialized) {
      revert AlreadyInitialized();
    }
    state.metadataOperator = metadataOperator_;
    state.contractMetadataComponent = contractMetadataComponent_;
    state.metadataComponent = metadataComponent_;
    state.isInitialized = true;
  }

  function supportsInterface(
    bytes4 interfaceId
  ) public view virtual returns (bool) {
    return
      // supports IERC4906
      interfaceId == 0x49064906;
  }

  modifier onlyMetadataOperator() {
    if (_metadataLogicStorage().metadataOperator != _msgSender()) {
      revert CallerNotMetadataOperator();
    }
    _;
  }

  function transferMetadataOperator(
    address _metadataOperator
  ) public onlyAdmin {
    ERC721CMetadataLogicStorage storage state = _metadataLogicStorage();
    state.metadataOperator = _metadataOperator;
  }

  function setMetadataComponent(
    address _component
  ) external onlyMetadataOperator {
    _metadataLogicStorage().metadataComponent = _component;
    emit UpdatedMetadataComponent(_component);
  }

  function setContractMetadataComponent(
    address _component
  ) external onlyMetadataOperator {
    _metadataLogicStorage().contractMetadataComponent = _component;
    emit UpdatedContractMetadataComponent(_component);
  }

  function emitMetadataUpdated(uint fromTokenId, uint toTokenId) external {
    if (fromTokenId == toTokenId) {
      emit MetadataUpdate(fromTokenId);
    } else {
      emit BatchMetadataUpdate(fromTokenId, toTokenId);
    }
  }

  function contractURI() external view virtual returns (string memory) {
    return
      string(
        IComponent(_metadataLogicStorage().contractMetadataComponent).render('')
      );
  }

  function tokenURI(
    uint256 tokenId
  ) external view virtual returns (string memory) {
    return
      string(
        IComponent(_metadataLogicStorage().metadataComponent).render(
          abi.encodePacked(tokenId)
        )
      );
  }
}


// ============================================================================
// FILE: @protocol/erc721c/contracts/tokens/ERC721CMintingBase.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import './ERC721C.sol';

error EmergencyShutdownInPlace();
error MintingGroupNotActive();
error ExceedsMintingGroupSupply();
error MintingGroupNotTransferrable();
error ExceedsMintingGroupTransferrableSupply();
error SettingMintingGroupThatIsImmutable();
error CallerNotMintingAuthority();

abstract contract ERC721CMintingBase is ERC721C {
  bytes32 internal constant ERC721C_MINTING_BASE =
    keccak256('com.erc721c.ERC721CMintingBase');

  event EmergencyShutdown(bool emergencyShutdown);
  event UpdatedMintingGroup(uint id);
  event TransferredMintingSupply(uint fromId, uint toId, uint quantity);
  event MintedFromGroup(uint id, address to, uint quantity);
  event UpdatedMintingAuthority(address mintingAuthority);

  struct ERC721CMetadataLogicStorage {
    bool emergencyShutdown;
    mapping(uint => MintingGroup) mintingGroups;
  }

  struct MintingGroup {
    address mintingAuthority;
    uint64 supply; // max size of a group is 64 bits
    uint64 numMinted;
    uint40 activeFromTimestamp;
    uint40 endAtTimestamp;
    bool isTransferrable; // dictates if supply can be moved
    bool isImmutable; // dictates if minting parameters can be changed, time stamp + authority
  }

  constructor(MintingGroup[] memory mintingGroups_) {
    for (uint i = 0; i < mintingGroups_.length; ++i) {
      MintingGroup memory group = mintingGroups_[i];
      _ERC721CMintingBaseStorage().mintingGroups[i] = group;
    }
  }

  function _ERC721CMintingBaseStorage()
    internal
    pure
    returns (ERC721CMetadataLogicStorage storage state)
  {
    bytes32 position = ERC721C_MINTING_BASE;
    assembly {
      state.slot := position
    }
  }

  function mintingGroup(uint id) external view returns (MintingGroup memory) {
    return _ERC721CMintingBaseStorage().mintingGroups[id];
  }

  function emergencyShutdown() external view returns (bool) {
    return _ERC721CMintingBaseStorage().emergencyShutdown;
  }

  function setEmergencyShutdown(bool _emergencyShutdown) external onlyAdmin {
    ERC721CMetadataLogicStorage storage state = _ERC721CMintingBaseStorage();
    state.emergencyShutdown = _emergencyShutdown;
    emit EmergencyShutdown(state.emergencyShutdown);
  }

  function setIsImmutable(
    uint _mintingGroupIndex,
    bool _isImmutable
  ) external onlyAdmin onlyNotImmutable(_mintingGroupIndex) {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[
      _mintingGroupIndex
    ];
    group.isImmutable = _isImmutable;
    emit UpdatedMintingGroup(_mintingGroupIndex);
  }

  function setIsTransferrable(
    uint _mintingGroupIndex,
    bool _isTransferrable
  ) external onlyAdmin onlyNotImmutable(_mintingGroupIndex) {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[
      _mintingGroupIndex
    ];
    group.isTransferrable = _isTransferrable;
    emit UpdatedMintingGroup(_mintingGroupIndex);
  }

  function setMintingAuthority(
    uint _mintingGroupIndex,
    address _mintingAuthority
  ) external onlyAdmin onlyNotImmutable(_mintingGroupIndex) {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[
      _mintingGroupIndex
    ];
    group.mintingAuthority = _mintingAuthority;
    emit UpdatedMintingGroup(_mintingGroupIndex);
  }

  function setTimestamp(
    uint _mintingGroupIndex,
    uint40 _activeFromTimestamp,
    uint40 _endAtTimestamp
  ) external onlyAdmin onlyNotImmutable(_mintingGroupIndex) {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[
      _mintingGroupIndex
    ];
    group.activeFromTimestamp = _activeFromTimestamp;
    group.endAtTimestamp = _endAtTimestamp;
    emit UpdatedMintingGroup(_mintingGroupIndex);
  }

  modifier onlyNotImmutable(uint id) {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[id];
    if (group.isImmutable) revert SettingMintingGroupThatIsImmutable();
    _;
  }

  modifier onlyIsActive(uint id) {
    if (_ERC721CMintingBaseStorage().emergencyShutdown)
      revert EmergencyShutdownInPlace();
    ERC721CMintingBase.MintingGroup storage group = _ERC721CMintingBaseStorage()
      .mintingGroups[id];
    if (
      (group.activeFromTimestamp > block.timestamp ||
        group.endAtTimestamp < block.timestamp)
    ) revert MintingGroupNotActive();
    _;
  }

  function _mintFromGroup(address to, uint64 numMints, uint id) internal {
    MintingGroup storage group = _ERC721CMintingBaseStorage().mintingGroups[id];
    unchecked {
      if (group.numMinted + numMints > group.supply) {
        revert ExceedsMintingGroupSupply();
      }
      group.numMinted += numMints;
      _mint(to, numMints);
      emit MintedFromGroup(id, to, numMints);
    }
  }

  function _transferMintGroupSupply(
    uint fromId,
    uint toId,
    uint64 quantity
  ) internal {
    MintingGroup storage fromGroup = _ERC721CMintingBaseStorage().mintingGroups[
      fromId
    ];
    if (!fromGroup.isTransferrable) revert MintingGroupNotTransferrable();
    unchecked {
      if (quantity > fromGroup.supply - fromGroup.numMinted)
        revert ExceedsMintingGroupTransferrableSupply();
      _ERC721CMintingBaseStorage().mintingGroups[toId].supply += quantity;
      fromGroup.supply -= quantity;
      emit TransferredMintingSupply(fromId, toId, quantity);
    }
  }

  function numberMinted(address minter) external view returns (uint256) {
    return _numberMinted(minter);
  }

  function totalMinted() external view returns (uint256) {
    return _totalMinted();
  }

  function nextTokenId() external view returns (uint256) {
    return _nextTokenId();
  }

  modifier onlyMintingAuthority(uint mintingGroupIndex) {
    if (
      _msgSender() !=
      _ERC721CMintingBaseStorage()
        .mintingGroups[mintingGroupIndex]
        .mintingAuthority
    ) revert CallerNotMintingAuthority();
    _;
  }

  function transferMintGroupSupply(
    uint fromId,
    uint toId,
    uint64 quantity
  ) public onlyAdmin onlyIsActive(fromId) {
    _transferMintGroupSupply(fromId, toId, quantity);
  }
}


// ============================================================================
// FILE: contracts/metadata/HiraethMetadataRegistry.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;
import '@protocol/core/contracts/interfaces/IComponent.sol';
import '@protocol/core/contracts/libraries/bytes/BytesUtils.sol';
import '@openzeppelin/contracts/utils/introspection/ERC165.sol';
import '@openzeppelin/contracts/utils/Strings.sol';
import '@openzeppelin/contracts/utils/Base64.sol';
import '@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol';
import '@openzeppelin/contracts/utils/cryptography/ECDSA.sol';
import '@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol';
import '@protocol/core/contracts/utils/EIP712.sol';

import '@protocol/core/contracts/libraries/sstore2/SSTORE2.sol';
import '@protocol/erc721c/contracts/ownable/MultiRoleAuthority.sol';

import '../nft/Hiraeth.sol';

error HiraethMetadataRegistryNotTxnHashOwnerOrAuthorized();
error HiraethMetadataRegistryTxnHashOwner();
error HiraethMetadataRegistryNotAuthor();
error HiraethMetadataRegistryAlreadyInitialized();

abstract contract HiraethMetadataRegistry is
  MultiRoleAuthorityBase,
  EIP712Upgradeable
{
  bytes32 public constant HIRAETH_METADATA_BASE =
    keccak256('com.hiraeth.HiraethMetadata');

  uint8 public constant METADATA_TYPE_SSTORE = 0;
  uint8 public constant METADATA_TYPE_SSTORE_2 = 1;

  struct HiraethMetadata {
    bytes32 value;
    address author;
  }

  struct HiraethMetadataStorage {
    mapping(bytes32 => mapping(bytes32 => HiraethMetadata)) txnHashToMetadata;
    mapping(bytes32 => mapping(address => mapping(address => bool))) approvedWriters;
    bool isInitialized;
    address hiraeth;
  }

  event UpdatedApprovedWriter(
    bytes32 txnHash,
    address owner,
    address writer,
    bool status
  );

  event MetadataSet(
    bytes32 txnHash,
    uint8 metadataType,
    bytes31 key,
    address author
  );

  constructor() MultiRoleAuthorityBase() {}

  function _initializeMetadata(
    address hiraeth_,
    string memory eip712Name,
    string memory eip712Version
  ) internal onlyAdmin {
    HiraethMetadataStorage storage state = _HiraethMetadataStorage();
    if (state.isInitialized) {
      revert HiraethMetadataRegistryAlreadyInitialized();
    }
    state.hiraeth = hiraeth_;
    _HiraethMetadataStorage().isInitialized = true;
    __EIP712_init(eip712Name, eip712Version);
  }

  function _hiraeth() internal view returns (address) {
    return _HiraethMetadataStorage().hiraeth;
  }

  function approveWriter(
    bytes32 txnHash_,
    address writer_,
    bool status_
  ) public {
    address owner = Hiraeth(_hiraeth()).ownerOfByTxnHash(txnHash_);
    if (owner != _msgSender()) {
      revert HiraethMetadataRegistryTxnHashOwner();
    }
    _HiraethMetadataStorage().approvedWriters[txnHash_][owner][
      writer_
    ] = status_;
    emit UpdatedApprovedWriter(txnHash_, owner, writer_, status_);
  }

  function getApprovedWriterStatus(
    bytes32 txnHash_,
    address owner_,
    address writer_
  ) public view returns (bool) {
    return _HiraethMetadataStorage().approvedWriters[txnHash_][owner_][writer_];
  }

  function _HiraethMetadataStorage()
    internal
    pure
    returns (HiraethMetadataStorage storage state)
  {
    bytes32 position = HIRAETH_METADATA_BASE;
    assembly {
      state.slot := position
    }
  }

  function _getMetadataKey(
    uint8 metadataType,
    bytes31 key
  ) internal pure returns (bytes32) {
    // first byte is the metadata type
    return bytes32(key) | bytes32(uint(metadataType));
  }

  struct SetMetadata {
    uint8 metadataType;
    bytes31 key;
    bytes32 salt;
    address author;
    bytes value;
  }

  bytes32 public constant SET_METADATA_TYPE =
    keccak256(
      'SetMetadata(bytes32 txnHash,bytes32 metadataKey,bytes32 salt,address author,bytes value)'
    );

  function getSetMetadataDigest(
    bytes32 txnHash,
    SetMetadata calldata param
  ) public view returns (bytes32) {
    return
      _hashTypedDataV4(
        keccak256(
          abi.encode(
            SET_METADATA_TYPE,
            txnHash,
            _getMetadataKey(param.metadataType, param.key),
            param.salt,
            param.author,
            keccak256(param.value)
          )
        )
      );
  }

  function verifyAuthorship(
    bytes32 txnHash,
    SetMetadata calldata param,
    bytes memory signature
  ) public view returns (bool) {
    return
      SignatureChecker.isValidSignatureNow(
        param.author,
        getSetMetadataDigest(txnHash, param),
        signature
      );
  }

  function getMetadata(
    bytes32 txnHash,
    uint8 metadataType,
    bytes31 key
  ) public view returns (HiraethMetadata memory) {
    bytes32 metadataKey = _getMetadataKey(metadataType, key);
    return _HiraethMetadataStorage().txnHashToMetadata[txnHash][metadataKey];
  }

  function getMetadataStoredValue(
    bytes32 txnHash,
    uint8 metadataType,
    bytes31 key
  ) public view returns (bytes memory value) {
    HiraethMetadata memory metadata = getMetadata(txnHash, metadataType, key);
    if (metadataType == METADATA_TYPE_SSTORE_2) {
      address pointer = address(bytes20(metadata.value));
      if (pointer != address(0)) {
        value = SSTORE2.read(pointer);
      }
    }
  }

  modifier onlyTxnHashOwnerOrApproved(bytes32 txnHash) {
    address owner = Hiraeth(_hiraeth()).ownerOfByTxnHash(txnHash);
    bool isOwner = owner == _msgSender();
    bool isAuthorizedWriter = _HiraethMetadataStorage().approvedWriters[
      txnHash
    ][owner][_msgSender()];
    if (!isOwner && !isAuthorizedWriter) {
      revert HiraethMetadataRegistryNotTxnHashOwnerOrAuthorized();
    }
    _;
  }

  function setMetadata(
    bytes32 txnHash,
    SetMetadata[] calldata params,
    bytes[] calldata signatures
  ) public onlyTxnHashOwnerOrApproved(txnHash) {
    _setMetadata(txnHash, params, signatures, false);
  }

  function setMetadataByAdmin(
    bytes32 txnHash,
    SetMetadata[] calldata params,
    bytes[] calldata signatures
  ) public onlyAdmin {
    _setMetadata(txnHash, params, signatures, true);
  }

  function _setMetadata(
    bytes32 txnHash,
    SetMetadata[] calldata params,
    bytes[] calldata signatures,
    bool isAdmin
  ) internal {
    for (uint i = 0; i < params.length; i++) {
      SetMetadata calldata param = params[i];
      bytes memory signature = signatures[i];

      bytes32 storedValue = bytes32(0);
      if (param.value.length != 0) {
        if (param.metadataType == METADATA_TYPE_SSTORE_2) {
          address pointer = SSTORE2.write(param.value);
          storedValue = bytes32(bytes20(pointer));
        } else if (param.metadataType == METADATA_TYPE_SSTORE) {
          bytes memory value = param.value;
          assembly {
            storedValue := mload(add(value, 0x20))
          }
        }
      }

      address author = _msgSender();
      if (isAdmin) {
        author = param.author;
      } else if (param.salt != bytes32(0)) {
        if (verifyAuthorship(txnHash, param, signature)) {
          author = param.author;
        } else {
          revert HiraethMetadataRegistryNotAuthor();
        }
      }

      _HiraethMetadataStorage().txnHashToMetadata[txnHash][
        _getMetadataKey(param.metadataType, param.key)
      ] = HiraethMetadata(storedValue, author);
      emit MetadataSet(txnHash, param.metadataType, param.key, author);
    }
  }
}


// ============================================================================
// FILE: contracts/nft/Hiraeth.sol
// ============================================================================

// SPDX-License-Identifier: LicenseRef-AllRightsReserved

pragma solidity ^0.8.4;
import '@protocol/erc721c/contracts/tokens/ERC721CMintingBase.sol';
import './HiraethBase.sol';

error HiraethUnsetMintNotAllowed();
error HiraethAlreadyInitialized();

contract Hiraeth is ERC721CMintingBase, HiraethBase {
  constructor(
    string memory name_,
    string memory symbol_,
    ERC721CMintingBase.MintingGroup[] memory mintingGroups_,
    address logic,
    address admin,
    uint256 epochSize
  )
    MultiRoleAuthority(admin)
    ERC721A(name_, symbol_)
    ERC721C(logic)
    ERC721CMintingBase(mintingGroups_)
  {
    _HiraethStorage().epochSize = epochSize;
  }

  function _startTokenId() internal view virtual override returns (uint256) {
    return 1;
  }

  event HiraethClaimed(uint256 tokenId, bytes32 txnHash);

  function getEpochSize() external view returns (uint) {
    return _HiraethStorage().epochSize;
  }

  function tokenMetadata(
    uint256 tokenId
  ) public view returns (HiraethTokenMetadata memory) {
    HiraethTokenMetadata memory metadata;

    while (true) {
      metadata = _HiraethStorage().tokenMetadata[tokenId];
      // ERC721A does not allow for a null address mint, so this should be a good check for initialized metadata
      if (metadata.minter != address(0) || tokenId == 0) {
        return metadata;
      }
      // if (tokenId == 0) {
      //   return HiraethTokenMetadata(address(0), 0x000000);
      // }
      unchecked {
        tokenId -= 1;
      }
    }

    return HiraethTokenMetadata(address(0), 0x000000);
  }

  function tokenMetadataByTxnHash(
    bytes32 txnHash
  ) external view returns (HiraethTokenMetadata memory metadata) {
    uint256 tokenId = _HiraethStorage().txnHashToTokenId[txnHash];
    return tokenMetadata(tokenId);
  }

  function tokenIdToTxnHash(
    uint256 tokenId
  ) external view returns (bytes32 txnHash) {
    return _HiraethStorage().tokenIdToTxnHash[tokenId];
  }

  function txnHashToTokenId(
    bytes32 txnHash
  ) external view returns (uint256 tokenId) {
    return _HiraethStorage().txnHashToTokenId[txnHash];
  }

  function ownerOfByTxnHash(
    bytes32 txnHash
  ) external view returns (address owner) {
    return ownerOf(_HiraethStorage().txnHashToTokenId[txnHash]);
  }

  function getEpoch(uint256 tokenId) public view returns (uint256) {
    return ((tokenId - _startTokenId()) / _HiraethStorage().epochSize) + 1;
  }

  function isTxnHashMintable(bytes32 txnHash) public view virtual returns (bool) {
    return txnHash != 0 && _HiraethStorage().txnHashToTokenId[txnHash] == 0;
  }

  function _inscribeHiraethMints(
    address minter,
    bytes32[] memory txnHashes
  ) internal returns (uint64) {
    HiraethStorage storage state = _HiraethStorage();

    unchecked {
      uint64 numMints = 0;
      uint256 currentIndex = _nextTokenId();
      for (uint256 i = 0; i < txnHashes.length; ++i) {
        bytes32 txnHash = txnHashes[i];
        if (isTxnHashMintable(txnHash)) {
          // we will write the metadata to the first token minted in a multi-mint
          // !BUG, Was `if (i == 0)`, if the first transaction is invalid, then the rest do not have the correct metadata. Can be found in a17e830b32df371ba81db0a2722f3f37034b6f40
          if (numMints == 0) {
            state.tokenMetadata[currentIndex] = HiraethTokenMetadata(
              minter,
              0x000000
            );
          }

          state.tokenIdToTxnHash[currentIndex] = txnHash;
          state.txnHashToTokenId[txnHash] = currentIndex;
          emit HiraethClaimed(currentIndex, txnHash);

          currentIndex++;
          numMints++;
        }
      }
      return numMints;
    }
  }

  function mintHiraeth(
    uint id,
    address to,
    address minter,
    bytes32[] memory txnHashes
  ) public onlyMintingAuthority(id) onlyIsActive(id) returns (uint64 numMints) {
    numMints = _inscribeHiraethMints(minter, txnHashes);
    if (numMints != 0) {
      _mintFromGroup(to, numMints, id);
    }
  }
}


// ============================================================================
// FILE: contracts/nft/HiraethBase.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

abstract contract HiraethBase {
  bytes32 internal constant HIRAETH_BASE = keccak256('com.hiraeth.Hiraeth');

  struct HiraethTokenMetadata {
    address minter;
    bytes12 data; // extra data space for future use
  }

  struct HiraethStorage {
    // for the sake of gas efficiency, tokenMetadata will only be set on the leading token in a multi-mint;
    mapping(uint256 => HiraethTokenMetadata) tokenMetadata;
    mapping(uint256 => bytes32) tokenIdToTxnHash;
    mapping(bytes32 => uint256) txnHashToTokenId;
    uint epochSize;
  }

  function _HiraethStorage()
    internal
    pure
    returns (HiraethStorage storage state)
  {
    bytes32 position = HIRAETH_BASE;
    assembly {
      state.slot := position
    }
  }
}


// ============================================================================
// FILE: contracts/nft/HiraethLogicV1FixMetadata.sol
// ============================================================================

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.4;

import '@protocol/erc721c/contracts/tokens/ERC721CLogicBase.sol';
import '../metadata/HiraethMetadataRegistry.sol';
import './HiraethBase.sol';
import './Hiraeth.sol';

contract HiraethLogicV1FixMetadata is
  ERC721CLogicBase,
  HiraethBase,
  HiraethMetadataRegistry
{
  bytes32 internal constant HIRAETH_LOGIC_BASE =
    keccak256('com.hiraeth.HiraethLogic');

  constructor() ERC721CLogicBase() HiraethMetadataRegistry() {}

  function initialize(
    address contractMetadataComponent_,
    address metadataComponent_,
    address metadataOperator_,
    address hiraeth,
    string memory eip712Name,
    string memory eip712Version
  ) public onlyAdmin {
    _initializeLogic(
      contractMetadataComponent_,
      metadataComponent_,
      metadataOperator_
    );
    _initializeMetadata(hiraeth, eip712Name, eip712Version);
  }

  struct HiraethLogicStorage {
    mapping(uint256 => bytes32) epochToSeed;
  }

  function _HiraethLogicStorage()
    internal
    pure
    returns (HiraethLogicStorage storage state)
  {
    bytes32 position = HIRAETH_LOGIC_BASE;
    assembly {
      state.slot := position
    }
  }

  function getEpochSeed(uint256 epoch) public view returns (bytes32) {
    return _HiraethLogicStorage().epochToSeed[epoch];
  }

  function setEpochSeed(
    uint256 epoch,
    bytes32 seed
  ) public onlyMetadataOperator {
    _HiraethLogicStorage().epochToSeed[epoch] = seed;
  }

  function tokenURI(
    uint256 tokenId
  ) public view virtual override returns (string memory) {
    HiraethTokenMetadata memory metadata = Hiraeth(_hiraeth()).tokenMetadata(tokenId);
    return
      string(
        IComponent(_metadataLogicStorage().metadataComponent).render(
          abi.encodePacked(
            address(this),
            tokenId,
            _HiraethStorage().tokenIdToTxnHash[tokenId],
            metadata.minter,
            metadata.data
          )
        )
      );
  }
}
