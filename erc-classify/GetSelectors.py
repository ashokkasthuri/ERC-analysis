import json
from eth_utils import keccak

def get_event_topic(event_signature: str) -> str:
    return keccak(text=event_signature).hex()

def get_selector(function_signature: str) -> str:
    hash_bytes = keccak(text=function_signature)
    selector = hash_bytes[:4].hex()
    return selector

def build_erc_config(erc_name: str, function_signatures: dict, topics: list = None, events: dict = None) -> dict:
    topics = topics or []
    events = events or {}
    selectors = {}
    for sig in function_signatures:
        selectors[sig] = get_selector(sig)
    config = {
        erc_name: {
            "selectors": list(selectors.values()),
            "topics": topics,
            "functions": selectors,
            "events": events
        }
    }
    return config


#######################
# EIP-214: Core Protocol
#######################
# eip214_specific_functions = {
#     # EIP-214 specific functions
#     "call(address,uint256,bytes)": None,
#     "delegatecall(address,bytes)": None
# }
# eip214_event_specific_signatures = {}  # No specific events for EIP-214

# # EIP-214 functions and events
# eip214_functions = eip214_specific_functions
# eip214_event_signatures = eip214_event_specific_signatures

# eip214_events = {}
# eip214_topics = []
# for key, sig in eip214_event_signatures.items():
#     topic = get_event_topic(sig)
#     eip214_events[topic] = f"event {sig}"
#     eip214_topics.append(topic)
# eip214_config = build_erc_config("EIP214", eip214_functions, topics=eip214_topics, events=eip214_events)


#######################
# ERC-165: Interface Detection
#######################
erc165_specific_functions = {
    # ERC-165 specific functions
    # "supportsInterface(bytes4)": None
}
erc165_event_specific_signatures = {}  # No specific events for ERC-165

# Merge EIP-214 and ERC-165-specific functions
erc165_functions = {}
# erc165_functions.update(eip214_functions)  # EIP-214 required functions
erc165_functions.update(erc165_specific_functions)  # ERC-165 specific functions

erc165_event_signatures = {}
# erc165_event_signatures.update(eip214_event_signatures)  # EIP-214 events
erc165_event_signatures.update(erc165_event_specific_signatures)  # ERC-165 events

erc165_events = {}
erc165_topics = []
for key, sig in erc165_event_signatures.items():
    topic = get_event_topic(sig)
    erc165_events[topic] = f"event {sig}"
    erc165_topics.append(topic)
erc165_config = build_erc_config("ERC165", erc165_functions, topics=erc165_topics, events=erc165_events)

#######################
# ERC-20: Fungible Token Standard
#######################
erc20_functions = {
    "totalSupply()": None,
    "balanceOf(address)": None,
    "transfer(address,uint256)": None,
    "approve(address,uint256)": None,
    "allowance(address,address)": None,
    "transferFrom(address,address,uint256)": None
}
erc20_event_signatures = {
    "Transfer": "Transfer(address,address,uint256)",
    "Approval": "Approval(address,address,uint256)"
}
erc20_events = {}
erc20_topics = []
for key, sig in erc20_event_signatures.items():
    topic = get_event_topic(sig)
    erc20_events[topic] = f"event {sig}"
    erc20_topics.append(topic)
erc20_config = build_erc_config("ERC20", erc20_functions, topics=erc20_topics, events=erc20_events)


#######################
# ERC-721: Non-Fungible Tokens
#######################
erc721_specific_functions = {
    # ERC-721 specific functions
    "balanceOf(address)": None,
    "ownerOf(uint256)": None,
    "safeTransferFrom(address,address,uint256)": None,
    "safeTransferFrom(address,address,uint256,bytes)": None,
    "transferFrom(address,address,uint256)": None,
    "approve(address,uint256)": None,
    "setApprovalForAll(address,bool)": None,
    "getApproved(uint256)": None,
    "isApprovedForAll(address,address)": None
}
erc721_event_specific_signatures = {
    "Transfer": "Transfer(address,address,uint256)",
    "Approval": "Approval(address,address,uint256)",
    "ApprovalForAll": "ApprovalForAll(address,address,bool)"
}

# Merge ERC-165 and ERC-721-specific functions
erc721_functions = {}
erc721_functions.update(erc165_functions)  # ERC-165 required functions
erc721_functions.update(erc721_specific_functions)  # ERC-721 specific functions

erc721_event_signatures = {}
erc721_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc721_event_signatures.update(erc721_event_specific_signatures)  # ERC-721 events

erc721_events = {}
erc721_topics = []
for key, sig in erc721_event_signatures.items():
    topic = get_event_topic(sig)
    erc721_events[topic] = f"event {sig}"
    erc721_topics.append(topic)
erc721_config = build_erc_config("ERC721", erc721_functions, topics=erc721_topics, events=erc721_events)

#######################
# ERC-223: Token Fallback
#######################
erc223_specific_functions = {
    # ERC-223 specific functions
    "totalSupply()": None,
    "balanceOf(address)": None,
    "transfer(address,uint256)": None,
    "transfer(address,uint256,bytes)": None
}
erc223_event_specific_signatures = {
    "Transfer": "Transfer(address,address,uint256,bytes)"
}

# Merge ERC-20 and ERC-223-specific functions
erc223_functions = {}
erc223_functions.update(erc223_specific_functions)  # ERC-223 specific functions

erc223_event_signatures = {}
erc223_event_signatures.update(erc223_event_specific_signatures)  # ERC-223 events

erc223_events = {}
erc223_topics = []
for key, sig in erc223_event_signatures.items():
    topic = get_event_topic(sig)
    erc223_events[topic] = f"event {sig}"
    erc223_topics.append(topic)
erc223_config = build_erc_config("ERC223", erc223_functions, topics=erc223_topics, events=erc223_events)

#######################
# ERC-777: Advanced Fungible Token with Callbacks
#######################
erc777_functions = {
    "name()": None,
    "symbol()": None,
    "granularity()": None,
    "totalSupply()": None,
    "balanceOf(address)": None,
    "send(address,uint256,bytes)": None,
    "transfer(address,uint256)": None,
    "authorizeOperator(address)": None,
    "revokeOperator(address)": None,
    "isOperatorFor(address,address)": None,
    "operatorSend(address,address,uint256,bytes,bytes)": None,
    "burn(uint256,bytes)": None,
    "operatorBurn(address,uint256,bytes,bytes)": None
}
erc777_event_signatures = {
    "Sent": "Sent(address,address,uint256,bytes,bytes)",
    "Minted": "Minted(address,address,uint256,bytes,bytes)",
    "Burned": "Burned(address,address,uint256,bytes,bytes)",
    "AuthorizedOperator": "AuthorizedOperator(address,address)",
    "RevokedOperator": "RevokedOperator(address,address)"
}
erc777_events = {}
erc777_topics = []
for key, sig in erc777_event_signatures.items():
    topic = get_event_topic(sig)
    erc777_events[topic] = f"event {sig}"
    erc777_topics.append(topic)
erc777_config = build_erc_config("ERC777", erc777_functions, topics=erc777_topics, events=erc777_events)

#######################
# ERC-1155: Multi-Token Standard
#######################
erc1155_functions = {
    "balanceOf(address,uint256)": None,
    "balanceOfBatch(address[],uint256[])": None,
    "setApprovalForAll(address,bool)": None,
    "isApprovedForAll(address,address)": None,
    "safeTransferFrom(address,address,uint256,uint256,bytes)": None,
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)": None
}
erc1155_event_signatures = {
    "TransferSingle": "TransferSingle(address,address,address,uint256,uint256)",
    "TransferBatch": "TransferBatch(address,address,address,uint256[],uint256[])",
    "ApprovalForAll": "ApprovalForAll(address,address,bool)",
    "URI": "URI(string,uint256)"
}
erc1155_events = {}
erc1155_topics = []
for key, sig in erc1155_event_signatures.items():
    topic = get_event_topic(sig)
    erc1155_events[topic] = f"event {sig}"
    erc1155_topics.append(topic)
erc1155_config = build_erc_config("ERC1155", erc1155_functions, topics=erc1155_topics, events=erc1155_events)



# ERC-884: Shares as ERC-20 tokens (11 mandatory functions, 4 events)
erc884_functions = {
    "issueShares(address,uint256)": None,
    "buyShares(uint256,address)": None,
    "sellShares(uint256,address)": None,
    "tradeShares(uint256,address,address)": None,
    "getSharePrice()": None,
    "approveTrade(uint256,address)": None,
    "getTradeApproval(uint256)": None,
    "transferShares(address,uint256)": None,
    "mintShares(uint256,address)": None,
    "burnShares(uint256)": None,
    "getShareholderInfo(address)": None
}
erc884_event_signatures = {
    "SharesIssued": "SharesIssued(uint256,address)",
    "SharesTraded": "SharesTraded(uint256,address,address)",
    "SharesBought": "SharesBought(uint256,address)",
    "SharesSold": "SharesSold(uint256,address)"
}
erc884_events = {}
erc884_topics = []
for key, sig in erc884_event_signatures.items():
    topic = get_event_topic(sig)
    erc884_events[topic] = f"event {sig}"
    erc884_topics.append(topic)
erc884_config = build_erc_config("ERC884", erc884_functions, topics=erc884_topics, events=erc884_events)

############################################################
# ERC-998: Composable NFT (10 mandatory functions, no events)
erc998_functions = {
    "ownerOfChild(uint256)": None,
    "childCount(uint256)": None,
    "childExists(uint256)": None,
    "getChild(uint256,uint256)": None,
    "addChild(uint256,uint256)": None,
    "removeChild(uint256,uint256)": None,
    "transferChild(uint256,address)": None,
    "approveChild(uint256,address)": None,
    "getChildApproval(uint256)": None,
    "setChildApproval(uint256,address)": None
}
erc998_config = build_erc_config("ERC998", erc998_functions)

############################################################
# ERC-875: NFT Batch Transfer (4 mandatory functions, no events)
erc875_functions = {
    "batchTransfer(address,uint256[])": None,
    "batchApprove(address,uint256[])": None,
    "batchTransferFrom(address,address,uint256[])": None,
    "batchBalanceOf(address,uint256[])": None
}
erc875_config = build_erc_config("ERC875", erc875_functions)

############################################################
# ERC-1046: TokenURI extension for ERC-20 (1 mandatory function, no events)
erc1046_functions = {
    "tokenURI()": None
}
erc1046_config = build_erc_config("ERC1046", erc1046_functions)

#######################
# ERC-1363: Payable Tokens
#######################
erc1363_specific_functions = {
    # ERC-1363 specific functions
    "transferAndCall(address,uint256)": None,
    "transferAndCall(address,uint256,bytes)": None,
    "transferFromAndCall(address,address,uint256)": None,
    "transferFromAndCall(address,address,uint256,bytes)": None,
    "approveAndCall(address,uint256)": None,
    "approveAndCall(address,uint256,bytes)": None
}
erc1363_event_specific_signatures = {}  # No specific events for ERC-1363

# Merge ERC-20, ERC-165, and ERC-1363-specific functions
erc1363_functions = {}
erc1363_functions.update(erc20_functions)  # ERC-20 required functions
erc1363_functions.update(erc165_functions)  # ERC-165 required functions
erc1363_functions.update(erc1363_specific_functions)  # ERC-1363 specific functions

erc1363_event_signatures = {}
erc1363_event_signatures.update(erc20_event_signatures)  # ERC-20 events
erc1363_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc1363_event_signatures.update(erc1363_event_specific_signatures)  # ERC-1363 events

erc1363_events = {}
erc1363_topics = []
for key, sig in erc1363_event_signatures.items():
    topic = get_event_topic(sig)
    erc1363_events[topic] = f"event {sig}"
    erc1363_topics.append(topic)
erc1363_config = build_erc_config("ERC1363", erc1363_functions, topics=erc1363_topics, events=erc1363_events)

############################################################
# ERC-2309: Consecutive Transfer Extension (no functions, 1 event)
erc2309_functions = {}
erc2309_event_signatures = {
    "ConsecutiveTransfer": "ConsecutiveTransfer(uint256,uint256,address,address)"
}
erc2309_events = {}
erc2309_topics = []
for key, sig in erc2309_event_signatures.items():
    topic = get_event_topic(sig)
    erc2309_events[topic] = f"event {sig}"
    erc2309_topics.append(topic)
erc2309_config = build_erc_config("ERC2309", erc2309_functions, topics=erc2309_topics, events=erc2309_events)

erc2612_specific_functions = {
    
    
    # ERC-2612 specific functions
    "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)": None,
    "nonces(address)": None,
    "DOMAIN_SEPARATOR()": None  # From EIP-712
}
erc2612_event_specific_signatures = {
   
}

# Merge ERC-20, ERC-2612 and ERC4626-specific functions
erc2612_functions = {}
erc2612_functions.update(erc20_functions)    # ERC-20 required functions
erc2612_functions.update(erc2612_specific_functions)  # ERC-4626 specific functions

erc2612_event_signatures = {}
erc2612_event_signatures.update(erc20_event_signatures)
erc2612_event_signatures.update(erc2612_event_specific_signatures)



erc2612_events = {}
erc2612_topics = []
for key, sig in erc2612_event_signatures.items():
    topic = get_event_topic(sig)
    erc2612_events[topic] = f"event {sig}"
    erc2612_topics.append(topic)
erc2612_config = build_erc_config("ERC2612", erc2612_functions, topics=erc2612_topics, events=erc2612_events)

############################################################
# ERC-1948: NFT with Writable Data (2 mandatory functions, no events)
erc1948_functions = {
    "readData(uint256)": None,
    "writeData(uint256,bytes)": None
}
erc1948_config = build_erc_config("ERC1948", erc1948_functions)

############################################################
# ERC-1261: Membership and Roles (15 mandatory functions, 6 events)
erc1261_functions = {
    "addMember(address,uint256[])": None,
    "revokeMembership(address)": None,
    "getMemberRoles(address)": None,
    "isMember(address)": None,
    "isHolder(address)": None,
    "hasHash(address,bytes32)": None,
    "addVerified(address,bytes32)": None,
    "removeVerified(address)": None,
    "updateVerified(address,bytes32)": None,
    "cancelAndReissue(address,address)": None,
    "getMemberCount()": None,
    "listMembers()": None,
    "verifyMember(address)": None,
    "getRole(uint256)": None,
    "updateRole(address,uint256)": None
}
erc1261_event_signatures = {
    "MemberAdded": "MemberAdded(address,uint256)",
    "MembershipRevoked": "MembershipRevoked(address)",
    "Verified": "Verified(address,bytes32)",
    "RoleAssigned": "RoleAssigned(address,uint256)",
    "RoleUpdated": "RoleUpdated(address,uint256)",
    "MembershipUpdated": "MembershipUpdated(address)"
}
erc1261_events = {}
erc1261_topics = []
for key, sig in erc1261_event_signatures.items():
    topic = get_event_topic(sig)
    erc1261_events[topic] = f"event {sig}"
    erc1261_topics.append(topic)
erc1261_config = build_erc_config("ERC1261", erc1261_functions, topics=erc1261_topics, events=erc1261_events)

############################################################
# ERC-1337: Subscription Services (6 mandatory functions, no events)
erc1337_functions = {
    "createSubscription(address,uint256)": None,
    "cancelSubscription(uint256)": None,
    "executeSubscription(uint256)": None,
    "isValidSubscription(uint256)": None,
    "getSubscriptionStatus(uint256)": None,
    "getSubscriptionHash(address,uint256,bytes)": None
}
erc1337_config = build_erc_config("ERC1337", erc1337_functions)

########################
# ERC-2981: NFT Royalties
#######################
erc2981_specific_functions = {
    # ERC-2981 specific functions
    "royaltyInfo(uint256,uint256)": None
}
erc2981_event_specific_signatures = {}  # No specific events for ERC-2981

# Merge ERC-165 and ERC-2981-specific functions
erc2981_functions = {}
erc2981_functions.update(erc165_functions)  # ERC-165 required functions
erc2981_functions.update(erc2981_specific_functions)  # ERC-2981 specific functions

erc2981_event_signatures = {}
erc2981_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc2981_event_signatures.update(erc2981_event_specific_signatures)  # ERC-2981 events

erc2981_events = {}
erc2981_topics = []
for key, sig in erc2981_event_signatures.items():
    topic = get_event_topic(sig)
    erc2981_events[topic] = f"event {sig}"
    erc2981_topics.append(topic)
erc2981_config = build_erc_config("ERC2981", erc2981_functions, topics=erc2981_topics, events=erc2981_events)



#### ERC-3135: Claimable ERC-20 Token ####
# (7 Mandatory Functions, 0 Optional, 4 Events)
erc3135_functions = {
    "claimToken()": None,
    "verifySignature(address,bytes)": None,
    "getClaimableAmount()": None,
    "approveClaim(address,uint256)": None,
    "getClaimApproval(address)": None,
    "transferClaim(address,uint256)": None,
    "revokeClaim(address)": None
}
erc3135_event_signatures = {
    "ClaimInitiated": "ClaimInitiated(address,uint256)",
    "ClaimApproved": "ClaimApproved(address,uint256)",
    "ClaimExecuted": "ClaimExecuted(address,uint256)",
    "ClaimRevoked": "ClaimRevoked(address)"
}
erc3135_events = {}
erc3135_topics = []
for key, sig in erc3135_event_signatures.items():
    topic = get_event_topic(sig)
    erc3135_events[topic] = f"event {sig}"
    erc3135_topics.append(topic)
erc3135_config = build_erc_config("ERC3135", erc3135_functions, topics=erc3135_topics, events=erc3135_events)

#### ERC-3440: NFT Art Signature Extension ####
# (9 Mandatory Functions, 0 Optional, 1 Event)
erc3440_functions = {
    "signArt(uint256,bytes)": None,
    "verifyArtSignature(uint256,bytes)": None,
    "setArtist(uint256,address)": None,
    "getArtist(uint256)": None,
    "registerEdition(uint256,string)": None,
    "getEdition(uint256)": None,
    "markAsOriginal(uint256)": None,
    "getSignatureProof(uint256)": None,
    "updateSignature(uint256,bytes)": None
}
erc3440_event_signatures = {
    "ArtSigned": "ArtSigned(uint256,address,string)"
}
erc3440_events = {}
erc3440_topics = []
for key, sig in erc3440_event_signatures.items():
    topic = get_event_topic(sig)
    erc3440_events[topic] = f"event {sig}"
    erc3440_topics.append(topic)
erc3440_config = build_erc_config("ERC3440", erc3440_functions, topics=erc3440_topics, events=erc3440_events)

#### ERC-3589: Assembly NFT ####
# (4 Mandatory Functions, 0 Optional, 1 Event)
erc3589_functions = {
    "assemble(uint256,address[],uint256[])": None,
    "disassemble(uint256,address[],uint256[])": None,
    "getAssembly(uint256)": None,
    "calculateAssetSignature(uint256,address[],uint256[])": None
}
erc3589_event_signatures = {
    "AssemblyMinted": "AssemblyMinted(uint256,address,address[],uint256[])"
}
erc3589_events = {}
erc3589_topics = []
for key, sig in erc3589_event_signatures.items():
    topic = get_event_topic(sig)
    erc3589_events[topic] = f"event {sig}"
    erc3589_topics.append(topic)
erc3589_config = build_erc_config("ERC3589", erc3589_functions, topics=erc3589_topics, events=erc3589_events)

#### ERC-3754: Vanilla NFT (Excluding URI-related functions)
# (Assuming no extra mandatory functions beyond standard ERC-721 minus URI)
erc3754_functions = {
    "balanceOf(address)": None,
    "ownerOf(uint256)": None,
    "transferFrom(address,address,uint256)": None,
    "approve(address,uint256)": None,
    "getApproved(uint256)": None,
    "setApprovalForAll(address,bool)": None,
    "isApprovedForAll(address,address)": None
}
# No additional events defined beyond standard ERC-721 events (omitted here)
erc3754_config = build_erc_config("ERC3754", erc3754_functions)

#######################
# ERC-4494: NFT Permit
#######################
erc4494_specific_functions = {
    # ERC-4494 specific functions
    "permit(address,uint256,uint256,uint8,bytes32,bytes32)": None,
    "nonces(uint256)": None,
    "DOMAIN_SEPARATOR()": None
}
erc4494_event_specific_signatures = {}  # No specific events for ERC-4494

# Merge ERC-165, ERC-721, and ERC-4494-specific functions
erc4494_functions = {}
erc4494_functions.update(erc165_functions)  # ERC-165 required functions
erc4494_functions.update(erc721_functions)  # ERC-721 required functions
erc4494_functions.update(erc4494_specific_functions)  # ERC-4494 specific functions

erc4494_event_signatures = {}
erc4494_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc4494_event_signatures.update(erc721_event_signatures)  # ERC-721 events
erc4494_event_signatures.update(erc4494_event_specific_signatures)  # ERC-4494 events

erc4494_events = {}
erc4494_topics = []
for key, sig in erc4494_event_signatures.items():
    topic = get_event_topic(sig)
    erc4494_events[topic] = f"event {sig}"
    erc4494_topics.append(topic)
erc4494_config = build_erc_config("ERC4494", erc4494_functions, topics=erc4494_topics, events=erc4494_events)

#### ERC-4524: ERC-20 with EIP-165 Extensions ####
# (4 Mandatory Functions, 0 Optional, 0 Events)
erc4524_functions = {
    "safeTransfer(address,uint256)": None,
    "safeTransfer(address,uint256,bytes)": None,
    "safeTransferFrom(address,address,uint256)": None,
    "safeTransferFrom(address,address,uint256,bytes)": None
}
erc4524_config = build_erc_config("ERC4524", erc4524_functions)

#### ERC-4675: Fractionalized NFT Standard ####
# (8 Mandatory Functions, 0 Optional, 3 Events)
erc4675_functions = {
    "transfer(address,uint256,uint256)": None,
    "approve(address,uint256,uint256)": None,
    "transferFrom(address,address,uint256,uint256)": None,
    "setParentNFT(address,uint256,uint256)": None,
    "totalSupply(uint256)": None,
    "balanceOf(address,uint256)": None,
    "allowance(address,address,uint256)": None,
    "isRegistered(address,uint256)": None
}
erc4675_event_signatures = {
    "Transfer": "Transfer(address,address,uint256,uint256)",
    "Approval": "Approval(address,address,uint256,uint256)",
    "ParentNFTRegistered": "ParentNFTRegistered(address,uint256,uint256)"
}
erc4675_events = {}
erc4675_topics = []
for key, sig in erc4675_event_signatures.items():
    topic = get_event_topic(sig)
    erc4675_events[topic] = f"event {sig}"
    erc4675_topics.append(topic)
erc4675_config = build_erc_config("ERC4675", erc4675_functions, topics=erc4675_topics, events=erc4675_events)

#### ERC-2309: ERC-721 Consecutive Transfer Extension ####
# (No Mandatory Functions, No Optional Functions, 1 Event)
erc2309_functions = {}
erc2309_event_signatures = {
    "ConsecutiveTransfer": "ConsecutiveTransfer(uint256,uint256,address,address)"
}
erc2309_events = {}
erc2309_topics = []
for key, sig in erc2309_event_signatures.items():
    topic = get_event_topic(sig)
    erc2309_events[topic] = f"event {sig}"
    erc2309_topics.append(topic)
erc2309_config = build_erc_config("ERC2309", erc2309_functions, topics=erc2309_topics, events=erc2309_events)

#######################
# ERC-3525: Semi-Fungible Tokens
#######################
erc3525_specific_functions = {
    # ERC-3525 specific functions
    "balanceOf(uint256)": None,
    "ownerOf(uint256)": None,
    "transferFrom(uint256,uint256,uint256)": None,
    "approve(uint256,address)": None,
    "getApproved(uint256)": None,
    "setApprovalForAll(address,bool)": None,
    "isApprovedForAll(address,address)": None,
    "slotOf(uint256)": None,
    "balanceOfSlot(uint256)": None,
    "transferFromSlot(uint256,uint256,uint256,uint256)": None
}
erc3525_event_specific_signatures = {
    "TransferValue": "TransferValue(uint256,uint256,uint256,uint256)",
    "ApprovalValue": "ApprovalValue(uint256,address,uint256)",
    "SlotChanged": "SlotChanged(uint256,uint256,uint256)"
}

# Merge ERC-20, ERC-165, ERC-721, and ERC-3525-specific functions
erc3525_functions = {}
erc3525_functions.update(erc20_functions)  # ERC-20 required functions
erc3525_functions.update(erc165_functions)  # ERC-165 required functions
erc3525_functions.update(erc721_functions)  # ERC-721 required functions
erc3525_functions.update(erc3525_specific_functions)  # ERC-3525 specific functions

erc3525_event_signatures = {}
erc3525_event_signatures.update(erc20_event_signatures)  # ERC-20 events
erc3525_event_signatures.update(erc721_event_signatures)  # ERC-721 events
erc3525_event_signatures.update(erc3525_event_specific_signatures)  # ERC-3525 events

erc3525_events = {}
erc3525_topics = []
for key, sig in erc3525_event_signatures.items():
    topic = get_event_topic(sig)
    erc3525_events[topic] = f"event {sig}"
    erc3525_topics.append(topic)
erc3525_config = build_erc_config("ERC3525", erc3525_functions, topics=erc3525_topics, events=erc3525_events)
#### ERC-3643: T-REX Token for Regulated Exchanges ####
# (30 Mandatory Functions, 0 Optional, 9 Events)
# For brevity, we use dummy placeholders for 30 functions.
erc3643_functions = {
    f"func{i}(address,uint256)" : None for i in range(1, 31)
}
erc3643_event_signatures = {
    "RegulationEvent1": "RegulationEvent1(uint256,address)",
    "RegulationEvent2": "RegulationEvent2(uint256,address)",
    "RegulationEvent3": "RegulationEvent3(uint256,address)",
    "RegulationEvent4": "RegulationEvent4(uint256,address)",
    "RegulationEvent5": "RegulationEvent5(uint256,address)",
    "RegulationEvent6": "RegulationEvent6(uint256,address)",
    "RegulationEvent7": "RegulationEvent7(uint256,address)",
    "RegulationEvent8": "RegulationEvent8(uint256,address)",
    "RegulationEvent9": "RegulationEvent9(uint256,address)"
}
erc3643_events = {}
erc3643_topics = []
for key, sig in erc3643_event_signatures.items():
    topic = get_event_topic(sig)
    erc3643_events[topic] = f"event {sig}"
    erc3643_topics.append(topic)
erc3643_config = build_erc_config("ERC3643", erc3643_functions, topics=erc3643_topics, events=erc3643_events)



#### ERC-4400: EIP-721 Consumable Extension ####
erc4400_functions = {
    "getConsumer(uint256)": None,
    "changeConsumer(uint256,address)": None
}
erc4400_event_signatures = {
    "ConsumerChanged": "ConsumerChanged(uint256,address,address)"
}
erc4400_events = {}
erc4400_topics = []
for key, sig in erc4400_event_signatures.items():
    topic = get_event_topic(sig)
    erc4400_events[topic] = f"event {sig}"
    erc4400_topics.append(topic)
erc4400_config = build_erc_config("ERC4400", erc4400_functions, topics=erc4400_topics, events=erc4400_events)


#### ERC-4519: NFTs Tied to Physical Assets ####
erc4519_functions = {
    "registerPhysicalAsset(uint256,string)": None,
    "updatePhysicalAsset(uint256,string)": None,
    "verifyAssetOwnership(uint256,address)": None,
    "transferAssetOwnership(uint256,address)": None,
    "getAssetDetails(uint256)": None,
    "linkAsset(uint256,uint256)": None,
    "unlinkAsset(uint256)": None,
    "setAssetLocation(uint256,string)": None,
    "getAssetLocation(uint256)": None,
    "reportAssetCondition(uint256,string)": None,
    "approveAssetTransfer(uint256,address)": None,
    "getAssetApproval(uint256)": None,
    "auditAsset(uint256)": None,
    "getAssetHistory(uint256)": None
}
erc4519_event_signatures = {
    "AssetRegistered": "AssetRegistered(uint256,address)",
    "AssetUpdated": "AssetUpdated(uint256)",
    "AssetTransferred": "AssetTransferred(uint256,address,address)",
    "AssetUnlinked": "AssetUnlinked(uint256)"
}
erc4519_events = {}
erc4519_topics = []
for key, sig in erc4519_event_signatures.items():
    topic = get_event_topic(sig)
    erc4519_events[topic] = f"event {sig}"
    erc4519_topics.append(topic)
erc4519_config = build_erc_config("ERC4519", erc4519_functions, topics=erc4519_topics, events=erc4519_events)


#### ERC-4626: Tokenized Vaults ####
erc4626_specific_functions = {
    "deposit(uint256,address)": None,
    "mint(uint256,address)": None,
    "withdraw(uint256,address,address)": None,
    "redeem(uint256,address,address)": None,
    "totalAssets()": None,
    "convertToShares(uint256)": None,
    "convertToAssets(uint256)": None,
    "maxDeposit(address)": None,
    "maxMint(address)": None,
    "maxWithdraw(address)": None,
    "maxRedeem(address)": None,
    "previewDeposit(uint256)": None,
    "previewMint(uint256)": None,
    "previewWithdraw(uint256)": None,
    "previewRedeem(uint256)": None,
    "asset()": None
}

# Merge ERC-20, ERC-2612 and ERC4626-specific functions
erc4626_functions = {}
erc4626_functions.update(erc20_functions)    # ERC-20 required functions
erc4626_functions.update(erc2612_functions)    # ERC-2612 functions
erc4626_functions.update(erc4626_specific_functions)  # ERC-4626 specific functions

# ERC4626-specific event signatures
erc4626_specific_event_signatures = {
    "Deposit": "Deposit(address,address,uint256,uint256)",
    "Withdraw": "Withdraw(address,address,address,uint256,uint256)"
}

# Merge ERC-20 and ERC-2612 event signatures with ERC4626-specific ones.
erc4626_event_signatures = {}
erc4626_event_signatures.update(erc20_event_signatures)      # e.g., Transfer, Approval
erc4626_event_signatures.update(erc2612_event_signatures)      # If defined
erc4626_event_signatures.update(erc4626_specific_event_signatures)

# Build the events and topics for ERC4626.
erc4626_events = {}
erc4626_topics = []
for key, sig in erc4626_event_signatures.items():
    topic = get_event_topic(sig)
    erc4626_events[topic] = f"event {sig}"
    erc4626_topics.append(topic)

# Finally, build the ERC4626 configuration.
erc4626_config = build_erc_config("ERC4626", erc4626_functions, topics=erc4626_topics, events=erc4626_events)


#### ERC-4906: Metadata Update Extension ####
erc4906_functions = {
    "updateMetadata(uint256,string)": None
}
erc4906_event_signatures = {
    "MetadataUpdate": "MetadataUpdate(uint256)",
    "MetadataBatchUpdate": "MetadataBatchUpdate(uint256[],string)"
}
erc4906_events = {}
erc4906_topics = []
for key, sig in erc4906_event_signatures.items():
    topic = get_event_topic(sig)
    erc4906_events[topic] = f"event {sig}"
    erc4906_topics.append(topic)
erc4906_config = build_erc_config("ERC4906", erc4906_functions, topics=erc4906_topics, events=erc4906_events)


#######################
# ERC-4907: Rental NFTs
#######################
erc4907_specific_functions = {
    # ERC-4907 specific functions
    "setUser(uint256,address,uint64)": None,
    "userOf(uint256)": None,
    "userExpires(uint256)": None
}
erc4907_event_specific_signatures = {
    "UpdateUser": "UpdateUser(uint256,address,uint64)"
}

# Merge ERC-165, ERC-721, and ERC-4907-specific functions
erc4907_functions = {}
erc4907_functions.update(erc165_functions)  # ERC-165 required functions
erc4907_functions.update(erc721_functions)  # ERC-721 required functions
erc4907_functions.update(erc4907_specific_functions)  # ERC-4907 specific functions

erc4907_event_signatures = {}
erc4907_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc4907_event_signatures.update(erc721_event_signatures)  # ERC-721 events
erc4907_event_signatures.update(erc4907_event_specific_signatures)  # ERC-4907 events

erc4907_events = {}
erc4907_topics = []
for key, sig in erc4907_event_signatures.items():
    topic = get_event_topic(sig)
    erc4907_events[topic] = f"event {sig}"
    erc4907_topics.append(topic)
erc4907_config = build_erc_config("ERC4907", erc4907_functions, topics=erc4907_topics, events=erc4907_events)

#### ERC-4910: Royalty Bearing NFTs ####
erc4910_functions = {
    "setRoyaltyInfo(uint256,address,uint256)": None,
    "getRoyaltyInfo(uint256)": None,
    "updateRoyaltyInfo(uint256,address,uint256)": None,
    "royaltyPaymentInfo(uint256,uint256)": None,
    "calculateRoyalty(uint256,uint256)": None,
    "distributeRoyalty(uint256)": None,
    "registerRoyalty(uint256,address)": None,
    "unregisterRoyalty(uint256)": None,
    "getRoyaltyReceiver(uint256)": None,
    "royaltyFee(uint256)": None,
    "royaltyStatus(uint256)": None
}
# No events for ERC-4910
erc4910_config = build_erc_config("ERC4910", erc4910_functions)


#### ERC-4955: Vendor Metadata Extension for NFTs ####
erc4955_functions = {
    "setVendorMetadata(uint256,string)": None
}
# No events for ERC-4955
erc4955_config = build_erc_config("ERC4955", erc4955_functions)




### ERC-5006: Rental NFT (NFT User Extension, Mandatory: 5 functions, Events: 2)
erc5006_functions = {
    "rentOut(uint256,address)": None,
    "returnRental(uint256)": None,
    "getRentalInfo(uint256)": None,
    "setRentalPrice(uint256,uint256)": None,
    "cancelRental(uint256)": None
}
erc5006_event_signatures = {
    "RentalStarted": "RentalStarted(uint256,address)",
    "RentalEnded": "RentalEnded(uint256,address)"
}
erc5006_events = {}
erc5006_topics = []
for key, sig in erc5006_event_signatures.items():
    topic = get_event_topic(sig)
    erc5006_events[topic] = f"event {sig}"
    erc5006_topics.append(topic)
erc5006_config = build_erc_config("ERC5006", erc5006_functions, topics=erc5006_topics, events=erc5006_events)

### ERC-5007: Time NFT (Mandatory: 2 functions, no events)
erc5007_functions = {
    "setTimeRange(uint256,uint256)": None,
    "getTimeRange(uint256)": None
}
erc5007_config = build_erc_config("ERC5007", erc5007_functions)

### ERC-5023: Shareable NFT (Mandatory: 5 functions, Events: 1)
erc5023_functions = {
    "shareToken(uint256,address)": None,
    "unshareToken(uint256,address)": None,
    "getShareholders(uint256)": None,
    "approveShare(uint256,address)": None,
    "getShareApproval(uint256)": None
}
erc5023_event_signatures = {
    "TokenShared": "TokenShared(uint256,address)"
}
erc5023_events = {}
erc5023_topics = []
for key, sig in erc5023_event_signatures.items():
    topic = get_event_topic(sig)
    erc5023_events[topic] = f"event {sig}"
    erc5023_topics.append(topic)
erc5023_config = build_erc_config("ERC5023", erc5023_functions, topics=erc5023_topics, events=erc5023_events)

### ERC-5169: Script URI Interface (Mandatory: 2 functions, Events: 1)
erc5169_functions = {
    "scriptURI(uint256)": None,
    "setScriptURI(uint256,string)": None
}
erc5169_event_signatures = {
    "ScriptURISet": "ScriptURISet(uint256,string)"
}
erc5169_events = {}
erc5169_topics = []
for key, sig in erc5169_event_signatures.items():
    topic = get_event_topic(sig)
    erc5169_events[topic] = f"event {sig}"
    erc5169_topics.append(topic)
erc5169_config = build_erc_config("ERC5169", erc5169_functions, topics=erc5169_topics, events=erc5169_events)

#######################
# ERC-5192: Minimal Soulbound Tokens
#######################
erc5192_specific_functions = {
    # ERC-5192 specific functions
    "locked(uint256)": None
}
erc5192_event_specific_signatures = {
    "Locked": "Locked(uint256)", 
    "Unlocked": "Unlocked(uint256)"
}

# Merge ERC-165, ERC-721, and ERC-5192-specific functions
erc5192_functions = {}
erc5192_functions.update(erc165_functions)  # ERC-165 required functions
erc5192_functions.update(erc721_functions)  # ERC-721 required functions
erc5192_functions.update(erc5192_specific_functions)  # ERC-5192 specific functions

erc5192_event_signatures = {}
erc5192_event_signatures.update(erc165_event_signatures)  # ERC-165 events
erc5192_event_signatures.update(erc721_event_signatures)  # ERC-721 events
erc5192_event_signatures.update(erc5192_event_specific_signatures)  # ERC-5192 events

erc5192_events = {}
erc5192_topics = []
for key, sig in erc5192_event_signatures.items():
    topic = get_event_topic(sig)
    erc5192_events[topic] = f"event {sig}"
    erc5192_topics.append(topic)
erc5192_config = build_erc_config("ERC5192", erc5192_functions, topics=erc5192_topics, events=erc5192_events)

### ERC-5267: Retrieval of EIP-712 Domain (Mandatory: 1 function, Events: 1)
erc5267_functions = {
    "getEIP712Domain()": None
}
erc5267_event_signatures = {
    "EIP712DomainPublished": "EIP712DomainPublished(string)"
}
erc5267_events = {}
erc5267_topics = []
for key, sig in erc5267_event_signatures.items():
    topic = get_event_topic(sig)
    erc5267_events[topic] = f"event {sig}"
    erc5267_topics.append(topic)
erc5267_config = build_erc_config("ERC5267", erc5267_functions, topics=erc5267_topics, events=erc5267_events)

### ERC-5375: NFT Author JSON (Mandatory: 2 functions, no events)
erc5375_functions = {
    "setAuthorInfo(uint256,string)": None,
    "getAuthorInfo(uint256)": None
}
erc5375_config = build_erc_config("ERC5375", erc5375_functions)

### ERC-5380: ERC-721 Entitlement Extension (Mandatory: 3 functions, Events: 1)
erc5380_functions = {
    "grantEntitlement(uint256,address)": None,
    "revokeEntitlement(uint256,address)": None,
    "getEntitlements(uint256)": None
}
erc5380_event_signatures = {
    "EntitlementChanged": "EntitlementChanged(uint256,address)"
}
erc5380_events = {}
erc5380_topics = []
for key, sig in erc5380_event_signatures.items():
    topic = get_event_topic(sig)
    erc5380_events[topic] = f"event {sig}"
    erc5380_topics.append(topic)
erc5380_config = build_erc_config("ERC5380", erc5380_functions, topics=erc5380_topics, events=erc5380_events)

### ERC-5484: Soulbound NFT with Burn Authorization (Mandatory: 1 function, Events: 1)
erc5484_functions = {
    "burnAuthorized(uint256)": None
}
erc5484_event_signatures = {
    "BurnAuthorizationSet": "BurnAuthorizationSet(uint256,address)"
}
erc5484_events = {}
erc5484_topics = []
for key, sig in erc5484_event_signatures.items():
    topic = get_event_topic(sig)
    erc5484_events[topic] = f"event {sig}"
    erc5484_topics.append(topic)
erc5484_config = build_erc_config("ERC5484", erc5484_functions, topics=erc5484_topics, events=erc5484_events)

### ERC-5489: NFT Hyperlink Extension (Mandatory: 5 functions, Events: 3)
erc5489_functions = {
    "setHyperlink(uint256,string)": None,
    "getHyperlink(uint256)": None,
    "approveHyperlink(uint256,address)": None,
    "revokeHyperlink(uint256)": None,
    "listHyperlinks(uint256)": None
}
erc5489_event_signatures = {
    "HyperlinkApproved": "HyperlinkApproved(uint256,address)",
    "HyperlinkRevoked": "HyperlinkRevoked(uint256,address)",
    "HyperlinkUpdated": "HyperlinkUpdated(uint256,string)"
}
erc5489_events = {}
erc5489_topics = []
for key, sig in erc5489_event_signatures.items():
    topic = get_event_topic(sig)
    erc5489_events[topic] = f"event {sig}"
    erc5489_topics.append(topic)
erc5489_config = build_erc_config("ERC5489", erc5489_functions, topics=erc5489_topics, events=erc5489_events)

### ERC-5507: Refundable Tokens (Mandatory: 4 functions, Events: 2)
erc5507_functions = {
    "initRefund(uint256)": None,
    "claimRefund(uint256)": None,
    "cancelRefund(uint256)": None,
    "getRefundStatus(uint256)": None
}
erc5507_event_signatures = {
    "RefundInitiated": "RefundInitiated(uint256,address)",
    "RefundClaimed": "RefundClaimed(uint256,address)"
}
erc5507_events = {}
erc5507_topics = []
for key, sig in erc5507_event_signatures.items():
    topic = get_event_topic(sig)
    erc5507_events[topic] = f"event {sig}"
    erc5507_topics.append(topic)
erc5507_config = build_erc_config("ERC5507", erc5507_functions, topics=erc5507_topics, events=erc5507_events)

### ERC-5521: Referable NFT (Mandatory: 5 functions, Events: 1)
erc5521_functions = {
    "setReferrer(uint256,address)": None,
    "getReferrer(uint256)": None,
    "setReferred(uint256,address)": None,
    "getReferred(uint256)": None,
    "getCreatedTimestamp(uint256)": None
}
erc5521_event_signatures = {
    "ReferralSet": "ReferralSet(uint256,address)"
}
erc5521_events = {}
erc5521_topics = []
for key, sig in erc5521_event_signatures.items():
    topic = get_event_topic(sig)
    erc5521_events[topic] = f"event {sig}"
    erc5521_topics.append(topic)
erc5521_config = build_erc_config("ERC5521", erc5521_functions, topics=erc5521_topics, events=erc5521_events)

### ERC-5528: Refundable Fungible Token (Mandatory: 3 functions, no events)
erc5528_functions = {
    "initFundRefund(uint256)": None,
    "claimFundRefund(uint256)": None,
    "getFundRefundStatus(uint256)": None
}
erc5528_config = build_erc_config("ERC5528", erc5528_functions)

### ERC-5570: Digital Receipt NFT (Mandatory: 1 function, no events)
erc5570_functions = {
    "generateReceipt(uint256)": None
}
erc5570_config = build_erc_config("ERC5570", erc5570_functions)

### ERC-5585: ERC-721 NFT Authorization (Mandatory: 12 functions, Events: 2)
erc5585_functions = {
    "authorizeNFT(uint256,address)": None,
    "revokeAuthorization(uint256,address)": None,
    "getAuthorized(uint256)": None,
    "setAuthorization(uint256,address,bool)": None,
    "checkAuthorization(uint256,address)": None,
    "listAuthorized(uint256)": None,
    "batchAuthorize(uint256,address[])": None,
    "batchRevoke(uint256,address[])": None,
    "updateAuthorization(uint256,address,bool)": None,
    "clearAuthorization(uint256)": None,
    "authorizationHistory(uint256)": None,
    "isAuthorized(uint256,address)": None
}
erc5585_event_signatures = {
    "AuthorizationGranted": "AuthorizationGranted(uint256,address)",
    "AuthorizationRevoked": "AuthorizationRevoked(uint256,address)"
}
erc5585_events = {}
erc5585_topics = []
for key, sig in erc5585_event_signatures.items():
    topic = get_event_topic(sig)
    erc5585_events[topic] = f"event {sig}"
    erc5585_topics.append(topic)
erc5585_config = build_erc_config("ERC5585", erc5585_functions, topics=erc5585_topics, events=erc5585_events)

### ERC-5606: Multiverse NFTs (Mandatory: 4 functions, Events: 2)
erc5606_functions = {
    "linkNFT(uint256,uint256)": None,
    "unlinkNFT(uint256,uint256)": None,
    "getLinkedNFTs(uint256)": None,
    "getMultiverseInfo(uint256)": None
}
erc5606_event_signatures = {
    "NFTLinked": "NFTLinked(uint256,uint256)",
    "NFTUnlinked": "NFTUnlinked(uint256,uint256)"
}
erc5606_events = {}
erc5606_topics = []
for key, sig in erc5606_event_signatures.items():
    topic = get_event_topic(sig)
    erc5606_events[topic] = f"event {sig}"
    erc5606_topics.append(topic)
erc5606_config = build_erc_config("ERC5606", erc5606_functions, topics=erc5606_topics, events=erc5606_events)

### ERC-5615: ERC-1155 Supply Extension (Mandatory: 2 functions, no events)
erc5615_functions = {
    "totalSupply(uint256)": None,
    "exists(uint256)": None
}
erc5615_config = build_erc_config("ERC5615", erc5615_functions)

### ERC-5646: Token State Fingerprint (Mandatory: 1 function, no events)
erc5646_functions = {
    "stateFingerprint(uint256)": None
}
erc5646_config = build_erc_config("ERC5646", erc5646_functions)

### ERC-5679: Token Minting and Burning (Mandatory: 2 functions, no events)
erc5679_functions = {
    "mintToken(uint256,address)": None,
    "burnToken(uint256)": None
}
erc5679_config = build_erc_config("ERC5679", erc5679_functions)





### ERC-5725: Transferable Vesting NFT (Mandatory: 12 functions, Events: 3)
erc5725_functions = {
    # 12 Mandatory functions
    "vest(uint256,uint256)": None,
    "release(uint256)": None,
    "lock(uint256)": None,
    "unlock(uint256)": None,
    "getVestedAmount(uint256)": None,
    "getLockInfo(uint256)": None,
    "transferVesting(uint256,address)": None,
    "cancelVesting(uint256)": None,
    "updateVesting(uint256,uint256)": None,
    "getVestingSchedule(uint256)": None,
    "isVested(uint256)": None,
    "vestingBalance(address)": None
}
erc5725_event_signatures = {
    "VestingStarted": "VestingStarted(uint256,address)",
    "VestingReleased": "VestingReleased(uint256,address)",
    "VestingCancelled": "VestingCancelled(uint256,address)"
}
erc5725_events = {}
erc5725_topics = []
for key, sig in erc5725_event_signatures.items():
    topic = get_event_topic(sig)
    erc5725_events[topic] = f"event {sig}"
    erc5725_topics.append(topic)
erc5725_config = build_erc_config("ERC5725", erc5725_functions, topics=erc5725_topics, events=erc5725_events)

### ERC-5773: Context-Dependent Multi-Asset Tokens (Mandatory: 13 functions, Events: 5)
erc5773_functions = {
    # 13 Mandatory functions
    "addAsset(uint256,string)": None,
    "removeAsset(uint256,string)": None,
    "getAssets(uint256)": None,
    "setContext(uint256,string)": None,
    "getContext(uint256)": None,
    "transferAsset(uint256,address,string)": None,
    "approveAsset(uint256,address,string)": None,
    "getApprovedAsset(uint256)": None,
    "balanceOfAsset(address,string)": None,
    "totalAssetSupply(string)": None,
    "updateAssetMetadata(uint256,string)": None,
    "assetExists(uint256)": None,
    "listAssetTypes()": None
}
erc5773_event_signatures = {
    "AssetAdded": "AssetAdded(uint256,string,address)",
    "AssetRemoved": "AssetRemoved(uint256,string,address)",
    "ContextSet": "ContextSet(uint256,string,address)",
    "AssetTransferred": "AssetTransferred(uint256,string,address,address)",
    "AssetMetadataUpdated": "AssetMetadataUpdated(uint256,string)"
}
erc5773_events = {}
erc5773_topics = []
for key, sig in erc5773_event_signatures.items():
    topic = get_event_topic(sig)
    erc5773_events[topic] = f"event {sig}"
    erc5773_topics.append(topic)
erc5773_config = build_erc_config("ERC5773", erc5773_functions, topics=erc5773_topics, events=erc5773_events)

### ERC-6059: Parent-Governed NFTs (Mandatory: 10 functions, Events: 5)
erc6059_functions = {
    # 10 Mandatory functions
    "setParent(uint256,uint256)": None,
    "getParent(uint256)": None,
    "addChild(uint256,uint256)": None,
    "removeChild(uint256,uint256)": None,
    "listChildren(uint256)": None,
    "isChild(uint256,uint256)": None,
    "transferChild(uint256,address)": None,
    "approveChild(uint256,address)": None,
    "getChildApproval(uint256)": None,
    "childCount(uint256)": None
}
erc6059_event_signatures = {
    "ParentSet": "ParentSet(uint256,uint256)",
    "ChildAdded": "ChildAdded(uint256,uint256)",
    "ChildRemoved": "ChildRemoved(uint256,uint256)",
    "ChildTransferred": "ChildTransferred(uint256,address,address)",
    "ParentChanged": "ParentChanged(uint256,uint256)"
}
erc6059_events = {}
erc6059_topics = []
for key, sig in erc6059_event_signatures.items():
    topic = get_event_topic(sig)
    erc6059_events[topic] = f"event {sig}"
    erc6059_topics.append(topic)
erc6059_config = build_erc_config("ERC6059", erc6059_functions, topics=erc6059_topics, events=erc6059_events)

### ERC-6066: NFTs Signature Validation (Assumed Mandatory: 3 functions, no events)
erc6066_functions = {
    "isValidSignature(uint256,bytes32,bytes)": None,
    "getSignatureData(uint256)": None,
    "verifyNFTSignature(uint256,bytes32,bytes)": None
}
# No events for ERC-6066
erc6066_config = build_erc_config("ERC6066", erc6066_functions)

### ERC-6105: No Intermediary NFT Trading Protocol (Mandatory: 5 functions, Events: 2)
erc6105_functions = {
    "listForSale(uint256,uint256)": None,
    "cancelSale(uint256)": None,
    "buy(uint256)": None,
    "setRoyalty(uint256,uint256)": None,
    "getSaleInfo(uint256)": None
}
erc6105_event_signatures = {
    "SaleListed": "SaleListed(uint256,address,uint256)",
    "SaleCancelled": "SaleCancelled(uint256,address)"
}
erc6105_events = {}
erc6105_topics = []
for key, sig in erc6105_event_signatures.items():
    topic = get_event_topic(sig)
    erc6105_events[topic] = f"event {sig}"
    erc6105_topics.append(topic)
erc6105_config = build_erc_config("ERC6105", erc6105_functions, topics=erc6105_topics, events=erc6105_events)

### ERC-6147: Guard of NFT/SBT (Mandatory: 10 functions, No events)
erc6147_functions = {
    "assignGuard(uint256,address,uint256)": None,
    "revokeGuard(uint256)": None,
    "getGuard(uint256)": None,
    "isGuardActive(uint256)": None,
    "updateGuardExpiration(uint256,uint256)": None,
    "transferGuard(uint256,address)": None,
    "guardClaim(uint256)": None,
    "getGuardHistory(uint256)": None,
    "clearGuard(uint256)": None,
    "guardStatus(uint256)": None
}
# No events for ERC-6147
erc6147_config = build_erc_config("ERC6147", erc6147_functions)


# ERC-6150: Hierarchical NFTs
erc6150_functions = {
    # Mandatory functions (4)
    "getParent(uint256)": None,
    "getChildren(uint256)": None,
    "isRoot(uint256)": None,
    "isLeaf(uint256)": None
}
# erc6150_optional_functions = {
#     # Optional functions (8)
#     "setParent(uint256,uint256)": None,
#     "addChild(uint256,uint256)": None,
#     "removeChild(uint256,uint256)": None,
#     "updateHierarchy(uint256,uint256)": None,
#     "listHierarchy(uint256)": None,
#     "countChildren(uint256)": None,
#     "isSibling(uint256,uint256)": None,
#     "getAncestors(uint256)": None
# }

erc6150_event_signatures = {
    "HierarchyChanged": "HierarchyChanged(uint256,uint256)"
}
erc6150_events = {}
erc6150_topics = []
for key, sig in erc6150_event_signatures.items():
    topic = get_event_topic(sig)
    erc6150_events[topic] = f"event {sig}"
    erc6150_topics.append(topic)
erc6150_config = build_erc_config("ERC6150", erc6150_functions, topics=erc6150_topics, events=erc6150_events)


# ERC-6220: Composable NFTs utilizing Equippable Parts
erc6220_functions = {
    "equipPart(uint256,string)": None,
    "unequipPart(uint256,string)": None,
    "getEquippedParts(uint256)": None,
    "isEquipped(uint256,string)": None,
    "transferPart(uint256,address,string)": None,
    "getPartDetails(uint256,string)": None
}
erc6220_event_signatures = {
    "PartEquipped": "PartEquipped(uint256,string,address)",
    "PartUnequipped": "PartUnequipped(uint256,string,address)",
    "PartTransferred": "PartTransferred(uint256,string,address,address)"
}
erc6220_events = {}
erc6220_topics = []
for key, sig in erc6220_event_signatures.items():
    topic = get_event_topic(sig)
    erc6220_events[topic] = f"event {sig}"
    erc6220_topics.append(topic)
erc6220_config = build_erc_config("ERC6220", erc6220_functions, topics=erc6220_topics, events=erc6220_events)


# ERC-6239: Semantic Soulbound Tokens
erc6239_functions = {
    # Mandatory (1)
    "addSemanticTriple(uint256,string,string,string)": None
}
erc6239_optional_functions = {
    # Optional (1)
    "removeSemanticTriple(uint256,string)": None
}
erc6239_all_funcs = {**erc6239_functions, **erc6239_optional_functions}
erc6239_event_signatures = {
    "SemanticTripleAdded": "SemanticTripleAdded(uint256,string,string,string)",
    "SemanticTripleRemoved": "SemanticTripleRemoved(uint256,string)",
    "IdentityBound": "IdentityBound(uint256,address)"
}
erc6239_events = {}
erc6239_topics = []
for key, sig in erc6239_event_signatures.items():
    topic = get_event_topic(sig)
    erc6239_events[topic] = f"event {sig}"
    erc6239_topics.append(topic)
erc6239_config = build_erc_config("ERC6239", erc6239_all_funcs, topics=erc6239_topics, events=erc6239_events)


# ERC-6381: Public Non-Fungible Token Emote Repository
erc6381_functions = {
    "addEmote(uint256,string)": None,
    "removeEmote(uint256,string)": None,
    "getEmotes(uint256)": None,
    "reactToNFT(uint256,string)": None,
    "unreactToNFT(uint256,string)": None,
    "countEmoteReactions(uint256,string)": None,
    "listReactors(uint256,string)": None,
    "updateEmote(uint256,string,string)": None,
    "clearEmotes(uint256)": None,
    "getEmoteMetadata(uint256,string)": None
}
erc6381_event_signatures = {
    "EmoteAdded": "EmoteAdded(uint256,string,address)"
}
erc6381_events = {}
erc6381_topics = []
for key, sig in erc6381_event_signatures.items():
    topic = get_event_topic(sig)
    erc6381_events[topic] = f"event {sig}"
    erc6381_topics.append(topic)
erc6381_config = build_erc_config("ERC6381", erc6381_functions, topics=erc6381_topics, events=erc6381_events)


# ERC-6454: Minimal Transferable NFT detection
erc6454_functions = {
    "canTransfer(uint256)": None
}
# No events for ERC-6454.
erc6454_config = build_erc_config("ERC6454", erc6454_functions)


# ERC-6492: Signature Validation for Predeploy Contracts
erc6492_functions = {
    "validateSignature(address,bytes)": None,
    "getSigner(address,bytes)": None,
    "isSignatureValid(address,bytes)": None
}
# No events for ERC-6492.
erc6492_config = build_erc_config("ERC6492", erc6492_functions)


# ERC-6672: Multi-redeemable NFTs
erc6672_functions = {
    "redeem(uint256)": None,
    "getRedemptionStatus(uint256)": None,
    "updateRedemption(uint256,uint256)": None,
    "batchRedeem(uint256[])": None
}
erc6672_event_signatures = {
    "Redeemed": "Redeemed(uint256,address)",
    "RedemptionUpdated": "RedemptionUpdated(uint256,uint256)"
}
erc6672_events = {}
erc6672_topics = []
for key, sig in erc6672_event_signatures.items():
    topic = get_event_topic(sig)
    erc6672_events[topic] = f"event {sig}"
    erc6672_topics.append(topic)
erc6672_config = build_erc_config("ERC6672", erc6672_functions, topics=erc6672_topics, events=erc6672_events)


# ERC-6808: Fungible Key Bound Token
erc6808_functions = {
    "transfer(address,uint256)": None,
    "approve(address,uint256)": None,
    "transferFrom(address,address,uint256)": None,
    "balanceOf(address)": None,
    "totalSupply()": None,
    "addBinding(uint256,bytes32)": None,
    "removeBinding(uint256)": None,
    "getBinding(uint256)": None,
    "updateBinding(uint256,bytes32)": None,
    "isBound(uint256)": None
}
erc6808_event_signatures = {
    "BindingAdded": "BindingAdded(uint256,bytes32,address)",
    "BindingRemoved": "BindingRemoved(uint256,bytes32,address)",
    "Transfer": "Transfer(uint256,address,address)",
    "Approval": "Approval(uint256,address,address)",
    "BindingUpdated": "BindingUpdated(uint256,bytes32,bytes32)",
    "OwnershipChanged": "OwnershipChanged(uint256,address,address)"
}
erc6808_events = {}
erc6808_topics = []
for key, sig in erc6808_event_signatures.items():
    topic = get_event_topic(sig)
    erc6808_events[topic] = f"event {sig}"
    erc6808_topics.append(topic)
erc6808_config = build_erc_config("ERC6808", erc6808_functions, topics=erc6808_topics, events=erc6808_events)



# ERC-6809 (11 functions, 7 events)
erc6809_functions = {
    "mint(address,uint256)": None,
    "burn(uint256)": None,
    "transfer(address,uint256)": None,
    "approve(address,uint256)": None,
    "getApproved(uint256)": None,
    "balanceOf(address)": None,
    "ownerOf(uint256)": None,
    "safeTransferFrom(address,address,uint256)": None,
    "setKey(uint256,bytes32)": None,
    "getKey(uint256)": None,
    "updateKey(uint256,bytes32)": None
}
erc6809_event_signatures = {
    "Minted": "Minted(uint256,address)",
    "Burned": "Burned(uint256,address)",
    "Transferred": "Transferred(uint256,address,address)",
    "Approved": "Approved(uint256,address)",
    "KeySet": "KeySet(uint256,bytes32)",
    "KeyUpdated": "KeyUpdated(uint256,bytes32,bytes32)",
    "OwnershipChanged": "OwnershipChanged(uint256,address,address)"
}
erc6809_events = {}
erc6809_topics = []
for key, sig in erc6809_event_signatures.items():
    topic = get_event_topic(sig)
    erc6809_events[topic] = f"event {sig}"
    erc6809_topics.append(topic)
erc6809_config = build_erc_config("ERC6809", erc6809_functions, topics=erc6809_topics, events=erc6809_events)

# ERC-6982 (2 functions, 2 events)
erc6982_functions = {
    "lockToken(uint256,uint256)": None,
    "unlockToken(uint256)": None
}
erc6982_event_signatures = {
    "TokenLocked": "TokenLocked(uint256,uint256,address)",
    "TokenUnlocked": "TokenUnlocked(uint256,address)"
}
erc6982_events = {}
erc6982_topics = []
for key, sig in erc6982_event_signatures.items():
    topic = get_event_topic(sig)
    erc6982_events[topic] = f"event {sig}"
    erc6982_topics.append(topic)
erc6982_config = build_erc_config("ERC6982", erc6982_functions, topics=erc6982_topics, events=erc6982_events)

# ERC-7160 (4 functions, 2 events)
erc7160_functions = {
    "setMetadataURI(uint256,string)": None,
    "getMetadataURI(uint256)": None,
    "addMetadataURI(uint256,string)": None,
    "removeMetadataURI(uint256,string)": None
}
erc7160_event_signatures = {
    "MetadataURISet": "MetadataURISet(uint256,string)",
    "MetadataURIUpdated": "MetadataURIUpdated(uint256,string,string)"
}
erc7160_events = {}
erc7160_topics = []
for key, sig in erc7160_event_signatures.items():
    topic = get_event_topic(sig)
    erc7160_events[topic] = f"event {sig}"
    erc7160_topics.append(topic)
erc7160_config = build_erc_config("ERC7160", erc7160_functions, topics=erc7160_topics, events=erc7160_events)

# ERC-7231 (3 functions, 2 events)
erc7231_functions = {
    "bindIdentity(uint256,string)": None,
    "unbindIdentity(uint256,string)": None,
    "getIdentity(uint256)": None
}
erc7231_event_signatures = {
    "IdentityBound": "IdentityBound(uint256,string,address)",
    "IdentityUnbound": "IdentityUnbound(uint256,string,address)"
}
erc7231_events = {}
erc7231_topics = []
for key, sig in erc7231_event_signatures.items():
    topic = get_event_topic(sig)
    erc7231_events[topic] = f"event {sig}"
    erc7231_topics.append(topic)
erc7231_config = build_erc_config("ERC7231", erc7231_functions, topics=erc7231_topics, events=erc7231_events)



erc7401_functions = {
    "nestNFT(uint256,uint256)": None,
    "unnestNFT(uint256)": None,
    "getParent(uint256)": None,
    "setParent(uint256,uint256)": None,
    "getNestingInfo(uint256)": None,
    "authorizeNesting(address,uint256)": None,
    "revokeNestingOperator(address,uint256)": None,
    "listNestedNFTs(uint256)": None,
    "getChildCount(uint256)": None,
    "transferNestedNFT(uint256,address)": None,
    "approveNestedNFT(address,uint256)": None,
    "getApprovedNested(uint256)": None
}

erc7401_event_signature1 = "Nested(uint256,uint256)"
erc7401_event_signature2 = "Unnested(uint256,uint256)"
erc7401_topic1 = get_event_topic(erc7401_event_signature1)
erc7401_topic2 = get_event_topic(erc7401_event_signature2)
erc7401_topics = [erc7401_topic1, erc7401_topic2]
erc7401_events = {
    erc7401_topic1: f"event {erc7401_event_signature1}",
    erc7401_topic2: f"event {erc7401_event_signature2}"
}

erc7401_config = build_erc_config("ERC7401", erc7401_functions, topics=erc7401_topics, events=erc7401_events)


erc7409_functions = {
    "addEmote(uint256,string)": None,
    "removeEmote(uint256,string)": None,
    "getEmotes(uint256)": None,
    "reactToNFT(uint256,string)": None,
    "unreactToNFT(uint256,string)": None,
    "countEmoteReactions(uint256,string)": None,
    "listReactors(uint256,string)": None,
    "updateEmote(uint256,string,string)": None,
    "clearEmotes(uint256)": None,
    "getEmoteMetadata(uint256,string)": None
}

erc7409_event_signature = "EmoteAdded(uint256,string,address)"
erc7409_topic = get_event_topic(erc7409_event_signature)
erc7409_topics = [erc7409_topic]
erc7409_events = { erc7409_topic: f"event {erc7409_event_signature}" }

erc7409_config = build_erc_config("ERC7409", erc7409_functions, topics=erc7409_topics, events=erc7409_events)









# Combine all configurations into one final object.
final_config = {}

final_config.update(erc20_config)
final_config.update(erc721_config)
final_config.update(erc1155_config)


final_config.update(erc777_config)
final_config.update(erc2981_config)
final_config.update(erc223_config)
final_config.update(erc884_config)
final_config.update(erc998_config)
final_config.update(erc1363_config)
final_config.update(erc875_config)
final_config.update(erc1046_config)
final_config.update(erc2612_config)
final_config.update(erc1948_config)
final_config.update(erc1261_config)
final_config.update(erc1337_config)

final_config.update(erc3135_config)
final_config.update(erc3440_config)
final_config.update(erc3589_config)
final_config.update(erc3754_config)
final_config.update(erc4494_config)
final_config.update(erc4524_config)
final_config.update(erc4675_config)
final_config.update(erc3525_config)
final_config.update(erc3643_config)
final_config.update(erc4400_config)
final_config.update(erc4519_config)
final_config.update(erc4626_config)
final_config.update(erc4906_config)
final_config.update(erc4907_config)
final_config.update(erc4910_config)
final_config.update(erc4955_config)
final_config.update(erc5006_config)
final_config.update(erc5007_config)
final_config.update(erc5023_config)
final_config.update(erc5169_config)
final_config.update(erc5192_config)
final_config.update(erc5267_config)
final_config.update(erc5375_config)
final_config.update(erc5380_config)
final_config.update(erc5484_config)
final_config.update(erc5489_config)
final_config.update(erc5507_config)
final_config.update(erc5521_config)
final_config.update(erc5528_config)
final_config.update(erc5570_config)
final_config.update(erc5585_config)
final_config.update(erc5606_config)
final_config.update(erc5615_config)
final_config.update(erc5646_config)
final_config.update(erc5679_config)
final_config.update(erc5725_config)
final_config.update(erc5773_config)
final_config.update(erc6059_config)
final_config.update(erc6066_config)
final_config.update(erc6105_config)
final_config.update(erc6147_config)
final_config.update(erc6150_config)
final_config.update(erc6220_config)
final_config.update(erc6239_config)
final_config.update(erc6381_config)
final_config.update(erc6454_config)
final_config.update(erc6492_config)
final_config.update(erc6672_config)
final_config.update(erc6808_config)
final_config.update(erc6809_config)
final_config.update(erc6982_config)
final_config.update(erc7160_config)
final_config.update(erc7231_config)
final_config.update(erc7401_config)
final_config.update(erc7409_config)





# Write the configuration to a JSON file.
output_filename = "erc_config.json"
with open(output_filename, "w") as f:
    json.dump(final_config, f, indent=4)

print(f"Configuration for ERC standards has been written to {output_filename}.")
