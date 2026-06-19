#!/usr/bin/env python3
"""
Domain Separator Construction Analyzer

Analyze Solidity .sol files for EIP-712 DOMAIN_SEPARATOR construction risks.

Requirement-level checks, grouped by taxonomy:
  T1/R1   Missing DOMAIN_SEPARATOR/EIP712Domain in permit-enabled contract
  T1/R2   Missing EIP-191 typed-data prefix
  T2/R3   Missing chainId in EIP712Domain typehash
  T2/R4   Hardcoded / constant chainId
  T3/R5   Missing verifyingContract in EIP712Domain typehash
  T3/R6   Incorrect verifyingContract binding, address(this) absent
  T3/R7   Hardcoded verifier address
  T4/R8   Missing logical-domain discriminator in multi-domain context
  T4/R9   Hardcoded salt
  T4/R10  Zero salt
  T5/R11  Stale cached DOMAIN_SEPARATOR
  T5/R12  Proxy / upgradeable stale-domain risk

Taxonomy:
  T1  Unseparated Signing Domain
  T2  Cross-Chain Replay
  T3  Cross-Contract Replay
  T4  Logical-Domain Replay
  T5  Domain Freshness Failure

Example:
  python3 domain_separator_analyzer.py \
    --input-dir /path/to/sol/files \
    --output-json results/domain_separator_results.json \
    --output-summary results/domain_separator_summary.json \
    --max-files 200
"""

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


DOMAIN_SEPARATOR_REQUIREMENTS = {
    "R1_MISSING_DOMAIN_SEPARATOR": {
        "taxonomy": "T1_UNSEPARATED_SIGNING_DOMAIN",
        "description": "permit-enabled code should contain DOMAIN_SEPARATOR, domainSeparator, _domainSeparatorV4, or an EIP712Domain typehash.",
        "risk_if_missing": "Unseparated signing domain.",
        "severity": "High",
    },
    "R2_EIP191_PREFIX_PRESENT": {
        "taxonomy": "T1_UNSEPARATED_SIGNING_DOMAIN",
        "description": "Typed-data permit digests should use the EIP-191/EIP-712 prefix \\x19\\x01 or a helper such as toTypedDataHash().",
        "risk_if_missing": "Signature digest may not be domain-separated as EIP-712 typed data.",
        "severity": "High",
    },
    "R3_CHAIN_ID_PRESENT": {
        "taxonomy": "T2_CROSS_CHAIN_REPLAY",
        "description": "EIP712Domain typehash/construction should include uint256 chainId when signatures must be chain-bound.",
        "risk_if_missing": "Cross-chain replay risk.",
        "severity": "High",
    },
    "R4_DYNAMIC_CHAIN_ID": {
        "taxonomy": "T2_CROSS_CHAIN_REPLAY",
        "description": "DOMAIN_SEPARATOR should use block.chainid or chainid(), not a stale/hardcoded chain ID.",
        "risk_if_missing": "Fork/cross-chain replay risk.",
        "severity": "High/Medium",
    },
    "R5_VERIFYING_CONTRACT_PRESENT": {
        "taxonomy": "T3_CROSS_CONTRACT_REPLAY",
        "description": "EIP712Domain typehash/construction should include address verifyingContract.",
        "risk_if_missing": "Cross-contract replay risk.",
        "severity": "High",
    },
    "R6_CORRECT_VERIFYING_CONTRACT": {
        "taxonomy": "T3_CROSS_CONTRACT_REPLAY",
        "description": "DOMAIN_SEPARATOR should bind to address(this) unless a deliberate external verifier is used.",
        "risk_if_missing": "Wrong verifier binding or cross-contract replay risk.",
        "severity": "High",
    },
    "R7_NO_HARDCODED_VERIFIER": {
        "taxonomy": "T3_CROSS_CONTRACT_REPLAY",
        "description": "verifyingContract should not be a hardcoded address unless explicitly justified.",
        "risk_if_missing": "Cross-contract replay or wrong-verifier binding.",
        "severity": "High/Medium",
    },
    "R8_LOGICAL_DOMAIN_DISAMBIGUATION": {
        "taxonomy": "T4_LOGICAL_DOMAIN_REPLAY",
        "description": "If one verifier handles multiple logical domains, the domain or signed struct should include salt/poolId/marketId/vaultId/accountId or equivalent.",
        "risk_if_missing": "Cross-pool/cross-subdomain replay risk.",
        "severity": "Medium",
    },
    "R9_NO_HARDCODED_SALT": {
        "taxonomy": "T4_LOGICAL_DOMAIN_REPLAY",
        "description": "Salt should be meaningful and unique per logical signing domain.",
        "risk_if_missing": "False sense of domain uniqueness or duplicated logical domains.",
        "severity": "Medium",
    },
    "R10_NO_ZERO_SALT": {
        "taxonomy": "T4_LOGICAL_DOMAIN_REPLAY",
        "description": "If salt is used in EIP712Domain, it should not be zero unless deliberately justified.",
        "risk_if_missing": "False sense of domain uniqueness.",
        "severity": "Medium",
    },
    "R11_NO_STALE_CACHED_DOMAIN": {
        "taxonomy": "T5_DOMAIN_FRESHNESS_FAILURE",
        "description": "If DOMAIN_SEPARATOR is cached in constructor/initializer, permit() should use recomputation or chainId invalidation.",
        "risk_if_missing": "Stale domain separator after chain split/fork.",
        "severity": "High/Medium",
    },
    "R12_PROXY_SAFE_DOMAIN": {
        "taxonomy": "T5_DOMAIN_FRESHNESS_FAILURE",
        "description": "Upgradeable/proxy contracts should avoid stale cached domains and bind signatures to the proxy/verifier actually used.",
        "risk_if_missing": "Cross-version/proxy-context replay risk.",
        "severity": "Medium/High",
    },
}


DOMAIN_SEPARATOR_TAXONOMY = {
    "T1_UNSEPARATED_SIGNING_DOMAIN": {
        "name": "Unseparated Signing Domain",
        "description": "The permit signing domain is absent or the typed-data digest misses EIP-191/EIP-712 framing.",
        "subcategories": [
            "missing_domain_separator",
            "missing_eip191_prefix",
        ],
        "attack_boundary": "generic signing-domain boundary",
    },
    "T2_CROSS_CHAIN_REPLAY": {
        "name": "Cross-Chain Replay",
        "description": "A signature may be replayable across chains or forks.",
        "subcategories": [
            "missing_chainId",
            "hardcoded_chainId",
        ],
        "attack_boundary": "chain/fork boundary",
    },
    "T3_CROSS_CONTRACT_REPLAY": {
        "name": "Cross-Contract Replay",
        "description": "A signature may be replayable across different verifier contracts.",
        "subcategories": [
            "missing_verifyingContract",
            "incorrect_verifyingContract",
            "hardcoded_verifier",
        ],
        "attack_boundary": "contract/verifier boundary",
    },
    "T4_LOGICAL_DOMAIN_REPLAY": {
        "name": "Logical-Domain Replay",
        "description": "A signature may be replayable across pools, vaults, markets, routers, modules, or other logical domains handled by the same verifier.",
        "subcategories": [
            "missing_logical_domain_disambiguator",
            "hardcoded_salt",
            "zero_salt_used",
        ],
        "attack_boundary": "application/logical-domain boundary",
    },
    "T5_DOMAIN_FRESHNESS_FAILURE": {
        "name": "Domain Freshness Failure",
        "description": "The domain separator may become stale because it is cached without recomputation or used in a proxy/upgradeable context.",
        "subcategories": [
            "stale_cached_DOMAIN_SEPARATOR",
            "proxy_stale_domain",
        ],
        "attack_boundary": "fork/proxy/upgrade/version boundary",
    },
}


def strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)
    code = re.sub(r"//.*", "", code)
    return code


def extract_balanced_block(code: str, start_index: int) -> str:
    brace_start = code.find("{", start_index)
    if brace_start == -1:
        return ""

    depth = 0
    for i in range(brace_start, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                return code[start_index:i + 1]

    return code[start_index:]


def extract_function_bodies(code: str) -> Dict[str, List[str]]:
    functions: Dict[str, List[str]] = {}
    pattern = re.compile(
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*\{",
        re.DOTALL,
    )

    for m in pattern.finditer(code):
        name = m.group(1)
        body = extract_balanced_block(code, m.start())
        if body:
            functions.setdefault(name, []).append(body)

    return functions


def extract_constructor_and_initializer_bodies(code: str) -> List[str]:
    bodies: List[str] = []
    patterns = [
        r"\bconstructor\s*\([^)]*\)[^{;]*\{",
        r"\bfunction\s+initialize\s*\([^)]*\)[^{;]*\{",
        r"\bfunction\s+init\s*\([^)]*\)[^{;]*\{",
        r"\bfunction\s+__[^\(\s]*init[^\(\s]*\s*\([^)]*\)[^{;]*\{",
    ]

    for pat in patterns:
        for m in re.finditer(pat, code, flags=re.DOTALL | re.IGNORECASE):
            body = extract_balanced_block(code, m.start())
            if body:
                bodies.append(body)

    return bodies


def find_domain_typehashes(code: str) -> List[str]:
    return re.findall(
        r"EIP712Domain\s*\(([^)]*)\)",
        code,
        flags=re.IGNORECASE | re.DOTALL,
    )


def has_dynamic_chainid(expr: str) -> bool:
    return bool(
        re.search(r"\bblock\.chainid\b", expr)
        or re.search(r"\bchainid\s*(?:\(\s*\))?\b", expr)
        or re.search(r"_getChainId\s*\(", expr)
    )


def has_address_this(expr: str) -> bool:
    return bool(
        re.search(r"\baddress\s*\(\s*this\s*\)", expr, re.IGNORECASE)
        or re.search(r"\baddress\s*\(\s*\)", expr)
    )

def has_hex1901_assembly_digest(code: str) -> bool:
    compact = re.sub(r"\s+", "", code)
    compact = compact.replace('hex"19_01"', 'hex"1901"')
    compact = compact.replace("hex'19_01'", "hex'1901'")

    return bool(
        re.search(r'mstore\([A-Za-z_][A-Za-z0-9_]*,hex["\']1901["\']\)', compact, re.IGNORECASE)
        and re.search(r"mstore\(add\([A-Za-z_][A-Za-z0-9_]*,0x02\),", compact, re.IGNORECASE)
        and re.search(r"mstore\(add\([A-Za-z_][A-Za-z0-9_]*,0x22\),", compact, re.IGNORECASE)
        and re.search(r"keccak256\([A-Za-z_][A-Za-z0-9_]*,0x42\)", compact, re.IGNORECASE)
    )



def has_eip712_assembly_digest(code: str) -> bool:
    compact = re.sub(r"\s+", "", code)

    return bool(
        "_DOMAIN_TYPEHASH" in compact
        and "chainid()" in compact
        and "address()" in compact
        and (
            "mstore(0x0e," in compact
            or "0x1901" in compact
        )
        and "mstore(0x2e,keccak256(" in compact
        and "mstore(0x4e,keccak256(" in compact
        and "keccak256(0x2c,0x42)" in compact
    )
    
def has_hardcoded_chainid(expr: str) -> bool:
    common_chain_ids = [
        1, 3, 4, 5, 10, 56, 97, 100, 137, 250, 324, 1101,
        8453, 42161, 42170, 43114, 11155111,
    ]

    for cid in common_chain_ids:
        if re.search(rf"(?<![A-Za-z0-9_]){cid}(?![A-Za-z0-9_])", expr):
            return True

    if re.search(r"\b(CHAIN_ID|chainID|chainId|_CHAIN_ID|INITIAL_CHAIN_ID|CACHED_CHAIN_ID)\b", expr):
        if not has_dynamic_chainid(expr):
            return True

    return False


def detect_domain_separator_function(code: str) -> bool:
    funcs = extract_function_bodies(code)

    for name, bodies in funcs.items():
        relevant = (
            name == "DOMAIN_SEPARATOR"
            or name == "_DOMAIN_SEPARATOR"
            or "domainSeparator" in name
            or "_domainSeparator" in name
            or name == "_domainSeparatorV4"
            or name == "_buildDomainSeparator"
            or name == "computeDomainSeparator"
            or name == "_computeDomainSeparator"
            or name == "_calculateDomainSeparator"
            
        )

        if not relevant:
            continue

        for body in bodies:
            if has_dynamic_chainid(body) and (
                "computeDomainSeparator" in body
                or "_computeDomainSeparator" in body
                or "_buildDomainSeparator" in body
                or "keccak256" in body
                or "_domainSeparatorV4" in body
                or "INITIAL_DOMAIN_SEPARATOR" in body
                or "_CACHED_DOMAIN_SEPARATOR" in body
                or "_cachedDomainSeparator" in body
            ):
                return True

            if re.search(r"block\.chainid\s*==|==\s*block\.chainid", body):
                return True

            if re.search(r"chainid\s*\(\s*\)", body) and "keccak256" in body:
                return True

    return False


def detect_permit_uses_domain_separator_directly(code: str) -> bool:
    funcs = extract_function_bodies(code)

    for body in funcs.get("permit", []):
        direct_var = re.search(r"\bDOMAIN_SEPARATOR\b(?!\s*\()", body)
        safe_call = re.search(
            r"\bDOMAIN_SEPARATOR\s*\(\s*\)|_domainSeparatorV4\s*\(\s*\)|_domainSeparator\s*\(\s*\)|domainSeparator\s*\(\s*\)",
            body,
        )

        if direct_var and not safe_call:
            return True

    return False


def detect_proxy_or_upgradeable(code: str) -> bool:
    return bool(
        re.search(
            r"\binitializer\b|Initializable|Upgradeable|UUPS|TransparentUpgradeableProxy|ERC1967|delegatecall|proxy",
            code,
            re.IGNORECASE,
        )
    )


def detect_multi_domain_context(code: str) -> bool:
    return bool(
        re.search(
            r"\bpoolId\b|\bpool\b|\bmarketId\b|\bmarket\b|\bvaultId\b|\bvault\b|"
            r"\bsubdomain\b|\baccountId\b|\bwallet\b|\brouter\b|\bfactory\b|\bclone\b|"
            r"\bcollectionId\b|\btokenId\b|\bstrategy\b|\bmodule\b",
            code,
            re.IGNORECASE,
        )
    )


def detect_salt_usage(code: str) -> Dict[str, Any]:
    salt_mentions = re.findall(
        r"\bsalt\b|_salt|DOMAIN_SALT|domainSalt",
        code,
        flags=re.IGNORECASE,
    )

    salt_in_typehash = bool(
        re.search(
            r"EIP712Domain\s*\([^)]*bytes32\s+salt[^)]*\)",
            code,
            flags=re.IGNORECASE | re.DOTALL,
        )
    )

    zero_salt = bool(
        re.search(
            r"bytes32\s*\(\s*0\s*\)|bytes32\s*\(\s*uint256\s*\(\s*0\s*\)\s*\)|0x0{8,}|DOMAIN_SALT\s*=\s*bytes32\s*\(\s*0\s*\)",
            code,
            flags=re.IGNORECASE,
        )
    )

    hardcoded_salt = bool(
        re.search(
            r"DOMAIN_SALT\s*=\s*0x[0-9a-fA-F]{64}|_salt\s*=\s*0x[0-9a-fA-F]{64}|salt\s*=\s*0x[0-9a-fA-F]{64}",
            code,
            flags=re.IGNORECASE,
        )
    )

    salt_from_hash = bool(
        re.search(
            r"salt\s*=\s*keccak256|DOMAIN_SALT\s*=\s*keccak256|_salt\s*=\s*keccak256",
            code,
            flags=re.IGNORECASE,
        )
    )

    return {
        "mentions_salt": len(salt_mentions) > 0,
        "salt_in_typehash": salt_in_typehash,
        "zero_salt": zero_salt,
        "hardcoded_salt": hardcoded_salt,
        "salt_from_hash": salt_from_hash,
    }
def is_domain_separator_function_name(name: str) -> bool:
    normalized = name.replace("_", "").lower()
    return "domainseparator" in normalized

def extract_domain_construction_contexts(code: str) -> str:
    chunks = []

    # Constructor / initializer domain construction.
    for body in extract_constructor_and_initializer_bodies(code):
        if "DOMAIN_SEPARATOR" in body and "keccak256" in body:
            chunks.append(body)

    funcs = extract_function_bodies(code)

    # Covers DOMAIN_SEPARATOR, getDomainSeparator, _domainSeparatorV4,
    # _buildDomainSeparator, computeDomainSeparator, etc.
    for name, bodies in funcs.items():
        if is_domain_separator_function_name(name):
            chunks.extend(bodies)

    # Follow direct helpers called from selected domain-construction bodies.
    # E.g., getDomainSeparator() -> getChainId() -> chainid().
    pending = list(chunks)
    seen = set(chunks)

    for _ in range(2):
        discovered = []

        for body in pending:
            called_names = re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(",
                body,
            )

            for called_name in called_names:
                for helper_body in funcs.get(called_name, []):
                    if helper_body in seen:
                        continue

                    if (
                        has_dynamic_chainid(helper_body)
                        or has_address_this(helper_body)
                    ):
                        chunks.append(helper_body)
                        seen.add(helper_body)
                        discovered.append(helper_body)

        if not discovered:
            break

        pending = discovered

    return "\n".join(chunks)
    


def classify_taxonomy(result: Dict[str, Any]) -> Dict[str, Any]:
    categories = set(result.get("risk_category", []))
    has_permit = result.get("has_permit", False)
    has_domain = result.get("has_domain_separator", False) or result.get("has_eip712_domain_typehash", False)
    proxy_context = result.get("proxy_or_upgradeable_context", False)
    multi_domain = result.get("multi_domain_context", False)

    taxonomy_findings = []

    def add_taxonomy(
        tid: str,
        matched_categories: List[str],
        severity: str,
        confidence: str,
        reason: str,
    ) -> None:
        spec = DOMAIN_SEPARATOR_TAXONOMY[tid]
        taxonomy_findings.append({
            "taxonomy_id": tid,
            "taxonomy_name": spec["name"],
            "attack_boundary": spec["attack_boundary"],
            "matched_categories": sorted(matched_categories),
            "severity": severity,
            "confidence": confidence,
            "reason": reason,
        })

    t1_cats = categories.intersection({
        "missing_domain_separator",
        "missing_eip191_prefix",
    })

    if t1_cats:
        add_taxonomy(
            "T1_UNSEPARATED_SIGNING_DOMAIN",
            list(t1_cats),
            "High" if has_permit else "Medium",
            "High" if has_domain else "Medium",
            "The EIP-712 signing domain is missing one or more core domain-separation fields.",
        )

    t2_cats = categories.intersection({
        "missing_chainId",
        "hardcoded_chainId",
    })

    if t2_cats and has_permit:
        add_taxonomy(
            "T2_CROSS_CHAIN_REPLAY",
            list(t2_cats),
            "High" if has_permit else "Medium",
            "High",
            "The domain separator may not bind signatures to the current chain or fork.",
        )

    t3_cats = categories.intersection({
        "missing_verifyingContract",
        "incorrect_verifyingContract",
        "hardcoded_verifier",
    })

    if t3_cats and has_permit:
        add_taxonomy(
            "T3_CROSS_CONTRACT_REPLAY",
            list(t3_cats),
            "High",
            "High" if (
                "missing_verifyingContract" in t3_cats
                or "incorrect_verifyingContract" in t3_cats
            ) else "Medium",
            "The domain separator may not bind signatures to the verifying contract address.",
        )

    t4_cats = categories.intersection({
        "missing_logical_domain_disambiguator",
        "hardcoded_salt",
        "zero_salt_used",
    })

    if t4_cats and has_permit:
        add_taxonomy(
            "T4_LOGICAL_DOMAIN_REPLAY",
            list(t4_cats),
            "High" if multi_domain and "missing_logical_domain_disambiguator" in t4_cats else "Medium",
            "Medium",
            "The same verifier appears to serve multiple logical domains without a strong domain discriminator.",
        )

    t5_cats = categories.intersection({
        "proxy_stale_domain",
        "stale_cached_DOMAIN_SEPARATOR",
    })

    if t5_cats:
        add_taxonomy(
            "T5_DOMAIN_FRESHNESS_FAILURE",
            list(t5_cats),
            "High" if "proxy_stale_domain" in t5_cats else "Medium",
            "Medium",
            "The contract appears upgradeable/proxy-based and may cache or bind the domain separator in a stale context.",
        )

    if taxonomy_findings:
        max_sev = "High" if any(t["severity"] == "High" for t in taxonomy_findings) else "Medium"
    else:
        max_sev = result.get("risk_level", "Info")

    return {
        "taxonomy": taxonomy_findings,
        "taxonomy_risk_level": max_sev,
        "taxonomy_ids": [t["taxonomy_id"] for t in taxonomy_findings],
        "taxonomy_names": [t["taxonomy_name"] for t in taxonomy_findings],
    }

def has_permit_implementation(code: str) -> bool:
    # Real function body only. Excludes interface declarations and external calls like token.permit(...).
    return bool(
        re.search(
            r"\bfunction\s+permit\s*\([^)]*\)\s*(?:public|external)?[^{;]*\{",
            code,
            re.IGNORECASE | re.DOTALL,
        )
    )


def has_external_permit_call(code: str) -> bool:
    return bool(re.search(r"\.\s*permit\s*\(", code))


def analyze_domain_separator_construction(solidity_code: str) -> Dict[str, Any]:
    code = strip_comments(solidity_code)

    result: Dict[str, Any] = {
        "requirements": DOMAIN_SEPARATOR_REQUIREMENTS,
        "has_domain_separator": False,
        "has_permit": False,
        "has_eip712_domain_typehash": False,
        "domain_typehashes": [],
        "uses_chainId_in_typehash": False,
        "uses_verifyingContract_in_typehash": False,
        "uses_salt_in_typehash": False,
        "uses_dynamic_chainid": False,
        "uses_address_this": False,
        "hardcoded_chainid": False,
        "hardcoded_verifier": False,
        "domain_separator_assigned_in_constructor_or_initializer": False,
        "domain_separator_recomputed_or_chainid_checked": False,
        "permit_uses_domain_separator_directly": False,
        "proxy_or_upgradeable_context": False,
        "multi_domain_context": False,
        "salt": {},
        "risk_level": "Info",
        "risk_category": [],
        "findings": [],
        "warnings": [],
        "critical_issues": [],
    }

    result["has_domain_separator"] = bool(
        re.search(
            r"\b(?:DOMAIN_SEPARATOR|getDomainSeparator|"
            r"_?domainSeparator(?:V4)?|"
            r"_?buildDomainSeparator|"
            r"_?computeDomainSeparator)\b",
            code,
            re.IGNORECASE,
        )
    )

    result["has_permit"] = has_permit_implementation(code)
    result["calls_external_permit"] = has_external_permit_call(code)
    
    OZ_EIP712_TYPEHASH = "0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"

    result["has_oz_eip712_typehash"] = OZ_EIP712_TYPEHASH in code.lower()
    
    result["has_eip191_prefix"] = bool(
        re.search(
            r'\\x19\\x01|"\x19\x01"|toTypedDataHash\s*\(|_hashTypedDataV4\s*\(|hashTypedDataV4\s*\(',
            code
        )
        or has_eip712_assembly_digest(code)
        or has_hex1901_assembly_digest(code)
    )

    domain_typehashes = find_domain_typehashes(code)
    result["domain_typehashes"] = domain_typehashes

    has_string_domain_typehash = bool(
        re.search(
            r'EIP712Domain\s*\(\s*string\s+name\s*,\s*string\s+version\s*,\s*uint256\s+chainId\s*,\s*address\s+verifyingContract',
            code,
            re.IGNORECASE,
        )
    )

    result["has_eip712_domain_typehash"] = bool(domain_typehashes) or has_string_domain_typehash

    joined_typehash = " ".join(domain_typehashes)

    result["uses_chainId_in_typehash"] = bool(
        re.search(r"uint256\s+chainId", joined_typehash, re.IGNORECASE)
    )

    result["uses_verifyingContract_in_typehash"] = bool(
        re.search(r"address\s+verifyingContract", joined_typehash, re.IGNORECASE)
    )

    result["uses_salt_in_typehash"] = bool(
        re.search(r"bytes32\s+salt", joined_typehash, re.IGNORECASE)
    )

    domain_ctx = extract_domain_construction_contexts(code)
    
    has_safe_domain_construction = (
    "block.chainid" in domain_ctx
    and re.search(r"address\s*\(\s*this\s*\)", domain_ctx)
    )

    if has_safe_domain_construction:
        result["uses_chainId_in_typehash"] = True
        result["uses_verifyingContract_in_typehash"] = True
        result["uses_dynamic_chainid"] = True
        result["uses_address_this"] = True

    result["uses_dynamic_chainid"] = has_dynamic_chainid(domain_ctx)
    result["uses_address_this"] = has_address_this(domain_ctx)

    result["hardcoded_chainid"] = (
        bool(domain_ctx)
        and has_hardcoded_chainid(domain_ctx)
        and not result["uses_dynamic_chainid"]
    )

    result["hardcoded_verifier"] = (
        bool(domain_ctx)
        and bool(re.search(r"0x[a-fA-F0-9]{40}", domain_ctx))
        and not result["uses_address_this"]
    )

    result["domain_separator_recomputed_or_chainid_checked"] = detect_domain_separator_function(code)
    result["permit_uses_domain_separator_directly"] = detect_permit_uses_domain_separator_directly(code)

    for body in extract_constructor_and_initializer_bodies(code):
        if re.search(r"domain.?separator", body, re.IGNORECASE) and "keccak256" in body:
            result["domain_separator_assigned_in_constructor_or_initializer"] = True

    result["proxy_or_upgradeable_context"] = detect_proxy_or_upgradeable(code)
    result["multi_domain_context"] = detect_multi_domain_context(code)
    result["salt"] = detect_salt_usage(code)
    
    if result["has_oz_eip712_typehash"]:
        result["has_eip712_domain_typehash"] = True
        result["uses_chainId_in_typehash"] = True
        result["uses_verifyingContract_in_typehash"] = True

        if "block.chainid" in code and re.search(r"address\s*\(\s*this\s*\)", code):
            result["uses_dynamic_chainid"] = True
            result["uses_address_this"] = True

    if result["has_permit"] and not result["has_eip191_prefix"]:
            result["critical_issues"].append("R2: Missing EIP-191 typed-data prefix.")
            result["risk_category"].append("missing_eip191_prefix")
            
    if not result["has_domain_separator"] and not result["has_eip712_domain_typehash"]:
        if result["has_permit"]:
            result["critical_issues"].append(
                "R1: Missing DOMAIN_SEPARATOR/EIP712Domain in permit-enabled contract."
            )
            result["risk_category"].append("missing_domain_separator")
            result["risk_level"] = "High"
        else:
            result["warnings"].append("No obvious DOMAIN_SEPARATOR or EIP712Domain typehash found.")
            result["risk_level"] = "Info"
            return result

    if result["has_domain_separator"] and not domain_ctx and not result["critical_issues"]:
        result["warnings"].append(
            "DOMAIN_SEPARATOR declaration found, but no implementation/construction body found; likely interface-only or abstract declaration."
        )
        result["risk_level"] = "Info"
        return result

    if result["has_eip712_domain_typehash"] and not result["uses_chainId_in_typehash"]:
        result["critical_issues"].append(
            "R3: Missing chainId in EIP712Domain typehash/construction; possible cross-chain replay risk."
        )
        result["risk_category"].append("missing_chainId")

    if result["has_eip712_domain_typehash"] and not result["uses_verifyingContract_in_typehash"]:
        result["critical_issues"].append(
            "R5: Missing verifyingContract in EIP712Domain typehash/construction; possible cross-contract replay risk."
        )
        result["risk_category"].append("missing_verifyingContract")

    if result["hardcoded_chainid"] and not result["uses_dynamic_chainid"]:
        result["critical_issues"].append(
            "R4: Hardcoded or constant chainId detected instead of block.chainid/chainid()."
        )
        result["risk_category"].append("hardcoded_chainId")

    elif result["hardcoded_chainid"] and result["uses_dynamic_chainid"]:
        result["warnings"].append(
            "R4: ChainId-related constant detected; verify it is not used in DOMAIN_SEPARATOR."
        )

    if result["uses_verifyingContract_in_typehash"] and not result["uses_address_this"]:
        result["critical_issues"].append(
            "R6: verifyingContract is in typehash but address(this) is not visible; possible incorrect verifier binding."
        )
        result["risk_category"].append("incorrect_verifyingContract")

    if result["hardcoded_verifier"]:
        result["critical_issues"].append(
            "R7: Hardcoded address detected with no address(this); possible hardcoded verifier."
        )
        result["risk_category"].append("hardcoded_verifier")

    if (
        result["domain_separator_assigned_in_constructor_or_initializer"]
        and not result["domain_separator_recomputed_or_chainid_checked"]
    ):
        result["critical_issues"].append(
            "R11: Stale cached DOMAIN_SEPARATOR: assigned in constructor/initializer and used directly in permit() without chainId recomputation."
        )
        result["risk_category"].append("stale_cached_DOMAIN_SEPARATOR")

    if (
        result["proxy_or_upgradeable_context"]
        and result["domain_separator_assigned_in_constructor_or_initializer"]
        and not result["domain_separator_recomputed_or_chainid_checked"]
    ):
        result["critical_issues"].append(
            "R12: Upgradeable/proxy context with cached DOMAIN_SEPARATOR and no visible recomputation."
        )
        result["risk_category"].append("proxy_stale_domain")

    if result["multi_domain_context"]:
        has_equivalent_id = bool(
            re.search(
                r"\bpoolId\b|\bmarketId\b|\bvaultId\b|\baccountId\b|\bchainId\b|\btokenId\b|\bcollectionId\b|\bmodule\b",
                code,
                re.IGNORECASE,
            )
        )

        if not result["uses_salt_in_typehash"] and not has_equivalent_id:
            result["warnings"].append(
                "R8: Multi-domain context detected but no salt or obvious domain-specific identifier found."
            )
            result["risk_category"].append("missing_logical_domain_disambiguator")

    if result["salt"].get("hardcoded_salt"):
        result["warnings"].append(
            "R9: Hardcoded salt detected; verify uniqueness per logical signing domain."
        )
        result["risk_category"].append("hardcoded_salt")

    if result["salt"].get("zero_salt") and result["uses_salt_in_typehash"]:
        result["warnings"].append(
            "R10: Salt appears present in EIP712Domain but may be zero."
        )
        result["risk_category"].append("zero_salt_used")

    if result["critical_issues"]:
        result["risk_level"] = "High"
    elif result["warnings"]:
        result["risk_level"] = "Medium"
    elif result["has_domain_separator"] or result["has_eip712_domain_typehash"]:
        result["risk_level"] = "Low"
    else:
        result["risk_level"] = "Info"

    result["risk_category"] = sorted(set(result["risk_category"]))

    taxonomy_result = classify_taxonomy(result)
    result.update(taxonomy_result)

    if result.get("taxonomy_risk_level") == "High":
        result["risk_level"] = "High"
    elif result.get("taxonomy_risk_level") == "Medium" and result["risk_level"] != "High":
        result["risk_level"] = "Medium"

    return result


def analyze_file(file_path: Path) -> Dict[str, Any]:
    try:
        solidity_code = file_path.read_text(encoding="utf-8", errors="ignore")
        result = analyze_domain_separator_construction(solidity_code)
        result["file"] = str(file_path)
        result["status"] = "ok"
        return result

    except Exception as e:
        return {
            "file": str(file_path),
            "status": "error",
            "error": str(e),
            "risk_level": "Error",
            "risk_category": ["analysis_error"],
        }


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary: Dict[str, Any] = {
        "total_files": len(results),
        "risk_level_counts": {},
        "risk_category_counts": {},
        "requirement_issue_counts": {},
        "taxonomy_counts": {},
        "taxonomy_severity_counts": {},
        "high_risk_files": [],
        "medium_risk_files": [],
    }

    for r in results:
        risk = r.get("risk_level", "Unknown")
        summary["risk_level_counts"][risk] = summary["risk_level_counts"].get(risk, 0) + 1

        for cat in r.get("risk_category", []):
            summary["risk_category_counts"][cat] = summary["risk_category_counts"].get(cat, 0) + 1

        for issue in r.get("critical_issues", []):
            key = issue.split(":")[0] if ":" in issue else issue[:40]
            summary["requirement_issue_counts"][key] = summary["requirement_issue_counts"].get(key, 0) + 1

        for warn in r.get("warnings", []):
            key = warn.split(":")[0] if ":" in warn else warn[:40]
            summary["requirement_issue_counts"][key] = summary["requirement_issue_counts"].get(key, 0) + 1

        for t in r.get("taxonomy", []):
            tid = t.get("taxonomy_id", "UNKNOWN")
            sev = t.get("severity", "Unknown")
            summary["taxonomy_counts"][tid] = summary["taxonomy_counts"].get(tid, 0) + 1
            summary["taxonomy_severity_counts"][sev] = summary["taxonomy_severity_counts"].get(sev, 0) + 1

        if risk == "High":
            summary["high_risk_files"].append(r.get("file"))
        elif risk == "Medium":
            summary["medium_risk_files"].append(r.get("file"))

    return summary


def collect_solidity_files(input_dir: Path, max_files: Optional[int] = None) -> List[Path]:
    files = sorted(input_dir.rglob("*.sol"))
    return files[:max_files] if max_files is not None else files


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze Solidity files for EIP-712 DOMAIN_SEPARATOR construction risks."
    )

    parser.add_argument(
        "--input-dir",
        required=True,
        help="Directory containing .sol files.",
    )

    parser.add_argument(
        "--output-json",
        required=True,
        help="Output JSON path for per-file results.",
    )

    parser.add_argument(
        "--output-summary",
        required=True,
        help="Output JSON path for summary results.",
    )

    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Maximum number of .sol files to analyze.",
    )

    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    output_json = Path(args.output_json)
    output_summary = Path(args.output_summary)

    if not input_dir.exists():
        raise FileNotFoundError(f"Input directory does not exist: {input_dir}")

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_summary.parent.mkdir(parents=True, exist_ok=True)

    files = collect_solidity_files(input_dir, args.max_files)

    print(f"Input directory: {input_dir}")
    print(f"Solidity files found: {len(files)}")
    print(f"Output JSON: {output_json}")
    print(f"Output summary: {output_summary}")

    results: List[Dict[str, Any]] = []

    for i, file_path in enumerate(files, 1):
        print(f"[{i}/{len(files)}] Analyzing {file_path}")
        result = analyze_file(file_path)
        results.append(result)

        if i % 25 == 0 or i == len(files):
            output_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    summary = summarize_results(results)
    output_summary.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("\nAnalysis complete.")
    print("Risk levels:")
    print(json.dumps(summary.get("risk_level_counts", {}), indent=2))
    print("Taxonomy counts:")
    print(json.dumps(summary.get("taxonomy_counts", {}), indent=2))
    print(f"Saved per-file results: {output_json}")
    print(f"Saved summary: {output_summary}")


if __name__ == "__main__":
    main()
    
    
    
