import os
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from eth_utils import keccak

def find_functions_by_signature(functions: List[Dict], target_signature: str) -> List[Dict]:
    """Find all functions matching the normalized signature with parameter types."""
    print(f"target_signature:{target_signature}")
    target_normalized = normalize_signature(target_signature)
    print(f"target_normalized:{target_normalized}")
    target_normalized_hash = keccak(text=target_normalized).hex()
    # print(f"target_normalized_hash:{target_normalized_hash}")
    matching_functions = []
    
    for func in functions:
        current_sig = f"{func['name']}({func['params']})"
        current_normalized = normalize_signature(current_sig)
        # print(f"current_normalized:{current_normalized}")
        current_normalized_hash = keccak(text=current_normalized).hex()
        
        if current_normalized_hash == target_normalized_hash :
            print(f"current_normalized_hash:{current_normalized_hash}")
            # Add parameters to function info
            func['parameters'] = get_parameter_dict(func['params'])
            matching_functions.append(func)
    
    # print(f"matching_functions:{len(matching_functions)}")
    return matching_functions

def get_all_internal_calls(function_body: str, all_functions: List[Dict], visited: Set[str] = None) -> List[Dict]:
    """Recursively get all internal function calls (including nested calls)."""
    if visited is None:
        visited = set()
    
    internal_calls = []
    
    # Split code into tokens to better identify function calls
    tokens = re.split(r'(\W)', function_body)  # Split on non-word characters
    tokens = [t for t in tokens if t.strip()]  # Remove empty tokens
    
    i = 0
    while i < len(tokens):
        token = tokens[i]
        
        # Look for potential function calls (identifier followed by parenthesis)
        if (token.isidentifier() and i+1 < len(tokens) and 
            tokens[i+1] == '(' and 
            token not in visited):
            
            call_name = token
            # print(f"call_name:{call_name}")
            
            # Skip keywords and built-ins
            if (call_name.lower() in {
                'require', 'assert', 'revert', 'emit', 'new', 'return',
                'returns', 'if', 'try', 'iscontract', 'continue', 'break',
                'for', 'while', 'do', 'else', 'catch', 'delete', 'length'
            } or call_name in {
                'gasleft', 'msg', 'block', 'tx', 'abi', 'type', 'this', 'selfdestruct', 'sha3', 'keccak256', 'ripemd160',
                'ecrecover', 'addmod', 'mulmod', 'balance', 'sub', 'add'
            }):
                i += 1
                continue
            
            # Skip library calls (those with dots)
            if '.' in call_name:
                i += 1
                continue
            
            # Find matching function definition
            for func in all_functions:
                if func['name'] == call_name:
                    # # Skip self-references
                    # if func['body'] == function_body:
                    #     continue
                    
                    # Only process if we haven't visited this function before
                    # if call_name not in visited:
                    #     visited.add(call_name)
                    
                    if func['body'] != function_body:
                        
                        visited.add(call_name)
                        internal_calls.append(func)
                        # Recursively get calls from this function
                        nested_calls = get_all_internal_calls(func['body'], all_functions, visited)
                        if nested_calls:  # Only extend if we got valid results
                            internal_calls.extend(nested_calls)
            
            # Skip past the parameters
            paren_count = 1
            i += 2  # Skip past '('
            while i < len(tokens) and paren_count > 0:
                if tokens[i] == '(':
                    paren_count += 1
                elif tokens[i] == ')':
                    paren_count -= 1
                i += 1
        else:
            i += 1
    
    return internal_calls if internal_calls else None


def find_if_revert_conditions(code: str):
    """Find all if conditions containing revert statements"""
    conditions = []
    pos = 0
    code_len = len(code)
    
    while pos < code_len:
        # Find the next 'if' keyword
        if_pos = code.find('if', pos)
        if if_pos == -1:
            break
            
        # Check if it's a real if statement (not part of another word)
        if if_pos > 0 and (code[if_pos-1].isalnum() or code[if_pos-1] == '_'):
            pos = if_pos + 2
            continue
            
        # Find the opening parenthesis after 'if'
        paren_pos = code.find('(', if_pos)
        if paren_pos == -1 or paren_pos > if_pos + 10:  # Allow some whitespace
            pos = if_pos + 2
            continue
            
        # Find matching closing parenthesis
        paren_level = 1
        end_pos = paren_pos + 1
        while end_pos < code_len and paren_level > 0:
            if code[end_pos] == '(':
                paren_level += 1
            elif code[end_pos] == ')':
                paren_level -= 1
            end_pos += 1
            
        if paren_level != 0:
            pos = if_pos + 2
            continue
            
        # Look for revert in the if block (either single line or braced)
        block_start = end_pos
        block_end = code.find('}', block_start)
        semi_pos = code.find(';', block_start)
        
        # Determine the block end position
        if block_end == -1 or (semi_pos != -1 and semi_pos < block_end):
            block_end = semi_pos
        if block_end == -1:
            pos = if_pos + 2
            continue
            
        # Check for revert in this block
        revert_pos = code.find('revert', block_start, block_end)
        if revert_pos != -1:
            # Extract the condition
            condition = code[paren_pos+1:end_pos-1].strip()
            condition = re.sub(r'\s+', ' ', condition)
            conditions.append(condition)
            
        pos = end_pos
        
    return conditions

def extract_parameters(target_func: Dict) -> Dict:
    """Extract and return all relevant parameters from the target function."""
    params = list(target_func.get('parameters', {}).items())
    return {
        'from_param': params[0][0] if len(params) > 0 else None,
        'to_param': params[1][0] if len(params) > 1 else None,
        'ids_param': params[2][0] if len(params) > 2 else None,
        'amounts_param': params[3][0] if len(params) > 3 else None,
        'data_param': params[4][0] if len(params) > 4 else None
    }

def find_length_assignments(all_code: List[Tuple[str, str]], ids_param: str) -> Dict:
    """Find all length assignments in the provided code."""
    length_assignments = {}
    for code, source in all_code:
        # Look for both direct and indirect length assignments
        matches = re.finditer(
            rf'uint256\s+(\w+)\s*=\s*{re.escape(ids_param)}\s*\.\s*length\s*;',
            code,
            re.DOTALL
        )
        for match in matches:
            var_name = match.group(1)
            length_assignments[var_name] = {
                'source': source,
                'full_match': match.group(0)
            }
    return length_assignments

def verify_erc1155_requirements(target_func: Dict, internal_functions: List[Dict]) -> Dict:
    
    
    """Verify if the function and its internal calls meet ERC1155 requirements."""
    requirements = {
        'sender_check': False,
        'approval_check': False,
        'zero_address_check': False,
        'length_matching_check': False,
       
        'event_emission_before_transfers': False,
        'transfer_batch_event_found': False,
        'to_isContract_check':False,
        'on_received_check': False
        
    }
    #  'balance_checks': False,
    
    params = extract_parameters(target_func)
    from_param = params['from_param']
    to_param = params['to_param']
    ids_param = params['ids_param']
    amounts_param = params['amounts_param']
    data_param = params['data_param']
    
    # Combine all code to analyze (main function + internal calls)
    all_code = [(target_func['body'], "main function")]
    for func in internal_functions:
        # print(f"func['body']:{func['body']}")
        
        # if target_func['body'] != func['body'] and len(internal_functions) != 1:
        all_code.append((func['body'], f"internal function {func['name']}"))
            
        
    # Find all length assignments first
    length_assignments = find_length_assignments(all_code, ids_param) if ids_param else {}
    all_conditions = []
    event_pos = None
    
    
    for code, source in all_code:
        
        condition_matches = []
        # Pattern for require statements
        require_pattern = r'require\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)'
        # Find all require matches
        require_matches = re.finditer(require_pattern, code, re.DOTALL)
        
        for match in require_matches:
            req_content = re.sub(r'\s+', ' ', match.group(1).strip())
            condition_matches.append((req_content, source, 'require'))
        
        # Usage in your code:
        if_revert_conditions = find_if_revert_conditions(code)
        
        for condition in if_revert_conditions:
            condition_matches.append((condition, source, 'if-revert'))
            
        all_conditions.extend(condition_matches)
    
    # Possible sender representations
    sender_reprs = ['msg.sender', '_msgSender()', 'sender']
    
    # Check conditions
    for condition_content, condition_source, condition_type in all_conditions:
        # Check for sender condition
        # Check for sender condition
        if from_param and not requirements['sender_check']:
            for sender in sender_reprs:
                if condition_type == "if-revert":
                    print(f"condition_type :{condition_type}")
                    # Basic inequality checks (complete conditions)
                    pattern1 = rf'{re.escape(sender)}\s*!=\s*{from_param}'
                    pattern2 = rf'{from_param}\s*!=\s*{re.escape(sender)}'
                    
                    # Combined sender and approval check
                    pattern3 = rf'if\s*\(\s*{re.escape(sender)}\s*!=\s*{from_param}\s*&&\s*!isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)\s*\)'
                    
                    # New patterns for partial conditions
                    pattern4 = rf'if\s*\(\s*{from_param}\s*!=\s*{re.escape(sender)}'  # matches "if (from != sender"
                    pattern5 = rf'if\s*\(\s*{re.escape(sender)}\s*!=\s*{from_param}'  # matches "if (sender != from"
                    
                    if (re.search(pattern1, condition_content) or 
                        re.search(pattern2, condition_content) or
                        re.search(pattern3, condition_content) or 
                        re.search(pattern4, condition_content) or
                        re.search(pattern5, condition_content)):
                        requirements['sender_check'] = True
                        break
                    
                if condition_type == "require":
                    pattern6 = rf'{re.escape(sender)}\s*==\s*{from_param}'
                    pattern7 = rf'{from_param}\s*==\s*{re.escape(sender)}'
                    if re.search(pattern6, condition_content) or re.search(pattern7, condition_content):
                        requirements['sender_check'] = True
                        break

        # Check for approval condition
        if from_param and not requirements['approval_check']:
            for sender in sender_reprs:
                if condition_type == "if-revert":
                    print(f"condition_type :{condition_type}")
                    pattern1 = rf'!isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)'
                    exact_pattern1 = rf'operatorApproval\[{from_param}\]\[{re.escape(sender)}\]\s*==\s*false'
                    # New pattern for mapping-style access
                    mapping_pattern1 = rf'!isApprovedForAll\[{from_param}\]\[{re.escape(sender)}\]'
                    # New pattern for combined check with revert
                    pattern2 = rf'if\s*\(\s*{re.escape(sender)}\s*!=\s*{from_param}\s*&&\s*!isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)\s*\)\s*{{\s*revert\s*ERC1155MissingApprovalForAll\(\s*{re.escape(sender)}\s*,\s*{from_param}\s*\)'
                    if (re.search(pattern1, condition_content) or 
                        re.search(exact_pattern1, condition_content, re.IGNORECASE) or
                        re.search(mapping_pattern1, condition_content) or
                        re.search(pattern2, condition_content)):
                        requirements['approval_check'] = True
                        break
                    if not requirements['approval_check']:
                        if (re.search(r'Approval', condition_content, re.IGNORECASE) and
                            re.search(rf'{from_param}', condition_content) and
                            re.search(rf'{re.escape(sender)}', condition_content) and
                            re.search(r'false', condition_content, re.IGNORECASE)):
                            requirements['approval_check'] = True
                            break
                if condition_type == "require":
                    pattern3 = rf'isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)'
                    exact_pattern2 = rf'operatorApproval\[{from_param}\]\[{re.escape(sender)}\]\s*==\s*true'
                    # New pattern for mapping-style access in require
                    mapping_pattern2 = rf'isApprovedForAll\[{from_param}\]\[{re.escape(sender)}\]'
                    # New pattern for specific case you mentioned
                    specific_case_pattern = rf'require\(\s*isApprovedForAll\[{from_param}\]\[{re.escape(sender)}\]\s*,\s*[\'"]NOT_AUTHORIZED[\'"]\s*\)'
                    
                    if (re.search(pattern3, condition_content) or 
                        re.search(exact_pattern2, condition_content, re.IGNORECASE) or
                        re.search(mapping_pattern2, condition_content) or
                        re.search(specific_case_pattern, condition_content)):
                        requirements['approval_check'] = True
                        break
                    if not requirements['approval_check']:
                        if (re.search(r'Approval', condition_content, re.IGNORECASE) and
                            re.search(rf'{from_param}', condition_content) and
                            re.search(rf'{re.escape(sender)}', condition_content) and
                            re.search(r'true', condition_content, re.IGNORECASE)):
                            requirements['approval_check'] = True
                            break
        
        # Check for zero address condition
        if to_param and not requirements['zero_address_check']:
            if condition_type == "if-revert":
                zero_addr_pattern1 = [
                    rf'{to_param}\s*==\s*address\(0\)',
                    rf'address\(0\)\s*==\s*{to_param}',
                    rf'{to_param}\s*==\s*address\(0x0\)',
                    rf'address\(0x0\)\s*==\s*{to_param}',
                    rf'recipient\s*==\s*address\(0\)',  # Added recipient check
                    rf'recipient\s*==\s*address\(0x0\)'  # Added recipient check
                ]
                for pattern in zero_addr_pattern1:
                    if re.search(pattern, condition_content):
                        requirements['zero_address_check'] = True
                        break
                    
            if condition_type == "require":
                zero_addr_pattern2 = [
                    rf'{to_param}\s*!=\s*address\(0\)',
                    rf'address\(0\)\s*!=\s*{to_param}',
                    rf'{to_param}\s*!=\s*address\(0x0\)',
                    rf'address\(0x0\)\s*!=\s*{to_param}',
                    rf'recipient\s*!=\s*address\(0\)',  # Added recipient check
                    rf'recipient\s*!=\s*address\(0x0\)',  # Added recipient check
                    rf'require\s*\(\s*recipient\s*!=\s*address\(0\)\s*,\s*[\'"]ERC1155:\s*transfer\s*to\s*the\s*zero\s*address[\'"]\s*\)'  # Specific ERC1155 case
                ]
                for pattern in zero_addr_pattern2:
                    if re.search(pattern, condition_content):
                        requirements['zero_address_check'] = True
                        break
            
        # Check for length matching condition
        if ids_param and amounts_param and not requirements['length_matching_check']:
            assigned_var = None
            # Check direct length comparisons
            direct_patterns = [
                rf'{ids_param}\.length\s*[!=]=\s*{amounts_param}\.length',
                rf'{amounts_param}\.length\s*[!=]=\s*{ids_param}\.length',
                rf'{ids_param}\.length\s*[==]=\s*{amounts_param}\.length',
                rf'{amounts_param}\.length\s*[==]=\s*{ids_param}\.length',
               
                ]
            # direct_patterns = [
            #     rf'{ids_param}\.length\s*[!=]=\s*{amounts_param}\.length',
            #     rf'{amounts_param}\.length\s*[!=]=\s*{ids_param}\.length',
            #     r'(?!(?:ids|values?|amounts?)\.length\s*!=\s*(?:ids|values?|amounts?)\.length)'
            #     r'([A-Za-z_][A-Za-z0-9_]*)\.length\s*!=\s*([A-Za-z_][A-Za-z0-9_]*)\.length'
            # ]


            assigned_patterns = []
            for var_name in length_assignments:
                assigned_patterns.extend([
                    rf'{var_name}\s*[!=]=\s*{amounts_param}\.length',
                    rf'{amounts_param}\.length\s*[!=]=\s*{var_name}'
                ])
            if any(re.search(p, condition_content) for p in direct_patterns + assigned_patterns):
                requirements['length_matching_check'] = True
  
        # # Check for balance checks
        # if from_param and ids_param and amounts_param and not requirements['balance_checks']:
        #     balance_pattern = rf'balanceOf\(\s*{from_param}\s*,\s*{ids_param}\[i\]\)\s*>=\s*{amounts_param}\[i\]'
        #     if re.search(balance_pattern, condition_content):
        #         requirements['balance_checks'] = True
    
    # Check for event emission and onReceived in the code
    for code, source in all_code:
        # Event emission check
        if 'emit TransferBatch(' in code and not requirements['transfer_batch_event_found']:
            requirements['transfer_batch_event_found'] = True
            event_pos = (source, code.find('emit TransferBatch('))
        
        # Check if transfers happen after event emission
        if requirements['transfer_batch_event_found'] and source == event_pos[0]:
            event_pos_num = event_pos[1]
            post_event_code = code[event_pos_num:]
            if 'safeTransferFrom(' in post_event_code or 'safeBatchTransferFrom(' in post_event_code:
                requirements['event_emission_before_transfers'] = False
            else:
                requirements['event_emission_before_transfers'] = True
        # Normalize code by removing comments and extra spaces
        normalized_code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
        normalized_code = re.sub(r'\s+', ' ', normalized_code)
        
    
        # 1. Check for isContract() guard
        contract_check_patterns = [
        # Standard if(isContract()) checks
        rf'if\s*\(\s*{to_param}\s*\.\s*isContract\s*\(\s*\)\s*\)',
        
        # Various code.length comparisons
        rf'if\s*\(\s*{to_param}\s*\.\s*code\s*\.\s*length\s*[!=]=\s*0\s*\)',
        rf'if\s*\(\s*{to_param}\s*\.\s*code\s*\.\s*length\s*>\s*0\s*\)',
        
        # Ternary require checks
        rf'require\s*\(\s*{to_param}\s*\.\s*code\s*\.\s*length\s*==\s*0\s*\?\s*{to_param}\s*!=\s*address\s*\(\s*0\s*\)',
        rf'require\s*\(\s*{to_param}\s*\.\s*code\s*\.\s*length\s*==\s*0\s*\?\s*{to_param}\s*!=\s*0x0\b',
        rf'require\s*\(\s*{to_param}\s*\.\s*code\s*\.\s*length\s*==\s*0\s*\?\s*{to_param}\s*!=\s*address\s*\(\s*0\s*\)\s*:'
        ]

        if any(re.search(pattern, normalized_code) for pattern in contract_check_patterns):
            requirements['to_isContract_check'] = True
        # Check for onReceived implementation in functions called after the event
        if event_pos and source != event_pos[0]:
            if requirements['to_isContract_check'] and check_on_received_implementation(code, params, requirements['to_isContract_check']):
                requirements['on_received_check'] = True
            elif not requirements['to_isContract_check'] and check_on_received_implementation(code, params, requirements['to_isContract_check']):
                requirements['on_received_check'] = True

    return requirements


def verify_erc2612_requirements(target_func: Dict, internal_functions: List[Dict]) -> Dict:
    """Verify if the function and its internal calls meet ERC2612 requirements."""
    requirements = {
        'deadline_check': False,
        'timestamp_check': False,
        'signature_validation': False,
        'nonce_usage': False,
        'domain_separator_usage': False,
        'permit_function_exists': False,
        'owner_check': False,
        'spender_approval': False
    }

    # Extract parameters
    params = extract_parameters(target_func)
    owner_param = params.get('owner_param', 'owner')
    spender_param = params.get('spender_param', 'spender')
    value_param = params.get('value_param', 'value')
    deadline_param = params.get('deadline_param', 'deadline')
    v_param = params.get('v_param', 'v')
    r_param = params.get('r_param', 'r')
    s_param = params.get('s_param', 's')

    # Combine all code to analyze (main function + internal calls)
    all_code = [(target_func['body'], "main function")]
    for func in internal_functions:
        if target_func['body'] != func['body']:
            all_code.append((func['body'], f"internal function {func['name']}"))

    all_conditions = []
    
    for code, source in all_code:
        condition_matches = []
        
        # Pattern for require statements
        require_pattern = r'require\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)'
        require_matches = re.finditer(require_pattern, code, re.DOTALL)
        
        for match in require_matches:
            req_content = re.sub(r'\s+', ' ', match.group(1).strip())
            condition_matches.append((req_content, source, 'require'))
        
        # Find if-revert conditions
        if_revert_conditions = find_if_revert_conditions(code)
        for condition in if_revert_conditions:
            condition_matches.append((condition, source, 'if-revert'))
            
        all_conditions.extend(condition_matches)

    # Check conditions
    for condition_content, condition_source, condition_type in all_conditions:
        # Check for deadline validation
        if deadline_param and not requirements['deadline_check']:
            if condition_type == "if-revert":
                deadline_patterns = [
                    rf'{deadline_param}\s*<\s*block\.timestamp',
                    rf'block\.timestamp\s*>\s*{deadline_param}',
                    rf'isExpired\(\s*{deadline_param}\s*\)',
                    rf'!isValid\(\s*{deadline_param}\s*\)'
                ]
            else:  # require
                deadline_patterns = [
                    rf'{deadline_param}\s*>=\s*block\.timestamp',
                    rf'block\.timestamp\s*<=\s*{deadline_param}',
                    rf'!isExpired\(\s*{deadline_param}\s*\)',
                    rf'isValid\(\s*{deadline_param}\s*\)'
                ]
            
            if any(re.search(p, condition_content) for p in deadline_patterns):
                requirements['deadline_check'] = True

        # Check for timestamp validation (separate from deadline)
        if not requirements['timestamp_check']:
            timestamp_patterns = [
                r'block\.timestamp',
                r'now\s*[<>=]',
                r'timestamp\s*[<>=]'
            ]
            if any(re.search(p, condition_content) for p in timestamp_patterns):
                requirements['timestamp_check'] = True

        # Check for signature validation
        if (v_param and r_param and s_param) and not requirements['signature_validation']:
            sig_patterns = [
                r'ecrecover\s*\(',
                r'ECDSA\.recover\s*\(',
                r'signature\s*=\s*abi\.encodePacked\s*\(',
                r'\.verify\s*\('
            ]
            if any(re.search(p, condition_content) for p in sig_patterns):
                requirements['signature_validation'] = True

        # Check for nonce usage
        if not requirements['nonce_usage']:
            if re.search(r'nonces\[', condition_content) or re.search(r'incrementNonce\s*\(', condition_content):
                requirements['nonce_usage'] = True

    # Additional checks that don't depend on conditions
    for code, source in all_code:
        # Check for DOMAIN_SEPARATOR usage
        if not requirements['domain_separator_usage']:
            if re.search(r'DOMAIN_SEPARATOR', code) or re.search(r'domainSeparator\s*\(', code):
                requirements['domain_separator_usage'] = True

        # Check for permit function existence
        if not requirements['permit_function_exists']:
            if re.search(r'function\s+permit\s*\(', code):
                requirements['permit_function_exists'] = True

        # Check for owner validation
        if owner_param and not requirements['owner_check']:
            owner_patterns = [
                rf'{owner_param}\s*==\s*msg\.sender',
                rf'msg\.sender\s*==\s*{owner_param}',
                rf'isOwner\(\s*{owner_param}\s*\)',
                rf'ownerOf\(\s*{owner_param}\s*\)'
            ]
            if any(re.search(p, code) for p in owner_patterns):
                requirements['owner_check'] = True

        # Check for spender approval
        if spender_param and not requirements['spender_approval']:
            if re.search(rf'approve\(\s*{spender_param}\s*,', code):
                requirements['spender_approval'] = True

    return requirements


def verify_erc5267_requirements(target_func: Dict, internal_functions: List[Dict]) -> Dict:
    """Verify ERC-5267 compliance with enhanced security checks.
    
    Args:
        target_func: The eip712Domain function to analyze
        internal_functions: List of related internal functions
        
    Returns:
        Dict containing verification results and warnings
    """
    requirements = {
        # Core compliance checks
        'eip712Domain_function_exists': False,
        'returns_correct_fields': False,
        'typehash_declared': False,
        'domain_separator_usage': False,
        
        # Field-specific validations
        'fields': {
            'valid': False,
            'value': None,
            'required_bits': {'name': True, 'version': True, 'chainId': True, 
                             'verifyingContract': True, 'salt': False, 'extensions': False}
        },
        'name': {'valid': False, 'immutable': False, 'non_empty': False},
        'version': {'valid': False, 'immutable': False},
        'chainId': {'valid': False, 'uses_block_chainid': False},
        'verifyingContract': {'valid': False, 'uses_address_this': False, 'proxy_safe': False},
        'salt': {'valid': False, 'non_zero': False},
        'extensions': {'valid': False, 'non_empty': False},
        
        # Security flags
        'warnings': [],
        'critical_issues': []
    }

    # Combine all code to analyze
    all_code = [(target_func['body'], "main function")]
    for func in internal_functions:
        if target_func['body'] != func['body']:
            all_code.append((func['body'], f"internal function {func['name']}"))

    # Enhanced patterns
    eip712_domain_pattern = re.compile(
        r'function\s+eip712Domain\s*\(\s*\)\s*(?:external|public)\s+view\s+returns\s*\(\s*'
        r'bytes1\s+\w+\s*,\s*'          # fields
        r'string\s+(?:memory\s+)?\w+\s*,\s*'  # name
        r'string\s+(?:memory\s+)?\w+\s*,\s*'  # version
        r'uint256\s+\w+\s*,\s*'         # chainId
        r'address\s+\w+\s*,\s*'         # verifyingContract
        r'bytes32\s+\w+\s*,\s*'         # salt
        r'uint256\[\]\s+(?:memory\s+)?\w+\s*\)',  # extensions
        re.DOTALL
    )

    return_pattern = re.compile(
        r'return\s*\(\s*'
        r'(bytes1\(.*?\)|hex"[0-9a-fA-F]+"|[\w\d]+)\s*,\s*'  # fields
        r'("[^"]*"|_\w+\.toString\(\)|[\w\d]+)\s*,\s*'       # name
        r'("[^"]*"|_\w+\.toString\(\)|[\w\d]+)\s*,\s*'       # version
        r'(block\.chainid|_\w+|\d+)\s*,\s*'                  # chainId
        r'(address\(this\)|_\w+|\w+)\s*,\s*'                 # verifyingContract
        r'(bytes32\(.*?\)|_\w+|0x[0-9a-fA-F]+)\s*,\s*'       # salt
        r'(new\s*uint256\[\]\(.*?\)|_\w+|\[\])\s*\)\s*;',    # extensions
        re.DOTALL
    )

    # Immutability checks
    immutable_pattern = re.compile(r'(?:immutable|constant)\s+(string|bytes32)\s+(_name|_version|_hashedName|_salt)')
    
    for code, source in all_code:
        # Check function existence and signature
        if eip712_domain_pattern.search(code):
            requirements['eip712Domain_function_exists'] = True
            
            # Check return values
            if return_match := return_pattern.search(code):
                fields, name, version, chainId, verifyingContract, salt, extensions = return_match.groups()
                
                # Validate fields bitmap
                if hex_match := re.search(r'hex"([0-9a-fA-F]{1,2})"', fields):
                    fields_hex = int(hex_match.group(1), 16)
                    requirements['fields']['value'] = fields_hex
                    # Verify all required bits are set
                    required_bits = 0x0f  # 00001111 in binary (name|version|chainId|verifyingContract)
                    if (fields_hex & required_bits) == required_bits:
                        requirements['fields']['valid'] = True
                    else:
                        requirements['critical_issues'].append(
                            f"Fields bitmap 0x{fields_hex:x} missing required bits (needs 0x{required_bits:x})"
                        )
                
                # Validate name
                if re.match(r'".+"', name) or ('toString()' in name and '_name' in name):
                    requirements['name']['non_empty'] = True
                    requirements['name']['valid'] = True
                    if '_name' in name and 'immutable' in code:
                        requirements['name']['immutable'] = True
                
                # Validate version (can be empty)
                if re.match(r'""|".+"', version) or ('toString()' in version and '_version' in version):
                    requirements['version']['valid'] = True
                    if '_version' in version and 'immutable' in code:
                        requirements['version']['immutable'] = True
                
                # Validate chainId
                if 'block.chainid' in chainId.lower():
                    requirements['chainId']['uses_block_chainid'] = True
                    requirements['chainId']['valid'] = True
                else:
                    requirements['warnings'].append("chainId should use block.chainid for fork safety")
                
                # Validate verifyingContract
                if 'address(this)' in verifyingContract.lower():
                    requirements['verifyingContract']['uses_address_this'] = True
                    requirements['verifyingContract']['valid'] = True
                    # Check for proxy patterns
                    if re.search(r'\.delegatecall', code) or re.search(r'proxy', code, re.I):
                        requirements['verifyingContract']['proxy_safe'] = False
                        requirements['critical_issues'].append(
                            "Proxy pattern detected but no proxy address handling"
                        )
                
                # Validate salt
                if 'bytes32(' in salt or re.match(r'0x[0-9a-fA-F]{64}', salt):
                    requirements['salt']['valid'] = True
                    if not ('0' in salt or '00' in salt):
                        requirements['salt']['non_zero'] = True
                    if '_salt' in salt and 'immutable' in code:
                        requirements['salt']['immutable'] = True
                
                # Validate extensions
                if 'new uint256[]' in extensions or '[]' in extensions:
                    requirements['extensions']['valid'] = True
                    if not ('[]' in extensions or '0' in extensions):
                        requirements['extensions']['non_empty'] = True
            
            # Check for immutability of critical parameters
            if immutable_pattern.search(code):
                for match in immutable_pattern.finditer(code):
                    var_type, var_name = match.groups()
                    if var_name == '_name':
                        requirements['name']['immutable'] = True
                    elif var_name == '_version':
                        requirements['version']['immutable'] = True
                    elif var_name == '_salt':
                        requirements['salt']['immutable'] = True
    
    # Additional security checks
    for code, source in all_code:
        # Domain separator usage check
        if re.search(r'_domainSeparatorV4\(\)|DOMAIN_SEPARATOR', code):
            requirements['domain_separator_usage'] = True
        
        # Typehash declaration check
        if re.search(
            r'bytes32\s+[A-Z_]+\s*=\s*keccak256\s*\(\s*"EIP712Domain\s*\(.*?\)\s*"\)',
            code
        ):
            requirements['typehash_declared'] = True
    
    # Final validation logic
    if requirements['eip712Domain_function_exists']:
        requirements['returns_correct_fields'] = all([
            requirements['fields']['valid'],
            requirements['name']['valid'],
            requirements['version']['valid'],
            requirements['chainId']['valid'],
            requirements['verifyingContract']['valid'],
            requirements['salt']['valid'],
            requirements['extensions']['valid']
        ])
        
        # Add critical issues if immutable params aren't enforced
        if not requirements['name']['immutable']:
            requirements['critical_issues'].append("name parameter should be immutable")
        if not requirements['version']['immutable']:
            requirements['warnings'].append("version parameter should be immutable for security")
    
    return requirements


def check_on_received_implementation(code: str, params, isContract) -> bool:
    # Get parameters by position (assuming standard ERC1155 order)
    from_param = params['from_param']
    to_param = params['to_param']
    ids_param = params['ids_param']
    amounts_param = params['amounts_param']
    data_param = params['data_param']
    
    # Operator is typically not a parameter in safeBatchTransferFrom,
    # but comes from msg.sender in the actual call
    operator_param = "operator"
    
    operator_var = None
    operator_assignment = re.search(
        r'(address\s+(\w+)\s*=\s*(?:msg\.sender|_msgSender\(\))\s*;)',
        code
    )
    
    if operator_assignment:
        operator_var = operator_assignment.group(2)
        
    
    # Normalize code by removing comments and extra spaces
    normalized_code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
    normalized_code = re.sub(r'\s+', ' ', normalized_code)
    
    if not isContract:
        # 1. Check for isContract() guard
        if not re.search(rf'if\s*\(\s*{to_param}\s*\.\s*isContract\s*\(\s*\)\s*\)', normalized_code):
            # print(f"no is isContract() check")
            return False
    
    # 2. Check for onERC1155BatchReceived call with increasingly flexible parameter matching
    receiver_pattern = None
    param_matched = False
    
    
    # Attempt 1: Exact parameter name matching (with operator or msg.sender)
    if not param_matched:
        param_patterns = [
        operator_var or operator_param or r'(msg\.sender|_msgSender\(\))',
        from_param or r'_\w+',
        ids_param or r'_\w+',
        amounts_param or r'_\w+',
        data_param or r'_\w+'
        ]
        receiver_pattern = (
            r'\.onERC1155BatchReceived'
            r'(?:\s*\{[^}]*\})?'
            r'\s*\(\s*'
            + r'\s*,\s*'.join(param_patterns) +
            r'\s*\)'
        )
        # print(f"receiver_pattern:{receiver_pattern}")
        param_matched = re.search(receiver_pattern, normalized_code) is not None
        # print(f"param_matched:{param_matched}")
    
    # Attempt 2: Type-based parameter matching
    if not param_matched:
        type_patterns = [
            r'address',        # operator
            r'address',        # from
            r'uint256\[\]',    # ids
            r'uint256\[\]',    # amounts
            r'bytes'           # data
        ]
        receiver_pattern = (
            r'\.onERC1155BatchReceived'
            r'(?:\s*\{[^}]*\})?'
            r'\s*\(\s*'
            r'[^,)]+\s*,\s*' * 4 +  # First 4 params
            r'[^)]+'                # Last param
            r'\s*\)'
        )
        
        # print(f"receiver_pattern:{receiver_pattern}")
        call_match = re.search(receiver_pattern, normalized_code)
        # print(f"call_match:{call_match}")
        if call_match:
            # Then check if the surrounding code has matching types
            context = normalized_code[max(0, call_match.start()-100):call_match.end()+100]
            param_matched = all(
                re.search(type_pattern, context)
                for type_pattern in type_patterns
            )
    
    # Attempt 3: Simple parameter count check
    if not param_matched:
        receiver_pattern = (
            r'\.onERC1155BatchReceived'
            r'(?:\s*\{[^}]*\})?'
            r'\s*\(\s*'
            r'([^,)]+\s*,\s*){4}'  # Exactly 4 commas = 5 params
            r'[^)]+'               # Last param
            r'\s*\)'
        )
        param_matched = re.search(receiver_pattern, normalized_code) is not None
        # print(f"param_matched:{param_matched}")
    
    if param_matched:
        print("parameters matched")
    else:
        print("Failed to match receiver parameters with any method")
        # return False
    
    # 3. Check return value capture
    return_valid = False
    
    # Optimized pattern that will definitely work
    pattern = r'''
        (?:require|if)\s*\(                          # Start with require or if
        [^)]*?                                       # Any characters (non-greedy)
        (?:[a-zA-Z_][\w.]*\s*\(\s*[^)]*\s*\)\s*\.)? # Optional contract prefix with params
        onERC1155BatchReceived\s*\(                  # The target function
        [^)]*                                        # Parameters
        \s*\)                                        # Closing paren of function call
        [^)]*                                        # Any remaining condition
        \)                                           # Closing paren of require/if
    '''

    # Use re.VERBOSE to allow comments and ignore whitespace in pattern
    if re.search(pattern, normalized_code, re.VERBOSE | re.DOTALL) and param_matched:
        return_valid = True
    
    # Approach 2: Check for bytes4 return value capture and validation
    if not return_valid:
        # Pattern to capture the return value assignment
        retval_pattern = (
            r'(bytes4\s+(\w+)\s*=\s*'  # Return value declaration
            r'[^;]*?\.onERC1155BatchReceived'
            r'(?:\s*\{[^}]*\})?'
            r'\([^)]+\)'
            r'\s*;)'
        )
        
        retval_match1 = re.search(retval_pattern, normalized_code)
            
        if retval_match1:
            retval_name = retval_match1.group(2)
            # print(f"retval_name:{retval_name}")
            retval_check_pattern = (
                r'(?:require|if)\s*\(\s*' + 
                re.escape(retval_name) + 
                r'\s*(==|!=)\s*[^)]+' +
                r'\s*\)'
)
            if re.search(retval_check_pattern, normalized_code):
                return_valid = True
    
    # Approach 3: Check returns() clause in try-catch pattern
    if not return_valid:
        returns_pattern = (
            r'try\s+[^.]*\.onERC1155BatchReceived'
            r'(?:\s*\{[^}]*\})?'
            r'\([^)]+\)'
            r'\s+returns\s*\(\s*bytes4\s+(\w+)\s*\)'
        )
        returns_match = re.search(returns_pattern, normalized_code)
        
        
        if returns_match:
            retval_name = returns_match.group(1)
            # print(f"retval_name :{retval_name}")
            
            # Check if the return value is used in the try block
            try_block_pattern = (
                r'(?:require|if)\s*\(\s*[^)]*?' + 
                re.escape(retval_name) + 
                r'[^)]*\)'
            )
            
            if re.search(try_block_pattern, normalized_code, re.DOTALL):
                return_valid = True
    
    if not return_valid:
        print("Failed to validate return value check")
        return False
    
    return True


def analyze_safe_batch_transfer(solidity_code: str, target_sig) -> Dict:
    """Main analysis function for safeBatchTransferFrom compliance."""
    all_functions = find_all_functions(solidity_code)
    
    target_funcs = find_functions_by_signature(all_functions, target_sig)
    # print(f"target_funcs:{target_funcs}")
    
    if not target_funcs:
        return {"error": "safeBatchTransferFrom function not found"}
    
    results = []
    for target_func in target_funcs:
        internal_calls = get_all_internal_calls(target_func['body'], all_functions)
        
        # Skip analysis if we got None (self-recursive call detected)
        # if internal_calls is None:
        #     continue
            
        print(f"\nAnalyzing function implementation: {target_func['name']}")
        print("Found internal calls:", [f['name'] for f in internal_calls])
        # if "safeBatchTransferFrom" in target_sig:
        requirements = verify_erc1155_requirements(target_func, internal_calls)
        # if "permit" in target_sig:
        #     requirements = verify_erc2612_requirements(target_func, internal_calls)
        # if "eip712Domain" in target_sig:
        #     requirements = verify_erc5267_requirements(target_func, internal_calls)
        # Calculate whether all requirements are met for this implementation
        all_reqs = [
            'sender_check',
            'approval_check',
            'zero_address_check',
            'length_matching_check',
            'event_emission_before_transfers',
            'transfer_batch_event_found',
            'to_isContract_check',
            'on_received_check'
        ]
        all_met = all(requirements.get(req, False) for req in all_reqs)
        some_met = any(requirements.get(req, False) for req in all_reqs)
        
        results.append({
            "function": target_func['name'],
            "implementation_location": f"Line {target_func['start']}-{target_func['end']}",
            "parameters": target_func.get('parameters', {}),
            "requirements": requirements,
            "internal_calls": [f['name'] for f in internal_calls],
            # "transfer_batch_event_found": requirements.get('transfer_batch_event_found', False),
            # "on_received_check_found": requirements.get('on_received_check', False),
            # "all_requirements_met": all_met,
            # "some_requirements_met": some_met
        })
    
    # Return consolidated results
    if results:
        return {
            "all_implementations": results,
            # "summary": {
            #     "total_implementations": len(results),
            #     "fully_compliant": sum(1 for r in results if r.get('all_requirements_met', False)),
            #     "partially_compliant": sum(1 for r in results if r.get('some_requirements_met', False))
            # }
        }
    return {"error": "No valid implementations found (possibly due to recursive calls)"}

def analyze_directory(directory_path: str, output_file, target_sig) -> List[Dict]:
    """Analyze all Solidity files in a directory for ERC1155 compliance."""
    results = []
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.sol'):
                # file.startswith("ERC1155_0xedbaee53b410d2c59f1b73144e8d500e94b496a0.sol") and
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        solidity_code = f.read()
                    
                    result = analyze_safe_batch_transfer(solidity_code, target_sig)
                    result['file'] = file_path
                    results.append(result)
                    """Save analysis results to a JSON file."""
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=2)
                    print(f"Analysis complete. Results saved to {output_file}")
                    
                except Exception as e:
                    results.append({
                        'file': file_path,
                        'error': f"Error processing file: {str(e)}"
                    })
    
    return results

def save_results_to_json(results: List[Dict], output_path: str) -> None:
    """Save analysis results to a JSON file."""
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

def find_all_functions(solidity_code: str) -> List[Dict]:
    """Find all function declarations in Solidity code, handling both implementations and interfaces."""
    # Pattern to match both:
    # 1. Full function implementations (with body)
    # 2. Interface function declarations (ending with ;)
    func_pattern = re.compile(
        r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)'  # Function name and params
        r'([^{;]*)'                                           # Modifiers
        r'(?:\{)',                                          # Body start or declaration end
        re.DOTALL
    )
    
    functions = []
    for match in func_pattern.finditer(solidity_code):
        func_name = match.group(1)
        params = match.group(2).strip()
        modifiers = match.group(3).strip()
        start_pos = match.start()
        declaration_end = match.end()
        
        # Determine if this is an implementation (has body) or interface declaration
        if solidity_code[declaration_end - 1] == '{':
            # Implementation with body
            open_brace_pos = declaration_end - 1
            brace_level = 1
            close_brace_pos = open_brace_pos + 1
            
            while brace_level > 0 and close_brace_pos < len(solidity_code):
                char = solidity_code[close_brace_pos]
                if char == '{':
                    brace_level += 1
                elif char == '}':
                    brace_level -= 1
                close_brace_pos += 1
            
            if brace_level == 0:
                functions.append({
                    'name': func_name,
                    'params': params,
                    'modifiers': modifiers,
                    'start': start_pos,
                    'end': close_brace_pos,
                    'body': solidity_code[start_pos:close_brace_pos].strip(),
                    'is_implementation': True
                })
        else:
            # Interface declaration (ends with semicolon)
            functions.append({
                'name': func_name,
                'params': params,
                'modifiers': modifiers,
                'start': start_pos,
                'end': declaration_end,
                'body': solidity_code[start_pos:declaration_end].strip(),
                'is_implementation': False
            })
    
    return functions

def normalize_signature(signature: str) -> str:
    """Normalize function signature for comparison, matching Etherscan's behavior.
    Converts 'uint' to 'uint256' but preserves explicit sizes like 'uint8'."""
    if '(' not in signature:
        return signature
    
    func_name = signature.split('(')[0].strip()
    params = signature[len(func_name):].strip('()').split(',')
    
    param_types = []
    for param in params:
        param = param.strip()
        # Remove parameter name if present (anything after last space)
        if ' ' in param:
            param = param.rsplit(' ', 1)[0].strip()
        # Remove storage location keywords
        param = re.sub(r'\s+(memory|calldata|storage)\b', '', param)
        # Convert 'uint' to 'uint256' but keep 'uint8', 'uint16', etc.
        if param == 'uint':
            param = 'uint256'
        elif re.match(r'uint(?!\d)', param):  # catches 'uint' followed by non-digit
            param = 'uint256'
        param_types.append(param)
    
    normalized = f"{func_name}({','.join(param_types)})"
    return normalized

def get_parameter_dict(params_str: str) -> Dict[str, str]:
    """Convert parameters string to dictionary of name: type"""
    params = {}
    for param in params_str.split(','):
        param = param.strip()
        if param:
            parts = [p.strip() for p in param.split()]
            if len(parts) >= 2:
                param_type = ' '.join(parts[:-1])
                param_name = parts[-1]
                params[param_name] = param_type
    return params

def get_function_parameters(function_body: str) -> Dict[str, str]:
    """Extract parameter names and types from function signature."""
    params = {}
    # Match function parameters
    param_pattern = re.compile(r'function\s+\w+\s*\((.*?)\)')
    match = param_pattern.search(function_body)
    if match:
        param_list = match.group(1).split(',')
        for param in param_list:
            param = param.strip()
            if param:
                parts = param.split()
                if len(parts) >= 2:
                    param_type = parts[-2]
                    param_name = parts[-1]
                    params[param_name] = param_type
    return params


if __name__ == "__main__":
    
    # erc1155_directory = "/home/ashok/output/ERC1155_Solidity_SourceCode/ERC1155"
    # erc1155_output_file = "/home/ashok/ERC-analysis/erc-classify/erc1155_TEST_TEST_analysis_results.json"
    # erc1155_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source/ERC1155"
    erc1155_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC1155_Solidity_SourceCode/ERC1155"
    
    # erc1155_output_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc1155_TEST_TEST_analysis_results.json"
    erc1155_output_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc1155_ONE_analysis_results.json"
    # erc1155_directory = "/home/ashok/ERC-analysis/erc-classify/ERC_Solidity_Source/ERC1155"
    # erc1155_output_file = "/home/ashok/ERC-analysis/erc-classify/erc1155_analysis_results.json"
    erc1155_target_sig = "safeBatchTransferFrom(address from, address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)"
    
    # analysis_results = analyze_directory(erc1155_directory, erc1155_output_file, erc1155_target_sig)
    # save_results_to_json(analysis_results, output_file)
    
    # erc2612_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source/ERC2612"
    # erc2612_output_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc2612_analysis_results.json"
    # erc2612_target_sig = "permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s)"
    # analysis_results = analyze_directory(erc2612_directory, erc2612_output_file, erc2612_target_sig)
    
    erc5267_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source/ERC5267"
    erc5267_output_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc5267_analysis_results.json"
    erc5267_target_sig = "eip712Domain()"
    analysis_results = analyze_directory(erc1155_directory, erc1155_output_file, erc1155_target_sig)
    
    print(f"Total files analyzed: {len(analysis_results)}")
    
    # print(f"analysis_results requirements: {analysis_results}")
    
    # Print summary statistics
    compliant_files = [r for r in analysis_results if not r.get('error')]
    print(f"\nFiles with safeBatchTransferFrom implementation: {len(compliant_files)}")
    
    if compliant_files:
        # Collect all implementations across all files
        all_implementations = []
        for result in compliant_files:
            if 'all_implementations' in result:
                all_implementations.extend(result['all_implementations'])
        
        if all_implementations:
            print("\nRequirement compliance summary across all implementations:")
            for req in ['sender_check', 'approval_check', 'zero_address_check', 
                       'length_matching_check', 
                       'event_emission_before_transfers',
                       'transfer_batch_event_found', 'to_isContract_check', 'on_received_check']:
                count = sum(1 for impl in all_implementations 
                          if impl.get('requirements', {}).get(req, False))
                print(f"- {req}: {count}/{len(all_implementations)} compliant")
            
            # Print overall compliance
            fully_compliant = sum(
                1 for impl in all_implementations
                if all(impl.get('requirements', {}).get(req, False) 
                    for req in ['sender_check', 'approval_check', 'zero_address_check',
                                'length_matching_check', 'event_emission_before_transfers',
                                'transfer_batch_event_found', 'to_isContract_check', 
                                'on_received_check'])
            )
            print(f"\nFully compliant implementations: {fully_compliant}/{len(all_implementations)}")
    
    error_files = [r for r in analysis_results if r.get('error')]
    if error_files:
        print("\nFiles with processing errors:")
        for file in error_files:
            print(f"- {file['file']}: {file['error']}")