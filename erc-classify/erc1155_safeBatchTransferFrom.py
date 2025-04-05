import os
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from eth_utils import keccak

def find_functions_by_signature(functions: List[Dict], target_signature: str) -> List[Dict]:
    """Find all functions matching the normalized signature with parameter types."""
    target_normalized = normalize_signature(target_signature)
    target_normalized_hash = keccak(text=target_normalized).hex()
    print(f"target_normalized_hash:{target_normalized_hash}")
    matching_functions = []
    
    for func in functions:
        current_sig = f"{func['name']}({func['params']})"
        current_normalized = normalize_signature(current_sig)
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
            
            # Skip keywords and built-ins
            if (call_name.lower() in {
                'require', 'assert', 'revert', 'emit', 'new', 'return',
                'returns', 'if', 'try', 'iscontract', 'continue', 'break',
                'for', 'while', 'do', 'else', 'catch', 'delete', 'length'
            } or call_name in {
                'gasleft', 'msg', 'block', 'tx', 'abi', 'type', 'this',
                'super', 'selfdestruct', 'sha3', 'keccak256', 'ripemd160',
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
                    # Skip self-references
                    if func['body'] == function_body:
                        continue
                    
                    # Only process if we haven't visited this function before
                    if call_name not in visited:
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
        'balance_checks': False,
        'event_emission_before_transfers': False,
        'transfer_batch_event_found': False,
        'to_isContract_check':False,
        'on_received_check': False
        
    }
    
    
    params = extract_parameters(target_func)
    from_param = params['from_param']
    to_param = params['to_param']
    ids_param = params['ids_param']
    amounts_param = params['amounts_param']
    data_param = params['data_param']
    
    # Combine all code to analyze (main function + internal calls)
    all_code = [(target_func['body'], "main function")]
    for func in internal_functions:
        if target_func['body'] != func['body'] and len(internal_functions) != 1:
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
    sender_reprs = ['msg.sender', '_msgSender()']
    
    # Check conditions
    for condition_content, condition_source, condition_type in all_conditions:
        # Check for sender condition
        if from_param and not requirements['sender_check']:
            for sender in sender_reprs:
                if condition_type == "if-revert" :
                    pattern1 = rf'{re.escape(sender)}\s*!=\s*{from_param}'
                    pattern2 = rf'{from_param}\s!=\s*{re.escape(sender)}'
                    if re.search(pattern1, condition_content) or re.search(pattern2, condition_content):
                        requirements['sender_check'] = True
                        break
                    
                if condition_type == "require":
                    pattern3 = rf'{re.escape(sender)}\s*==\s*{from_param}'
                    pattern4 = rf'{from_param}\s*==\s*{re.escape(sender)}'
                    if re.search(pattern3, condition_content) or re.search(pattern4, condition_content):
                        requirements['sender_check'] = True
                        break

        # Check for approval condition
        if from_param and not requirements['approval_check']:
            for sender in sender_reprs:
                if condition_type == "if-revert":
                    pattern1 = rf'!isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)'
                    exact_pattern1 = rf'operatorApproval\[{from_param}\]\[{re.escape(sender)}\]\s*==\s*false'
                    if re.search(pattern1, condition_content) or re.search(exact_pattern1, condition_content, re.IGNORECASE):
                        requirements['approval_check'] = True
                        break
                    if not requirements['approval_check']:
                        if (re.search(r'Approval', condition_content, re.IGNORECASE) and
                            re.search(rf'{from_param}', condition_content) and
                            re.search(rf'{re.escape(sender)}', condition_content) and
                            re.search(r'false', condition_content, re.IGNORECASE)):
                            requirements['approval_check'] = True
                            break
                if condition_type == "require" :
                    pattern2 = rf'isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)'
                    # Check for operatorApproval[from][sender] == true
                    exact_pattern2 = rf'operatorApproval\[{from_param}\]\[{re.escape(sender)}\]\s*==\s*true'
                    
                    if re.search(pattern2, condition_content) or re.search(exact_pattern2, condition_content, re.IGNORECASE):
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
                rf'address\(0x0\)\s*==\s*{to_param}'
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
                rf'address\(0x0\)\s*!=\s*{to_param}'
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
                rf'{amounts_param}\.length\s*[!=]=\s*{ids_param}\.length'
                ]
            assigned_patterns = []
            for var_name in length_assignments:
                assigned_patterns.extend([
                    rf'{var_name}\s*[!=]=\s*{amounts_param}\.length',
                    rf'{amounts_param}\.length\s*[!=]=\s*{var_name}'
                ])
            if any(re.search(p, condition_content) for p in direct_patterns + assigned_patterns):
                requirements['length_matching_check'] = True
  
        # Check for balance checks
        if from_param and ids_param and amounts_param and not requirements['balance_checks']:
            balance_pattern = rf'balanceOf\(\s*{from_param}\s*,\s*{ids_param}\[i\]\)\s*>=\s*{amounts_param}\[i\]'
            if re.search(balance_pattern, condition_content):
                requirements['balance_checks'] = True
    
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
        if re.search(rf'if\s*\(\s*{to_param}\s*\.\s*isContract()\s*\(\s*\)\s*\)', normalized_code):
            requirements['to_isContract_check'] = True
        # Check for onReceived implementation in functions called after the event
        if event_pos and source != event_pos[0]:
            if requirements['to_isContract_check'] and check_on_received_implementation(code, params, requirements['to_isContract_check']):
                requirements['on_received_check'] = True
            elif not requirements['to_isContract_check'] and check_on_received_implementation(code, params, requirements['to_isContract_check']):
                requirements['on_received_check'] = True

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


def analyze_safe_batch_transfer(solidity_code: str) -> Dict:
    """Main analysis function for safeBatchTransferFrom compliance."""
    all_functions = find_all_functions(solidity_code)
    target_sig = "safeBatchTransferFrom(address from, address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data)"
    target_funcs = find_functions_by_signature(all_functions, target_sig)
    
    if not target_funcs:
        return {"error": "safeBatchTransferFrom function not found"}
    
    results = []
    for target_func in target_funcs:
        internal_calls = get_all_internal_calls(target_func['body'], all_functions)
        
        # Skip analysis if we got None (self-recursive call detected)
        if internal_calls is None:
            continue
            
        print(f"\nAnalyzing function implementation: {target_func['name']}")
        print("Found internal calls:", [f['name'] for f in internal_calls])
        
        requirements = verify_erc1155_requirements(target_func, internal_calls)
        
        results.append({
            "function": target_func['name'],
            "implementation_location": f"Line {target_func['start']}-{target_func['end']}",
            "parameters": target_func.get('parameters', {}),
            "requirements": requirements,
            "internal_calls": [f['name'] for f in internal_calls],
            "transfer_batch_event_found": requirements.get('transfer_batch_event_found', False),
            "on_received_check_found": requirements.get('on_received_check', False)
        })
    
    # Return consolidated results
    if results:
        return {
            "all_implementations": results,
            "summary": {
                "total_implementations": len(results),
                "fully_compliant": all(r['requirements'].get('all_requirements_met', False) for r in results),
                "partially_compliant": any(r['requirements'].get('some_requirements_met', False) for r in results)
            }
        }
    return {"error": "No valid implementations found (possibly due to recursive calls)"}

def analyze_directory(directory_path: str) -> List[Dict]:
    """Analyze all Solidity files in a directory for ERC1155 compliance."""
    results = []
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.sol'):
                # file .startswith("ERC1155_0xf98502110") and
                
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        solidity_code = f.read()
                    
                    result = analyze_safe_batch_transfer(solidity_code)
                    result['file'] = file_path
                    results.append(result)
                    
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
    """Normalize function signature for comparison, matching Etherscan's behavior."""
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
    erc1155_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source/ERC1155"
    output_file = "erc1155_analysis_results.json"
    
    analysis_results = analyze_directory(erc1155_directory)
    save_results_to_json(analysis_results, output_file)
    
    print(f"Analysis complete. Results saved to {output_file}")
    print(f"Total files analyzed: {len(analysis_results)}")
    
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
                       'length_matching_check', 'balance_checks', 
                       'event_emission_before_transfers',
                       'transfer_batch_event_found', 'to_isContract_check', 'on_received_check']:
                count = sum(1 for impl in all_implementations 
                          if impl.get('requirements', {}).get(req, False))
                print(f"- {req}: {count}/{len(all_implementations)} compliant")
            
            # Print overall compliance
            fully_compliant = sum(1 for result in compliant_files 
                                if result.get('summary', {}).get('fully_compliant', False))
            print(f"\nFully compliant implementations: {fully_compliant}/{len(all_implementations)}")
    
    error_files = [r for r in analysis_results if r.get('error')]
    if error_files:
        print("\nFiles with processing errors:")
        for file in error_files:
            print(f"- {file['file']}: {file['error']}")