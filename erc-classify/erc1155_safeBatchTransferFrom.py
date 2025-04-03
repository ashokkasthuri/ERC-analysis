import os
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from eth_utils import keccak

def find_functions_by_signature(functions: List[Dict], target_signature: str) -> List[Dict]:
    """Find all functions matching the normalized signature with parameter types."""
    target_normalized = normalize_signature(target_signature)
    target_normalized_hash = keccak(text=target_normalized).hex()
    
    matching_functions = []
    
    for func in functions:
        current_sig = f"{func['name']}({func['params']})"
        current_normalized = normalize_signature(current_sig)
        current_normalized_hash = keccak(text=current_normalized).hex()
        # print(f"current_normalized:{current_normalized}")
        
        if current_normalized_hash == target_normalized_hash:
            # Add parameters to function info
            func['parameters'] = get_parameter_dict(func['params'])
            matching_functions.append(func)
    
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
                    visited.add(call_name)
                    internal_calls.append(func)
                    # Recursively get calls from this function
                    internal_calls.extend(get_all_internal_calls(func['body'], all_functions, visited))
                    break
            
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
    
    return internal_calls


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
        'on_received_check': False
    }
    
    # Get parameter names from the target function
    params = target_func.get('parameters', {})
    from_param = next((k for k in params if k.lower() in ['from', '_from']), None)
    to_param = next((k for k in params if k.lower() in ['to', '_to']), None)
    ids_param = next((k for k in params if k.lower() in ['ids', '_ids']), None)
    amounts_param = next((k for k in params if k.lower() in ['amounts', '_amounts']), None)
    
    # Combine all code to analyze (main function + internal calls)
    all_code = [(target_func['body'], "main function")]
    # print (f"all_code:{all_code}")
    for func in internal_functions:
        
        all_code.append((func['body'], f"internal function {func['name']}"))
        
            
    
    
    # print(f"Debug: all_code:{all_code}")
    # Track all require statements
    all_requires = []
    event_pos = None
    
    for code, source in all_code:
        # Improved require statement extraction that handles multi-line requires
        requires = []
        require_matches = re.finditer(r'require\s*\(((?:[^()]|\((?:[^()]|\([^()]*\))*\))*)\)', code, re.DOTALL)
        # print(f"code:{code}")
        # print(f"source:{source}")
        for match in require_matches:
            # Clean up the require content
            req_content = match.group(1)
            req_content = re.sub(r'\s+', ' ', req_content.strip())
            requires.append(req_content)
        all_requires.extend([(req, source) for req in requires])
        
        
        # Possible sender representations
        sender_reprs = ['msg.sender', '_msgSender()']
        
        # Check for sender condition in any require
        if from_param:
            for req, _ in all_requires:
                for sender in sender_reprs:
                    # Check both "sender == from" and "from == sender" patterns
                    pattern1 = rf'{re.escape(sender)}\s*==\s*{from_param}'
                    pattern2 = rf'{from_param}\s*==\s*{re.escape(sender)}'
                    if re.search(pattern1, req) or re.search(pattern2, req):
                        requirements['sender_check'] = True
                        break
                if requirements['sender_check']:
                    break
        
        # Check for approval condition in any require
        if from_param:
            for req, _ in all_requires:
                for sender in sender_reprs:
                    pattern = rf'isApprovedForAll\(\s*{from_param}\s*,\s*{re.escape(sender)}\s*\)'
                    if re.search(pattern, req):
                        requirements['approval_check'] = True
                        break
                if requirements['approval_check']:
                    break
        
        # Check for zero address condition in any require
        if to_param:
            zero_addr_patterns = [
                rf'{to_param}\s*!=\s*address\(0\)',
                rf'address\(0\)\s*!=\s*{to_param}'
            ]
            for req, _ in all_requires:
                for pattern in zero_addr_patterns:
                    if re.search(pattern, req):
                        requirements['zero_address_check'] = True
                        break
                if requirements['zero_address_check']:
                    break
        
        # Check for length matching condition in any require
        if ids_param and amounts_param:
            length_patterns = [
                rf'{ids_param}\.length\s*==\s*{amounts_param}\.length',
                rf'{amounts_param}\.length\s*==\s*{ids_param}\.length'
            ]
            for req, _ in all_requires:
                for pattern in length_patterns:
                    if re.search(pattern, req):
                        requirements['length_matching_check'] = True
                        break
                if requirements['length_matching_check']:
                    break
        
        # Check for balance checks in any require
        if from_param and ids_param and amounts_param:
            balance_pattern = rf'balanceOf\(\s*{from_param}\s*,\s*{ids_param}\[i\]\)\s*>=\s*{amounts_param}\[i\]'
            for req, _ in all_requires:
                if re.search(balance_pattern, req):
                    requirements['balance_checks'] = True
                    break
        
        # Event emission check
        if 'emit TransferBatch(' in code and not requirements['transfer_batch_event_found']:
            requirements['transfer_batch_event_found'] = True
            event_pos = (source, code.find('emit TransferBatch('))

    # Check for onReceived in functions called after the event
    if event_pos:
        event_source, event_pos_num = event_pos
        found_event = False
        
        for code, source in all_code:
            if source == event_source:
                found_event = True
                continue
            if found_event:
                # Use the dedicated checker for onReceived implementation
                if check_on_received_implementation(code, target_func.get('parameters', {})):
                    requirements['on_received_check'] = True
                    break

    # Check if transfers happen after event emission
    if requirements['transfer_batch_event_found']:
        for code, source in all_code:
            if source == event_source:
                event_pos = code.find('emit TransferBatch(')
                post_event_code = code[event_pos:]
                if 'safeTransferFrom(' in post_event_code or 'safeBatchTransferFrom(' in post_event_code:
                    requirements['event_emission_before_transfers'] = False
                else:
                    requirements['event_emission_before_transfers'] = True
                break

    return requirements


def check_on_received_implementation(code: str, params: Dict[str, str]) -> bool:
    """
    Verify the complete onERC1155BatchReceived implementation with fallback checks:
    1. First try exact parameter name matching
    2. Then try type-based matching (address, address, uint256[], uint256[], bytes)
    3. Finally verify parameter count == 5
    """
    # Get parameter names
    from_param = next((k for k in params if k.lower() in ['from', '_from']), None)
    to_param = next((k for k in params if k.lower() in ['to', '_to']), None)
    ids_param = next((k for k in params if k.lower() in ['ids', '_ids']), None)
    amounts_param = next((k for k in params if k.lower() in ['amounts', '_amounts']), None)
    data_param = next((k for k in params if k.lower() in ['data', '_data']), None)
    operator_param = next((k for k in params if k.lower() in ['operator', '_operator']), None)
    
    # Normalize code by removing comments and extra spaces
    normalized_code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
    normalized_code = re.sub(r'\s+', ' ', normalized_code)
    
    # print(f"normalized_code:{normalized_code}")
    
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
            operator_param or r'(msg\.sender|_msgSender\(\))',
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
    
    if not param_matched:
        print("Failed to match receiver parameters with any method")
        return False
    
    # 3. Check return value capture
    return_valid = False
    
    # Approach 1: Check if the entire call is in a require/if condition
    direct_check_pattern = (
        r'(?:require|if)\s*\(\s*'
        r'[^)]*?\.onERC1155BatchReceived'
        r'(?:\s*\{[^}]*\})?'
        r'\s*\([^)]+\)'
        r'[^)]*'
        r'\s*\)'
    )
    if re.search(direct_check_pattern, normalized_code) and param_matched:
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
    requirements = {}
    
    if not target_funcs:
        return {"error": "safeBatchTransferFrom function not found"}
    
    results = []
    for target_func in target_funcs:
        print(f"\nAnalyzing function implementation: {target_func['name']}")
        
        # Get ALL internal calls recursively
        internal_calls = get_all_internal_calls(target_func['body'], all_functions)
        print("Found internal calls:", [f['name'] for f in internal_calls])
        
        for func in internal_calls:
            if target_func['body'] != func['body']:
                # Verify requirements
                requirements = verify_erc1155_requirements(target_func, internal_calls)
            else:
                print("self call")
                # all_code = []
        
        
        
        if requirements != None :
            # print(f"DEBUG: requirements : {requirements}")
            results.append({
                "function": target_func['name'],
                "implementation_location": f"Line {target_func['start']}-{target_func['end']}",
                "parameters": target_func.get('parameters', {}),
                "requirements": requirements,
                "internal_calls": [f['name'] for f in internal_calls],
                "transfer_batch_event_found": requirements['transfer_batch_event_found'],
                "on_received_check_found": requirements['on_received_check']
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


def analyze_directory(directory_path: str) -> List[Dict]:
    """Analyze all Solidity files in a directory for ERC1155 compliance."""
    results = []
    
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.sol'):
                # file .startswith("ERC1155_0x8ac865") and
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
    """Find all function declarations in Solidity code."""
    func_pattern = re.compile(
        r'function\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)'
        r'([^{]*)\{',
        re.DOTALL
    )
    
    functions = []
    for match in func_pattern.finditer(solidity_code):
        func_name = match.group(1)
        params = match.group(2).strip()
        modifiers = match.group(3).strip()
        start_pos = match.start()
        open_brace_pos = match.end() - 1
        
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
                'body': solidity_code[start_pos:close_brace_pos].strip()
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
                       'transfer_batch_event_found', 'on_received_check']:
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