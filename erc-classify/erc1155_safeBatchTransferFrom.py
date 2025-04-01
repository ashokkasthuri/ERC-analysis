import os
import re
from typing import List, Dict, Optional
import json

def find_function_by_signature(functions: List[Dict], target_signature: str) -> Optional[Dict]:
    """Find a function by its normalized signature."""
    target_normalized = normalize_signature(target_signature)
    
    for func in functions:
        current_sig = f"{func['name']}({func['params']})"
        current_normalized = normalize_signature(current_sig)
        
        if current_normalized == target_normalized:
            return func
    return None

def trace_internal_calls(function_body: str, all_functions: List[Dict]) -> List[Dict]:
    """Trace all internal function calls within a function body."""
    internal_calls = []
    
    # Pattern to match function calls (simplified)
    call_pattern = re.compile(r'(\w+)\s*\([^)]*\)\s*(?={|;)')
    
    for match in call_pattern.finditer(function_body):
        call_name = match.group(1)
        
        # Skip known keywords and built-ins
        if call_name in ['require', 'assert', 'revert', 'emit', 'new', 'return']:
            continue
            
        # Find the called function in all_functions
        for func in all_functions:
            if func['name'] == call_name:
                internal_calls.append(func)
                break
                
    return internal_calls

def verify_requirements(function_body: str, internal_functions: List[Dict]) -> Dict:
    """Verify if the function and its internal calls meet ERC1155 requirements."""
    requirements = {
        'approval_check': False,
        'zero_address_check': False,
        'length_matching_check': False,
        'balance_checks': False,
        'event_emission_before_transfers': False,
        'transfer_batch_event_found': False
    }
    
    # Combine all code to analyze (main function + internal calls)
    all_code = [function_body]
    for func in internal_functions:
        all_code.append(func['body'])
    
    # Check each requirement across all code segments
    for code in all_code:
        # Approval check
        if re.search(r'require\(\(msg\.sender == _from\) \|\| isApprovedForAll\(_from, msg\.sender\)', code):
            requirements['approval_check'] = True
            
        # Zero address check
        if re.search(r'require\(_to != address\(0\)', code):
            requirements['zero_address_check'] = True
            
        # Length matching check
        if re.search(r'require\(_ids\.length == _amounts\.length', code):
            requirements['length_matching_check'] = True
            
        # Balance checks
        if re.search(r'require\(balanceOf\(_from, _ids\[i\]\) >= _amounts\[i\]', code):
            requirements['balance_checks'] = True
            
        # Event emission before transfers
        if 'emit TransferBatch(' in code and not requirements['transfer_batch_event_found']:
            requirements['transfer_batch_event_found'] = True
            # Check if there are transfers after the event
            event_pos = code.find('emit TransferBatch(')
            if 'safeTransferFrom(' in code[event_pos:] or 'safeBatchTransferFrom(' in code[event_pos:]:
                requirements['event_emission_before_transfers'] = False
            else:
                requirements['event_emission_before_transfers'] = True
    
    return requirements

def analyze_safe_batch_transfer(solidity_code: str) -> Dict:
    """Main analysis function for safeBatchTransferFrom compliance."""
    # Find all functions in the contract
    all_functions = find_all_functions(solidity_code)
    
    # Target function signature
    target_sig = "safeBatchTransferFrom(address _from, address _to, uint256[] memory _ids, uint256[] memory _amounts, bytes memory _data)"
    
    # Find the target function
    target_func = find_function_by_signature(all_functions, target_sig)
    if not target_func:
        return {"error": "safeBatchTransferFrom function not found"}
    
    # Trace internal calls
    internal_calls = trace_internal_calls(target_func['body'], all_functions)
    
    # Verify requirements
    requirements = verify_requirements(target_func['body'], internal_calls)
    
    # Check if we found the TransferBatch event
    if not requirements['transfer_batch_event_found']:
        # Search deeper in internal calls if needed
        for func in internal_calls:
            deeper_calls = trace_internal_calls(func['body'], all_functions)
            for deep_func in deeper_calls:
                if 'emit TransferBatch(' in deep_func['body']:
                    requirements['transfer_batch_event_found'] = True
                    break
            if requirements['transfer_batch_event_found']:
                break
    
    return {
        "function": target_func['name'],
        "requirements": requirements,
        "internal_calls": [f['name'] for f in internal_calls],
        "transfer_batch_event_found": requirements['transfer_batch_event_found']
    }

# Helper functions from your existing code
def normalize_signature(signature: str) -> str:
    """Normalize function signature for comparison."""
    if '(' not in signature:
        return signature
    
    func_name = signature.split('(')[0]
    params = signature[len(func_name)+1:-1].split(',')
    param_types = []
    
    for param in params:
        param = param.strip()
        if ' ' in param:
            param = param.rsplit(' ', 1)[0].strip()
        param_types.append(param)
    
    return f"{func_name}({','.join(param_types)})"

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


def analyze_directory(directory_path: str) -> List[Dict]:
    """Analyze all Solidity files in a directory for ERC1155 compliance."""
    results = []
    
    # Walk through all files in the directory
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.sol'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        solidity_code = f.read()
                    
                    # Analyze the file
                    result = analyze_safe_batch_transfer(solidity_code)
                    result['file'] = file_path  # Add file path to results
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

if __name__ == "__main__":
    # Directory containing ERC1155 Solidity files
    erc1155_directory = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source/ERC1155"
    
    # Output file for results
    output_file = "erc1155_analysis_results.json"
    
    # Analyze all files in the directory
    analysis_results = analyze_directory(erc1155_directory)
    
    # Save results to JSON file
    save_results_to_json(analysis_results, output_file)
    
    print(f"Analysis complete. Results saved to {output_file}")
    print(f"Total files analyzed: {len(analysis_results)}")
    
    # Print summary of findings
    compliant_files = [r for r in analysis_results if not r.get('error') and r.get('requirements', {}).get('transfer_batch_event_found')]
    print(f"\nFiles with proper safeBatchTransferFrom implementation: {len(compliant_files)}")
    
    # Print files with errors
    error_files = [r for r in analysis_results if r.get('error')]
    if error_files:
        print("\nFiles with processing errors:")
        for file in error_files:
            print(f"- {file['file']}: {file['error']}")