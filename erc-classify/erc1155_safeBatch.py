import os
import re
import json
from typing import List, Dict, Optional, Set, Tuple
from eth_utils import keccak



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
    """Verify ERC1155 compliance using data flow analysis"""
    # Initialize analysis framework
    analyzer = ERC1155Analyzer(target_func, internal_functions)
    
    # Phase 1: Forward Data Flow Analysis
    analyzer.analyze_forward_flow()
    
    # Phase 2: Backward Data Flow Analysis 
    analyzer.analyze_backward_flow()
    
    # Phase 3: Control Flow Verification
    analyzer.verify_control_flow()
    
    return analyzer.get_results()

class ERC1155Analyzer:
    def __init__(self, target_func, internal_functions):
        self.requirements = {
            'sender_check': False,
            'approval_check': False,
            'zero_address_check': False,
            'length_matching_check': False,
            'event_emission_before_transfers': False,
            'transfer_batch_event_found': False,
            'to_isContract_check': False,
            'on_received_check': False
        }
        self.params = extract_parameters(target_func)
        self.all_code = self._build_code_flow(target_func, internal_functions)
        self.data_flow_graph = self._build_data_flow_graph()

    def _build_code_flow(self, target_func, internal_functions):
        """Construct the combined code flow graph"""
        flow = [(target_func['body'], "main function")]
        for func in internal_functions:
            flow.append((func['body'], f"internal function {func['name']}"))
        return flow

    def _build_data_flow_graph(self):
        """Construct data flow dependencies"""
        dfg = {
            'length_assignments': find_length_assignments(self.all_code, self.params['ids_param']),
            'conditions': self._extract_all_conditions(),
            'event_positions': None
        }
        return dfg

    def _extract_all_conditions(self):
        """Backward analysis: Extract all conditions from code"""
        conditions = []
        for code, source in self.all_code:
            conditions.extend(self._find_require_conditions(code, source))
            conditions.extend(self._find_if_revert_conditions(code, source))
        return conditions

    def analyze_forward_flow(self):
        """Forward analysis: Check data flows from declarations to usage"""
        # Track length assignments forward through code
        if self.params['ids_param']:
            self._verify_length_flow()
        
        # Track event emissions before transfers
        self._verify_event_ordering()

    def analyze_backward_flow(self):
        """Backward analysis: Check requirements from usage points to sources"""
        for condition in self.data_flow_graph['conditions']:
            self._check_condition_backward(condition)

    def verify_control_flow(self):
        """Verify cross-cutting control flow constraints"""
        self._verify_contract_guards()
        self._verify_callbacks()

    # Implementation of analysis methods (maintaining your original logic)
    def _verify_length_flow(self):
        """Forward analysis of array length handling"""
        for condition in self.data_flow_graph['conditions']:
            content, _, typ = condition
            if self._match_length_condition(content, typ):
                self.requirements['length_matching_check'] = True
                break

    def _verify_event_ordering(self):
        """Forward analysis of event emission ordering"""
        for code, source in self.all_code:
            if 'emit TransferBatch(' in code:
                self.requirements['transfer_batch_event_found'] = True
                pos = code.find('emit TransferBatch(')
                self._check_post_event_operations(code[pos:])

    def _check_condition_backward(self, condition):
        """Backward analysis of individual conditions"""
        content, _, typ = condition
        self._check_sender_approval(content, typ)
        self._check_zero_address(content, typ)

    def _check_sender_approval(self, content, typ):
        """Your original sender/approval check logic"""
        # ... (maintain your exact pattern matching logic)
        
    def _check_zero_address(self, content, typ):
        """Your original zero address check logic"""
        # ... (maintain your exact pattern matching logic)

    def _verify_contract_guards(self):
        """Control flow verification"""
        for code, _ in self.all_code:
            norm_code = re.sub(r'//.*?\n|/\*.*?\*/', '', code, flags=re.DOTALL)
            norm_code = re.sub(r'\s+', ' ', norm_code)
            if self._match_contract_checks(norm_code):
                self.requirements['to_isContract_check'] = True

    def get_results(self):
        """Return final verification results"""
        return self.requirements