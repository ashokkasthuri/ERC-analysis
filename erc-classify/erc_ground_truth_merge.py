import os

import json
from eth_utils import keccak
from web3 import Web3
from typing import Dict, List, Optional
import re




# Define the folder path where the ERC folders are located
folder_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_source_code_ground_truth"
# folder_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ground_truth_test"


# Define the dependencies for each ERC standard
erc_dependencies = {
    "ERC20": [],
    "ERC165": ["ERC214"],
    "ERC173": ["ERC165"],
    "ERC721": ["ERC165"],
    "ERC223": [],
    "ERC777": ["ERC1820"],
    "ERC1155": ["ERC165"],
    "ERC884": [],
    "ERC998": ["ERC20", "ERC165", "ERC721"],
    "ERC875": [],
    "ERC1046": ["ERC20", "ERC721", "ERC1155"],
    "ERC1363": ["ERC20", "ERC165"],
    "ERC2135": ["ERC165", "ERC721", "ERC1155"],
    "ERC2309": ["ERC721"],
    "ERC2612": ["ERC20", "ERC712"],
    "ERC1948": ["ERC721"],
    "ERC1261": ["ERC165", "ERC173"],
    "ERC1271": [],
    "ERC1337": ["ERC20", "ERC165"],
    "ERC1820": ["ERC165", "ERC214"],
    "ERC2021": ["ERC20", "ERC1066", "ERC1996"],
    "ERC2018": ["ERC1996"],
    "ERC2019": ["ERC20"],
    "ERC1996": ["ERC20"],
    "ERC2020": ["ERC20", "ERC1066", "ERC1996", "ERC2009", "ERC2018", "ERC2019", "ERC2021"],
    "ERC2981": ["ERC165"],
    "ERC3135": ["ERC20"],
    "ERC3440": ["ERC712", "ERC721"],
    "ERC3589": ["ERC721"],
    "ERC3754": [],
    "ERC4494": ["ERC165", "ERC712", "ERC721"],
    "ERC4524": ["ERC20", "ERC165"],
    "ERC4675": ["ERC165", "ERC721"],
    "ERC3525": ["ERC20", "ERC165", "ERC721"],
    "ERC3643": ["ERC20", "ERC173"],
    "ERC4400": ["ERC165", "ERC721"],
    "ERC4519": ["ERC165", "ERC721"],
    "ERC4626": ["ERC20", "ERC2612"],
    "ERC4906": ["ERC165", "ERC721"],
    "ERC4907": ["ERC165", "ERC721"],
    "ERC4337": ["ERC712", "ERC7562"],
    "ERC4910": ["ERC165", "ERC721"],
    "ERC4955": ["ERC721", "ERC1155"],
    "ERC5006": ["ERC165", "ERC1155"],
    "ERC5007": ["ERC165", "ERC721"],
    "ERC5023": ["ERC165"],
    "ERC5169": ["ERC20", "ERC165", "ERC721", "ERC777", "ERC1155"],
    "ERC5192": ["ERC165", "ERC721"],
    "ERC5267": ["ERC155", "ERC712", "ERC2612"],
    "ERC5375": ["ERC55", "ERC155", "ERC712", "ERC721", "ERC1155"],
    "ERC5380": ["ERC165", "ERC721", "ERC1046"],
    "ERC5484": ["ERC165", "ERC721"],
    "ERC5489": ["ERC165", "ERC721"],
    "ERC5507": ["ERC20", "ERC165", "ERC721", "ERC1155"],
    "ERC5521": ["ERC165", "ERC721"],
    "ERC5528": ["ERC20"],
    "ERC5570": ["ERC721"],
    "ERC5585": ["ERC721"],
    "ERC5606": ["ERC721", "ERC1155"],
    "ERC5615": ["ERC1155"],
    "ERC5646": ["ERC165"],
    "ERC5679": ["ERC20", "ERC165", "ERC721", "ERC1155"],
    "ERC5725": ["ERC721"],
    "ERC5773": ["ERC165", "ERC721"],
    "ERC6059": ["ERC165", "ERC721"],
    "ERC6066": ["ERC165", "ERC721", "ERC1155", "ERC1271", "ERC5750"],
    "ERC6105": ["ERC20", "ERC165", "ERC721", "ERC2981"],
    "ERC6147": ["ERC165", "ERC721"],
    "ERC6150": ["ERC165", "ERC721"],
    "ERC6220": ["ERC165", "ERC721", "ERC5773", "ERC6059"],
    "ERC6239": ["ERC165", "ERC721", "ERC5192"],
    "ERC6381": ["ERC165"],
    "ERC6454": ["ERC165", "ERC721"],
    "ERC6492": ["ERC1271"],
    "ERC6551": ["ERC165", "ERC721", "ERC1167", "ERC1271"],
    "ERC6672": ["ERC165", "ERC721"],
    "ERC6808": ["ERC20"],
    "ERC6809": ["ERC721"],
    "ERC6982": ["ERC165", "ERC721"],
    "ERC7160": ["ERC165", "ERC721"],
    "ERC7231": ["ERC165", "ERC721", "ERC1271"],
    "ERC7401": ["ERC165", "ERC721"],
    "ERC7409": ["ERC165"]
}
def get_erc_file_name(erc):
    return f"I{erc}.sol"

def read_file_contents(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_file_contents(file_path, contents):
    with open(file_path, 'w') as file:
        file.write(contents)

def merge_dependencies(erc, dependencies):
    erc_file_name = get_erc_file_name(erc)
    erc_file_path = os.path.join(folder_path, erc, erc_file_name)
    
    if not os.path.exists(erc_file_path):
        print(f"File {erc_file_path} does not exist.")
        return
    
    # Generate the new file name
    if dependencies:
        new_file_name = f"final_{erc}_with_{'_'.join(dependencies)}.sol"
    else:
        new_file_name = f"final_{erc}_with_no_dependencies.sol"
    new_file_path = os.path.join(folder_path, erc, new_file_name)
    
    merged_contents = ""
    
    # Read and append dependency files
    for dependency in dependencies:
        dependency_file_name = get_erc_file_name(dependency)
        dependency_file_path = os.path.join(folder_path, dependency, dependency_file_name)
        
        if os.path.exists(dependency_file_path):
            merged_contents += read_file_contents(dependency_file_path) + "\n"
        else:
            print(f"Dependency file {dependency_file_path} does not exist.")
    
    # Append the original ERC file content
    merged_contents += read_file_contents(erc_file_path)
    
    # Write the merged contents to the new file
    write_file_contents(new_file_path, merged_contents)
    print(f"Created new file {new_file_path} with merged dependencies")








    main()
    final_json = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith("final_ERC") and file.endswith(".sol"):
                erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
                file_path = os.path.join(root, file)
                functions, events = extract_functions_and_events(file_path)
                erc_json = generate_json_structure(erc_name, functions, events)
                final_json.update(erc_json)
    
    # Write the final JSON to a file
    with open("final_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_erc_specifications.json")
    final_json = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith("final_ERC") and file.endswith(".sol"):
                erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
                file_path = os.path.join(root, file)
                functions, events = extract_functions_and_events(file_path)
                erc_json = generate_json_structure(erc_name, functions, events)
                final_json.update(erc_json)
    
    # Write the final JSON to a file
    with open("final_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_erc_specifications.json")
    final_json = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith("final_ERC") and file.endswith(".sol"):
                erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
                file_path = os.path.join(root, file)
                functions, events = extract_functions_and_events(file_path)
                erc_json = generate_json_structure(erc_name, functions, events)
                final_json.update(erc_json)
    
    # Write the final JSON to a file
    with open("final_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_erc_specifications.json")









    final_json = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith("final_ERC") and file.endswith(".sol"):
                erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
                file_path = os.path.join(root, file)
                functions, events = extract_functions_and_events(file_path)
                erc_json = generate_json_structure(erc_name, functions, events)
                final_json.update(erc_json)
    
    # Write the final JSON to a file
    with open("final_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_erc_specifications.json")





def clean_signature(signature):
    # Remove newlines and extra spaces
    cleaned = " ".join(signature.replace("\n", " ").split())
    
    # Remove "function" or "event" keyword
    if cleaned.startswith("function "):
        cleaned = cleaned[len("function "):]
    elif cleaned.startswith("event "):
        cleaned = cleaned[len("event "):]
    
    # Remove trailing semicolon
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1]
    
    # Extract the function name and parameters
    if "(" in cleaned and ")" in cleaned:
        func_name = cleaned.split("(")[0]
        params = cleaned.split("(")[1].split(")")[0]
        
        # Clean parameters: remove parameter names and keep data types
        cleaned_params = []
        for param in params.split(","):
            param = param.strip()
            if param:
                # Extract the data type (e.g., "address", "uint256", etc.)
                data_type = param.split()[0]
                
                # Replace "uint" with "uint256" if necessary
                if data_type == "uint" :
                    data_type = "uint256"
                if data_type == "uint[]" :
                    data_type = "uint256[]"
                
                cleaned_params.append(data_type)
        
        # Reconstruct the cleaned signature
        cleaned = f"{func_name}({','.join(cleaned_params)})"
    
    return cleaned

# Function to check if a line is a comment
def is_comment(line):
    # Check if the line starts with a comment indicator
    return line.strip().startswith(("//", "///", "*", "/*", "*/", "**"))

def get_event_topic(event_signature: str) -> str:
    return keccak(text=event_signature).hex()

def get_selector(function_signature: str) -> str:
    hash_bytes = keccak(text=function_signature)
    selector = hash_bytes[:4].hex()
    # print(f"selector : {selector}")
    return selector


def extract_custom_functions(file_path):
    functions = {}
    events = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
        # Track whether we are inside a multi-line comment
        inside_multi_line_comment = False
        
        # Iterate through each line
        for i, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                continue
            
            # Handle multi-line comments
            if line.strip().startswith("/*"):
                inside_multi_line_comment = True
            if inside_multi_line_comment:
                if line.strip().endswith("*/"):
                    inside_multi_line_comment = False
                continue
            
            # Skip single-line comments
            if is_comment(line):
                continue
            
            # Extract functions
            if line.strip().__contains__("function"):
                # Capture the entire function signature
                function_signature = line.strip()
                # Continue reading until we find the closing parenthesis
                try:
                    while ")" not in function_signature:
                        i += 1
                        next_line = lines[i].strip()
                        function_signature += " " + next_line
                except IndexError:
                    # Handle the case where the file ends unexpectedly
                    print(f"Warning: Incomplete function signature in file {file_path}")
                    continue
                # Clean up the signature
                function_signature = clean_signature(function_signature)
                
                # Generate the function hash
                function_hash = get_selector(function_signature)
                # function_hash = get_selector("balanceOf(address who)")
                # print(f"function_hash : {function_hash}")
                functions[function_signature] = function_hash
                
    return functions, events
# Function to extract functions and events from a Solidity file
def extract_functions_and_events(file_path):
    functions = {}
    events = {}
    with open(file_path, 'r') as file:
        lines = file.readlines()
        
        # Track whether we are inside a multi-line comment
        inside_multi_line_comment = False
        
        # Iterate through each line
        for i, line in enumerate(lines):
            # Skip empty lines
            if not line.strip():
                continue
            
            # Handle multi-line comments
            if line.strip().startswith("/*"):
                inside_multi_line_comment = True
            if inside_multi_line_comment:
                if line.strip().endswith("*/"):
                    inside_multi_line_comment = False
                continue
            
            # Skip single-line comments
            if is_comment(line):
                continue
            
            # Extract functions
            if line.strip().startswith("function"):
                # Capture the entire function signature
                function_signature = line.strip()
                # Continue reading until we find the closing parenthesis
                try:
                    while ")" not in function_signature:
                        i += 1
                        next_line = lines[i].strip()
                        function_signature += " " + next_line
                except IndexError:
                    # Handle the case where the file ends unexpectedly
                    print(f"Warning: Incomplete function signature in file {file_path}")
                    continue
                # Clean up the signature
                function_signature = clean_signature(function_signature)
                
                # Generate the function hash
                function_hash = get_selector(function_signature)
                # function_hash = get_selector("balanceOf(address who)")
                # print(f"function_hash : {function_hash}")
                functions[function_signature] = function_hash
                
            
            # Extract events
            if line.strip().startswith("event"):
                # Capture the entire event signature
                event_signature = line.strip()
                # Continue reading until we find the closing parenthesis
                try:
                    while ")" not in event_signature:
                        i += 1
                        next_line = lines[i].strip()
                        event_signature += " " + next_line
                except IndexError:
                    # Handle the case where the file ends unexpectedly
                    print(f"Warning: Incomplete event signature in file {file_path}")
                    continue
                # Clean up the signature
                event_signature = clean_signature(event_signature)
                # Generate the event hash
                # event_hash = keccak(text=event_signature).hex()
                event_hash = get_event_topic(event_signature)
                events[event_hash] = event_signature
                
    
    return functions, events

# Function to generate the JSON structure
def generate_json_structure(erc_name, functions, events):
    selectors = list(functions.values())
    topics = list(events.keys())
    return {
        erc_name: {
            "selectors": selectors,
            "topics": topics,
            "functions": functions,
            "events": events
        }
    }



   
   

# Function to load the final ERC specifications
def load_final_erc_specifications(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Function to calculate precision and recall
def calculate_precision_recall(extracted_functions, extracted_events, erc_spec):
    # Get the expected functions and events from the ERC specification
    expected_functions = erc_spec.get("functions", {})
    expected_events = erc_spec.get("events", {})
    
    # Calculate true positives (TP), false positives (FP), and false negatives (FN)
    tp_functions = 0
    fp_functions = 0
    fn_functions = 0
    
    tp_events = 0
    fp_events = 0
    fn_events = 0
    
    
    for func, hash_ in expected_functions.items():
        # print(f"func : {func}")
        if func in extracted_functions and extracted_functions[func] == hash_:
            tp_functions += 1
        else:
            
            fp_functions += 1
    
    for func in expected_functions:
        if func not in extracted_functions:
            # print(f"missing func : {func}")
            fn_functions += 1
   
    # for func, hash_ in extracted_functions.items():
    #     # print(f"func : {func}")
    #     if func in expected_functions and expected_functions[func] == hash_:
    #         # tp_functions += 1
    #         continue
    #     else:
    #         print(f"func : {func}")
    
    # for func in extracted_functions:
    #     if func not in expected_functions:
    #         print(f"missing func : {func}")
            
            
    # print(f"extracted_events :{extracted_functions}")
    # print(f"\nextracted_events :{extracted_events}")
    
    for event_hash, event_sig in expected_events.items():
        if event_hash in extracted_events and extracted_events[event_hash] == event_sig:
            tp_events += 1
        else:
            fp_events += 1
    
    for event_hash in expected_events:
        if event_hash not in extracted_events:
            fn_events += 1
    
    # Calculate precision and recall for functions
    precision_functions = tp_functions / (tp_functions + fp_functions) if (tp_functions + fp_functions) > 0 else 0
    recall_functions = tp_functions / (tp_functions + fn_functions) if (tp_functions + fn_functions) > 0 else 0
    
    # Calculate precision and recall for events
    precision_events = tp_events / (tp_events + fp_events) if (tp_events + fp_events) > 0 else 0
    recall_events = tp_events / (tp_events + fn_events) if (tp_events + fn_events) > 0 else 0
    
    # return {
    #     "functions": {"tp": tp_functions, "fp": fp_functions, "fn": fn_functions},
    #     "events": {"tp": tp_events, "fp": fp_events, "fn": fn_events}
    # }
    return {
        "functions": {"precision": precision_functions, "recall": recall_functions},
        "events": {"precision": precision_events, "recall": recall_events}
    }

# Function to calculate overall precision and recall
# def calculate_overall_precision_recall(results):
#     # total_tp_functions = 0
#     # total_fp_functions = 0
#     # total_fn_functions = 0
    
#     # total_tp_events = 0
#     # total_fp_events = 0
#     # total_fn_events = 0
    
#     # Aggregate TP, FP, and FN for functions and events
#     # for result in results:
#     #     total_tp_functions += result["functions"]["tp"]
#     #     total_fp_functions += result["functions"]["fp"]
#     #     total_fn_functions += result["functions"]["fn"]
        
#     #     total_tp_events += result["events"]["tp"]
#     #     total_fp_events += result["events"]["fp"]
#     #     total_fn_events += result["events"]["fn"]
        
#     for result in results:
#         precision_functions += result["functions"]["precision"]
#         recall_functions += result["functions"]["recall"]
        
#         precision_events += result["events"]["precision"]
#         recall_events += result["events"]["recall"]
        
#     print(f"total_tp_functions :{total_tp_functions}")
#     print(f"total_fp_functions :{total_fp_functions}")
#     print(f"total_fn_functions :{total_fn_functions}")
#     print(f"total_tp_events :{total_tp_events}")
#     print(f"total_fp_events :{total_fp_events}")
#     print(f"total_fn_events :{total_fn_events}")
#     # Calculate overall precision and recall for functions
#     # precision_functions = total_tp_functions / (total_tp_functions + total_fp_functions) if (total_tp_functions + total_fp_functions) > 0 else 0
#     # recall_functions = total_tp_functions / (total_tp_functions + total_fn_functions) if (total_tp_functions + total_fn_functions) > 0 else 0
    
#     precision_functions = precision_functions/len(precision_functions)
#     recall_functions = recall_functions/len(recall_functions)
    
#     precision_events = precision_events/len(precision_events)
#     recall_events = recall_events/len(recall_events)
    
#     # Calculate overall precision and recall for events
#     # precision_events = total_tp_events / (total_tp_events + total_fp_events) if (total_tp_events + total_fp_events) > 0 else 0
#     # recall_events = total_tp_events / (total_tp_events + total_fn_events) if (total_tp_events + total_fn_events) > 0 else 0
    
#     return {
#         "functions": {"precision": precision_functions, "recall": recall_functions},
#         "events": {"precision": precision_events, "recall": recall_events}
#     }

# Function to calculate overall precision and recall
def calculate_overall_precision_recall(results):
    # Initialize variables to store cumulative precision and recall
    precision_functions = 0
    recall_functions = 0
    precision_events = 0
    recall_events = 0
    
    # Aggregate precision and recall for functions and events
    for result in results:
        precision_functions += result["functions"]["precision"]
        recall_functions += result["functions"]["recall"]
        
        precision_events += result["events"]["precision"]
        recall_events += result["events"]["recall"]
    
    # Calculate average precision and recall for functions and events
    num_results = len(results)
    if num_results > 0:
        precision_functions /= num_results
        recall_functions /= num_results
        
        precision_events /= num_results
        recall_events /= num_results
    
    # Return the overall precision and recall
    return {
        "functions": {"precision": precision_functions, "recall": recall_functions},
        "events": {"precision": precision_events, "recall": recall_events}
    }

def custom_functions(extracted_functions, extracted_events, erc_spec):
    # Get expected functions and events from the ERC specification
    expected_functions = erc_spec.get("functions", {})
    expected_events = erc_spec.get("events", {})
    
    # Initialize lists to store custom functions and events
    custom_functions = []
    custom_events = []
    
    # Check for custom functions
    for func, hash_ in extracted_functions.items():
        # If the function is not in the expected list or the hash doesn't match, it's custom
        if func not in expected_functions or expected_functions[func] != hash_:
            custom_functions.append({"function": func, "hash": hash_})
    
    # Check for custom events
    # for event_hash, event_sig in extracted_events.items():
    #     # If the event is not in the expected list or the signature doesn't match, it's custom
    #     if event_hash not in expected_events or expected_events[event_hash] != event_sig:
    #         custom_events.append({"event_hash": event_hash, "event_signature": event_sig})
    
    # Return the custom functions and events
    return {
        "custom_functions": custom_functions
    }

# Save custom functions and events to a JSON file
def save_to_json(custom_data, filename="custom_functions_events.json"):
    with open(filename, "w") as file:
        json.dump(custom_data, file, indent=4)

def precision_and_recall(final_erc_file, erc_base_path):
    
    final_erc = load_final_erc_specifications(final_erc_file)
    # Initialize dictionaries for matched and non-matched ERCs
    matched_ercs = {}
    non_matched_ercs = {} 
    partial_matched_ercs = {}      
    
    # Initialize list to store precision and recall results
    precision_recall_results = []
    
    erc_name_present_count = 0
    erc_name_NOT_present_count = 0
    contract_files = 0
    missing_count = 0 
    
    print(f"final_erc : {len(final_erc)}")
    # Iterate through each ERC folder
    for erc_name in final_erc:
        erc_folder = os.path.join(erc_base_path, erc_name)
        if not os.path.exists(erc_folder):
            print(f"ERC folder {erc_folder} does not exist.")
            erc_name_NOT_present_count = erc_name_NOT_present_count + 1
            continue
        else:
            erc_name_present_count = erc_name_present_count + 1
        # Initialize lists for matched and non-matched files for this ERC
        matched_files = []
        non_matched_files = []
        
        partial_matched_files = []
        
        
        
      # Iterate through all Solidity files in the ERC folder (including subfolders)
        for root, _, files in os.walk(erc_folder):
            for file in files:
                if file.startswith("ERC") and file.endswith(".sol") and "_contract" in file:
                # if file.startswith("ERC") and file.endswith(".sol"):
                    contract_files = contract_files + 1
                # if file.endswith(".sol"):    
                    file_path = os.path.join(root, file)
                    # Extract functions and events from the Solidity file
                    extracted_functions, extracted_events = extract_functions_and_events(file_path)
                    
                        
                    
                    # Compare with the ERC specification
                    erc_spec = final_erc[erc_name]
                    precision_recall = calculate_precision_recall(extracted_functions, extracted_events, erc_spec)
                    
                    precision_recall_results.append(precision_recall)
                    
                    if (precision_recall['functions']['precision'] == 1 and \
                        precision_recall['functions']['recall'] == 1 and \
                        precision_recall['events']['precision'] == 1 and 
                        precision_recall['events']['recall'] == 1) :
                        
                        matched_files.append(file_path)
                    
                    
                    elif (precision_recall['functions']['precision'] > 0.7 and \
                        precision_recall['functions']['recall'] > 0.7 and \
                        precision_recall['events']['precision'] > 0.7 and 
                        precision_recall['events']['recall'] > 0.7) :
                        
                        partial_matched_files.append(file_path)
                        
                    elif(precision_recall['functions']['precision'] == 1 and \
                        precision_recall['functions']['recall'] == 1 ):
                        
                        matched_files.append(file_path)
                        
                    elif(precision_recall['functions']['precision'] > 0.7 and \
                        precision_recall['functions']['recall'] > 0.7):
                        
                        partial_matched_files.append(file_path)
                        
                    elif(precision_recall['events']['precision'] == 1 and \
                        precision_recall['events']['recall'] == 1):
                        
                        matched_files.append(file_path)    
                        
                    elif(precision_recall['events']['precision'] > 0.7 and \
                        precision_recall['events']['recall'] > 0.7):
                        
                        partial_matched_files.append(file_path)
                        
                    else:
                        missing_count = missing_count + 1
                        non_matched_files.append(file_path)
 
                        
        # Add to the matched or non-matched collections
        if matched_files:
            matched_ercs[erc_name] = matched_files
            
        if partial_matched_files:
            partial_matched_ercs[erc_name] = matched_files
            
        if non_matched_files and erc_name not in matched_ercs:
            non_matched_ercs[erc_name] = non_matched_files
            
    print(f"erc_name_present_count : {erc_name_present_count}")
    print(f"erc_name_NOT_present_count : {erc_name_NOT_present_count}")
    
    print(f"contract_files : {contract_files}")
    
    print(f"matched_ercs : {len(matched_ercs)}")
    print(f"partial_matched_ercs : {len(partial_matched_ercs)}")
    print(f"non_matched_ercs : {len(non_matched_ercs)}")
    print(f"missing_count: {missing_count}")
            
     # Calculate overall precision and recall
    overall_precision_recall = calculate_overall_precision_recall(precision_recall_results)
   
    # Print overall precision and recall
    print("Overall Precision and Recall:")
    print(f"Functions - Precision: {overall_precision_recall['functions']['precision']}, Recall: {overall_precision_recall['functions']['recall']}")
    print(f"Events - Precision: {overall_precision_recall['events']['precision']}, Recall: {overall_precision_recall['events']['recall']}")
            
    # Print matched ERCs
    # print("Matched ERCs:")
    # for erc_name, files in matched_ercs.items():
    #     print(f"- ERC: {erc_name}")
        # for file_path in files:
        #     print(f"  - File: {file_path}")
    
    # Print non-matched ERCs
    print("\nNon-Matched ERCs:")
    for erc_name, files in non_matched_ercs.items():
        print(f"- ERC: {erc_name}")
        # for file_path in files:
        #     print(f"  - File: {file_path}")


def final_erc_specifications():
    final_json = {}
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            if file.startswith("final_ERC") and file.endswith(".sol"):
                erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
                file_path = os.path.join(root, file)
                functions, events = extract_functions_and_events(file_path)
                erc_json = generate_json_structure(erc_name, functions, events)
                final_json.update(erc_json)
    
    # Write the final JSON to a file
    with open("final_full_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_full_erc_specifications.json")
    
def final_basic_erc_specifications():
    final_json = {}
     
    for erc_folder in os.listdir(folder_path):
        erc_folder_path = os.path.join(folder_path, erc_folder)
        
        if os.path.isdir(erc_folder_path) and erc_folder.startswith("ERC"):
            # Iterate through files directly inside the folder (not subfolders)
            for file in os.listdir(erc_folder_path):
                file_path = os.path.join(erc_folder_path, file)
                
                # Check if the file starts with "IERC" and ends with ".sol"
                if file.startswith("IERC") and file.endswith(".sol"):
                    erc_name = file.split("I")[1].split(".")[0]  # Extract ERC name from file name
                    # print(f"erc_name: {erc_name}")
                    # print(f"file_path: {file_path}")
                    functions, events = extract_functions_and_events(file_path)
                    erc_json = generate_json_structure(erc_name, functions, events)
                    final_json.update(erc_json)
    # # Write the final JSON to a file
    with open("final_basic_erc_specifications.json", "w") as json_file:
        json.dump(final_json, json_file, indent=4)
    print("Final JSON file created: final_basic_erc_specifications.json")
    
    

def find_all_functions(solidity_code: str) -> List[Dict]:
    """
    Find all function declarations in Solidity code and return their positions.
    Returns a list of dictionaries with function info including start/end positions.
    """
    # Pattern to find function declarations (simplified but effective)
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
        open_brace_pos = match.end() - 1  # Position of opening brace
        
        # Find matching closing brace
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
    """Normalize function signature for comparison."""
    # Remove all whitespace and parameter names, keep only types
    if '(' not in signature:
        return signature
    
    func_name = signature.split('(')[0]
    params = signature[len(func_name)+1:-1].split(',')
    param_types = []
    
    for param in params:
        param = param.strip()
        # Remove parameter name if present (anything after last space)
        if ' ' in param:
            param = param.rsplit(' ', 1)[0].strip()
        param_types.append(param)
    
    return f"{func_name}({','.join(param_types)})"

def extract_matching_functions(custom_data: Dict, solidity_file_path: str) -> Dict[str, str]:
    """Extract functions matching custom_data signatures from Solidity file."""
    with open(solidity_file_path, 'r', encoding='utf-8') as f:
        solidity_code = f.read()
    
    # First find all functions in the file
    all_functions = find_all_functions(solidity_code)
    matched_functions = {}
    
    if "custom_functions" not in custom_data:
        return matched_functions
    
    for target in custom_data["custom_functions"]:
        target_sig = target["function"]
        target_normalized = normalize_signature(target_sig)
        found = False
        
        for func in all_functions:
            # Build the signature from the found function
            current_sig = f"{func['name']}({func['params']})"
            current_normalized = normalize_signature(current_sig)
            
            if current_normalized == target_normalized:
                print(f"func['modifiers']: {func['modifiers']}")
                if "onlyOwner" in  func['modifiers']:
                    matched_functions[target_sig] = func['body']
                    found = True
                    break
        
        if not found:
            print(f"Function not found: {target_sig}")
    
    return matched_functions

# Updated main processing function
def custom_function_erc_folders(final_erc_file, erc_base_path):
    # Load final ERC specifications
    final_erc = load_final_erc_specifications(final_erc_file)
    
    # Iterate through each ERC folder
    for erc_name in final_erc:
        erc_folder = os.path.join(erc_base_path, erc_name)
        if not os.path.exists(erc_folder):
            continue
        
        # Iterate through all Solidity files in the ERC folder
        for root, _, files in os.walk(erc_folder):
            for file in files:
                if file.startswith("ERC4494_0x1e1b4e1") and file.endswith(".sol"):
                    file_path = os.path.join(root, file)
                    print(f"Processing file: {file_path}")
                    
                    # Extract functions and events from the Solidity file
                    # extracted_functions, extracted_events = extract_functions_and_events(file_path)
                    extracted_functions, extracted_events = extract_custom_functions(file_path)
                    
                    
                    # Compare with the ERC specification
                    erc_spec = final_erc[erc_name]
                    
                    # Calculate custom functions and events
                    custom_data = custom_functions(extracted_functions, extracted_events, erc_spec)
                    
                    # Save custom data to JSON
                    output_file = os.path.join(root, f"{os.path.splitext(file)[0]}_custom.json")
                    save_to_json(custom_data, output_file)
                    print(f"Saved custom data to: {output_file}")
                    
                    # Extract and save function bodies
                    matched_functions = extract_matching_functions(custom_data, file_path)
                    if matched_functions:
                        functions_output_file = os.path.join(
                            root, f"{os.path.splitext(file)[0]}_function_bodies.json"
                        )
                        save_to_json(matched_functions, functions_output_file)
                        print(f"Saved function bodies to: {functions_output_file}")


# Main function
def main():
    # Example usage
    # final_erc_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/final_erc_specifications.json"
    final_erc_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/final_full_erc_specifications.json"
    # erc_base_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_source_code_ground_truth"
    # erc_base_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ground_truth_test"
    erc_base_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/ERC_Solidity_Source"
    
    
    custom_function_erc_folders(final_erc_file, erc_base_path)
    # for erc, dependencies in erc_dependencies.items():
    #     merge_dependencies(erc, dependencies)
    
    # print(f"erc_dependencies : {len(erc_dependencies)}")
    
    # final_erc_specifications()
    # final_basic_erc_specifications()
    # precision_and_recall(final_erc_file, erc_base_path)
    
    
   
    
    


if __name__ == "__main__":
    main()
