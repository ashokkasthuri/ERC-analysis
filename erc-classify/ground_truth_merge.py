import os

import json
from eth_utils import keccak



# Define the folder path where the ERC folders are located
folder_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_source_code_ground_truth"
# folder_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ground_truth_test"


# Define the dependencies for each ERC standard
erc_dependencies = {
    "ERC20": [],
    "ERC165": ["ERC214"],
    "ERC173": [],
    "ERC721": ["ERC165"],
    "ERC223": [],
    "ERC777": ["ERC1820"],
    "ERC1155": ["ERC165"],
    "ERC884": [],
    "ERC998": ["ERC20", "ERC165", "ERC721"],
    "ERC875": [],
    "ERC1046": ["ERC20", "ERC721", "ERC1155"],
    "ERC1363": ["ERC20", "ERC165"],
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





# Function to clean up function or event signature
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
    return selector
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
                # function_hash = keccak(text=function_signature).hex()[:8]
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

# Main function to process all ERC files
# def main():
#     final_json = {}
#     for root, dirs, files in os.walk(folder_path):
#         for file in files:
#             if file.startswith("final_ERC") and file.endswith(".sol"):
#                 erc_name = file.split("_")[1].split(".")[0]  # Extract ERC name from file name
#                 file_path = os.path.join(root, file)
#                 functions, events = extract_functions_and_events(file_path)
#                 erc_json = generate_json_structure(erc_name, functions, events)
#                 final_json.update(erc_json)
    
#     # Write the final JSON to a file
#     with open("final_erc_specifications.json", "w") as json_file:
#         json.dump(final_json, json_file, indent=4)
#     print("Final JSON file created: final_erc_specifications.json")

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
    
    # Compare extracted functions with expected functions
    for func, hash_ in extracted_functions.items():
        if func in expected_functions and expected_functions[func] == hash_:
            tp_functions += 1
        else:
            fp_functions += 1
    
    for func in expected_functions:
        if func not in extracted_functions:
            fn_functions += 1
    
    # Compare extracted events with expected events
    for event_hash, event_sig in extracted_events.items():
        if event_hash in expected_events and expected_events[event_hash] == event_sig:
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
    
    return {
        "functions": {"precision": precision_functions, "recall": recall_functions},
        "events": {"precision": precision_events, "recall": recall_events}
    }



# Main function
def main():
    # Path to the final ERC specifications
    final_erc_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/final_erc_specifications.json"
    final_erc = load_final_erc_specifications(final_erc_file)
    
    # Path to the directory containing ERC folders
    erc_base_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_source_code_ground_truth"
    # erc_base_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_ground_truth_test"
    
    
    # Initialize dictionaries for matched and non-matched ERCs
    matched_ercs = {}
    non_matched_ercs = {}
    
    # Iterate through each ERC folder
    for erc_name in final_erc:
        erc_folder = os.path.join(erc_base_path, erc_name)
        if not os.path.exists(erc_folder):
            print(f"ERC folder {erc_folder} does not exist.")
            continue
        # Initialize lists for matched and non-matched files for this ERC
        matched_files = []
        non_matched_files = []
        
      # Iterate through all Solidity files in the ERC folder (including subfolders)
        for root, _, files in os.walk(erc_folder):
            for file in files:
                if file.startswith("final_ERC") and file.endswith(".sol"):
                    file_path = os.path.join(root, file)
                    # Extract functions and events from the Solidity file
                    extracted_functions, extracted_events = extract_functions_and_events(file_path)
                    
                    # Compare with the ERC specification
                    erc_spec = final_erc[erc_name]
                    precision_recall = calculate_precision_recall(extracted_functions, extracted_events, erc_spec)
                    
                    # Determine if the ERC matches
                    if (precision_recall["functions"]["precision"] == 1.0 and
                        precision_recall["functions"]["recall"] == 1.0 and
                        precision_recall["events"]["precision"] == 1.0 and
                        precision_recall["events"]["recall"] == 1.0):
                        matched_files.append(file_path)
                    # if (precision_recall["functions"]["precision"] == 1.0):
                    #     matched_files.append(file_path)
                    else:
                        non_matched_files.append(file_path)
        # Add to the matched or non-matched collections
        if matched_files:
            matched_ercs[erc_name] = matched_files
        if non_matched_files:
            non_matched_ercs[erc_name] = non_matched_files
            
    # Print matched ERCs
    print("Matched ERCs:")
    for erc_name, files in matched_ercs.items():
        print(f"- ERC: {erc_name}")
        # for file_path in files:
        #     print(f"  - File: {file_path}")
    
    # Print non-matched ERCs
    print("\nNon-Matched ERCs:")
    for erc_name, files in non_matched_ercs.items():
        print(f"- ERC: {erc_name}")
        # for file_path in files:
        #     print(f"  - File: {file_path}")



# def main():
#     for erc, dependencies in erc_dependencies.items():
#         merge_dependencies(erc, dependencies)




# # Main function
# def main():
#     # Paths to the JSON files
#     final_erc_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/final_erc_specifications.json"
#     erc_config_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_config_top50.json"
    
#     # Compare the two JSON files
#     compare_json_files(final_erc_file, erc_config_file)

if __name__ == "__main__":
    main()
