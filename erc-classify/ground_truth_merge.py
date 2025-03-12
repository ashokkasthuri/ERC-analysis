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
                # print(f"function_signature : {function_signature}")
                
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


# def main():
#     for erc, dependencies in erc_dependencies.items():
#         merge_dependencies(erc, dependencies)



# Load the two JSON files
def load_json(file_path):
    with open(file_path, 'r') as file:
        return json.load(file)

# Normalize event signatures by removing the "event" keyword
def normalize_events(events):
    normalized = {}
    for hash_, signature in events.items():
        if signature.startswith("event "):
            signature = signature[len("event "):]
        normalized[hash_] = signature
    return normalized

# Compare two JSON files and identify differences
def compare_json_files(file1, file2):
    # Load the JSON data
    final_erc = load_json(file1)
    erc_config = load_json(file2)
    
    # Initialize lists to store matching and non-matching ERCs
    matching_ercs = []
    non_matching_ercs = []
    missing_in_config = []
    missing_in_final = []
    
    # Iterate through each ERC in the final_erc_specifications.json
    for erc_name, erc_data in final_erc.items():
        if erc_name in erc_config:
            # Compare functions and events
            config_data = erc_config[erc_name]
            
            # Normalize event signatures in erc_config_top50.json
            config_data["events"] = normalize_events(config_data.get("events", {}))
            
            # Get functions and events
            final_functions = erc_data.get("functions", {})
            config_functions = config_data.get("functions", {})
            
            final_events = erc_data.get("events", {})
            config_events = config_data.get("events", {})
            
            # Check if the number of functions and events matches
            num_functions_match = len(final_functions) == len(config_functions)
            num_events_match = len(final_events) == len(config_events)
            
            # Check if function hashes match (order-independent)
            functions_match = final_functions == config_functions
            
            # Check if event hashes match (order-independent)
            events_match = final_events == config_events
            
            # Determine if the ERC matches completely
            if num_functions_match and num_events_match and functions_match and events_match:
                matching_ercs.append(erc_name)
            else:
                non_matching_ercs.append(erc_name)
        else:
            missing_in_config.append(erc_name)
    
    # Check for ERCs in erc_config_top50.json that are not in final_erc_specifications.json
    for erc_name in erc_config:
        if erc_name not in final_erc:
            missing_in_final.append(erc_name)
    
    # Print results
    print(f"\nMatching ERCs: {matching_ercs}")
    # for erc in matching_ercs:
    #     print(f"- {erc} has the same number of functions and events, and all hashes match.")
    
    print(f"\nNon-Matching ERCs: {non_matching_ercs}")
    # for erc in non_matching_ercs:
    #     print(f"- {erc} has differences in the number of functions/events or their hashes.")
    
    print(f"\nERCs missing in 'erc_config_top50.json': {missing_in_config}")
    # for erc in missing_in_config:
    #     print(f"- {erc}")
    
    print(f"\nERCs missing in 'final_erc_specifications.json': {missing_in_final}")
    # for erc in missing_in_final:
    #     print(f"- {erc}")


# Main function
def main():
    # Paths to the JSON files
    final_erc_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/final_erc_specifications.json"
    erc_config_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/erc_config_top50.json"
    
    # Compare the two JSON files
    compare_json_files(final_erc_file, erc_config_file)

if __name__ == "__main__":
    main()
