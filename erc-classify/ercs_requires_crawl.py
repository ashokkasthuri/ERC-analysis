import requests
from bs4 import BeautifulSoup
import csv

# List of ERCs to check
erc_list = [
    20, 721, 223, 777, 1155, 884, 998, 875, 1046, 1363, 2309, 2612, 1948, 1261, 1337,
    2021, 2018, 2019, 1996, 2020, 2981, 3135, 3440, 3589, 3754, 4494, 4524, 4675,
    3525, 3643, 4400, 4519, 4626, 4906, 4907, 4910, 4955, 5006, 5007, 5023, 5169,
    5192, 5267, 5375, 5380, 5484, 5489, 5507, 5521, 5528, 5570, 5585, 5606, 5615,
    5646, 5679, 5725, 5773, 6059, 6066, 6105, 6147, 6150, 6220, 6239, 6381, 6454,
    6492, 6672, 6808, 6809, 6982, 7160, 7231, 7401, 7409
]

# List of ERCs that are token standards
token_ercs = {20, 721, 1155, 777, 1363, 2612, 3525, 3643, 4626, 4907, 5192, 5380}

# Base URL for EIP pages
base_url = "https://eips.ethereum.org/EIPS/eip-"

# Function to extract "Requires" information
def get_requires(erc_number):
    url = base_url + str(erc_number)
    response = requests.get(url)
    
    if response.status_code != 200:
        return None  # Return None if the page is not found or there's an error
    
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Look for the "Requires" section using 'string' instead of 'text'
    requires_section = soup.find('th', string='Requires')
    
    if requires_section:
        requires_value = requires_section.find_next('td').text.strip()
        return requires_value
    else:
        return None  # Return None if "Requires" section is not found

# Prepare data for CSV
data = []
for erc in erc_list:
    requires = get_requires(erc)
    if requires is not None:
        data.append({"ERC": f"ERC-{erc}", "Requires": requires})
    else:
        data.append({"ERC": f"ERC-{erc}", "Requires": "No 'Requires' section found."})

# Add "TOKEN" column to the data
tokens = []
non_tokens = []
for row in data:
    erc_number = int(row["ERC"].split("-")[1])  # Extract ERC number from "ERC-<number>"
    
    # Check if the ERC itself is a token standard
    if erc_number in token_ercs:
        row["TOKEN"] = "TOKEN"
        tokens.append(row["ERC"])
    else:
        # Check if the "Requires" column contains any token ERCs
        requires = row["Requires"]
        if requires != "No 'Requires' section found.":
            # Extract all ERC numbers from the "Requires" column
            requires_ercs = [int(s.split("-")[1]) for s in requires.split(", ") if s.startswith("EIP-")]
            # Check if any of the required ERCs are token standards
            if any(req_erc in token_ercs for req_erc in requires_ercs):
                row["TOKEN"] = "TOKEN"
                tokens.append(row["ERC"])
            else:
                row["TOKEN"] = "Not a TOKEN"
                non_tokens.append(row["ERC"])
        else:
            row["TOKEN"] = "Not a TOKEN"
            non_tokens.append(row["ERC"])

# Add a new row for "All Tokens" and "All Non-Tokens"
all_tokens_row = {"ERC": "All Tokens", "Requires": ", ".join(tokens), "TOKEN": ""}
all_non_tokens_row = {"ERC": "All Non-Tokens", "Requires": ", ".join(non_tokens), "TOKEN": ""}

# Insert the new rows at the beginning of the data
data.insert(0, all_non_tokens_row)
data.insert(0, all_tokens_row)

# Write data to CSV
csv_file = "erc_requires_with_token.csv"
with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
    writer = csv.DictWriter(file, fieldnames=["ERC", "Requires", "TOKEN"])
    writer.writeheader()
    writer.writerows(data)

print(f"Data has been written to {csv_file}")