import requests
import pandas as pd

# ✅ Etherscan API Key (Replace with your valid API Key)
API_KEY = "Z8IMKB1ZVRIER3Q6U66MJPAKFY1V68IT87"

# ✅ Load contract addresses from CSV file
input_file = "contract2skelcode.csv"  # CSV file containing contract addresses
output_file = "output_results.csv"  # Output file to store results

# Read CSV file
df = pd.read_csv(input_file)

# Ensure 'address' column exists
if "address" not in df.columns:
    raise ValueError("CSV file must have a column named 'address'.")

# ✅ Function to check if contract has `permit` function
def check_permit_function(contract_address):
    url = f"https://api.etherscan.io/api?module=proxy&action=eth_getCode&address={contract_address}&tag=latest&apikey={API_KEY}"
    response = requests.get(url).json()

    bytecode = response.get("result", "")

    if "d505accf" in bytecode:
        print(f"contract contains permit : {contract_address} ")
        return "Contains permit"
         
# ✅ Process the first 100 contracts in the CSV file
df_subset = df.head(10000).copy()  # Create an explicit copy of the first 100 rows

# Apply the function to check for the permit function using .loc to avoid the warning
df_subset.loc[:, "Permit Check"] = df_subset["address"].apply(check_permit_function)

# ✅ Save results to a new CSV file
# df_subset.to_csv(output_file, index=False)

# print(f"✅ Analysis complete. Results saved to {output_file}")
