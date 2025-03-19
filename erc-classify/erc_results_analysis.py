'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-03-09 18:53:43
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-03-19 10:13:12
FilePath: /ERC-analysis-master/erc-classify/results_analysis.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
import pandas as pd
import os

# Define the folder containing the CSV files
# folder_path = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/server_output"  # Replace with your actual file path
folder_path = "/home/ashok/ERC-analysis/erc-classify" 

output_combined_file = os.path.join(folder_path, "combined_erc_basic_analysis_results.csv")

# Ensure the folder exists
if not os.path.exists(folder_path):
    raise ValueError(f"Folder '{folder_path}' does not exist.")

# List all CSV files in the folder
csv_files = [f for f in os.listdir(folder_path) if f.startswith("final_basic_") and f.endswith(".csv")]

# Ensure there are CSV files to process
if not csv_files:
    raise ValueError("No CSV files found in the folder.")

# Create an empty list to store all results
all_results = []

# Iterate over each CSV file in the folder
for file_name in csv_files:
    file_path = os.path.join(folder_path, file_name)
    
    try:
        # Load the CSV file
        df = pd.read_csv(file_path)

        # Ensure required columns exist
        if "matched_erc" not in df.columns or "Binary Token Classification" not in df.columns:
            print(f"Skipping {file_name}: Missing required columns.")
            continue

        # Count occurrences of each unique ERC match
        erc_counts = df["matched_erc"].value_counts().reset_index()
        erc_counts.columns = ["ERC Type", "Count"]

        # Calculate percentage of total
        total_addresses = len(df)
        erc_counts["Percentage"] = (erc_counts["Count"] / total_addresses) * 100

        # Add filename column to track which file the data came from
        erc_counts["Source File"] = file_name

        # Append to the combined list
        all_results.append(erc_counts)

    except Exception as e:
        print(f"Error processing {file_name}: {e}")

# Combine all results into a single DataFrame
if all_results:
    combined_df = pd.concat(all_results, ignore_index=True)
    
    # Save combined results to a single CSV file
    combined_df.to_csv(output_combined_file, index=False)
    
    print(f"✅ Combined analysis saved to: {output_combined_file}")
else:
    print("⚠ No valid data to combine.")

