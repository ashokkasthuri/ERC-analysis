'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-03-09 18:53:43
LastEditors: ashokkasthuri ashokraj.kasthuri@gmail.com
LastEditTime: 2025-10-19 19:06:18
FilePath: /ERC-analysis-master/erc-classify/erc_results_analysis.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''

import pandas as pd
import os
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns



def combine_csv_results(csv_files, output_combined_file):
    
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


def visualize_erc_data(output_combined_file):
   
    df = pd.read_csv(output_combined_file)

    df['ERC Type'] = df['ERC Type'].str.split(';')

    df = df.explode('ERC Type')

    # Group by "ERC Type" and aggregate the "Count" and "Percentage"
    grouped_df = df.groupby('ERC Type').agg({
        'Count': 'sum',
        'Percentage': 'sum'
    }).reset_index()

    # Sort the DataFrame by "Count" in descending order
    grouped_df = grouped_df.sort_values(by='Count', ascending=False)

    # Display the grouped DataFrame
    print("Grouped Data:")
    print(grouped_df)

    # Visualization 1: Bar Plot of ERC Types by Count
    plt.figure(figsize=(10, 6))
    sns.barplot(x='ERC Type', y='Count', data=grouped_df, palette='viridis')
    plt.title('ERC Types by Count')
    plt.xlabel('ERC Type')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.show()

    # Visualization 2: Pie Chart of ERC Types by Percentage
    plt.figure(figsize=(8, 8))
    plt.pie(grouped_df['Percentage'], labels=grouped_df['ERC Type'], autopct='%1.1f%%', startangle=140, colors=sns.color_palette('viridis'))
    plt.title('ERC Types by Percentage')
    plt.show()

    # Visualization 3: Stacked Bar Plot of ERC Types by Source File
    source_file_df = df.groupby(['Source File', 'ERC Type']).agg({
        'Count': 'sum',
        'Percentage': 'sum'
    }).reset_index()

    plt.figure(figsize=(12, 6))
    sns.barplot(x='Source File', y='Count', hue='ERC Type', data=source_file_df, palette='viridis')
    plt.title('ERC Types by Source File')
    plt.xlabel('Source File')
    plt.ylabel('Count')
    plt.xticks(rotation=45)
    plt.legend(title='ERC Type', bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.show()

    # Visualization 4: Heatmap of ERC Types and Source Files
    heatmap_data = df.pivot_table(index='ERC Type', columns='Source File', values='Count', aggfunc='sum', fill_value=0)
    plt.figure(figsize=(10, 6))
    sns.heatmap(heatmap_data, annot=True, fmt='d', cmap='viridis')
    plt.title('Heatmap of ERC Types and Source Files')
    plt.xlabel('Source File')
    plt.ylabel('ERC Type')
    plt.show()


def erc_match_count():

    erc_match_counts_basic = {
        "Ethereum": {'ERC20': 508173, 'ERC173': 432867, 'ERC165': 118678, 'ERC721': 87046, 'ERC2612': 10029},
        "Binance":  {'ERC20': 1501163, 'ERC173': 1180861, 'ERC165': 88820, 'ERC721': 40071, 'ERC2612': 18499},
        "Polygon":  {'ERC173': 120221, 'ERC165': 95783, 'ERC721': 60443, 'ERC20': 39265},
        "Avalanche":{'ERC20': 32002, 'ERC173': 42786, 'ERC165': 12564, 'ERC721': 6227}
    }

    fig, ax = plt.subplots(figsize=(8,4))
    for chain, data in erc_match_counts_basic.items():
        df = pd.DataFrame.from_dict(data, orient='index', columns=['count'])
        df.sort_values('count', ascending=False).plot(kind='bar', ax=ax, label=chain)
    plt.ylabel("Contract Count")
    plt.title("Top ERC Implementations per Chain (Basic Config)")
    plt.legend()
    plt.tight_layout()
    plt.show()


def main():
#     folder_path = "/home/ashok/output" 
#     if not os.path.exists(folder_path):
#         raise ValueError(f"Folder '{folder_path}' does not exist.")
    
#     csv_files = [f for f in os.listdir(folder_path) if f.startswith("partial_match") and f.endswith(".csv")]
#     # output_combined_file = os.path.join(folder_path, "results_config_basic_analysis.csv")
#     output_combined_file = "/home/ashok/ERC-analysis/erc-classify/results_partial_match_config_FULL.csv"
    

    # combine_csv_results(csv_files, output_combined_file)
    
    # local_output_combined_file = "/Users/ashokk/Documents/ERC-analysis-master/erc-classify/results_partial_match_config_FULL.csv"
    # visualize_erc_data(local_output_combined_file)
    
    erc_match_count()


if __name__ == "__main__":
    main()