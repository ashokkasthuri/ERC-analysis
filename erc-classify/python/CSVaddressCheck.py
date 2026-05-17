'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-02-14 09:28:09
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-02-14 09:28:19
FilePath: /ERC-classify/CSVaddressCheck.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
import pandas as pd

 # Load the CSV files into dataframes.
df1 = pd.read_csv('test_erc_classification_results.csv')  # Replace with your first CSV file path
df2 = pd.read_csv('test1_erc_classification_results.csv')  # Replace with your second CSV file path

# Extract the "address" column from each DataFrame as a set.
addresses1 = set(df1['address'].dropna().unique())
addresses2 = set(df2['address'].dropna().unique())

# Compute unique addresses in each file.
unique_in_file1 = addresses1 - addresses2
unique_in_file2 = addresses2 - addresses1

print("Unique addresses in file1 (not in file2):")
for addr in unique_in_file1:
    print(addr)

print("\nUnique addresses in file2 (not in file1):")
for addr in unique_in_file2:
    print(addr)
