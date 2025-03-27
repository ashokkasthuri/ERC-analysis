'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-03-27 11:16:22
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-03-27 14:51:51
FilePath: /ERC-analysis-master/erc-classify/erc_data_visualize.py
Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
'''
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
from collections import defaultdict

# ERC classification results from different blockchains
erc_match_counts = {
    "ethereum": {'ERC20': 508173, 'ERC173': 432867, 'ERC165': 118678, 'ERC3754': 87046, 'ERC721': 87046, 'ERC2612': 10029, 'ERC2981': 13523, 'ERC5267': 4009, 'ERC4907': 328},
    "polygon": {'ERC2981': 7255, 'ERC165': 95783, 'ERC5615': 2959, 'ERC173': 120221, 'ERC3754': 60443, 'ERC721': 60443, 'ERC20': 39265},
    "binance": {'ERC173': 1180861, 'ERC20': 1501163, 'ERC165': 88820, 'ERC3754': 40071, 'ERC721': 40071, 'ERC2612': 18499, 'ERC5615': 1750, 'ERC1363': 431},
    "avalanche": {'ERC20': 32002, 'ERC173': 42786, 'ERC165': 12564, 'ERC3754': 6227, 'ERC721': 6227, 'ERC2981': 1953, 'ERC5267': 1379}
}

erc_match_counts_partial = {
    "ethereum": {'ERC223': 535423, 'ERC1155': 8745, 'ERC5507_refund_erc721': 85596, 'ERC20': 20571, 'ERC3754': 274, 'ERC721': 274, 'ERC777': 181},
    "polygon": {'ERC1155': 17180, 'ERC5507_refund_erc721': 60318, 'ERC223': 47152, 'ERC20': 9217, 'ERC3754': 79, 'ERC721': 79},
    "binance": {'ERC223': 1541596, 'ERC5507_refund_erc721': 39289, 'ERC20': 40251, 'ERC1155': 5758, 'ERC3754': 188, 'ERC721': 188},
    "avalanche": {'ERC223': 35743, 'ERC5507_refund_erc721': 6078, 'ERC20': 4249, 'ERC1155': 880, 'ERC3754': 2, 'ERC721': 2}
}

# Total number of smart contracts processed per blockchain
total_smart_contracts = {
    "ethereum": 1114861,
    "polygon": 288611,
    "binance": 2308899,
    "avalanche": 96173
}

total_smart_contracts = 3808544  # 3.8 million 
# ERC20      2080603.0
# ERC173     1776735.0
# ERC165      315845.0
# ERC3754     193787.0
# ERC721      193787.0
# ERC2612      28528.0
# ERC2981      22731.0
# ERC5267       5388.0
# ERC5615       4709.0
# ERC1363        431.0

# 📊 Convert Data to Pandas DataFrame
df_full = pd.DataFrame(erc_match_counts).fillna(0)
df_partial = pd.DataFrame(erc_match_counts_partial).fillna(0)

# 🔹 Compute Percentage Usage of ERC Types
df_full_percentage = df_full.div(df_full.sum(axis=0), axis=1) * 100
df_partial_percentage = df_partial.div(df_partial.sum(axis=0), axis=1) * 100

# 🔥 Identify Most Common ERC Types Across All Blockchains
top_ercs = df_full.sum(axis=1).sort_values(ascending=False)

# 📊 Visualization - ERC Type Usage Across Blockchains
plt.figure(figsize=(12, 6))
df_full.T.plot(kind='bar', stacked=True, figsize=(14, 7))
plt.title("ERC Type Distribution Across Blockchains (Full Matches)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📊 Visualization - Percentage Distribution of ERCs
plt.figure(figsize=(12, 6))
df_full_percentage.T.plot(kind='bar', stacked=True, colormap='viridis', figsize=(14, 7))
plt.title("ERC Type Percentage Distribution Across Blockchains")
plt.xlabel("Blockchain")
plt.ylabel("Percentage (%)")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📊 Pie Chart for Most Common ERC Types
plt.figure(figsize=(8, 8))
top_ercs[:10].plot(kind='pie', autopct='%1.1f%%', startangle=90, cmap='coolwarm')
plt.title("Top 10 Most Frequently Used ERC Standards")
plt.ylabel("")
plt.show()

# 📊 Comparing Full and Partial Match Results
plt.figure(figsize=(12, 6))
df_partial.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap='cool')
plt.title("ERC Type Distribution Across Blockchains (Partial Matches)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 🔥 Insights on ERC Usage
print("\n🔹 **Most Frequently Used ERC Standards Across All Blockchains:**")
print(top_ercs.head(10))

print("\n🔹 **ERC Type Breakdown Per Blockchain (Full Matches):**")
print(df_full)

print("\n🔹 **ERC Type Percentage Breakdown Per Blockchain (Full Matches):**")
print(df_full_percentage)

print("\n🔹 **ERC Type Breakdown Per Blockchain (Partial Matches):**")
print(df_partial)

print("\n🔹 **ERC Type Percentage Breakdown Per Blockchain (Partial Matches):**")
print(df_partial_percentage)
