'''
Author: ashokkasthuri ashokk@smu.edu.sg
Date: 2025-03-27 11:16:22
LastEditors: ashokkasthuri ashokk@smu.edu.sg
LastEditTime: 2025-07-22 14:11:42
'''
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
# import ace_tools as tools

# ERC classification results for Basic Config
erc_match_counts_basic = {
    "Ethereum": {'ERC20': 508173, 'ERC173': 432867, 'ERC165': 118678, 'ERC3754': 87046, 'ERC721': 87046, 'ERC2612': 10029, 'ERC2981': 13523, 'ERC5267': 4009},
    "Polygon": {'ERC2981': 7255, 'ERC165': 95783, 'ERC5615': 2959, 'ERC173': 120221, 'ERC3754': 60443, 'ERC721': 60443, 'ERC20': 39265},
    "Binance": {'ERC173': 1180861, 'ERC20': 1501163, 'ERC165': 88820, 'ERC3754': 40071, 'ERC721': 40071, 'ERC2612': 18499, 'ERC5615': 1750},
    "Avalanche": {'ERC20': 32002, 'ERC173': 42786, 'ERC165': 12564, 'ERC3754': 6227, 'ERC721': 6227, 'ERC2981': 1953, 'ERC5267': 1379}
}

erc_match_counts_partial_basic = {
    "Ethereum": {'ERC223': 535423, 'ERC1155': 8745, 'ERC5507_refund_erc721': 85596, 'ERC20': 20571, 'ERC3754': 274, 'ERC721': 274, 'ERC777': 181},
    "Polygon": {'ERC1155': 17180, 'ERC5507_refund_erc721': 60318, 'ERC223': 47152, 'ERC20': 9217, 'ERC3754': 79, 'ERC721': 79},
    "Binance": {'ERC223': 1541596, 'ERC5507_refund_erc721': 39289, 'ERC20': 40251, 'ERC1155': 5758, 'ERC3754': 188, 'ERC721': 188},
    "Avalanche": {'ERC223': 35743, 'ERC5507_refund_erc721': 6078, 'ERC20': 4249, 'ERC1155': 880, 'ERC3754': 2, 'ERC721': 2}
}

# Full Config Results
erc_match_counts_full = {
    "Ethereum": {'ERC20': 508173, 'ERC173': 88439, 'ERC165': 118678, 'ERC4906': 84501, 'ERC3754': 87046, 'ERC721': 85596, 'ERC2612': 9895, 'ERC2981': 13355, 'ERC5267': 3094},
    "Polygon": {'ERC2981': 7150, 'ERC165': 95783, 'ERC173': 64703, 'ERC3754': 60443, 'ERC721': 60318, 'ERC4906': 57208, 'ERC20': 39265},
    "Binance": {'ERC20': 1501163, 'ERC4906': 37988, 'ERC165': 88820, 'ERC3754': 40071, 'ERC721': 39289, 'ERC173': 43075, 'ERC2612': 18236},
    "Avalanche": {'ERC20': 32002, 'ERC173': 6333, 'ERC165': 12564, 'ERC3754': 6227, 'ERC721': 6078, 'ERC4906': 5815, 'ERC2981': 1927, 'ERC5267': 1148}
}

erc_match_counts_partial_full = {
    "Ethereum": {'ERC223': 535423, 'ERC1155': 8790, 'ERC1948': 87135, 'ERC4400': 87111, 'ERC5007': 87119, 'ERC5484': 87208, 'ERC6239': 87117},
    "Polygon": {'ERC5615': 3642, 'ERC1155': 17200, 'ERC1948': 60466, 'ERC4400': 60463, 'ERC5007': 60462, 'ERC5484': 60520, 'ERC6239': 60460},
    "Binance": {'ERC223': 1541596, 'ERC1948': 40171, 'ERC4400': 40124, 'ERC5007': 40126, 'ERC5484': 40230, 'ERC6239': 40126},
    "Avalanche": {'ERC223': 35743, 'ERC1948': 6227, 'ERC4400': 6227, 'ERC5007': 6227, 'ERC5484': 6228, 'ERC6239': 6227}
}

# Convert dictionaries to DataFrame
df_basic = pd.DataFrame(erc_match_counts_basic).fillna(0)
df_full = pd.DataFrame(erc_match_counts_full).fillna(0)
df_partial_basic = pd.DataFrame(erc_match_counts_partial_basic).fillna(0)
df_partial_full = pd.DataFrame(erc_match_counts_partial_full).fillna(0)

# Merge the data for combined analysis
df_combined = df_basic.add(df_full, fill_value=0)
df_partial_combined = df_partial_basic.add(df_partial_full, fill_value=0)

# Identify Most Common ERC Types
top_ercs_combined = df_combined.sum(axis=1).sort_values(ascending=False)

# 📊 Visualization - ERC Type Distribution for Basic Config
plt.figure(figsize=(12, 6))
df_basic.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap="Blues")
plt.title("ERC Type Distribution Across Blockchains (Basic Config)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📊 Visualization - ERC Type Distribution for Full Config
plt.figure(figsize=(12, 6))
df_full.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap="Oranges")
plt.title("ERC Type Distribution Across Blockchains (Full Config)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📊 Visualization - ERC Type Distribution Across Blockchains (Basic + Full)
plt.figure(figsize=(12, 6))
df_combined.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap="coolwarm")
plt.title("ERC Type Distribution Across Blockchains (Basic + Full Matches)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📊 Visualization - Partial Matches Across Blockchains
plt.figure(figsize=(12, 6))
df_partial_combined.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap="cool")
plt.title("ERC Type Distribution Across Blockchains (Partial Matches - Basic + Full)")
plt.xlabel("Blockchain")
plt.ylabel("Number of Contracts")
plt.xticks(rotation=45)
plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
plt.show()

# 📜 Display ERC Type Breakdown

# tools.display_dataframe_to_user(name="ERC Type Breakdown (Basic + Full Configurations)", dataframe=df_combined)
# tools.display_dataframe_to_user(name="ERC Type Breakdown (Partial Matches - Basic + Full Configurations)", dataframe=df_partial_combined)

print("ERC Type Breakdown (Basic + Full Configurations):")
print(df_combined)

print("\nERC Type Breakdown (Partial Matches - Basic + Full Configurations):")
print(df_partial_combined)
