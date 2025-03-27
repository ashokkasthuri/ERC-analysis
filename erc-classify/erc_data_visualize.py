# '''
# Author: ashokkasthuri ashokk@smu.edu.sg
# Date: 2025-03-27 11:16:22
# LastEditors: ashokkasthuri ashokk@smu.edu.sg
# LastEditTime: 2025-03-27 14:51:51
# FilePath: /ERC-analysis-master/erc-classify/erc_data_visualize.py
# Description: 这是默认设置,请设置`customMade`, 打开koroFileHeader查看配置 进行设置: https://github.com/OBKoro1/koro1FileHeader/wiki/%E9%85%8D%E7%BD%AE
# '''
# import matplotlib.pyplot as plt
# import pandas as pd
# import numpy as np
# from collections import defaultdict

# # ERC classification results from different blockchains
# erc_match_counts = {
#     "ethereum": {'ERC20': 508173, 'ERC173': 432867, 'ERC165': 118678, 'ERC3754': 87046, 'ERC721': 87046, 'ERC2612': 10029, 'ERC2981': 13523, 'ERC5267': 4009, 'ERC4907': 328},
#     "polygon": {'ERC2981': 7255, 'ERC165': 95783, 'ERC5615': 2959, 'ERC173': 120221, 'ERC3754': 60443, 'ERC721': 60443, 'ERC20': 39265},
#     "binance": {'ERC173': 1180861, 'ERC20': 1501163, 'ERC165': 88820, 'ERC3754': 40071, 'ERC721': 40071, 'ERC2612': 18499, 'ERC5615': 1750, 'ERC1363': 431},
#     "avalanche": {'ERC20': 32002, 'ERC173': 42786, 'ERC165': 12564, 'ERC3754': 6227, 'ERC721': 6227, 'ERC2981': 1953, 'ERC5267': 1379}
# }

# erc_match_counts_partial = {
#     "ethereum": {'ERC223': 535423, 'ERC1155': 8745, 'ERC5507_refund_erc721': 85596, 'ERC20': 20571, 'ERC3754': 274, 'ERC721': 274, 'ERC777': 181},
#     "polygon": {'ERC1155': 17180, 'ERC5507_refund_erc721': 60318, 'ERC223': 47152, 'ERC20': 9217, 'ERC3754': 79, 'ERC721': 79},
#     "binance": {'ERC223': 1541596, 'ERC5507_refund_erc721': 39289, 'ERC20': 40251, 'ERC1155': 5758, 'ERC3754': 188, 'ERC721': 188},
#     "avalanche": {'ERC223': 35743, 'ERC5507_refund_erc721': 6078, 'ERC20': 4249, 'ERC1155': 880, 'ERC3754': 2, 'ERC721': 2}
# }

# # Total number of smart contracts processed per blockchain
# total_smart_contracts = {
#     "ethereum": 1114861,
#     "polygon": 288611,
#     "binance": 2308899,
#     "avalanche": 96173
# }

# total_smart_contracts = 3808544  # 3.8 million 
# # ERC20      2080603.0
# # ERC173     1776735.0
# # ERC165      315845.0
# # ERC3754     193787.0
# # ERC721      193787.0
# # ERC2612      28528.0
# # ERC2981      22731.0
# # ERC5267       5388.0
# # ERC5615       4709.0
# # ERC1363        431.0

# # 📊 Convert Data to Pandas DataFrame
# df_full = pd.DataFrame(erc_match_counts).fillna(0)
# df_partial = pd.DataFrame(erc_match_counts_partial).fillna(0)

# # 🔹 Compute Percentage Usage of ERC Types
# df_full_percentage = df_full.div(df_full.sum(axis=0), axis=1) * 100
# df_partial_percentage = df_partial.div(df_partial.sum(axis=0), axis=1) * 100

# # 🔥 Identify Most Common ERC Types Across All Blockchains
# top_ercs = df_full.sum(axis=1).sort_values(ascending=False)

# # 📊 Visualization - ERC Type Usage Across Blockchains
# plt.figure(figsize=(12, 6))
# df_full.T.plot(kind='bar', stacked=True, figsize=(14, 7))
# plt.title("ERC Type Distribution Across Blockchains (Full Matches)")
# plt.xlabel("Blockchain")
# plt.ylabel("Number of Contracts")
# plt.xticks(rotation=45)
# plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
# plt.show()

# # 📊 Visualization - Percentage Distribution of ERCs
# plt.figure(figsize=(12, 6))
# df_full_percentage.T.plot(kind='bar', stacked=True, colormap='viridis', figsize=(14, 7))
# plt.title("ERC Type Percentage Distribution Across Blockchains")
# plt.xlabel("Blockchain")
# plt.ylabel("Percentage (%)")
# plt.xticks(rotation=45)
# plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
# plt.show()

# # 📊 Pie Chart for Most Common ERC Types
# plt.figure(figsize=(8, 8))
# top_ercs[:10].plot(kind='pie', autopct='%1.1f%%', startangle=90, cmap='coolwarm')
# plt.title("Top 10 Most Frequently Used ERC Standards")
# plt.ylabel("")
# plt.show()

# # 📊 Comparing Full and Partial Match Results
# plt.figure(figsize=(12, 6))
# df_partial.T.plot(kind='bar', stacked=True, figsize=(14, 7), colormap='cool')
# plt.title("ERC Type Distribution Across Blockchains (Partial Matches)")
# plt.xlabel("Blockchain")
# plt.ylabel("Number of Contracts")
# plt.xticks(rotation=45)
# plt.legend(title="ERC Type", bbox_to_anchor=(1, 1))
# plt.show()

# # 🔥 Insights on ERC Usage
# print("\n🔹 **Most Frequently Used ERC Standards Across All Blockchains:**")
# print(top_ercs.head(10))

# print("\n🔹 **ERC Type Breakdown Per Blockchain (Full Matches):**")
# print(df_full)

# print("\n🔹 **ERC Type Percentage Breakdown Per Blockchain (Full Matches):**")
# print(df_full_percentage)

# print("\n🔹 **ERC Type Breakdown Per Blockchain (Partial Matches):**")
# print(df_partial)

# print("\n🔹 **ERC Type Percentage Breakdown Per Blockchain (Partial Matches):**")
# print(df_partial_percentage)



import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict

# Data from your output
chain_data = {
    'ethereum': {
        'total_contracts': 1114861,
        'erc_match_counts': defaultdict(int, {'ERC20': 508173, 'ERC173': 432867, 'ERC165': 118678, 'ERC3754': 87046, 'ERC721': 87046, 'ERC2612': 10029, 'ERC2981': 13523, 'ERC5267': 4009, 'ERC4907': 328, 'ERC6492': 2637, 'ERC1271': 2637, 'ERC5615': 2259, 'ERC4626': 994, 'ERC6454': 24, 'ERC223': 2197, 'ERC1363': 339, 'ERC777': 187, 'ERC5192': 234, 'ERC4494': 34, 'ERC3525': 16, 'ERC1820': 24, 'ERC884': 7, 'ERC998': 16, 'ERC3643': 2, 'ERC5007': 22, 'ERC5169': 19, 'ERC6672': 2, 'ERC4524': 21, 'ERC875': 5, 'ERC5484': 8, 'ERC5023': 8, 'ERC3589': 1, 'ERC5773': 18, 'ERC4400': 12, 'ERC2021': 8, 'ERC6239': 5, 'ERC1948': 3, 'ERC5679Ext20': 1, 'ERC7160': 1, 'ERC5489': 5, 'ERC6808': 1, 'ERC6809': 1, 'ERC2135': 1, 'ERC6066': 5, 'ERC6150': 1, 'ERC6982': 2, 'ERC5006': 1}),
        'erc_match_counts_partial': defaultdict(int, {'ERC223': 535423, 'ERC1155': 8745, 'ERC5507_refund_erc721': 85596, 'ERC20': 20571, 'ERC3754': 274, 'ERC721': 274, 'ERC777': 181, 'ERC3525': 2, 'ERC4626': 62, 'ERC4524': 18, 'ERC3643': 3, 'ERC1820': 10, 'ERC998': 2, 'ERC6672': 1, 'ERC884': 3, 'ERC7401': 20, 'ERC6059': 20, 'ERC6220': 16, 'ERC875': 7, 'ERC3589': 4, 'ERC1996': 8, 'ERC1261': 2})
    },
    'polygon': {
        'total_contracts': 288611,
        'erc_match_counts': defaultdict(int, {'ERC2981': 7255, 'ERC165': 95783, 'ERC5615': 2959, 'ERC173': 120221, 'ERC3754': 60443, 'ERC721': 60443, 'ERC20': 39265, 'ERC5267': 3734, 'ERC2612': 5717, 'ERC6492': 1562, 'ERC1271': 1562, 'ERC1363': 112, 'ERC4626': 449, 'ERC4524': 15, 'ERC4907': 166, 'ERC6454': 22, 'ERC5773': 19, 'ERC5192': 298, 'ERC4494': 78, 'ERC223': 8, 'ERC5169': 8953, 'ERC5484': 6, 'ERC3525': 36, 'ERC6150': 2, 'ERC777': 48, 'ERC6239': 11, 'ERC884': 2, 'ERC3643': 18, 'ERC5007': 8, 'ERC6672': 5, 'ERC998': 3, 'ERC5679Ext721': 2, 'ERC6982': 1, 'ERC5006': 2}),
        'erc_match_counts_partial': defaultdict(int, {'ERC1155': 17180, 'ERC5507_refund_erc721': 60318, 'ERC223': 47152, 'ERC20': 9217, 'ERC3754': 79, 'ERC721': 79, 'ERC7401': 20, 'ERC6059': 20, 'ERC6220': 17, 'ERC4524': 28, 'ERC777': 34, 'ERC998': 1, 'ERC4626': 57, 'ERC3643': 5, 'ERC875': 1, 'ERC6672': 2})
    },
    'binance': {
        'total_contracts': 2308899,
        'erc_match_counts': defaultdict(int, {'ERC173': 1180861, 'ERC20': 1501163, 'ERC165': 88820, 'ERC3754': 40071, 'ERC721': 40071, 'ERC2612': 18499, 'ERC5615': 1750, 'ERC1363': 431, 'ERC6492': 1619, 'ERC1271': 1619, 'ERC2981': 2464, 'ERC5192': 225, 'ERC4907': 82, 'ERC4494': 33, 'ERC5267': 6896, 'ERC4626': 386, 'ERC223': 80, 'ERC777': 217, 'ERC4524': 16, 'ERC6454': 12, 'ERC5725': 8, 'ERC5484': 48, 'ERC6239': 1, 'ERC5007': 57, 'ERC5006': 1, 'ERC3525': 12, 'ERC1820': 3, 'ERC1155': 1, 'ERC5169': 57, 'ERC6672': 1, 'ERC7231': 1, 'ERC5773': 11, 'ERC998': 1, 'ERC5679Ext20': 3, 'ERC4400': 2, 'ERC6150': 1}),
        'erc_match_counts_partial': defaultdict(int, {'ERC223': 1541596, 'ERC5507_refund_erc721': 39289, 'ERC20': 40251, 'ERC1155': 5758, 'ERC3754': 188, 'ERC721': 188, 'ERC4524': 38, 'ERC4626': 31, 'ERC777': 97, 'ERC3589': 5, 'ERC875': 8, 'ERC7401': 12, 'ERC6059': 12, 'ERC6220': 11, 'ERC3525': 4, 'ERC1820': 1})
    },
    'avalanche': {
        'total_contracts': 96173,
        'erc_match_counts': defaultdict(int, {'ERC20': 32002, 'ERC173': 42786, 'ERC165': 12564, 'ERC3754': 6227, 'ERC721': 6227, 'ERC2981': 1953, 'ERC5267': 1379, 'ERC2612': 3070, 'ERC6492': 495, 'ERC1271': 495, 'ERC5615': 293, 'ERC4907': 14, 'ERC5192': 88, 'ERC1363': 25, 'ERC777': 12, 'ERC4494': 14, 'ERC4626': 124, 'ERC5484': 4, 'ERC3525': 3, 'ERC3643': 12, 'ERC5007': 5, 'ERC5679Ext20': 3, 'ERC7231': 3, 'ERC223': 4, 'ERC5006': 1, 'ERC5725': 1}),
        'erc_match_counts_partial': defaultdict(int, {'ERC223': 35743, 'ERC5507_refund_erc721': 6078, 'ERC20': 4249, 'ERC1155': 880, 'ERC3754': 2, 'ERC721': 2, 'ERC4626': 7, 'ERC3525': 3, 'ERC4524': 2, 'ERC777': 2})
    }
}

# Process data into DataFrame
data = []
for chain, values in chain_data.items():
    for erc, count in values['erc_match_counts'].items():
        data.append({
            'Chain': chain.capitalize(),
            'ERC': erc,
            'Count': count,
            'Type': 'Full',
            'Percentage': (count / values['total_contracts']) * 100
        })
    for erc, count in values['erc_match_counts_partial'].items():
        data.append({
            'Chain': chain.capitalize(),
            'ERC': erc,
            'Count': count,
            'Type': 'Partial',
            'Percentage': (count / values['total_contracts']) * 100
        })

df = pd.DataFrame(data)

# Visualization 1: Top ERC Standards Across All Chains
plt.figure(figsize=(14, 8))
top_ercs = df.groupby('ERC')['Count'].sum().nlargest(15).index
sns.barplot(data=df[df['ERC'].isin(top_ercs)], x='Count', y='ERC', hue='Type', 
            estimator=sum, ci=None, palette='viridis')
plt.title('Top 15 ERC Standards (Full vs Partial Implementation)')
plt.xlabel('Total Contracts')
plt.ylabel('ERC Standard')
plt.legend(title='Implementation')
plt.tight_layout()
plt.savefig('top_erc_standards.png')
plt.show()

# Visualization 2: ERC Adoption by Blockchain
plt.figure(figsize=(14, 8))
top_chains = df.groupby(['Chain', 'ERC'])['Count'].sum().unstack().fillna(0)
top_chains = top_chains[top_ercs].T
sns.heatmap(top_chains, annot=True, fmt='.0f', cmap='YlGnBu', 
            cbar_kws={'label': 'Number of Contracts'})
plt.title('ERC Standard Adoption by Blockchain')
plt.xlabel('Blockchain')
plt.ylabel('ERC Standard')
plt.tight_layout()
plt.savefig('erc_adoption_by_chain.png')
plt.show()

# Visualization 3: Implementation Completeness
impl_quality = df.groupby(['ERC', 'Type'])['Count'].sum().unstack().fillna(0)
impl_quality['Completion_Rate'] = impl_quality['Full'] / (impl_quality['Full'] + impl_quality['Partial']) * 100
impl_quality = impl_quality.nlargest(15, 'Completion_Rate')

plt.figure(figsize=(14, 8))
sns.barplot(data=impl_quality.reset_index(), x='Completion_Rate', y='ERC', 
            palette='coolwarm')
plt.title('Top 15 ERC Standards by Implementation Completeness')
plt.xlabel('Full Implementation Rate (%)')
plt.ylabel('ERC Standard')
plt.xlim(0, 100)
plt.tight_layout()
plt.savefig('implementation_completeness.png')
plt.show()

# Generate research priority table
research_priority = df.groupby('ERC').agg({
    'Count': 'sum',
    'Percentage': 'mean'
}).nlargest(10, 'Count')
research_priority['Priority'] = ['High' if erc in ['ERC20', 'ERC721', 'ERC1155', 'ERC2612'] 
                                else 'Medium' for erc in research_priority.index]
print("\nTop 10 ERC Standards for Research:")
print(research_priority[['Count', 'Percentage', 'Priority']].to_markdown())
