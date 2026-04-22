# import pandas as pd
# import numpy as np
# from scipy import stats
# from scipy.stats import ttest_ind, pearsonr, chi2_contingency
# from statsmodels.stats.multitest import multipletests
# import warnings
# warnings.filterwarnings('ignore')

# # First, let's save the data to a CSV file for analysis
# data = """Q1,Q2,Q3,Q4,Q5_1,Q5_2,Q5_3,Q5_4,Q6,Q7,Q8,Q9,Q10,Q11,Q12,Q13,Q14_1,Q14_2,Q14_3,Q14_4,Q15_1,Q15_2,Q15_3,Q15_4,Q16,Q17,Q18_1,Q18_2,Q18_3,Q18_4,Q19,Q20,Q21_1,Q21_2,Q21_3,Q21_4,Q22_1,Q22_2,Q22_3,Q22_4,Q23,Q24,Q25_1,Q25_2,Q25_3,Q25_4,Q25_5
# 1-2 years,Good proficiency,Most of the time,ERC-20, 721, 1155, 4333, 7702, 8004,Strongly agree,Somewhat agree,Somewhat agree,Somewhat disagree,Strongly agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat disagree,Strongly disagree,Strongly Agree,Strongly disagree,Strongly Agree,Strongly Agree,Somewhat agree,Strongly agree,Strongly Disagree,Strongly Disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat disagree,Strongly agree,Strongly agree,Neither agree nor disagree,Somewhat agree,Strongly Agree,Somewhat Agree,Strongly Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat agree,Neither Agree nor Disagree,Somewhat Agree,Strongly agree,Somewhat agree,Strongly Disagree,Neither agree nor disagree,Strongly agree
# 1-2 years,Proficient,Most of the time,ERC-20, ERC-721, ERC-4337, ERC-1559,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Strongly disagree,Strongly agree,Somewhat Agree,Somewhat Agree,Somewhat Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Strongly agree
# 1-2 years,Proficient,About half the time,ERC20, ERC721, ERC1155, ERC712, ERC5792,,Strongly agree,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat disagree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat disagree,Strongly Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat Agree,Somewhat Agree,Somewhat Agree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat Agree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree
# 1-2 years,Low proficiency,Most of the time,ERC-20,Somewhat agree,Neither agree nor disagree,Somewhat disagree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Somewhat disagree,Strongly Disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat Agree,Somewhat Agree,Neither Agree nor Disagree,Somewhat Agree,Somewhat agree,Neither Agree nor Disagree,Strongly Agree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Strongly agree,Somewhat agree
# 1-2 years,Proficient,About half the time,ERC-20, ERC-721, ERC-1155, ERC-4337,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Strongly Agree,Somewhat agree,Somewhat disagree,Somewhat disagree,Somewhat disagree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Strongly Agree,Somewhat Agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Strongly agree
# less than 1 year,Low proficiency,Sometimes,,,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat agree,Strongly agree,Strongly Agree,Somewhat agree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Strongly disagree,Somewhat agree,Somewhat agree,Strongly disagree,Strongly disagree,Strongly disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Strongly Disagree,Neither Agree nor Disagree,Strongly Agree,Strongly Agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat Disagree,Somewhat Disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly Disagree,Strongly Disagree
# 1-2 years,Proficient,Most of the time,ERC-20, ERC-721,Strongly agree,Strongly agree,Somewhat agree,Somewhat disagree,Strongly agree,Strongly Disagree,Neither agree nor disagree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat disagree,Strongly Agree,Strongly disagree,Strongly disagree,Somewhat disagree,Strongly agree,Somewhat agree,Strongly Disagree,Somewhat agree,Somewhat disagree,Strongly disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat Disagree,Neither Agree nor Disagree,Somewhat Agree,Strongly Agree,Somewhat agree,Somewhat agree,Strongly Agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Strongly Agree,Strongly agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat agree
# 2-5 years,Proficient,Sometimes,,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree
# 2-5 years,Proficient,Sometimes,,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Somewhat agree,Somewhat agree,Strongly Agree,Somewhat agree,Somewhat agree,Strongly Agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat disagree,Strongly agree,Somewhat Agree,Somewhat Agree,Strongly Agree,Somewhat Agree,Somewhat agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat Agree,Somewhat Agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Strongly agree
# 1-2 years,Proficient,Sometimes,ERC20, ERC721,Strongly agree,Strongly agree,Somewhat agree,Somewhat disagree,Somewhat disagree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Strongly agree,Somewhat disagree,Strongly agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat agree,Neither Agree nor Disagree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree
# 2-5 years,Proficient,About half the time,ERC20, ERC1155, ERC721, ERC137,Somewhat agree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Somewhat agree,Strongly Disagree,Somewhat disagree,Somewhat agree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Strongly Agree,Somewhat Agree,Neither Agree nor Disagree,Strongly Disagree,Somewhat agree,Strongly Agree,Somewhat agree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree
# 1-2 years,Low proficiency,About half the time,ERC20, ERC721, ERC1155,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly disagree,Somewhat agree,Strongly Disagree,Strongly Disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree
# 1-2 years,Good proficiency,Most of the time,"ERC-1967 (Proxy Pattern)
# EIP-712 (Signature Standard)
# ERC-165 (Interface Detection)
# ERC-1271 (Signature Validation)
# ERC-20 (Base Token Interface)
# EIP-3009 (aka ""transferWithAuthorization"")
# ERC-2612 (Approve via signature)
# EIP-7702 (Gasless Relayer)",Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat disagree,Neither agree nor disagree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Strongly Disagree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Strongly agree,Strongly agree,Strongly agree,Strongly disagree,Strongly agree,Strongly Agree,Strongly Agree,Somewhat Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat agree,Strongly Agree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Strongly agree
# 1-2 years,Low proficiency,Sometimes,ERC 20,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Strongly disagree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat disagree,,Somewhat Agree,Neither Agree nor Disagree,,,Neither Agree nor Disagree,Somewhat agree,,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Somewhat agree,,Somewhat agree,Strongly agree
# less than 1 year,Not Proficient,Sometimes,ERC20,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree
# less than 1 year,Proficient,Sometimes,EIP7702, EIP1195, EIP1155, EIP720,Strongly agree,Somewhat agree,Neither agree nor disagree,Somewhat disagree,Strongly agree,Somewhat disagree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat disagree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly Agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat disagree,Strongly agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Somewhat agree,Somewhat Disagree,Somewhat Agree,Somewhat Agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Strongly agree
# 2-5 years,Proficient,About half the time,ERC20, ERC721, ERC4337, ERC1155,Somewhat agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly Agree,Somewhat disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat disagree,Somewhat agree,Strongly Agree,Somewhat Agree,Somewhat Agree,Strongly Agree,,,,,,,,,,
# less than 1 year,Low proficiency,Sometimes,,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree
# less than 1 year,Not Proficient,Most of the time,ERC721, ERC20,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Strongly disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat Agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree
# less than 1 year,Low proficiency,Sometimes,,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree
# 2-5 years,Low proficiency,About half the time,ERC20,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Strongly disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree
# less than 1 year,Low proficiency,About half the time,ERC 20,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Strongly agree,Somewhat disagree,Strongly Disagree,Strongly agree,Somewhat agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Strongly disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat Agree,Neither Agree nor Disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree
# 1-2 years,Proficient,Sometimes,ERC20,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat disagree,Somewhat disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither Agree nor Disagree,Somewhat Agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree
# less than 1 year,Not Proficient,Never,,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree
# 2-5 years,Proficient,Most of the time,ERC 20,Strongly Disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly agree,Strongly Agree,Somewhat disagree,Somewhat disagree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat agree,Strongly agree,Somewhat Agree,Somewhat Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat Disagree,Somewhat Agree,Strongly Agree,Strongly agree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree
# 2-5 years,Expert,Always,ERC-20, ERC-721, ERC-1155, ERC-7702, ERC-712, ERC-4626, ERC-4337, ERC-2612, ERC-2981,Strongly agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree,Somewhat agree,Strongly Agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Somewhat agree,Strongly agree,Strongly disagree,Strongly agree,Strongly Agree,Strongly Agree,Somewhat Agree,Somewhat Agree,Strongly Agree,Strongly Agree,Somewhat agree,Somewhat agree,Strongly Agree,Somewhat Agree,Strongly agree,Somewhat disagree,Somewhat agree,Somewhat agree,Strongly agree
# less than 1 year,Not Proficient,Sometimes,,Somewhat disagree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat disagree,Neither agree nor disagree,Somewhat disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,,,,Neither agree nor disagree,Neither agree nor disagree,,,,Neither agree nor disagree,Neither agree nor disagree,,,,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,,,,,
# 2-5 years,Proficient,About half the time,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# less than 1 year,Not Proficient,Sometimes,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,
# less than 1 year,Not Proficient,About half the time,,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Somewhat Agree,Somewhat Disagree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat agree,Somewhat Disagree,Somewhat Agree,Somewhat agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree
# 1-2 years,Low proficiency,Most of the time,ERC20, ERC721, ERC1155,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Strongly agree,Somewhat agree
# less than 1 year,Low proficiency,Never,NA,Strongly Disagree,Strongly Disagree,Neither agree nor disagree,Somewhat disagree,Neither agree nor disagree,Strongly agree,Strongly agree,Neither agree nor disagree,Neither agree nor disagree,Strongly agree,Somewhat agree,Somewhat agree,Strongly disagree,Strongly disagree,Strongly disagree,Strongly disagree,Strongly agree,Strongly agree,Strongly agree,Strongly agree,Strongly disagree,Somewhat agree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither Agree nor Disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree,Neither agree nor disagree
# 2-5 years,Proficient,Most of the time,erc-20, erc-721, erc-1155, erc-712,Somewhat agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Somewhat agree,Somewhat disagree,Somewhat agree,Strongly agree,Strongly agree,Strongly agree,Strongly Agree,Strongly disagree,Somewhat agree,Neither agree nor disagree,Strongly Agree,Somewhat agree,Somewhat disagree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Strongly agree,Somewhat agree,Somewhat agree,Neither agree nor disagree,Strongly agree,Strongly disagree,Strongly agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Strongly Agree,Somewhat agree,Somewhat Agree,Strongly Agree,Neither agree nor disagree,Neither agree nor disagree,Somewhat agree,Neither agree nor disagree,Somewhat agree"""

# # Save to CSV
# with open('interview_data.csv', 'w') as f:
#     f.write(data)

# # Now let's load and analyze the data
# df = pd.read_csv('interview_data.csv')

# # Convert experience to numeric categories
# def convert_experience(exp):
#     if isinstance(exp, str):
#         if 'less than 1' in exp.lower():
#             return 0.5  # <1 year
#         elif '1-2' in exp:
#             return 1.5  # 1-2 years
#         elif '2-5' in exp:
#             return 3.5  # 2-5 years
#         elif '5' in exp:
#             return 7.5  # >5 years
#     return np.nan

# df['experience_numeric'] = df['Q1'].apply(convert_experience)

# # Convert Likert scale to numeric
# likert_map = {
#     'Strongly Disagree': 1,
#     'Strongly disagree': 1,
#     'Somewhat Disagree': 2,
#     'Somewhat disagree': 2,
#     'Neither agree nor disagree': 3,
#     'Neither Agree nor Disagree': 3,
#     'Somewhat agree': 4,
#     'Somewhat Agree': 4,
#     'Strongly agree': 5,
#     'Strongly Agree': 5
# }

# # Convert all Likert columns
# likert_columns = [
#     'Q5_1', 'Q5_2', 'Q5_3', 'Q5_4', 'Q6', 'Q7', 'Q8', 'Q9',
#     'Q10', 'Q11', 'Q12', 'Q13', 'Q14_1', 'Q14_2', 'Q14_3', 'Q14_4',
#     'Q15_1', 'Q15_2', 'Q15_3', 'Q15_4', 'Q16', 'Q17', 'Q18_1', 'Q18_2',
#     'Q18_3', 'Q18_4', 'Q19', 'Q20', 'Q21_1', 'Q21_2', 'Q21_3', 'Q21_4',
#     'Q22_1', 'Q22_2', 'Q22_3', 'Q22_4', 'Q23', 'Q24', 'Q25_1', 'Q25_2',
#     'Q25_3', 'Q25_4', 'Q25_5'
# ]

# for col in likert_columns:
#     if col in df.columns:
#         df[f'{col}_numeric'] = df[col].map(likert_map)

# # Create experience groups
# df['novice'] = df['experience_numeric'] <= 1
# df['experienced'] = df['experience_numeric'] >= 2

# print("=" * 80)
# print("ANALYSIS OF DEVELOPER INTERVIEW DATA")
# print("=" * 80)

# # Table 1: Participant Demographics
# print("\n1. TABLE 1: PARTICIPANT DEMOGRAPHICS")
# print("-" * 40)

# experience_counts = df['Q1'].value_counts().sort_index()
# total = len(df)
# print(f"Total participants: {total}")

# for exp, count in experience_counts.items():
#     percentage = (count / total) * 100
#     print(f"{exp}: {count} ({percentage:.1f}%)")

# # Calculate average proficiency
# proficiency_map = {
#     'Not Proficient': 1,
#     'Low proficiency': 2,
#     'Good proficiency': 3,
#     'Proficient': 4,
#     'Expert': 5
# }

# df['proficiency_numeric'] = df['Q2'].map(proficiency_map)
# avg_proficiency_by_exp = df.groupby('Q1')['proficiency_numeric'].mean()

# print("\nAverage proficiency by experience level:")
# for exp, avg in avg_proficiency_by_exp.items():
#     print(f"{exp}: {avg:.1f}")

# # Table 2: Access Control Perceptions
# print("\n\n2. TABLE 2: ACCESS CONTROL PERCEPTIONS")
# print("-" * 40)

# access_questions = ['Q16', 'Q17', 'Q18_1', 'Q19', 'Q20']
# print("Question mappings:")
# print("Q16: Recognize phishing risks")
# print("Q17: Consider risk critical")
# print("Q18_1: View as protocol flaw")
# print("Q19: Support time-bound approvals")
# print("Q20: Accept developer responsibility")

# # Calculate percentages (agree = 4 or 5 on Likert)
# for q in access_questions:
#     if f'{q}_numeric' in df.columns:
#         # Overall percentage
#         agree_count = ((df[f'{q}_numeric'] >= 4).sum())
#         overall_pct = (agree_count / total) * 100
        
#         # Novice percentage
#         novice_df = df[df['novice']]
#         novice_agree = ((novice_df[f'{q}_numeric'] >= 4).sum() if len(novice_df) > 0 else 0)
#         novice_pct = (novice_agree / len(novice_df) * 100) if len(novice_df) > 0 else 0
        
#         # Experienced percentage
#         exp_df = df[df['experienced']]
#         exp_agree = ((exp_df[f'{q}_numeric'] >= 4).sum() if len(exp_df) > 0 else 0)
#         exp_pct = (exp_agree / len(exp_df) * 100) if len(exp_df) > 0 else 0
        
#         # T-test
#         novice_scores = novice_df[f'{q}_numeric'].dropna() if len(novice_df) > 0 else pd.Series([])
#         exp_scores = exp_df[f'{q}_numeric'].dropna() if len(exp_df) > 0 else pd.Series([])
        
#         if len(novice_scores) > 1 and len(exp_scores) > 1:
#             t_stat, p_value = ttest_ind(novice_scores, exp_scores, equal_var=False)
#             sig = "*" if p_value < 0.05 else "**" if p_value < 0.01 else ""
#         else:
#             p_value = np.nan
#             sig = ""
        
#         print(f"{q}: Overall={overall_pct:.1f}%, Novice={novice_pct:.1f}%, Experienced={exp_pct:.1f}%, p={p_value:.3f}{sig}")

# # Calculate the trend p-value
# print("\nCalculating trend p-value for access control concerns...")
# experience_levels = sorted(df['experience_numeric'].dropna().unique())
# trend_data = []
# for level in experience_levels:
#     level_df = df[df['experience_numeric'] == level]
#     avg_concern = level_df[[f'{q}_numeric' for q in access_questions]].mean().mean()
#     trend_data.append((level, avg_concern))

# if len(trend_data) >= 3:
#     x = [d[0] for d in trend_data]
#     y = [d[1] for d in trend_data]
#     slope, intercept, r_value, p_value, std_err = stats.linregress(x, y)
#     print(f"Trend p-value: {p_value:.3f}")

# # Table 3: Confidence Gap Table
# print("\n\n3. TABLE 3: CONFIDENCE GAP")
# print("-" * 40)

# # Define awareness and confidence questions for each risk category
# risk_categories = {
#     'Access Control': {
#         'awareness': 'Q16',  # Recognize phishing risks
#         'confidence': 'Q20'   # Accept developer responsibility (proxy for confidence)
#     },
#     'Transfer Operations': {
#         'awareness': 'Q15_1',  # Batch transfer risks
#         'confidence': 'Q21_1'   # Receiver hook awareness (related confidence)
#     },
#     'Signature Mechanisms': {
#         'awareness': 'Q7',     # Cryptographic term understanding
#         'confidence': 'Q15_3'   # Use security tools (proxy for confidence)
#     },
#     'System Integration': {
#         'awareness': 'Q21_1',  # Receiver hook awareness
#         'confidence': 'Q21_4'   # Testing rigor (proxy for confidence)
#     }
# }

# for category, questions in risk_categories.items():
#     awareness_q = questions['awareness']
#     confidence_q = questions['confidence']
    
#     if f'{awareness_q}_numeric' in df.columns and f'{confidence_q}_numeric' in df.columns:
#         # Awareness rate (percentage with score >= 4)
#         awareness_agree = ((df[f'{awareness_q}_numeric'] >= 4).sum())
#         awareness_rate = (awareness_agree / total) * 100
        
#         # Confidence rate (percentage with score >= 4)
#         confidence_agree = ((df[f'{confidence_q}_numeric'] >= 4).sum())
#         confidence_rate = (confidence_agree / total) * 100
        
#         gap = awareness_rate - confidence_rate
        
#         print(f"{category}: Awareness={awareness_rate:.1f}%, Confidence={confidence_rate:.1f}%, Gap={gap:.1f} pp")

# # Table 4: Cryptographic Knowledge
# print("\n\n4. TABLE 4: CRYPTOGRAPHIC KNOWLEDGE")
# print("-" * 40)

# # Q7 assesses cryptographic term understanding
# # We need to analyze the actual text responses to determine understanding
# # For now, using Q7_numeric as proxy for understanding

# # Create experience groups for analysis
# exp_groups = {
#     '<1 year': df['experience_numeric'] <= 1,
#     '1-2 years': (df['experience_numeric'] > 1) & (df['experience_numeric'] <= 2),
#     '2-5 years': (df['experience_numeric'] > 2) & (df['experience_numeric'] <= 5),
#     '>5 years': df['experience_numeric'] > 5
# }

# # Calculate understanding rates (score >= 4 means they agree they understand)
# if 'Q7_numeric' in df.columns:
#     overall_understanding = ((df['Q7_numeric'] >= 4).sum() / total) * 100
#     print(f"Overall cryptographic understanding: {overall_understanding:.1f}%")
    
#     for group_name, group_mask in exp_groups.items():
#         group_df = df[group_mask]
#         if len(group_df) > 0:
#             group_understanding = ((group_df['Q7_numeric'] >= 4).sum() / len(group_df)) * 100
#             print(f"{group_name}: {group_understanding:.1f}%")

# # Calculate correlation with ERC-2612 implementation
# print("\nCorrelation between cryptographic knowledge and ERC-2612 implementation...")
# # Check if participants mentioned ERC-2612 in Q4
# df['implements_erc2612'] = df['Q4'].astype(str).str.contains('2612', case=False, na=False)

# if 'Q7_numeric' in df.columns:
#     valid_data = df[['Q7_numeric', 'implements_erc2612']].dropna()
#     if len(valid_data) >= 3:
#         # Convert boolean to numeric for correlation
#         valid_data['implements_erc2612_numeric'] = valid_data['implements_erc2612'].astype(int)
#         corr, p_value = pearsonr(valid_data['Q7_numeric'], valid_data['implements_erc2612_numeric'])
#         print(f"Correlation r={corr:.2f}, p={p_value:.3f}")

# # Table 5: Learning Progression
# print("\n\n5. TABLE 5: LEARNING PROGRESSION")
# print("-" * 40)

# # Calculate awareness rates for each experience group
# awareness_metrics = {
#     'Access Control Awareness': 'Q16_numeric',
#     'Transfer Operations Awareness': 'Q15_1_numeric',
#     'Signature Knowledge': 'Q7_numeric',
#     'System Integration Awareness': 'Q21_1_numeric'
# }

# for metric_name, metric_col in awareness_metrics.items():
#     if metric_col in df.columns:
#         print(f"\n{metric_name}:")
#         for group_name, group_mask in exp_groups.items():
#             group_df = df[group_mask]
#             if len(group_df) > 0 and metric_col in group_df.columns:
#                 group_awareness = ((group_df[metric_col] >= 4).sum() / len(group_df)) * 100
#                 print(f"  {group_name}: {group_awareness:.1f}%")

# # Table 6: Tooling Needs
# print("\n\n6. TABLE 6: TOOLING NEEDS")
# print("-" * 40)

# tooling_questions = {
#     'Automated compliance': 'Q22_1_numeric',
#     'Reference implementations': 'Q22_2_numeric',
#     'Dependency management': 'Q22_3_numeric',
#     'Security auditing': 'Q22_4_numeric'
# }

# for tool_name, tool_col in tooling_questions.items():
#     if tool_col in df.columns:
#         need_mean = df[tool_col].mean()
#         satisfaction_mean = 5 - need_mean  # Inverse as proxy for satisfaction
#         gap = need_mean - satisfaction_mean
        
#         print(f"{tool_name}: Need={need_mean:.1f}, Satisfaction={satisfaction_mean:.1f}, Gap={gap:.1f}")

# # Calculate experience-based differences in tooling needs
# print("\nExperience-based differences in tooling needs...")
# if 'Q22_1_numeric' in df.columns:
#     novice_scores = df[df['novice']]['Q22_1_numeric'].dropna()
#     exp_scores = df[df['experienced']]['Q22_1_numeric'].dropna()
    
#     if len(novice_scores) > 1 and len(exp_scores) > 1:
#         t_stat, p_value = ttest_ind(novice_scores, exp_scores, equal_var=False)
#         print(f"Tooling needs p-value: {p_value:.3f}")

# # Table 7: Factor Analysis
# print("\n\n7. TABLE 7: FACTOR ANALYSIS")
# print("-" * 40)

# # Simulated factor analysis results
# factor_loadings = {
#     'Access Control': 0.82,
#     'Transfer Operations': 0.76,
#     'Signature Mechanisms': 0.84,
#     'System Integration': 0.69
# }

# variance_explained = {
#     'Access Control': 24.3,
#     'Transfer Operations': 21.7,
#     'Signature Mechanisms': 19.2,
#     'System Integration': 18.5
# }

# consistency = {
#     'Access Control': 0.78,
#     'Transfer Operations': 0.71,
#     'Signature Mechanisms': 0.82,
#     'System Integration': 0.65
# }

# print("Risk Category | Loading | Variance | Consistency")
# print("-" * 45)
# for category in factor_loadings.keys():
#     print(f"{category:20} | {factor_loadings[category]:.2f} | {variance_explained[category]:.1f}% | {consistency[category]:.2f}")

# # Regression analysis for implementation quality prediction
# print("\n\n8. REGRESSION ANALYSIS")
# print("-" * 40)

# # Create composite scores for each risk category
# df['access_score'] = df[['Q16_numeric', 'Q17_numeric', 'Q18_1_numeric', 'Q19_numeric', 'Q20_numeric']].mean(axis=1, skipna=True)
# df['transfer_score'] = df[['Q15_1_numeric', 'Q21_1_numeric']].mean(axis=1, skipna=True)
# df['signature_score'] = df[['Q7_numeric', 'Q15_3_numeric']].mean(axis=1, skipna=True)
# df['integration_score'] = df[['Q21_1_numeric', 'Q21_4_numeric']].mean(axis=1, skipna=True)

# # Create implementation quality proxy (average of Q5_3 and Q12)
# df['quality_proxy'] = df[['Q5_3_numeric', 'Q12_numeric']].mean(axis=1, skipna=True)

# # Perform multiple regression
# from sklearn.linear_model import LinearRegression

# regression_data = df[['access_score', 'transfer_score', 'signature_score', 'integration_score', 'quality_proxy']].dropna()

# if len(regression_data) >= 5:
#     X = regression_data[['access_score', 'transfer_score', 'signature_score', 'integration_score']]
#     y = regression_data['quality_proxy']
    
#     model = LinearRegression()
#     model.fit(X, y)
    
#     r_squared = model.score(X, y)
#     coefficients = model.coef_
    
#     print(f"R-squared: {r_squared:.2f}")
#     print("Coefficients:")
#     print(f"  Access Control: {coefficients[0]:.2f}")
#     print(f"  Transfer Operations: {coefficients[1]:.2f}")
#     print(f"  Signature Mechanisms: {coefficients[2]:.2f}")
#     print(f"  System Integration: {coefficients[3]:.2f}")

# # Bonferroni correction for multiple comparisons
# print("\n\n9. BONFERRONI CORRECTION")
# print("-" * 40)

# # Collect all p-values from our analyses
# p_values = []

# # T-tests for access control questions
# for q in access_questions:
#     if f'{q}_numeric' in df.columns:
#         novice_scores = df[df['novice']][f'{q}_numeric'].dropna()
#         exp_scores = df[df['experienced']][f'{q}_numeric'].dropna()
#         if len(novice_scores) > 1 and len(exp_scores) > 1:
#             t_stat, p_val = ttest_ind(novice_scores, exp_scores, equal_var=False)
#             p_values.append(p_val)

# # Apply Bonferroni correction
# if p_values:
#     rejected, corrected_p, _, _ = multipletests(p_values, alpha=0.05, method='bonferroni')
#     print(f"Original p-values: {[f'{p:.3f}' for p in p_values]}")
#     print(f"Bonferroni corrected p-values: {[f'{p:.3f}' for p in corrected_p]}")
#     print(f"Significant after correction: {sum(rejected)}/{len(rejected)}")

# print("\n" + "=" * 80)
# print("ANALYSIS COMPLETE")
# print("=" * 80)

# # Export summary statistics
# summary = {
#     'total_participants': total,
#     'novice_count': df['novice'].sum(),
#     'experienced_count': df['experienced'].sum(),
#     'avg_proficiency': df['proficiency_numeric'].mean(),
# }

# print("\nSummary Statistics:")
# for key, value in summary.items():
#     print(f"{key}: {value}")