import pandas as pd
import numpy as np
from scipy import stats
import warnings
warnings.filterwarnings('ignore')

# Load your data
df = pd.read_csv('your_survey_data.csv')

print("="*60)
print("SIMPLE T-TEST ANALYSIS FOR SURVEY DATA")
print("="*60)

# STEP 1: Clean and prepare the data
# Convert all Likert responses to numbers
likert_mapping = {
    # Q5 to Q... questions (Strongly Disagree = 1 to Strongly Agree = 5)
    'Strongly Disagree': 1,
    'Somewhat disagree': 2,
    'Neither agree nor disagree': 3,
    'Somewhat agree': 4,
    'Strongly Agree': 5,
    # Q12, Q13, Q14 questions (reverse order - but we'll handle separately)
    'Strongly agree': 5,
    'Somewhat agree': 4,
    'Neither agree nor disagree': 3,
    'Somewhat disagree': 2,
    'Strongly disagree': 1
}

# Find all question columns (Q1 to Q...)
question_cols = [col for col in df.columns if col.startswith('Q') and col[1:].isdigit()]

print(f"\nFound {len(question_cols)} question columns")
print(f"Sample columns: {question_cols[:10]}...")

# STEP 2: Run t-tests for each question
print("\n" + "="*60)
print("ONE-SAMPLE T-TEST RESULTS (vs Neutral Point 3)")
print("="*60)

results = []

for col in question_cols:
    # Skip non-Likert questions
    if col in ['Q1', 'Q2', 'Q3', 'Q4']:
        continue
        
    # Get data for this question
    data_series = df[col].dropna()
    
    # Convert to numeric if needed
    if data_series.dtype == 'object':
        data_numeric = data_series.map(likert_mapping)
    else:
        data_numeric = data_series
    
    # Remove any non-numeric values
    data_numeric = pd.to_numeric(data_numeric, errors='coerce')
    data_numeric = data_numeric.dropna()
    
    # Only run t-test if we have enough data
    if len(data_numeric) >= 3:
        # Run one-sample t-test against neutral point (3)
        t_stat, p_value = stats.ttest_1samp(data_numeric, 3)
        
        # Calculate mean and standard deviation
        mean_val = np.mean(data_numeric)
        std_val = np.std(data_numeric)
        mean_diff = mean_val - 3
        
        # Calculate Cohen's d (effect size)
        cohens_d = abs(mean_diff / std_val) if std_val > 0 else 0
        
        # Determine significance and direction
        if p_value < 0.05:
            if mean_diff > 0:
                direction = "AGREE (significantly > neutral)"
                sig = "YES"
            else:
                direction = "DISAGREE (significantly < neutral)"
                sig = "YES"
        else:
            direction = "NEUTRAL (not different from 3)"
            sig = "NO"
        
        results.append({
            'Question': col,
            'N': len(data_numeric),
            'Mean': round(mean_val, 2),
            'Std': round(std_val, 2),
            't-stat': round(t_stat, 3),
            'p-value': round(p_value, 4),
            'Mean Diff': round(mean_diff, 2),
            "Cohen's d": round(cohens_d, 3),
            'Significant?': sig,
            'Direction': direction
        })

# Create results dataframe
results_df = pd.DataFrame(results)

# Sort by significance (most significant first)
results_df = results_df.sort_values('p-value')

print(f"\nAnalyzed {len(results_df)} questions")
print("\nTop 20 Most Significant Results:")

# Display top 20 results
print(results_df.head(20).to_string(index=False))

# STEP 3: Summary statistics
print("\n" + "="*60)
print("SUMMARY STATISTICS")
print("="*60)

# Count significant results
sig_count = len(results_df[results_df['p-value'] < 0.05])
total_count = len(results_df)

print(f"Total questions analyzed: {total_count}")
print(f"Significant results (p < 0.05): {sig_count} ({sig_count/total_count*100:.1f}%)")

# Count direction of significant results
if sig_count > 0:
    sig_results = results_df[results_df['p-value'] < 0.05]
    agree_count = len(sig_results[sig_results['Mean Diff'] > 0])
    disagree_count = len(sig_results[sig_results['Mean Diff'] < 0])
    
    print(f"  - Agree (mean > 3): {agree_count}")
    print(f"  - Disagree (mean < 3): {disagree_count}")

# STEP 4: Strongest effects
print("\nTop 5 Strongest Effects (by Cohen's d):")
strongest_effects = results_df.sort_values("Cohen's d", ascending=False).head(5)
print(strongest_effects[['Question', 'Mean', "Cohen's d", 'p-value', 'Direction']].to_string(index=False))

# STEP 5: Save results to CSV
results_df.to_csv('survey_t_test_results.csv', index=False)
print(f"\nResults saved to: survey_t_test_results.csv")

# STEP 6: Quick visualization of top results
print("\n" + "="*60)
print("QUICK VISUALIZATION")
print("="*60)

import matplotlib.pyplot as plt

# Get top 10 most significant questions
top_10 = results_df.head(10)

plt.figure(figsize=(12, 6))
bars = plt.barh(range(len(top_10)), top_10['Mean'], color='lightblue', edgecolor='black')

# Color bars by significance
for i, (mean_val, p_val) in enumerate(zip(top_10['Mean'], top_10['p-value'])):
    if p_val < 0.05:
        if mean_val > 3:
            bars[i].set_color('green')  # Significantly agree
        else:
            bars[i].set_color('red')    # Significantly disagree
    else:
        bars[i].set_color('gray')       # Not significant

plt.axvline(x=3, color='black', linestyle='--', alpha=0.5, label='Neutral (3)')
plt.xlabel('Mean Score (1-5 scale)')
plt.yticks(range(len(top_10)), top_10['Question'], fontsize=9)
plt.title('Top 10 Questions by Significance\n(Green=Agree, Red=Disagree, Gray=Not Significant)')
plt.legend()
plt.tight_layout()
plt.savefig('survey_t_test_plot.png', dpi=300, bbox_inches='tight')
plt.show()

print("\nPlot saved to: survey_t_test_plot.png")

# STEP 7: Simple interpretation
print("\n" + "="*60)
print("INTERPRETATION GUIDE")
print("="*60)
print("""
1. p-value < 0.05: Result is statistically significant
2. Mean > 3: Respondents tend to AGREE with the statement
3. Mean < 3: Respondents tend to DISAGREE with the statement
4. Cohen's d > 0.2: Small effect
5. Cohen's d > 0.5: Medium effect  
6. Cohen's d > 0.8: Large effect
""")