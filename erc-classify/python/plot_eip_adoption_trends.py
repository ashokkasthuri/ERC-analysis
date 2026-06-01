#!/usr/bin/env python3
import os
from pathlib import Path

import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import argparse


# =========================
# Paths
# =========================

# BASE_DIR = Path("/Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026")

# YEARLY_CSV = BASE_DIR / "yearly_matched_eip_trend_merged.csv"
# COMBO_CSV = BASE_DIR / "yearly_combo_summary_merged.csv"
# MATCHED_CSV = BASE_DIR / "ethereum_merged_old_new_matched_eip_contracts.csv"

# OUT_DIR = BASE_DIR / "figures"
# OUT_DIR.mkdir(parents=True, exist_ok=True)



def parse_args():
    parser = argparse.ArgumentParser(
        description="Plot EIP adoption trends from yearly/combo/matched CSV files."
    )
    parser.add_argument("--base-dir", required=True, help="Folder containing adoption CSV outputs.")
    parser.add_argument("--yearly-csv", default=None, help="Path to yearly trend CSV.")
    parser.add_argument("--combo-csv", default=None, help="Path to yearly combo summary CSV.")
    parser.add_argument("--matched-csv", default=None, help="Path to matched contracts CSV.")
    parser.add_argument("--outdir", default=None, help="Output directory for figures.")
    parser.add_argument("--chain-name", default="chain", help="Chain name used in printed output.")
    return parser.parse_args()


args = parse_args()

BASE_DIR = Path(args.base_dir)

YEARLY_CSV = Path(args.yearly_csv) if args.yearly_csv else BASE_DIR / "yearly_matched_eip_trend.csv"
COMBO_CSV = Path(args.combo_csv) if args.combo_csv else BASE_DIR / "yearly_combo_summary.csv"
MATCHED_CSV = Path(args.matched_csv) if args.matched_csv else BASE_DIR / "matched_contracts_with_deployment.csv"

OUT_DIR = Path(args.outdir) if args.outdir else BASE_DIR / "figures"
OUT_DIR.mkdir(parents=True, exist_ok=True)

CHAIN_NAME = args.chain_name


# =========================
# Academic plotting settings
# =========================

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "legend.fontsize": 10,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})


def savefig(name: str):
    pdf = OUT_DIR / f"{name}.pdf"
    png = OUT_DIR / f"{name}.png"
    plt.tight_layout()
    plt.savefig(pdf, bbox_inches="tight")
    plt.savefig(png, bbox_inches="tight")
    print(f"saved: {pdf}")
    print(f"saved: {png}")
    plt.close()


def load_data():
    yearly = pd.read_csv(YEARLY_CSV, low_memory=False)
    combos = pd.read_csv(COMBO_CSV, low_memory=False)
    matched = pd.read_csv(MATCHED_CSV, low_memory=False)

    yearly["year"] = pd.to_numeric(yearly["year"], errors="coerce")
    combos["year"] = pd.to_numeric(combos["year"], errors="coerce")

    yearly = yearly.dropna(subset=["year"]).copy()
    combos = combos.dropna(subset=["year"]).copy()

    yearly["year"] = yearly["year"].astype(int)
    combos["year"] = combos["year"].astype(int)

    yearly = yearly.sort_values("year")
    combos = combos.sort_values(["year", "count"], ascending=[True, False])

    return yearly, combos, matched


# =========================
# Figure 1: EIP counts over time
# =========================

def plot_eip_counts(yearly):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    series = {
        "ERC-2612 permit": "EIP2612_count",
        "EIP-712": "EIP712_count",
        "ERC-5267": "EIP5267_count",
        "ERC-1271": "EIP1271_count",
    }

    markers = ["o", "s", "^", "D"]

    for (label, col), marker in zip(series.items(), markers):
        if col in yearly.columns:
            ax.plot(
                yearly["year"],
                yearly[col],
                marker=marker,
                linewidth=2.0,
                markersize=5,
                label=label,
            )

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Number of detected contracts")
    ax.set_title("Detected EIP-related contracts over time")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig1_eip_counts_over_time")


# =========================
# Figure 2: Matched-set percentages
# =========================

def plot_eip_percentages(yearly):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    series = {
        "ERC-2612 permit": "EIP2612_pct_among_matched",
        "EIP-712": "EIP712_pct_among_matched",
        "ERC-5267": "EIP5267_pct_among_matched",
        "ERC-1271": "EIP1271_pct_among_matched",
    }

    markers = ["o", "s", "^", "D"]

    for (label, col), marker in zip(series.items(), markers):
        if col in yearly.columns:
            ax.plot(
                yearly["year"],
                yearly[col],
                marker=marker,
                linewidth=2.0,
                markersize=5,
                label=label,
            )

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Share among detected EIP-related contracts (%)")
    ax.set_title("Relative adoption among detected EIP-related contracts")
    ax.set_ylim(0, 105)
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig2_eip_percentage_trends")


# =========================
# Figure 3: ERC-5267 growth and ERC-2612 overlap
# =========================

def plot_erc5267_growth(yearly):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    ax.bar(
        yearly["year"],
        yearly["EIP5267_count"],
        label="ERC-5267 total",
        alpha=0.75,
    )

    if "EIP2612_EIP712_EIP5267_count" in yearly.columns:
        ax.plot(
            yearly["year"],
            yearly["EIP2612_EIP712_EIP5267_count"],
            marker="o",
            linewidth=2.2,
            markersize=5,
            label="ERC-2612 + EIP-712 + ERC-5267",
        )

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Number of contracts")
    ax.set_title("Growth of ERC-5267 and its overlap with ERC-2612")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig3_erc5267_growth_overlap")


# =========================
# Figure 4: Combination heatmap-style matrix
# =========================

def plot_combo_matrix(combos):
    top_combos = (
        combos.groupby("eip_combo")["count"]
        .sum()
        .sort_values(ascending=False)
        .head(8)
        .index
        .tolist()
    )

    pivot = (
        combos[combos["eip_combo"].isin(top_combos)]
        .pivot_table(
            index="eip_combo",
            columns="year",
            values="count",
            aggfunc="sum",
            fill_value=0,
        )
    )

    pivot = pivot.loc[top_combos]

    fig, ax = plt.subplots(figsize=(8.2, 4.8))
    im = ax.imshow(pivot.values, aspect="auto")

    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns.astype(int), rotation=0)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels(pivot.index)

    for i in range(pivot.shape[0]):
        for j in range(pivot.shape[1]):
            value = int(pivot.values[i, j])
            if value > 0:
                ax.text(j, i, str(value), ha="center", va="center", fontsize=8)

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("EIP combination")
    ax.set_title("Dominant EIP combinations over time")

    cbar = fig.colorbar(im, ax=ax)
    cbar.set_label("Number of contracts")

    savefig("fig4_eip_combo_matrix")


# =========================
# Figure 5: Cumulative adoption counts
# =========================

def plot_cumulative_counts(yearly):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    series = {
        "ERC-2612 permit": "EIP2612_count",
        "EIP-712": "EIP712_count",
        "ERC-5267": "EIP5267_count",
        "ERC-1271": "EIP1271_count",
    }

    markers = ["o", "s", "^", "D"]

    for (label, col), marker in zip(series.items(), markers):
        if col in yearly.columns:
            ax.plot(
                yearly["year"],
                yearly[col].cumsum(),
                marker=marker,
                linewidth=2.0,
                markersize=5,
                label=label,
            )

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Cumulative number of detected contracts")
    ax.set_title("Cumulative growth of detected EIP-related contracts")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig5_cumulative_eip_growth")


# =========================
# Figure 6: Grouped bar chart of EIP counts
# =========================

def plot_grouped_bar_counts(yearly):
    fig, ax = plt.subplots(figsize=(8.0, 4.4))

    years = yearly["year"].astype(int).to_numpy()
    x = np.arange(len(years))
    width = 0.20

    series = [
        ("ERC-2612", "EIP2612_count"),
        ("EIP-712", "EIP712_count"),
        ("ERC-5267", "EIP5267_count"),
        ("ERC-1271", "EIP1271_count"),
    ]

    offsets = [-1.5 * width, -0.5 * width, 0.5 * width, 1.5 * width]

    for (label, col), offset in zip(series, offsets):
        if col in yearly.columns:
            ax.bar(x + offset, yearly[col], width=width, label=label)

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Number of unique detected contracts")
    ax.set_title("Yearly adoption of signature-related EIPs")
    ax.set_xticks(x)
    ax.set_xticklabels(years)
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(ncol=2, frameon=True)
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig6_grouped_bar_eip_counts")


# =========================
# Figure 7: Stacked bar chart of EIP composition
# =========================

def plot_stacked_bar_counts(yearly):
    fig, ax = plt.subplots(figsize=(8.0, 4.4))

    years = yearly["year"].astype(int)
    bottom = np.zeros(len(yearly))

    series = [
        ("ERC-2612", "EIP2612_count"),
        ("ERC-5267", "EIP5267_count"),
        ("ERC-1271", "EIP1271_count"),
    ]

    for label, col in series:
        if col in yearly.columns:
            values = yearly[col].fillna(0).to_numpy()
            ax.bar(years, values, bottom=bottom, label=label)
            bottom += values

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Number of unique detected contracts")
    ax.set_title("Composition of detected signature-related standards")
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig7_stacked_bar_eip_composition")


# =========================
# Figure 8: ERC-5267 adoption share as bar chart
# =========================

def plot_erc5267_share_bar(yearly):
    fig, ax = plt.subplots(figsize=(7.2, 4.2))

    ax.bar(
        yearly["year"],
        yearly["EIP5267_pct_among_matched"],
        width=0.65,
        label="ERC-5267 share"
    )

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Share among detected EIP-related contracts (%)")
    ax.set_title("ERC-5267 adoption share over time")
    ax.set_ylim(0, max(5, yearly["EIP5267_pct_among_matched"].max() * 1.18))
    ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    for _, row in yearly.iterrows():
        value = row["EIP5267_pct_among_matched"]
        if pd.notna(value) and value > 0:
            ax.text(
                row["year"],
                value,
                f"{value:.1f}%",
                ha="center",
                va="bottom",
                fontsize=8,
            )

    savefig("fig8_erc5267_share_bar")


# =========================
# Figure 9: Top EIP combinations as horizontal bars
# =========================

def plot_top_combo_horizontal_bar(combos):
    total = (
        combos.groupby("eip_combo")["count"]
        .sum()
        .sort_values(ascending=True)
        .tail(10)
    )

    fig, ax = plt.subplots(figsize=(7.8, 4.8))

    ax.barh(total.index, total.values)

    ax.set_xlabel("Number of unique detected contracts")
    ax.set_ylabel("EIP combination")
    ax.set_title("Most frequent EIP combinations")
    ax.grid(True, axis="x", linestyle="--", linewidth=0.5, alpha=0.6)

    for i, value in enumerate(total.values):
        ax.text(value, i, f" {int(value):,}", va="center", fontsize=8)

    savefig("fig9_top_eip_combinations_bar")


# =========================
# Figure 10: Cumulative stacked area-style trend
# =========================

def plot_cumulative_stacked_area(yearly):
    fig, ax = plt.subplots(figsize=(8.0, 4.4))

    years = yearly["year"].astype(int).to_numpy()

    labels = ["ERC-2612", "EIP-712", "ERC-5267", "ERC-1271"]
    cols = ["EIP2612_count", "EIP712_count", "EIP5267_count", "EIP1271_count"]

    values = []
    kept_labels = []

    for label, col in zip(labels, cols):
        if col in yearly.columns:
            values.append(yearly[col].fillna(0).cumsum().to_numpy())
            kept_labels.append(label)

    ax.stackplot(years, values, labels=kept_labels, alpha=0.85)

    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Cumulative number of unique detected contracts")
    ax.set_title("Cumulative adoption composition of signature-related EIPs")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(loc="upper left", frameon=True)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

    savefig("fig10_cumulative_stacked_area")

# =========================
# Summary table for paper
# =========================

def export_latex_table(yearly):
    cols = [
        "year",
        "matched_contracts_with_timestamp",
        "EIP2612_count",
        "EIP712_count",
        "EIP5267_count",
        "EIP1271_count",
        "EIP2612_EIP712_EIP5267_count",
    ]

    cols = [c for c in cols if c in yearly.columns]
    table = yearly[cols].copy()

    out_tex = OUT_DIR / "table_yearly_eip_summary.tex"
    with open(out_tex, "w") as f:
        f.write(
            table.to_latex(
                index=False,
                escape=False,
                caption="Yearly distribution of detected EIP-related contracts.",
                label="tab:eip-adoption-yearly",
            )
        )

    print(f"saved: {out_tex}")


def main():
    yearly, combos, matched = load_data()

    print("Loaded:")
    print(f"  yearly rows: {len(yearly)}")
    print(f"  combo rows: {len(combos)}")
    print(f"  matched contracts: {len(matched)}")

    plot_eip_counts(yearly)
    plot_eip_percentages(yearly)
    plot_erc5267_growth(yearly)
    plot_combo_matrix(combos)
    plot_cumulative_counts(yearly)

    # New bar/variant figures
    plot_grouped_bar_counts(yearly)
    plot_stacked_bar_counts(yearly)
    plot_erc5267_share_bar(yearly)
    plot_top_combo_horizontal_bar(combos)
    plot_cumulative_stacked_area(yearly)

    export_latex_table(yearly)

    print(f"\nAll figures saved in: {OUT_DIR}")


if __name__ == "__main__":
    main()
    
    
    
    
    
    
    
#     python3 plot_eip_adoption_trends.py \
#   --base-dir /Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026 \
#   --yearly-csv /Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026/yearly_matched_eip_trend_merged.csv \
#   --combo-csv /Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026/yearly_combo_summary_merged.csv \
#   --matched-csv /Users/ashokk/Downloads/evm_data/eip_adoption_2024_2026/ethereum_merged_old_new_matched_eip_contracts.csv \
#   --chain-name ethereum



# python3 plot_eip_adoption_trends.py \
#   --base-dir /Users/ashokk/Downloads/evm_data/eip_adoption_polygon_v2 \
#   --chain-name polygon

# python3 plot_eip_adoption_trends.py \
#   --base-dir /Users/ashokk/Downloads/evm_data/eip_adoption_binance_v2_paid \
#   --chain-name binance
  
  
  
#   python3 plot_eip_adoption_trends.py \
#   --base-dir /Users/ashokk/Downloads/evm_data/eip_adoption_avalanche_v2_paid \
#   --chain-name avalanche