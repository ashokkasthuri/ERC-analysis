#!/usr/bin/env python3
from pathlib import Path
import argparse
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.labelsize": 12,
    "axes.titlesize": 13,
    "legend.fontsize": 9,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "pdf.fonttype": 42,
    "ps.fonttype": 42,
})

EIPS = [
    ("ERC-2612 permit", "EIP2612_count"),
    ("EIP-712", "EIP712_count"),
    ("ERC-5267", "EIP5267_count"),
    ("ERC-1271", "EIP1271_count"),
]

CHAIN_ORDER = ["ethereum", "polygon", "binance", "avalanche"]

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument(
        "--base-dir",
        default="/Users/ashokk/Downloads/evm_data/Allium_trend_data",
        help="Folder containing *_allium_yearly_trend_2020_2026.csv files.",
    )
    p.add_argument("--outdir", default=None)
    return p.parse_args()

def load_allium(base_dir: Path) -> pd.DataFrame:
    files = sorted(base_dir.glob("*_allium_yearly_trend_2020_2026.csv"))
    if not files:
        raise FileNotFoundError(f"No Allium trend CSVs found in {base_dir}")

    dfs = []
    for f in files:
        df = pd.read_csv(f)
        df.columns = [c.strip() for c in df.columns]

        if "chain_name" not in df.columns:
            chain = f.name.split("_allium_")[0]
            df["chain_name"] = chain
        if "chain_id" not in df.columns:
            df["chain_id"] = pd.NA

        df["chain_name"] = df["chain_name"].astype(str).str.lower()
        df["year"] = pd.to_numeric(df["year"], errors="coerce").astype("Int64")
        dfs.append(df)

    data = pd.concat(dfs, ignore_index=True)
    data = data.dropna(subset=["year"]).copy()
    data["year"] = data["year"].astype(int)

    for _, col in EIPS:
        data[col] = pd.to_numeric(data[col], errors="coerce").fillna(0).astype(int)

    data["matched_contracts_with_timestamp"] = pd.to_numeric(
        data["matched_contracts_with_timestamp"], errors="coerce"
    ).fillna(0).astype(int)

    for _, col in EIPS:
        pct = col.replace("_count", "_pct_among_matched")
        data[pct] = np.where(
            data["matched_contracts_with_timestamp"] > 0,
            data[col] / data["matched_contracts_with_timestamp"] * 100,
            0,
        )

    data["chain_name"] = pd.Categorical(data["chain_name"], CHAIN_ORDER, ordered=True)
    data = data.sort_values(["chain_name", "year"])
    return data

def savefig(outdir: Path, name: str):
    outdir.mkdir(parents=True, exist_ok=True)
    pdf = outdir / f"{name}.pdf"
    png = outdir / f"{name}.png"
    plt.tight_layout()
    plt.savefig(pdf, bbox_inches="tight")
    plt.savefig(png, bbox_inches="tight")
    print(f"saved: {pdf}")
    print(f"saved: {png}")
    plt.close()

def plot_total_by_chain(df, outdir):
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    for chain, g in df.groupby("chain_name", observed=False):
        if len(g) == 0:
            continue
        ax.plot(g["year"], g["matched_contracts_with_timestamp"],
                marker="o", linewidth=2.0, markersize=5, label=str(chain).title())
    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Unique detected contracts")
    ax.set_title("Signature-related contract adoption across chains")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True, ncol=2)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    savefig(outdir, "fig1_multichain_total_adoption")

def plot_eip_by_chain(df, outdir, label, col, fname):
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    for chain, g in df.groupby("chain_name", observed=False):
        if len(g) == 0:
            continue
        ax.plot(g["year"], g[col], marker="o", linewidth=2.0, markersize=5, label=str(chain).title())
    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Unique detected contracts")
    ax.set_title(f"{label} adoption across chains")
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True, ncol=2)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    savefig(outdir, fname)

def plot_erc5267_share(df, outdir):
    fig, ax = plt.subplots(figsize=(7.4, 4.2))
    col = "EIP5267_pct_among_matched"
    for chain, g in df.groupby("chain_name", observed=False):
        if len(g) == 0:
            continue
        ax.plot(g["year"], g[col], marker="o", linewidth=2.0, markersize=5, label=str(chain).title())
    ax.set_xlabel("Deployment year")
    ax.set_ylabel("Share among detected contracts (%)")
    ax.set_title("ERC-5267 domain-introspection adoption share")
    ax.set_ylim(0, max(5, df[col].max() * 1.15))
    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
    ax.legend(frameon=True, ncol=2)
    ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
    savefig(outdir, "fig6_multichain_erc5267_share")

def plot_2026_snapshot(df, outdir):
    latest = df[df["year"] == 2026].copy()
    latest = latest.sort_values("matched_contracts_with_timestamp", ascending=True)

    fig, ax = plt.subplots(figsize=(7.2, 4.0))
    ax.barh(latest["chain_name"].astype(str).str.title(), latest["matched_contracts_with_timestamp"])
    ax.set_xlabel("Unique detected contracts")
    ax.set_ylabel("Chain")
    ax.set_title("2026 snapshot of signature-related adoption")
    ax.grid(True, axis="x", linestyle="--", linewidth=0.5, alpha=0.6)

    for i, v in enumerate(latest["matched_contracts_with_timestamp"]):
        ax.text(v, i, f" {int(v):,}", va="center", fontsize=9)

    savefig(outdir, "fig7_2026_snapshot_by_chain")

def export_tables(df, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    df.to_csv(outdir / "allium_multichain_yearly_trend_2020_2026.csv", index=False)

    paper = df[[
        "chain_id", "chain_name", "year",
        "matched_contracts_with_timestamp",
        "EIP2612_count", "EIP712_count", "EIP5267_count", "EIP1271_count",
        "EIP2612_EIP712_EIP5267_count", "EIP712_EIP5267_count"
    ]].copy()

    paper.to_csv(outdir / "table_multichain_yearly_summary.csv", index=False)
    with open(outdir / "table_multichain_yearly_summary.tex", "w") as f:
        f.write(paper.to_latex(index=False, escape=False,
            caption="Multi-chain yearly distribution of detected signature-related contracts.",
            label="tab:multichain-eip-adoption"))

# =========================
# Figure family A: one plot per chain, all EIPs
# =========================

def plot_per_chain_all_eips(df, outdir):
    for chain, g in df.groupby("chain_name", observed=False):
        if len(g) == 0:
            continue

        fig, ax = plt.subplots(figsize=(7.4, 4.2))

        markers = ["o", "s", "^", "D"]
        for (label, col), marker in zip(EIPS, markers):
            ax.plot(
                g["year"],
                g[col],
                marker=marker,
                linewidth=2.0,
                markersize=5,
                label=label,
            )

        chain_title = str(chain).title()
        ax.set_xlabel("Deployment year")
        ax.set_ylabel("Unique detected contracts")
        ax.set_title(f"{chain_title}: yearly adoption by signature standard")
        ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.6)
        ax.legend(frameon=True, ncol=2)
        ax.xaxis.set_major_locator(mticker.MaxNLocator(integer=True))
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

        savefig(outdir, f"fig8_{str(chain)}_all_eip_trends")


# =========================
# Figure family B: grouped bars per chain, all EIPs
# =========================

def plot_per_chain_grouped_bars(df, outdir):
    for chain, g in df.groupby("chain_name", observed=False):
        if len(g) == 0:
            continue

        g = g.sort_values("year")
        years = g["year"].astype(int).to_numpy()
        x = np.arange(len(years))
        width = 0.20

        fig, ax = plt.subplots(figsize=(8.2, 4.4))

        offsets = [-1.5 * width, -0.5 * width, 0.5 * width, 1.5 * width]

        for (label, col), offset in zip(EIPS, offsets):
            ax.bar(
                x + offset,
                g[col].to_numpy(),
                width=width,
                label=label,
            )

        chain_title = str(chain).title()
        ax.set_xlabel("Deployment year")
        ax.set_ylabel("Unique detected contracts")
        ax.set_title(f"{chain_title}: grouped adoption by signature standard")
        ax.set_xticks(x)
        ax.set_xticklabels(years)
        ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
        ax.legend(frameon=True, ncol=2)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

        savefig(outdir, f"fig9_{str(chain)}_grouped_bar_all_eips")


# =========================
# Figure family C: one grouped bar per EIP, all chains
# =========================

def plot_per_eip_grouped_bars_all_chains(df, outdir):
    chain_labels = {
        "ethereum": "Ethereum",
        "polygon": "Polygon",
        "binance": "BNB Chain",
        "avalanche": "Avalanche",
    }

    for label, col in EIPS:
        pivot = (
            df.pivot_table(
                index="year",
                columns="chain_name",
                values=col,
                aggfunc="sum",
                fill_value=0,
            )
            .sort_index()
        )

        # Keep stable chain order.
        cols = [c for c in CHAIN_ORDER if c in pivot.columns]
        pivot = pivot[cols]

        years = pivot.index.astype(int).to_numpy()
        x = np.arange(len(years))
        width = 0.18

        fig, ax = plt.subplots(figsize=(8.2, 4.4))

        offsets = np.linspace(
            -width * (len(cols) - 1) / 2,
            width * (len(cols) - 1) / 2,
            len(cols),
        )

        for chain, offset in zip(cols, offsets):
            ax.bar(
                x + offset,
                pivot[chain].to_numpy(),
                width=width,
                label=chain_labels.get(str(chain), str(chain).title()),
            )

        ax.set_xlabel("Deployment year")
        ax.set_ylabel("Unique detected contracts")
        ax.set_title(f"{label}: yearly adoption across chains")
        ax.set_xticks(x)
        ax.set_xticklabels(years)
        ax.grid(True, axis="y", linestyle="--", linewidth=0.5, alpha=0.6)
        ax.legend(frameon=True, ncol=2)
        ax.yaxis.set_major_locator(mticker.MaxNLocator(integer=True))

        safe = col.replace("_count", "").lower()
        savefig(outdir, f"fig10_{safe}_grouped_bar_across_chains")


# =========================
# Figure family D: compact heatmap of EIP adoption by chain-year
# =========================

def plot_eip_chain_year_heatmaps(df, outdir):
    chain_labels = {
        "ethereum": "Ethereum",
        "polygon": "Polygon",
        "binance": "BNB Chain",
        "avalanche": "Avalanche",
    }

    for label, col in EIPS:
        pivot = (
            df.pivot_table(
                index="chain_name",
                columns="year",
                values=col,
                aggfunc="sum",
                fill_value=0,
            )
        )

        rows = [c for c in CHAIN_ORDER if c in pivot.index]
        pivot = pivot.loc[rows]
        pivot.index = [chain_labels.get(str(c), str(c).title()) for c in pivot.index]

        fig, ax = plt.subplots(figsize=(8.0, 3.6))
        im = ax.imshow(pivot.values, aspect="auto")

        ax.set_xticks(range(len(pivot.columns)))
        ax.set_xticklabels(pivot.columns.astype(int))
        ax.set_yticks(range(len(pivot.index)))
        ax.set_yticklabels(pivot.index)

        for i in range(pivot.shape[0]):
            for j in range(pivot.shape[1]):
                v = int(pivot.values[i, j])
                if v > 0:
                    ax.text(j, i, f"{v:,}", ha="center", va="center", fontsize=8)

        ax.set_xlabel("Deployment year")
        ax.set_ylabel("Chain")
        ax.set_title(f"{label}: chain-year adoption matrix")

        cbar = fig.colorbar(im, ax=ax)
        cbar.set_label("Unique detected contracts")

        safe = col.replace("_count", "").lower()
        savefig(outdir, f"fig11_{safe}_chain_year_heatmap")


def main():
    args = parse_args()
    base_dir = Path(args.base_dir)
    outdir = Path(args.outdir) if args.outdir else base_dir / "figures"

    df = load_allium(base_dir)
    print(df[["chain_name", "year", "matched_contracts_with_timestamp"]])

    plot_total_by_chain(df, outdir)

    for i, (label, col) in enumerate(EIPS, start=2):
        plot_eip_by_chain(
            df, outdir, label, col,
            f"fig{i}_multichain_{col.replace('_count','').lower()}_adoption"
        )

    plot_erc5267_share(df, outdir)
    plot_2026_snapshot(df, outdir)

    # New A* conference-ready figures
    plot_per_chain_all_eips(df, outdir)
    plot_per_chain_grouped_bars(df, outdir)
    plot_per_eip_grouped_bars_all_chains(df, outdir)
    plot_eip_chain_year_heatmaps(df, outdir)

    export_tables(df, outdir)

    print(f"\nAll figures/tables saved in: {outdir}")

if __name__ == "__main__":
    main()