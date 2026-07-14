import os
import argparse

os.environ.setdefault("MPLCONFIGDIR", ".matplotlib-cache")
os.environ.setdefault("XDG_CACHE_HOME", ".cache")
os.makedirs(os.environ["MPLCONFIGDIR"], exist_ok=True)
os.makedirs(os.environ["XDG_CACHE_HOME"], exist_ok=True)

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


INPUT_FILE = "performance_results.csv"
OUTPUT_DIR = Path("performance_plots")

BACKEND_ORDER = ["KNOT_DNS", "IPFS", "DNSLINK_IPFS"]
BACKEND_COLORS = {
    "KNOT_DNS": "#2F6F73",
    "IPFS": "#C65D3A",
    "DNSLINK_IPFS": "#5D6AAE",
}
PHASES = [
    "startup_scenario_total",
    "publish_scenario_total",
    "discovery_scenario_total",
    "dap_scenario_total",
    "idap_scenario_total",
    "crypto_scenario_total",
    "tampering_scenario_total",
]
PHASE_LABELS = {
    "startup_scenario_total": "Startup",
    "publish_scenario_total": "Publication",
    "discovery_scenario_total": "Discovery",
    "dap_scenario_total": "DAP",
    "idap_scenario_total": "IDAP",
    "crypto_scenario_total": "Crypto",
    "tampering_scenario_total": "Tampering",
}


def load_completed_rows(input_file, backend_order):
    df = pd.read_csv(input_file)
    df["duration_sec"] = df["duration_ms"].astype(float) / 1000

    completed_run_ids = set(
        df[
            (df["status"] == "SUCCESS")
            & (df["scenario"] == "summary")
            & (df["operation"] == "total_flow")
        ]["run_id"]
    )

    df = df[(df["run_id"].isin(completed_run_ids)) & (df["status"] == "SUCCESS")]
    df = df[df["backend"].isin(backend_order)]
    return df


def ordered_backends(df, backend_order):
    present = set(df["backend"])
    return [backend for backend in backend_order if backend in present]


def save(fig, filename, output_dir):
    output_dir.mkdir(exist_ok=True)
    path = output_dir / filename
    fig.tight_layout()
    fig.savefig(path, dpi=220, bbox_inches="tight")
    plt.close(fig)
    print(f"Wrote {path}")


def summarize(df, operation=None, scenario=None):
    subset = df
    if operation is not None:
        subset = subset[subset["operation"] == operation]
    if scenario is not None:
        subset = subset[subset["scenario"] == scenario]
    return subset.groupby("backend")["duration_sec"].agg(["count", "mean", "std"])


def plot_end_to_end(df, backend_order, output_dir):
    summary = summarize(df, operation="total_flow", scenario="summary")
    backends = ordered_backends(df, backend_order)

    means = [summary.loc[b, "mean"] for b in backends]
    stds = [summary.loc[b, "std"] if summary.loc[b, "count"] > 1 else 0 for b in backends]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.bar(
        backends,
        means,
        yerr=stds,
        capsize=5,
        color=[BACKEND_COLORS[b] for b in backends],
        edgecolor="#1f1f1f",
        linewidth=0.8,
    )
    ax.set_title("End-to-End Execution Time by Backend")
    ax.set_ylabel("Total flow time (seconds)")
    ax.grid(axis="y", alpha=0.25)
    save(fig, "01_end_to_end_execution_time.png", output_dir)


def scenario_totals(df):
    protocol = df[~df["scenario"].isin(["knot_dns", "ipfs", "dnslink_ipfs", "summary"])]
    per_run = (
        protocol.groupby(["backend", "run_id", "scenario"])["duration_sec"]
        .sum()
        .reset_index()
    )
    per_run["operation"] = per_run["scenario"] + "_scenario_total"
    return per_run


def plot_publication_breakdown(df, backend_order, output_dir):
    internals = df[df["scenario"].isin(["knot_dns", "ipfs", "dnslink_ipfs"])]
    publish_runs = df[
        (df["scenario"] == "publish")
        & (df["operation"].str.startswith("publish_"))
    ][["backend", "run_id", "operation", "duration_sec"]]

    components = []
    for backend in ordered_backends(df, backend_order):
        if backend == "KNOT_DNS":
            ops = ["dns_txt_update"]
            source = internals[(internals["backend"] == backend) & (internals["operation"].isin(ops))]
        elif backend == "IPFS":
            ops = ["ipfs_add_json", "ipfs_key_gen", "ipns_publish"]
            source = internals[(internals["backend"] == backend) & (internals["operation"].isin(ops))]
        elif backend == "DNSLINK_IPFS":
            ops = ["ipfs_add_json", "dns_txt_update"]
            source = internals[(internals["backend"] == backend) & (internals["operation"].isin(ops))]
        else:
            continue

        for op in ops:
            values = source[source["operation"] == op]
            per_run = values.groupby("run_id")["duration_sec"].sum()
            if not per_run.empty:
                components.append({"backend": backend, "component": op, "mean": per_run.mean()})

        # Include unclassified publication overhead only if it is measurable.
        total = publish_runs[publish_runs["backend"] == backend].groupby("run_id")["duration_sec"].sum()
        known = source.groupby("run_id")["duration_sec"].sum()
        overhead = (total - known).dropna()
        overhead = overhead[overhead > 0.001]
        if not overhead.empty:
            components.append({
                "backend": backend,
                "component": "other_publish_overhead",
                "mean": overhead.mean(),
            })

    plot_df = pd.DataFrame(components)
    backends = ordered_backends(df, backend_order)
    components_order = [
        "ipfs_add_json",
        "ipfs_key_gen",
        "ipns_publish",
        "dns_txt_update",
        "other_publish_overhead",
    ]
    colors = {
        "ipfs_add_json": "#6AA84F",
        "ipfs_key_gen": "#93C47D",
        "ipns_publish": "#C65D3A",
        "dns_txt_update": "#2F6F73",
        "other_publish_overhead": "#B7B7B7",
    }

    fig, ax = plt.subplots(figsize=(9, 5.5))
    bottoms = [0] * len(backends)
    for component in components_order:
        vals = []
        for backend in backends:
            match = plot_df[
                (plot_df["backend"] == backend)
                & (plot_df["component"] == component)
            ]
            vals.append(match["mean"].iloc[0] if not match.empty else 0)
        if any(vals):
            ax.bar(
                backends,
                vals,
                bottom=bottoms,
                label=component,
                color=colors[component],
                edgecolor="#1f1f1f",
                linewidth=0.5,
            )
            bottoms = [bottom + val for bottom, val in zip(bottoms, vals)]

    ax.set_title("Publication Phase Breakdown by Backend")
    ax.set_ylabel("Mean publication time per run (seconds)")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False)
    save(fig, "02_publication_phase_breakdown.png", output_dir)


def plot_mutable_update_distribution(df, output_dir):
    selections = [
        ("KNOT_DNS", "knot_dns", "dns_txt_update", "Knot DNS TXT update"),
        ("IPFS", "ipfs", "ipns_publish", "IPNS publish"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "dns_txt_update", "DNSLink TXT update"),
    ]
    labels = []
    data = []
    colors = []
    for backend, scenario, operation, label in selections:
        values = df[
            (df["backend"] == backend)
            & (df["scenario"] == scenario)
            & (df["operation"] == operation)
        ]["duration_sec"]
        if not values.empty:
            labels.append(label)
            data.append(values)
            colors.append(BACKEND_COLORS[backend])

    fig, ax = plt.subplots(figsize=(9, 5.5))
    box = ax.boxplot(data, tick_labels=labels, patch_artist=True, showfliers=True)
    for patch, color in zip(box["boxes"], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.75)
    ax.set_yscale("log")
    ax.set_title("Mutable Update Latency Distribution")
    ax.set_ylabel("Operation duration (seconds, log scale)")
    ax.grid(axis="y", alpha=0.25, which="both")
    plt.setp(ax.get_xticklabels(), rotation=15, ha="right")
    save(fig, "03_mutable_update_latency_distribution.png", output_dir)


def plot_protocol_phase_breakdown(df, backend_order, output_dir):
    totals = scenario_totals(df)
    grouped = (
        totals.groupby(["backend", "operation"])["duration_sec"]
        .mean()
        .unstack(fill_value=0)
    )
    backends = ordered_backends(df, backend_order)
    colors = {
        "startup_scenario_total": "#B7B7B7",
        "publish_scenario_total": "#C65D3A",
        "discovery_scenario_total": "#F1C232",
        "dap_scenario_total": "#6AA84F",
        "idap_scenario_total": "#3D85C6",
        "crypto_scenario_total": "#8E7CC3",
        "tampering_scenario_total": "#999999",
    }

    fig, ax = plt.subplots(figsize=(10, 5.8))
    bottoms = [0] * len(backends)
    for phase in PHASES:
        vals = [grouped.loc[b, phase] if phase in grouped.columns and b in grouped.index else 0 for b in backends]
        if any(vals):
            ax.bar(
                backends,
                vals,
                bottom=bottoms,
                label=PHASE_LABELS[phase],
                color=colors[phase],
                edgecolor="#1f1f1f",
                linewidth=0.5,
            )
            bottoms = [bottom + val for bottom, val in zip(bottoms, vals)]

    ax.set_title("Protocol Phase Breakdown")
    ax.set_ylabel("Mean phase time per run (seconds)")
    ax.grid(axis="y", alpha=0.25)
    ax.legend(frameon=False, ncol=2)
    save(fig, "04_protocol_phase_breakdown.png", output_dir)


def plot_backend_operation_log_scale(df, output_dir):
    operations = [
        ("KNOT_DNS", "knot_dns", "dns_txt_update", "Knot DNS: TXT update"),
        ("KNOT_DNS", "knot_dns", "dnssec_txt_resolve", "Knot DNS: DNSSEC TXT resolve"),
        ("KNOT_DNS", "knot_dns", "dns_txt_resolve", "Knot DNS: TXT resolve"),
        ("IPFS", "ipfs", "ipfs_add_json", "IPFS: add JSON"),
        ("IPFS", "ipfs", "ipns_publish", "IPFS: IPNS publish"),
        ("IPFS", "ipfs", "ipns_resolve", "IPFS: IPNS resolve"),
        ("IPFS", "ipfs", "ipfs_cat_json", "IPFS: cat JSON"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "ipfs_add_json", "DNSLink/IPFS: add JSON"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "dns_txt_update", "DNSLink/IPFS: TXT update"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "dnssec_txt_resolve", "DNSLink/IPFS: DNSSEC TXT resolve"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "dns_txt_resolve", "DNSLink/IPFS: TXT resolve"),
        ("DNSLINK_IPFS", "dnslink_ipfs", "ipfs_cat_json", "DNSLink/IPFS: cat JSON"),
    ]

    rows = []
    for backend, scenario, operation, label in operations:
        values = df[
            (df["backend"] == backend)
            & (df["scenario"] == scenario)
            & (df["operation"] == operation)
        ]["duration_sec"]
        if not values.empty:
            rows.append({
                "label": label,
                "backend": backend,
                "mean": values.mean(),
            })

    plot_df = pd.DataFrame(rows).sort_values("mean")
    fig, ax = plt.subplots(figsize=(10, 6.5))
    ax.barh(
        plot_df["label"],
        plot_df["mean"],
        color=[BACKEND_COLORS[b] for b in plot_df["backend"]],
        edgecolor="#1f1f1f",
        linewidth=0.5,
    )
    ax.set_xscale("log")
    ax.set_title("Backend Operation Latency on Log Scale")
    ax.set_xlabel("Mean operation duration (seconds, log scale)")
    ax.grid(axis="x", alpha=0.25, which="both")
    save(fig, "05_backend_operation_latency_log_scale.png", output_dir)


def main():
    parser = argparse.ArgumentParser(
        description="Generate performance plots from performance_results.csv."
    )
    parser.add_argument("--input", default=INPUT_FILE)
    parser.add_argument("--output-dir", default=str(OUTPUT_DIR))
    parser.add_argument(
        "--backends",
        default=",".join(BACKEND_ORDER),
        help="Comma-separated backend list in plot order.",
    )
    args = parser.parse_args()

    backend_order = [item.strip() for item in args.backends.split(",") if item.strip()]
    output_dir = Path(args.output_dir)
    df = load_completed_rows(args.input, backend_order)
    if df.empty:
        raise SystemExit(f"No completed successful runs found in {args.input}")

    counts = (
        df[
            (df["scenario"] == "summary")
            & (df["operation"] == "total_flow")
        ]
        .groupby("backend")["run_id"]
        .nunique()
    )
    print("Completed runs:")
    for backend in ordered_backends(df, backend_order):
        print(f"  {backend}: {counts.get(backend, 0)}")

    plot_end_to_end(df, backend_order, output_dir)
    plot_publication_breakdown(df, backend_order, output_dir)
    plot_mutable_update_distribution(df, output_dir)
    plot_protocol_phase_breakdown(df, backend_order, output_dir)
    plot_backend_operation_log_scale(df, output_dir)


if __name__ == "__main__":
    main()
