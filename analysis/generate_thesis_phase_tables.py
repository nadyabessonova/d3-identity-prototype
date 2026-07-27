"""Generate thesis-ready LaTeX phase-latency tables from performance CSV."""

import argparse
import csv
import os
import statistics
from collections import defaultdict

BACKEND_SCENARIOS = {"knot_dns", "ipfs", "dnslink_ipfs"}
BACKEND_LABELS = {
    "KNOT_DNS": "Knot DNS",
    "IPFS": "IPFS/IPNS",
    "DNSLINK_IPFS": "DNSLink/IPFS",
}
BACKEND_LABEL_IDS = {
    "KNOT_DNS": "knot_dns",
    "IPFS": "ipfs",
    "DNSLINK_IPFS": "dnslink_ipfs",
}
PHASES = [
    ("startup_scenario_total", "Identity generation (startup)"),
    ("publish_scenario_total", r"Identity \& metadata publication"),
    ("discovery_scenario_total", "Broker discovery"),
    ("dap_scenario_total", "DAP capability creation"),
    ("idap_scenario_total", "IDAP authorization"),
    ("tampering_scenario_total", "Tampering detection check"),
    ("crypto_scenario_total", "A2A session crypto"),
]


def read_rows(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def completed_rows(rows):
    completed = {
        row["run_id"]
        for row in rows
        if row["status"] == "SUCCESS"
        and row["scenario"] == "summary"
        and row["operation"] == "total_flow"
    }
    return [row for row in rows if row["run_id"] in completed and row["status"] == "SUCCESS"]


def values_by_backend_phase(rows):
    per_run_phase = defaultdict(float)
    total_flow = defaultdict(list)

    for row in rows:
        backend = row["backend"]
        scenario = row["scenario"]
        run_id = row["run_id"]
        duration = float(row["duration_ms"]) / 1000

        if scenario == "summary" and row["operation"] == "total_flow":
            total_flow[backend].append(duration)
            continue
        if scenario in BACKEND_SCENARIOS or scenario == "summary":
            continue
        per_run_phase[(backend, run_id, f"{scenario}_scenario_total")] += duration

    grouped = defaultdict(lambda: defaultdict(list))
    for (backend, _run_id, phase), duration in per_run_phase.items():
        grouped[backend][phase].append(duration)
    for backend, values in total_flow.items():
        grouped[backend]["total_flow"] = values
    return grouped


def stats(values):
    return {
        "mean": statistics.mean(values),
        "std": statistics.stdev(values) if len(values) > 1 else 0.0,
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def fmt(value):
    return f"{value:.5f}"


def table_for_backend(backend, groups):
    label = BACKEND_LABELS.get(backend, backend.replace("_", " "))
    label_id = BACKEND_LABEL_IDS.get(backend, backend.lower())
    lines = [
        r"\begin{table}[htb]",
        r"\centering",
        rf"\caption{{Execution time per protocol phase for the {label} backend, in seconds}}",
        rf"\label{{tab:phase-latency-{label_id}}}",
        r"\begin{tabular}{lrrrr}",
        r"\toprule",
        r"\textbf{Protocol phase} & \textbf{Mean} & \textbf{Std} & \textbf{Median} & \textbf{[Min, Max]} \\",
        r"\midrule",
    ]

    for phase, phase_label in PHASES:
        values = groups.get(phase, [])
        if not values:
            continue
        result = stats(values)
        lines.append(
            f"{phase_label:<34} & {fmt(result['mean'])} & {fmt(result['std'])} & "
            f"{fmt(result['median'])} & [{fmt(result['min'])}, {fmt(result['max'])}] \\\\"
        )

    result = stats(groups["total_flow"])
    lines.extend([
        r"\midrule",
        r"\textbf{End-to-end flow} & "
        rf"\textbf{{{fmt(result['mean'])}}} & \textbf{{{fmt(result['std'])}}} & "
        rf"\textbf{{{fmt(result['median'])}}} & \textbf{{[{fmt(result['min'])}, {fmt(result['max'])}]}} \\",
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="artifacts/performance/raw/performance_results_d3_conformant.csv",
    )
    parser.add_argument(
        "--output",
        default="artifacts/thesis/thesis_phase_tables_d3_conformant.tex",
    )
    parser.add_argument("--backends", default="KNOT_DNS,DNSLINK_IPFS,IPFS")
    args = parser.parse_args()

    rows = completed_rows(read_rows(args.input))
    grouped = values_by_backend_phase(rows)
    backends = [backend.strip() for backend in args.backends.split(",") if backend.strip()]
    tables = [table_for_backend(backend, grouped[backend]) for backend in backends if backend in grouped]

    directory = os.path.dirname(args.output)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(args.output, "w") as f:
        f.write("\n\n".join(tables))
        f.write("\n")
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
