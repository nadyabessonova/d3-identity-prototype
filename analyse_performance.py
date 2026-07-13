import csv
import statistics
from collections import Counter, defaultdict


INPUT_FILE = "performance_results.csv"
METRICS_OUTPUT_FILE = "performance_statistics.csv"
DNS_OUTPUT_FILE = "knot_dns_statistics.csv"
IPFS_OUTPUT_FILE = "ipfs_statistics.csv"
DNSLINK_IPFS_OUTPUT_FILE = "dnslink_ipfs_statistics.csv"

SUMMARY_SCENARIO = "summary"
SUMMARY_OPERATION = "total_flow"
BACKEND_SCENARIOS = {"knot_dns", "ipfs", "dnslink_ipfs"}


def _read_rows():
    with open(INPUT_FILE, newline="") as f:
        return list(csv.DictReader(f))


def _completed_run_ids(rows):
    return {
        row["run_id"]
        for row in rows
        if row["status"] == "SUCCESS"
        and row["scenario"] == SUMMARY_SCENARIO
        and row["operation"] == SUMMARY_OPERATION
    }


def _stats(values):
    count = len(values)
    return {
        "count": count,
        "mean": statistics.mean(values),
        "median": statistics.median(values),
        "std": statistics.stdev(values) if count > 1 else 0.0,
        "min": min(values),
        "max": max(values),
    }


def _operation_groups(rows, included_scenarios=None, exclude_backend_scenarios=False):
    groups = defaultdict(list)

    for row in rows:
        scenario = row["scenario"]
        if included_scenarios is not None and scenario not in included_scenarios:
            continue
        if exclude_backend_scenarios and scenario in BACKEND_SCENARIOS:
            continue

        operation = row["operation"]
        duration_seconds = float(row["duration_ms"]) / 1000
        groups[operation].append(duration_seconds)

    return groups


def _scenario_total_groups(rows):
    per_run_scenario = defaultdict(float)

    for row in rows:
        scenario = row["scenario"]
        if scenario in BACKEND_SCENARIOS or scenario == SUMMARY_SCENARIO:
            continue

        key = (row["run_id"], scenario)
        per_run_scenario[key] += float(row["duration_ms"]) / 1000

    groups = defaultdict(list)
    for (_, scenario), duration_seconds in per_run_scenario.items():
        groups[f"{scenario}_scenario_total"].append(duration_seconds)

    return groups


def _merge_groups(*group_sets):
    merged = defaultdict(list)
    for groups in group_sets:
        for operation, values in groups.items():
            merged[operation].extend(values)
    return merged


def _format_table(groups):
    rows = []
    for operation, values in sorted(groups.items()):
        result = _stats(values)
        rows.append((operation, result))

    operation_width = max(
        [len("operation")] + [len(operation) for operation, _ in rows]
    )
    header = (
        f"{'operation':<{operation_width}}"
        f"{'count':>8}"
        f"{'mean':>11}"
        f"{'median':>11}"
        f"{'std':>11}"
        f"{'min':>11}"
        f"{'max':>11}"
    )

    lines = [header, "-" * len(header)]
    for operation, result in rows:
        lines.append(
            f"{operation:<{operation_width}}"
            f"{result['count']:>8}"
            f"{result['mean']:>11.6f}"
            f"{result['median']:>11.6f}"
            f"{result['std']:>11.6f}"
            f"{result['min']:>11.6f}"
            f"{result['max']:>11.6f}"
        )

    return "\n".join(lines)


def _write_csv(path, groups):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "operation",
            "count",
            "mean_sec",
            "median_sec",
            "std_sec",
            "min_sec",
            "max_sec",
        ])

        for operation, values in sorted(groups.items()):
            result = _stats(values)
            writer.writerow([
                operation,
                result["count"],
                f"{result['mean']:.6f}",
                f"{result['median']:.6f}",
                f"{result['std']:.6f}",
                f"{result['min']:.6f}",
                f"{result['max']:.6f}",
            ])


def _write_backend_csv(path, backend_groups):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "backend",
            "operation",
            "count",
            "mean_sec",
            "median_sec",
            "std_sec",
            "min_sec",
            "max_sec",
        ])

        for backend, groups in sorted(backend_groups.items()):
            for operation, values in sorted(groups.items()):
                result = _stats(values)
                writer.writerow([
                    backend,
                    operation,
                    result["count"],
                    f"{result['mean']:.6f}",
                    f"{result['median']:.6f}",
                    f"{result['std']:.6f}",
                    f"{result['min']:.6f}",
                    f"{result['max']:.6f}",
                ])


def main():
    rows = _read_rows()
    completed_run_ids = _completed_run_ids(rows)

    completed_rows = [
        row
        for row in rows
        if row["run_id"] in completed_run_ids and row["status"] == "SUCCESS"
    ]

    ignored_failures = sum(1 for row in rows if row["status"] != "SUCCESS")
    run_backends = {}
    for row in completed_rows:
        run_backends.setdefault(row["run_id"], row["backend"])
    backends = Counter(run_backends.values())

    metrics_by_backend = {}
    for backend in sorted(backends):
        backend_rows = [
            row for row in completed_rows if row["backend"] == backend
        ]
        operation_groups = _operation_groups(
            backend_rows,
            exclude_backend_scenarios=True,
        )
        scenario_total_groups = _scenario_total_groups(backend_rows)
        metrics_by_backend[backend] = _merge_groups(
            operation_groups,
            scenario_total_groups,
        )

    dns_groups = _operation_groups(
        completed_rows,
        included_scenarios={"knot_dns"},
    )
    ipfs_groups = _operation_groups(
        completed_rows,
        included_scenarios={"ipfs"},
    )
    dnslink_ipfs_groups = _operation_groups(
        completed_rows,
        included_scenarios={"dnslink_ipfs"},
    )

    backend_text = ", ".join(
        f"{backend}: {count}" for backend, count in sorted(backends.items())
    )

    print(f"Runs: {len(completed_run_ids)} completed successful runs")
    print("Each run makes 1 full D3 demo flow")
    print(f"Backends: {backend_text or 'none'}")
    if ignored_failures:
        print(f"Ignored failed partial rows: {ignored_failures}")

    for backend, groups in metrics_by_backend.items():
        print(f"\n=== METRICS (sec): {backend} ===\n")
        print(_format_table(groups))

    if dns_groups:
        print("\n=== KNOT DNS STATS (sec) ===\n")
        print(_format_table(dns_groups))

    if ipfs_groups:
        print("\n=== IPFS STATS (sec) ===\n")
        print(_format_table(ipfs_groups))

    if dnslink_ipfs_groups:
        print("\n=== DNSLINK IPFS STATS (sec) ===\n")
        print(_format_table(dnslink_ipfs_groups))

    _write_backend_csv(METRICS_OUTPUT_FILE, metrics_by_backend)
    _write_csv(DNS_OUTPUT_FILE, dns_groups)
    _write_csv(IPFS_OUTPUT_FILE, ipfs_groups)
    _write_csv(DNSLINK_IPFS_OUTPUT_FILE, dnslink_ipfs_groups)

    print(f"\nWrote {METRICS_OUTPUT_FILE}")
    if dns_groups:
        print(f"Wrote {DNS_OUTPUT_FILE}")
    if ipfs_groups:
        print(f"Wrote {IPFS_OUTPUT_FILE}")
    if dnslink_ipfs_groups:
        print(f"Wrote {DNSLINK_IPFS_OUTPUT_FILE}")


if __name__ == "__main__":
    main()
