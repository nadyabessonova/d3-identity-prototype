"""Small append-only performance logger for prototype experiments."""

import csv
import os
import uuid
from datetime import datetime, timezone
from time import perf_counter


RUN_ID = str(uuid.uuid4())
RESULTS_FILE = os.environ.get("PERFORMANCE_RESULTS", "performance_results.csv")
CSV_COLUMNS = [
    "run_id",
    "timestamp",
    "backend",
    "scenario",
    "operation",
    "duration_ms",
    "status",
]


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def backend_name():
    store_type = os.environ.get("STORE_TYPE", "DNS_EMULATED")
    if store_type == "DNS":
        return "DNS_EMULATED"
    return store_type


def log_metric(scenario, operation, duration_seconds, status="SUCCESS"):
    file_exists = os.path.exists(RESULTS_FILE)
    write_header = not file_exists or os.path.getsize(RESULTS_FILE) == 0
    with open(RESULTS_FILE, "a", newline="") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=CSV_COLUMNS)
        if write_header:
            writer.writeheader()
        writer.writerow(
            {
                "run_id": RUN_ID,
                "timestamp": _timestamp(),
                "backend": backend_name(),
                "scenario": scenario,
                "operation": operation,
                "duration_ms": duration_seconds * 1000,
                "status": status,
            }
        )


def timed(label, scenario, operation, fn):
    start = perf_counter()
    status = "SUCCESS"
    try:
        return fn()
    except Exception:
        status = "FAILURE"
        raise
    finally:
        elapsed = perf_counter() - start
        print(f"[time] {label}: {elapsed:.3f}s")
        log_metric(scenario, operation, elapsed, status=status)
