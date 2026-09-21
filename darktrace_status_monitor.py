#!/usr/bin/env python3
"""Collect Darktrace /status metrics, append them to CSV, and update a graph.

Required environment variables:
  DARKTRACE_HOST          e.g. https://10.0.0.10
  DARKTRACE_PUBLIC_TOKEN
  DARKTRACE_PRIVATE_TOKEN

Example:
  python3 darktrace_status_monitor.py --csv darktrace_status.csv --graph darktrace_status.png
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import requests

ENDPOINT = "/status?format=json"
CSV_FIELDS = [
    "time",
    "hostname",
    "licenseIPCount",
    "subnets",
    "bandwidthAverage",
    "darkflowQueue",
    "recentUnidirectionalTrafficPercent",
    "recentUnidirectionalTrafficPercentAverage",
    "recentUnidirectionalTrafficPercentMaximum",
]


def build_headers(endpoint: str, public_token: str, private_token: str) -> dict[str, str]:
    """Build the Darktrace DTAPI HMAC-SHA1 authentication headers."""
    request_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    auth_string = f"{endpoint}\n{public_token}\n{request_time}\n"
    signature = hmac.new(
        private_token.encode("utf-8"),
        auth_string.encode("utf-8"),
        hashlib.sha1,
    ).hexdigest()
    return {
        "DTAPI-Token": public_token,
        "DTAPI-Date": request_time,
        "DTAPI-Signature": signature,
        "Accept": "application/json",
    }


def get_status(
    host: str,
    public_token: str,
    private_token: str,
    verify_ssl: bool,
    timeout: float,
) -> dict[str, Any]:
    host = host.rstrip("/")
    headers = build_headers(ENDPOINT, public_token, private_token)
    response = requests.get(
        f"{host}{ENDPOINT}",
        headers=headers,
        timeout=timeout,
        verify=verify_ssl,
    )
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("The /status response was not a JSON object")
    return data


def to_number(value: Any) -> float | int | None:
    if value in (None, ""):
        return None
    try:
        number = float(value)
        return int(number) if number.is_integer() else number
    except (TypeError, ValueError):
        return None


def extract_row(data: dict[str, Any]) -> dict[str, Any]:
    subnet_data = data.get("subnetData") or []
    if not isinstance(subnet_data, list):
        subnet_data = []

    percentages = []
    for subnet in subnet_data:
        if isinstance(subnet, dict):
            value = to_number(subnet.get("recentUnidirectionalTrafficPercent"))
            if value is not None:
                percentages.append(value)

    average = sum(percentages) / len(percentages) if percentages else None
    maximum = max(percentages) if percentages else None

    return {
        "time": data.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": data.get("hostname", ""),
        "licenseIPCount": (data.get("licenseCounts") or {}).get("licenseIPCount", ""),
        "subnets": data.get("subnets", ""),
        "bandwidthAverage": data.get("bandwidthAverage", ""),
        "darkflowQueue": data.get("darkflowQueue", ""),
        "recentUnidirectionalTrafficPercent": json.dumps(percentages, separators=(",", ":")),
        "recentUnidirectionalTrafficPercentAverage": "" if average is None else round(average, 4),
        "recentUnidirectionalTrafficPercentMaximum": "" if maximum is None else maximum,
    }


def append_csv(csv_path: Path, row: dict[str, Any]) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists() or csv_path.stat().st_size == 0
    with csv_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        if write_header:
            writer.writeheader()
        writer.writerow(row)


def read_history(csv_path: Path) -> list[dict[str, str]]:
    with csv_path.open("r", newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def parse_time(value: str) -> datetime | None:
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def create_graph(csv_path: Path, graph_path: Path) -> None:
    rows = read_history(csv_path)
    parsed = [(parse_time(row.get("time", "")), row) for row in rows]
    parsed = [(timestamp, row) for timestamp, row in parsed if timestamp is not None]
    if not parsed:
        raise ValueError("No valid timestamps were found in the CSV file")

    times = [item[0] for item in parsed]

    def series(field: str, divisor: float = 1.0) -> list[float]:
        output = []
        for _, row in parsed:
            value = to_number(row.get(field))
            output.append(float("nan") if value is None else float(value) / divisor)
        return output

    fig, axes = plt.subplots(3, 1, figsize=(12, 10), sharex=True)
    hostname = parsed[-1][1].get("hostname") or "Darktrace"
    fig.suptitle(f"{hostname} /status history")

    axes[0].plot(times, series("bandwidthAverage", 1_000_000), marker="o")
    axes[0].set_ylabel("Average bandwidth (Mbps)")
    axes[0].grid(True)

    axes[1].plot(times, series("darkflowQueue"), marker="o", label="Darkflow queue (s)")
    axes[1].plot(times, series("recentUnidirectionalTrafficPercentAverage"), marker="o", label="Unidirectional avg (%)")
    axes[1].plot(times, series("recentUnidirectionalTrafficPercentMaximum"), marker="o", label="Unidirectional max (%)")
    axes[1].set_ylabel("Queue / traffic percentage")
    axes[1].legend()
    axes[1].grid(True)

    axes[2].plot(times, series("licenseIPCount"), marker="o", label="Licensed IP count")
    axes[2].plot(times, series("subnets"), marker="o", label="Subnets")
    axes[2].set_ylabel("Count")
    axes[2].set_xlabel("Darktrace server time (UTC)")
    axes[2].legend()
    axes[2].grid(True)

    fig.autofmt_xdate()
    fig.tight_layout()
    graph_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(graph_path, dpi=150, bbox_inches="tight")
    plt.close(fig)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect Darktrace /status metrics into CSV and graph them")
    parser.add_argument("--host", default=os.getenv("DARKTRACE_HOST"))
    parser.add_argument("--public-token", default=os.getenv("DARKTRACE_PUBLIC_TOKEN"))
    parser.add_argument("--private-token", default=os.getenv("DARKTRACE_PRIVATE_TOKEN"))
    parser.add_argument("--csv", type=Path, default=Path("darktrace_status.csv"))
    parser.add_argument("--graph", type=Path, default=Path("darktrace_status.png"))
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification (not recommended)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    missing = [
        name
        for name, value in (
            ("DARKTRACE_HOST/--host", args.host),
            ("DARKTRACE_PUBLIC_TOKEN/--public-token", args.public_token),
            ("DARKTRACE_PRIVATE_TOKEN/--private-token", args.private_token),
        )
        if not value
    ]
    if missing:
        print("Missing required configuration: " + ", ".join(missing), file=sys.stderr)
        return 2

    try:
        data = get_status(
            args.host,
            args.public_token,
            args.private_token,
            verify_ssl=not args.insecure,
            timeout=args.timeout,
        )
        row = extract_row(data)
        append_csv(args.csv, row)
        create_graph(args.csv, args.graph)
    except requests.RequestException as exc:
        print(f"Darktrace API request failed: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Processing failed: {exc}", file=sys.stderr)
        return 1

    print(f"Appended status to {args.csv}")
    print(f"Updated graph at {args.graph}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
