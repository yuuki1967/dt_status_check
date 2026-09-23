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
import math
import re

ENDPOINT = "/status?format=json"
CSVFILE = "dist/sampledata1.csv"
PDFFILE="graph/samplegraph.pdf"
CSV_FIELDS = [
    "time",
    "hostname",
    "type",
    "licenseIPCount",
    "subnets",
    "bandwidthAverage",
    "darkflowQueue",
    "recentUnidirectionalTrafficPercent",
    "recentUnidirectionalTrafficPercentAverage",
    "recentUnidirectionalTrafficPercentMaximum",
    "probes[1].hostname",
    "probes[1].type",
    "probes[1].networkInterfacesReceived_eth1",
    "probes[1].networkInterfacesReceived_eth2",
    "probes[1].networkInterfacesReceived_eth3",
    "probes[1].networkInterfacesReceived_eth4",
    "probes[1].networkInterfacesReceived_eth5",
    "probes[1].networkInterfacesReceived_eth6",
    "probes[1].networkInterfacesReceived_eth7",
    "probes[2].hostname",
    "probes[2].type",
    "probes[2].networkInterfacesReceived_eth1",
    "probes[2].networkInterfacesReceived_eth2",
    "probes[2].networkInterfacesReceived_eth3",
    "probes[2].networkInterfacesReceived_eth4",
    "probes[2].networkInterfacesReceived_eth5",
    "probes[2].networkInterfacesReceived_eth6",
    "probes[2].networkInterfacesReceived_eth7",
    "probes[3].hostname",
    "probes[3].type",
    "probes[3].networkInterfacesReceived_eth1",
    "probes[3].networkInterfacesReceived_eth2",
    "probes[3].networkInterfacesReceived_eth3",
    "probes[3].networkInterfacesReceived_eth4",
    "probes[3].networkInterfacesReceived_eth5",
    "probes[3].networkInterfacesReceived_eth6",
    "probes[3].networkInterfacesReceived_eth7",
    "probes[4].hostname",
    "probes[4].type",
    "probes[4].networkInterfacesReceived_eth1",
    "probes[4].networkInterfacesReceived_eth2",
    "probes[4].networkInterfacesReceived_eth3",
    "probes[4].networkInterfacesReceived_eth4",
    "probes[4].networkInterfacesReceived_eth5",
    "probes[4].networkInterfacesReceived_eth6",
    "probes[4].networkInterfacesReceived_eth7",
    "probes[5].hostname",
    "probes[5].type",
    "probes[5].networkInterfacesReceived_eth1",
    "probes[5].networkInterfacesReceived_eth2",
    "probes[5].networkInterfacesReceived_eth3",
    "probes[5].networkInterfacesReceived_eth4",
    "probes[5].networkInterfacesReceived_eth5",
    "probes[5].networkInterfacesReceived_eth6",
    "probes[5].networkInterfacesReceived_eth7",
    "probes[6].hostname",
    "probes[6].type",
    "probes[6].networkInterfacesReceived_eth1",
    "probes[6].networkInterfacesReceived_eth2",
    "probes[6].networkInterfacesReceived_eth3",
    "probes[6].networkInterfacesReceived_eth4",
    "probes[6].networkInterfacesReceived_eth5",
    "probes[6].networkInterfacesReceived_eth6",
    "probes[6].networkInterfacesReceived_eth7",
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
   
    probes = data["probes"] 
    row={
        "time": data.get("time") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "hostname": data.get("hostname",""),
        "type": data.get("type",""),
        "licenseIPCount": (data.get("licenseCounts") or {}).get("licenseIPCount", ""),
        "subnets": data.get("subnets", ""),
        "bandwidthAverage": data.get("bandwidthAverage", ""),
        "darkflowQueue": data.get("darkflowQueue", ""),
        "recentUnidirectionalTrafficPercent": json.dumps(percentages, separators=(",", ":")),
        "recentUnidirectionalTrafficPercentAverage": "" if average is None else round(average, 4),
        "recentUnidirectionalTrafficPercentMaximum": "" if maximum is None else maximum,
    }
    for i,probe in data["probes"].items():
        row["probes["+str(probe.get("id"))+"].hostname"] = probe.get("hostname")
        row["probes["+str(probe.get("id"))+"].type"] = probe.get("type")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth1"] = probe.get("networkInterfacesReceived_eth1")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth2"] = probe.get("networkInterfacesReceived_eth2")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth3"] = probe.get("networkInterfacesReceived_eth3")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth4"] = probe.get("networkInterfacesReceived_eth4")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth5"] = probe.get("networkInterfacesReceived_eth5")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth6"] = probe.get("networkInterfacesReceived_eth6")
        row["probes["+str(probe.get("id"))+"].networkInterfacesReceived_eth7"] = probe.get("networkInterfacesReceived_eth7")
    print(row)
    
    return row

def append_csv(csv_path: Path, row: dict[str,Any]) -> None:
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

import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages

def create_graph(csv_path: Path, graph_path: Path) -> None:
    rows = read_history(csv_path)

    parsed = [
        (parse_time(row.get("time", "")), row)
        for row in rows
    ]

    parsed = [
        (timestamp, row)
        for timestamp, row in parsed
        if timestamp is not None
    ]

    if not parsed:
        raise ValueError(
            "No valid timestamps were found in the CSV file"
        )

    # A multi-page output must be a PDF file.
    if graph_path.suffix.lower() != ".pdf":
        graph_path = graph_path.with_suffix(".pdf")

    graph_path.parent.mkdir(parents=True, exist_ok=True)

    times = [timestamp for timestamp, _ in parsed]

    def series(
        field: str,
        divisor: float = 1.0
    ) -> list[float]:
        output: list[float] = []

        for _, row in parsed:
            value = to_number(row.get(field))

            if value is None:
                output.append(float("nan"))
            else:
                output.append(float(value) / divisor)
        return output

    def has_numeric_data(values: list[float]) -> bool:
        return any(not math.isnan(value) for value in values)

    def text_series(field: str) -> list[str]:
        output: list[str] = []

        for _, row in parsed:
            value = row.get(field)

            if value is not None and str(value).strip():
                output.append(str(value).strip())

        return output

    def find_probe_indices() -> list[int]:
        """
        Detect probe indices from flattened CSV column names such as:

        probes[0].hostname
        probes[0].networkInterfacesReceived_eth1
        probes[1].hostname
        """

        probe_pattern = re.compile(r"^probes\[(\d+)\]\.")

        indices: set[int] = set()

        for _, row in parsed:
            for field_name in row:
                match = probe_pattern.match(field_name)

                if match:
                    indices.add(int(match.group(1)))

        return sorted(indices)

    probe_indices = find_probe_indices()

    with PdfPages(graph_path) as pdf:
        # ========================================================
        # Page 1: Main appliance status
        # ========================================================

        fig, axes = plt.subplots(
            3,
            1,
            figsize=(12, 10),
            sharex=True
        )

        hostname = (
            parsed[-1][1].get("hostname")
            or "Darktrace"
        )

        fig.suptitle(f"{hostname} /status history")

        axes[0].plot(
            times,
            series("bandwidthAverage", 1_000_000),
            marker="o"
        )
        axes[0].set_ylabel("Average bandwidth (Mbps)")
        axes[0].grid(True)

        axes[1].plot(
            times,
            series("darkflowQueue"),
            marker="o",
            label="Darkflow queue (s)"
        )

        axes[1].plot(
            times,
            series(
                "recentUnidirectionalTrafficPercentAverage"
            ),
            marker="x",
            label="Unidirectional average (%)"
        )

        axes[1].plot(
            times,
            series(
                "recentUnidirectionalTrafficPercentMaximum"
            ),
            marker="+",
            label="Unidirectional maximum (%)"
        )

        axes[1].set_ylabel("Queue / traffic percentage")
        axes[1].legend()
        axes[1].grid(True)

        axes[2].plot(
            times,
            series("licenseIPCount"),
            marker="o",
            label="Licensed IP count"
        )

        axes[2].plot(
            times,
            series("subnets"),
            marker="x",
            label="Subnets"
        )

        axes[2].set_ylabel("Count")
        axes[2].set_xlabel(
            "Darktrace server time (UTC)"
        )
        axes[2].legend()
        axes[2].grid(True)

        fig.autofmt_xdate()
        fig.tight_layout(rect=[0, 0, 1, 0.96])

        pdf.savefig(
            fig,
            dpi=150,
            bbox_inches="tight"
        )

        plt.close(fig)

        # ========================================================
        # Additional pages: One page for each probe
        # ========================================================

        marker_list = [
            "o",
            "x",
            "+",
            "s",
            "^",
            "v",
            "D"
        ]

        for probe_index in probe_indices:
            fig, ax = plt.subplots(
                1,
                1,
                figsize=(12, 7)
            )

            hostname_field = (
                f"probes[{probe_index}].hostname"
            )

            probe_hostnames = text_series(hostname_field)

            if probe_hostnames:
                probe_hostname = probe_hostnames[-1]
            else:
                probe_hostname = f"Probe {probe_index}"

            fig.suptitle(
                f"{probe_hostname} /status history"
            )

            lines_added = 0

            for interface_number in range(1, 8):
                field_name = (
                    f"probes[{probe_index}]."
                    f"networkInterfacesReceived_eth"
                    f"{interface_number}"
                )

                interface_values = series(field_name)

                # Do not add an empty line if the CSV contains
                # no numeric values for this interface.
                if not has_numeric_data(interface_values):
                    continue

                ax.plot(
                    times,
                    interface_values,
                    marker=marker_list[
                        interface_number - 1
                    ],
                    label=f"eth{interface_number}"
                )

                lines_added += 1

            ax.set_ylabel("Received data")
            ax.set_xlabel(
                "Darktrace server time (UTC)"
            )
            ax.grid(True)

            if lines_added > 0:
                ax.legend()
            else:
                ax.text(
                    0.5,
                    0.5,
                    "No received-data values were found",
                    horizontalalignment="center",
                    verticalalignment="center",
                    transform=ax.transAxes
                )

            fig.autofmt_xdate()
            fig.tight_layout(rect=[0, 0, 1, 0.94])

            pdf.savefig(
                fig,
                dpi=150,
                bbox_inches="tight"
            )

            plt.close(fig)

    print(f"Graph report saved to: {graph_path}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Collect Darktrace /status metrics into CSV and graph them")
    parser.add_argument("--api")
    parser.add_argument("--host")
    parser.add_argument("--public_token")
    parser.add_argument("--private_token")
    return parser.parse_args()

def read_json_file(jsonfilename: str) -> dict[str, Any]:
    with open(jsonfilename, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data

def main() -> int:
    if len(sys.argv) == 5:
        # result=get_dartrace_status
        args=parse_args()
        print(args)
        missing = [
            name
            for name, value in (
                ("DARKTRACE_API/--api",args.api),
                ("DARKTRACE_HOST/--host",args.host),
                ("DARKTRACE_PUBLIC_TOKEN/--public-token",args.public_token),
                ("DARKTRACE_PRIVATE_TOKEN/--priovate-token",args.private_token),
            )
            if not value
        ]
        if missing:
            print("Missing required configuration: "+", ".join(missing), file=sys.stderr)
            return 2
        
        data = get_status(
             args.host,
             args.public_token,
             args.private_token,
             veryfy_ssl=not args.insecure,
             timeout=args.timeout,
        )
#       row = extract_row(data)

    elif sys.argv[1] == "--file":
        jsonfilename = sys.argv[2]
        data = read_json_file(jsonfilename)
    else:
       return 2 
    try:
        row = extract_row(data)
        csvfile =f"{CSVFILE}" 
        csvpath = Path(csvfile)
        graphfile=f"{PDFFILE}"
        graphpath = Path(graphfile)
        append_csv(csvpath, row)
        create_graph(csvpath, graphpath)
    except requests.RequestException as exc:
        print(f"Darktrace API request failed: {exc}", file=sys.stderr)
        return 1
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Processing failed: {exc}", file=sys.stderr)
        return 1

    print(f"Appended status to {csvpath }")
    print(f"Updated graph at {graphpath}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())