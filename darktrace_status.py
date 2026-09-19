#!/usr/bin/env python3
"""Collect Darktrace appliance health data and append it to a CSV file."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import hmac
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


CSV_FIELDS = [
    "timestamp_utc",
    "appliance_status",
    "cpu_usage_percent",
    "memory_usage_percent",
    "interface_name",
    "interface_status",
    "received_bytes",
    "received_bandwidth_bps",
    "license_ip_addresses",
    "subnet_count",
]


class CollectorError(RuntimeError):
    """Raised when the collector cannot safely produce the requested data."""


def _first_value(data: Any, paths: Sequence[str], label: str) -> Any:
    for path in paths:
        try:
            value = _get_path(data, path)
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        if value is not None:
            return value
    raise CollectorError(
        f"Could not find {label}. Checked JSON paths: {', '.join(paths)}"
    )


def _get_path(data: Any, path: str) -> Any:
    if path in ("", "$"):
        return data

    current = data
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            current = current[int(part)]
        else:
            raise TypeError(f"Cannot traverse {part!r} in {path!r}")
    return current


def _as_number(value: Any, label: str) -> float:
    if isinstance(value, bool):
        raise CollectorError(f"{label} must be numeric, not boolean")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise CollectorError(f"{label} must be numeric; received {value!r}") from exc


def _display_number(value: float) -> int | float:
    return int(value) if value.is_integer() else round(value, 3)


@dataclass(frozen=True)
class InterfaceSample:
    name: str
    status: str
    received_bytes: float


class DarktraceClient:
    def __init__(
        self,
        base_url: str,
        public_token: str,
        private_token: str,
        timeout: float = 30.0,
        verify_tls: bool = True,
    ) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise CollectorError(
                "The base URL must be an absolute HTTP(S) URL, "
                "for example https://darktrace.example.com"
            )
        if not public_token or not private_token:
            raise CollectorError("Both Darktrace public and private tokens are required")

        self.base_url = base_url.rstrip("/")
        self.public_token = public_token
        self.private_token = private_token
        self.timeout = timeout
        self.ssl_context = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()  # noqa: SLF001
        )

    def _headers(self, request_target: str, date: str | None = None) -> dict[str, str]:
        request_date = date or dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S")
        payload = f"{request_target}\n{request_date}".encode("ascii")
        signature = hmac.new(
            self.private_token.encode("ascii"), payload, hashlib.sha1
        ).hexdigest()
        return {
            "Accept": "application/json",
            "DTAPI-Token": self.public_token,
            "DTAPI-Date": request_date,
            "DTAPI-Signature": signature,
        }

    def get_json(self, endpoint: str) -> Any:
        if not endpoint.startswith("/"):
            raise CollectorError(f"API endpoint must begin with '/': {endpoint!r}")

        url = f"{self.base_url}{endpoint}"
        parsed = urllib.parse.urlsplit(url)
        request_target = parsed.path
        if parsed.query:
            request_target += f"?{parsed.query}"
        request = urllib.request.Request(
            url, headers=self._headers(request_target), method="GET"
        )

        try:
            with urllib.request.urlopen(
                request, timeout=self.timeout, context=self.ssl_context
            ) as response:
                charset = response.headers.get_content_charset() or "utf-8"
                body = response.read().decode(charset)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")[:500]
            raise CollectorError(
                f"Darktrace API returned HTTP {exc.code} for {endpoint}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise CollectorError(
                f"Could not reach Darktrace endpoint {endpoint}: {exc.reason}"
            ) from exc

        try:
            return json.loads(body)
        except json.JSONDecodeError as exc:
            raise CollectorError(
                f"Darktrace endpoint {endpoint} returned invalid JSON"
            ) from exc


def load_config(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as config_file:
            config = json.load(config_file)
    except OSError as exc:
        raise CollectorError(f"Could not read configuration {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise CollectorError(f"Configuration {path} is not valid JSON: {exc}") from exc

    if not isinstance(config, dict):
        raise CollectorError("The configuration root must be a JSON object")
    for section in ("endpoints", "paths"):
        if not isinstance(config.get(section), dict):
            raise CollectorError(f"Configuration must contain an object named {section!r}")
    return config


def _path_list(paths: Mapping[str, Any], key: str) -> list[str]:
    value = paths.get(key)
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) for item in value
    ):
        raise CollectorError(f"paths.{key} must be a non-empty list of JSON paths")
    return value


def extract_interfaces(
    response: Any, paths: Mapping[str, Any]
) -> list[InterfaceSample]:
    raw_interfaces = _first_value(
        response, _path_list(paths, "interfaces"), "network interfaces"
    )
    if not isinstance(raw_interfaces, list):
        raise CollectorError("The configured interfaces path must resolve to a JSON list")

    samples: list[InterfaceSample] = []
    seen_names: set[str] = set()
    for index, interface in enumerate(raw_interfaces):
        name = str(
            _first_value(
                interface,
                _path_list(paths, "interface_name"),
                f"name of interface {index}",
            )
        )
        if name in seen_names:
            raise CollectorError(f"Duplicate network interface name returned: {name!r}")
        seen_names.add(name)
        status = str(
            _first_value(
                interface,
                _path_list(paths, "interface_status"),
                f"status of interface {name}",
            )
        )
        received = _as_number(
            _first_value(
                interface,
                _path_list(paths, "received_bytes"),
                f"received-byte counter of interface {name}",
            ),
            f"received-byte counter of interface {name}",
        )
        if received < 0:
            raise CollectorError(
                f"Received-byte counter for interface {name!r} cannot be negative"
            )
        samples.append(InterfaceSample(name, status, received))

    if not samples:
        raise CollectorError("The Darktrace API returned no network interfaces")
    return samples


def calculate_bandwidth(
    first: Iterable[InterfaceSample],
    second: Iterable[InterfaceSample],
    elapsed_seconds: float,
) -> dict[str, float]:
    if elapsed_seconds <= 0:
        raise CollectorError("Bandwidth sampling interval must be greater than zero")

    first_by_name = {sample.name: sample for sample in first}
    bandwidth: dict[str, float] = {}
    for current in second:
        previous = first_by_name.get(current.name)
        if previous is None:
            raise CollectorError(
                f"Interface {current.name!r} appeared during bandwidth sampling"
            )
        delta = current.received_bytes - previous.received_bytes
        if delta < 0:
            raise CollectorError(
                f"Received-byte counter for interface {current.name!r} reset "
                "during bandwidth sampling"
            )
        bandwidth[current.name] = delta * 8.0 / elapsed_seconds
    return bandwidth


def _subnet_count(response: Any, paths: Mapping[str, Any]) -> int:
    value = _first_value(response, _path_list(paths, "subnets"), "subnets")
    if isinstance(value, list):
        return len(value)
    number = _as_number(value, "subnet count")
    if number < 0 or not number.is_integer():
        raise CollectorError(f"Subnet count must be a non-negative integer: {value!r}")
    return int(number)


def collect_rows(
    client: DarktraceClient, config: Mapping[str, Any], sample_seconds: float
) -> list[dict[str, Any]]:
    if sample_seconds <= 0:
        raise CollectorError("--sample-seconds must be greater than zero")

    endpoints = config["endpoints"]
    paths = config["paths"]
    required_endpoints = ("status", "network", "subnets")
    for key in required_endpoints:
        if not isinstance(endpoints.get(key), str):
            raise CollectorError(f"endpoints.{key} must be a string")

    first_network = extract_interfaces(client.get_json(endpoints["network"]), paths)
    start = time.monotonic()
    time.sleep(sample_seconds)
    second_network = extract_interfaces(client.get_json(endpoints["network"]), paths)
    elapsed = time.monotonic() - start
    bandwidth = calculate_bandwidth(first_network, second_network, elapsed)

    status_response = client.get_json(endpoints["status"])
    subnet_response = client.get_json(endpoints["subnets"])
    appliance_status = str(
        _first_value(
            status_response, _path_list(paths, "appliance_status"), "appliance status"
        )
    )
    cpu = _as_number(
        _first_value(status_response, _path_list(paths, "cpu_usage"), "CPU usage"),
        "CPU usage",
    )
    memory = _as_number(
        _first_value(
            status_response, _path_list(paths, "memory_usage"), "memory usage"
        ),
        "memory usage",
    )
    license_ips = _as_number(
        _first_value(
            status_response,
            _path_list(paths, "license_ip_addresses"),
            "licensed IP address count",
        ),
        "licensed IP address count",
    )
    if not 0 <= cpu <= 100 or not 0 <= memory <= 100:
        raise CollectorError(
            f"CPU and memory usage must be percentages from 0 to 100; "
            f"received CPU={cpu!r}, memory={memory!r}"
        )
    if license_ips < 0 or not license_ips.is_integer():
        raise CollectorError(
            f"Licensed IP address count must be a non-negative integer: {license_ips!r}"
        )

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat()
    subnet_count = _subnet_count(subnet_response, paths)
    return [
        {
            "timestamp_utc": timestamp,
            "appliance_status": appliance_status,
            "cpu_usage_percent": _display_number(cpu),
            "memory_usage_percent": _display_number(memory),
            "interface_name": interface.name,
            "interface_status": interface.status,
            "received_bytes": _display_number(interface.received_bytes),
            "received_bandwidth_bps": round(bandwidth[interface.name], 3),
            "license_ip_addresses": int(license_ips),
            "subnet_count": subnet_count,
        }
        for interface in second_network
    ]


def append_csv(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    if not rows:
        raise CollectorError("No rows were collected")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a+", encoding="utf-8", newline="") as output:
            output.seek(0, os.SEEK_END)
            write_header = output.tell() == 0
            writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
            if write_header:
                writer.writeheader()
            writer.writerows(rows)
    except OSError as exc:
        raise CollectorError(f"Could not write CSV file {path}: {exc}") from exc


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect Darktrace status and append one CSV row per interface."
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("DARKTRACE_BASE_URL"),
        help="Darktrace appliance URL (or set DARKTRACE_BASE_URL)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).with_name("darktrace_config.json"),
        help="Endpoint and JSON-path configuration",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("darktrace_status.csv"),
        help="CSV output path",
    )
    parser.add_argument(
        "--sample-seconds",
        type=float,
        default=5.0,
        help="Seconds between received-byte samples (default: 5)",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0, help="HTTP timeout in seconds"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (not recommended)",
    )
    args = parser.parse_args(argv)
    if not args.base_url:
        parser.error("--base-url or DARKTRACE_BASE_URL is required")
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    public_token = os.getenv("DARKTRACE_PUBLIC_TOKEN", "")
    private_token = os.getenv("DARKTRACE_PRIVATE_TOKEN", "")
    try:
        if args.insecure:
            print(
                "WARNING: TLS certificate verification is disabled",
                file=sys.stderr,
            )
        config = load_config(args.config)
        client = DarktraceClient(
            args.base_url,
            public_token,
            private_token,
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
        rows = collect_rows(client, config, args.sample_seconds)
        append_csv(args.output, rows)
    except CollectorError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print(f"Appended {len(rows)} interface row(s) to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
