import csv
import hashlib
import hmac
import tempfile
import unittest
from pathlib import Path

from darktrace_status import (
    DarktraceClient,
    InterfaceSample,
    append_csv,
    calculate_bandwidth,
    extract_interfaces,
)


PATHS = {
    "interfaces": ["interfaces"],
    "interface_name": ["name"],
    "interface_status": ["state"],
    "received_bytes": ["rxBytes"],
}


class DarktraceStatusTests(unittest.TestCase):
    def test_darktrace_signature(self):
        client = DarktraceClient(
            "https://darktrace.example.com", "public", "private"
        )
        headers = client._headers(
            "/network?include=statistics", date="20260919T063451"
        )
        expected = hmac.new(
            b"private",
            b"/network?include=statistics\n20260919T063451",
            hashlib.sha1,
        ).hexdigest()

        self.assertEqual(headers["DTAPI-Token"], "public")
        self.assertEqual(headers["DTAPI-Date"], "20260919T063451")
        self.assertEqual(headers["DTAPI-Signature"], expected)

    def test_extract_interfaces_and_calculate_bandwidth(self):
        first = extract_interfaces(
            {
                "interfaces": [
                    {"name": "eth0", "state": "up", "rxBytes": 1000},
                    {"name": "eth1", "state": "down", "rxBytes": 200},
                ]
            },
            PATHS,
        )
        second = [
            InterfaceSample("eth0", "up", 2000),
            InterfaceSample("eth1", "down", 200),
        ]

        result = calculate_bandwidth(first, second, 2.0)

        self.assertEqual(result, {"eth0": 4000.0, "eth1": 0.0})

    def test_append_csv_writes_one_header_and_appends(self):
        row = {
            "timestamp_utc": "2026-09-19T06:34:51+00:00",
            "appliance_status": "ok",
            "cpu_usage_percent": 12,
            "memory_usage_percent": 34,
            "interface_name": "eth0",
            "interface_status": "up",
            "received_bytes": 1000,
            "received_bandwidth_bps": 800,
            "license_ip_addresses": 500,
            "subnet_count": 4,
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "status.csv"
            append_csv(output, [row])
            append_csv(output, [row])

            with output.open(newline="", encoding="utf-8") as csv_file:
                rows = list(csv.DictReader(csv_file))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["interface_name"], "eth0")


if __name__ == "__main__":
    unittest.main()
