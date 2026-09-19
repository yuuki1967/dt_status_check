# Darktrace status CSV collector

`darktrace_status.py` queries a Darktrace appliance and appends one CSV row per
network interface. Each row contains:

- appliance status
- CPU and memory usage percentages
- interface name and state
- received-byte counter and sampled receive bandwidth in bits/second
- licensed IP address count
- subnet count

Darktrace appliance versions can return different JSON field names. The
collector therefore keeps endpoints and response paths in
`darktrace_config.json` and fails with a clear error if a required field cannot
be found.

## Configure

Compare the `/status`, `/network`, and `/subnets` responses from your appliance
with the candidate paths in `darktrace_config.json`. The
`darktrace_config.example.json` file is an unchanged reference copy. A path such as
`system.cpuUsage` means:

```json
{"system": {"cpuUsage": 18.2}}
```

`"$"` selects the complete response, which is useful when an endpoint returns a
top-level JSON list. Paths are tried from first to last.

Set credentials in environment variables rather than storing them in files:

```sh
export DARKTRACE_BASE_URL="https://darktrace.example.com"
export DARKTRACE_PUBLIC_TOKEN="your-public-token"
export DARKTRACE_PRIVATE_TOKEN="your-private-token"
```

The collector uses Darktrace's `DTAPI-Token`, `DTAPI-Date`, and
`DTAPI-Signature` headers. The signature is an HMAC-SHA1 digest of the request
path (including its query string), a newline, and the UTC request date.

## Run

```sh
python3 darktrace_status.py \
  --config darktrace_config.json \
  --output darktrace_status.csv \
  --sample-seconds 5
```

Run `python3 darktrace_status.py --help` for all options. TLS certificates are
verified by default. Use `--insecure` only for a controlled appliance with a
self-signed certificate and only after assessing the security risk.

Receive bandwidth is calculated from two received-byte counter samples:

```text
(second_received_bytes - first_received_bytes) * 8 / elapsed_seconds
```

Because all fields repeat for each interface, a single timestamp can be
filtered or grouped as one appliance snapshot.

## Schedule

For example, run every five minutes with cron:

```cron
*/5 * * * * cd /path/to/dt_status_check && /usr/bin/env python3 darktrace_status.py --output darktrace_status.csv >> collector.log 2>&1
```

Ensure the scheduler receives the three `DARKTRACE_*` environment variables.

## Test

```sh
python3 -m unittest -v
```
