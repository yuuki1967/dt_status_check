# Darktrace status CSV collector

## Prerequite
python3 -m pip list

| Package | Version|  
|-----------|:---------:|
|altgraph   |        0.17.2 |
|certifi    |        2026.7.22 |
|charset-normalizer | 3.5.1 |
|contourpy  |        1.3.0 |
|cycler |            0.12.1 |
|fonttools |         4.60.2 |
|future    |         0.18.2 |
|idna      |         3.20 |
|importlib_resources | 6.5.2 |
|kiwisolver  |        1.4.7 |
|macholib    |       1.15.2 |
|matplotlib  |       3.9.4 |
|numpy       |       2.0.2 |
|packaging   |       26.3 |
|pillow      |       11.3.0 |
|pip         |       21.2.4 |
|pyparsing   |       3.3.2 |
|python-dateutil |   2.9.0.post0 |
|requests        |   2.32.5 |
|setuptools      |   58.0.4 |
|six             |   1.15.0 |
|urllib3         |   2.6.3 |
|wheel           |   0.37.0 |
|zipp            |   3.23.1 |

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

## Check the API /status

1. http://<HOSTNAME>/status?format=json
2.  jq '.time,.hostname,.licenseCounts.licenseIPCount,.subnets,.bandwidthAverage,.darkflowQueue,.subnetData[].recentUnidirectionalTrafficPercent' ./sampledata1.json
3. here are the result.
"2026-09-20 02:27" "dt-50488-01" 841 32 398518000 -1 1 0 0 1 0 0 25 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

 jq '.time,.hostname,.licenseCounts.licenseIPCount,.subnets,.bandwidthAverage,.darkflowQueue,.probes[].hostname,.probes[].metadata.interfaces[].name,.probes[].metadata.interfaces[].type,.probes[].metadata.interfaces[]."link-up",.probes[].networkInterfacesState_eth1,.probes[].networkInterfacesReceived_eth2' ../sampledata1.json 

## How to run the script
  python3 darktrace_status_monitor.py --api status --host http://localhost --public_token 123 --private_token 123
  python3 darktrace_status_monitor.py --file ../sampledata1.json 

## Sample
![sample graph](graph/samplegraph.pdf)

