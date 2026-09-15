# Recon

Recon is a Python TCP port scanner. It resolves a hostname to an IPv4 address,
scans a configurable port range, checks which ports are open, and attempts to
collect service banners.

For open ports, Recon also attempts a TLS handshake. When the service responds
as HTTP over TLS, the result is reported as HTTPS and the scanner saves TLS and
certificate information such as:

- TLS version and cipher
- Certificate subject and issuer
- Serial number
- Valid-from and expiration dates
- Subject alternative names

Every scan rewrites `scan_result.json` with the latest results.

## Requirements

- Python 3.8 or newer
- Network access to the target

No third-party Python packages are required.

## Usage

Run the scanner from this directory:

```bash
python Recon.py <target> [options]
```

For example, scan ports 1 through 1024 on localhost:

```bash
python Recon.py 127.0.0.1 -s 1 -e 1024 -t 100
```

Scan a hostname and inspect its HTTPS port:

```bash
python Recon.py example.com -s 443 -e 443 -t 1
```

Scan a wider range with messages for closed ports:

```bash
python Recon.py example.com -s 1 -e 10000 -t 100 -v
```

## Options

| Option | Description | Default |
| --- | --- | --- |
| `target` | IPv4 address or hostname to scan | Required |
| `-s`, `--start` | First port in the scan range | `1` |
| `-e`, `--end` | Last port in the scan range | `1024` |
| `-t`, `--threads` | Number of concurrent scan workers | `100` |
| `-v`, `--verbose` | Print closed ports and scan errors |

## Results

Open ports are printed in the terminal. HTTPS ports are shown with their TLS
version and certificate status, for example:

```text
[+] Port 443 is open - HTTPS (TLSv1.3), certificate found
```

The full report is written to `scan_result.json`:

```json
{
	"target": "104.20.23.154",
	"hostname": "Unknown",
	"scanned_at": "2026-09-15T17:13:10",
	"port_range": {
		"start": 443,
		"end": 443
	},
	"open_ports": [
		{
			"port": 443,
			"state": "open",
			"service": "HTTPS (TLSv1.3), certificate found",
			"https": true,
			"tls_version": "TLSv1.3",
			"tls_cipher": "TLS_AES_256_GCM_SHA384",
			"certificate": {}
		}
	]
}
```

The actual `certificate` object contains the certificate fields returned by the
TLS server. It is `null` when no certificate is available.

## Viewing the JSON report

Print the report:

```bash
cat scan_result.json
```

Pretty-print and validate it with Python:

```bash
python -m json.tool scan_result.json
```

## Using `run.sh`

The included `run.sh` runs a predefined scan. Make it executable once if
needed:

```bash
chmod +x run.sh
./run.sh
```

To scan a different target with the script, edit the target and options in
`run.sh`, or run `Recon.py` directly.

Only scan systems that you own or have explicit permission to test.