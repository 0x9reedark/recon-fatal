# Recon Fatal

Recon Fatal is a small authorized reconnaissance helper for **web applications only**.

It gathers useful non-exploitative context for a domain or web app URL:

- Resolves common web-focused subdomains.
- Checks HTTP and HTTPS web endpoints on common web ports.
- Captures status codes, redirects, page titles, content metadata, and technology hint headers.
- Reviews common security headers such as CSP, HSTS, X-Frame-Options, and Referrer-Policy.
- Collects TLS certificate summary data for HTTPS ports.
- Checks `robots.txt`, `sitemap.xml`, and `/.well-known/security.txt`.
- Attempts MX and TXT DNS lookups through the system `nslookup` command when available.
- Can save text or JSON reports.

This project is not for exploitation. Use it ethically and only on systems you own or have explicit written permission to test.

## Usage

Basic web-app recon:

```powershell
python .\recon_combo.py example.com
```

Scan a specific app URL:

```powershell
python .\recon_combo.py https://app.example.com --https-only
```

Custom subdomains and web ports:

```powershell
python .\recon_combo.py example.com --subdomains www,app,api,staging --ports 80,443,8080,8443
```

Use a wordlist:

```powershell
python .\recon_combo.py example.com --wordlist .\subdomains.txt
```

Save JSON output:

```powershell
python .\recon_combo.py example.com --json --output results.json
```

## Safety Defaults

- The default subdomain list is web-application focused.
- The default port list is limited to common web ports.
- Port checks above 50 ports are refused unless `--allow-large-scan` is provided.
- Concurrency is limited by `--workers`, defaulting to `20`.
- HTTP(S) response bodies are capped with `--max-body`, defaulting to 64 KiB.
- The tool performs information gathering only. It does not fuzz forms, submit payloads, brute force directories, exploit vulnerabilities, or run destructive checks.

## Options

```text
target                  Domain or URL, such as example.com or https://app.example.com
--wordlist FILE         File containing subdomain labels, one per line
--subdomains LIST       Comma-separated labels, such as www,api,staging
--ports LIST            Web ports/ranges to check, default: 80,443,3000,5000,8000,8080,8081,8443,8888,9000
--no-root               Do not include the root domain as a web host candidate
--https-only            Only request HTTPS URLs
--http-only             Only request HTTP URLs
--paths LIST            Comma-separated well-known paths to check
--timeout SECONDS       Network timeout, default: 4.0
--workers COUNT         Concurrent workers, default: 20
--delay SECONDS         Delay before HTTP checks
--max-body BYTES        Maximum response bytes to read per request, default: 65536
--max-redirects COUNT   Maximum redirects to follow, default: 5
--allow-large-scan      Allow more than 50 web ports
--json                  Print JSON output
--output FILE           Save output to a file
```
