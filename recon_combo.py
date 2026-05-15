#!/usr/bin/env python3
"""
Authorized web application reconnaissance helper.

Use only against web applications you own or have explicit permission to test.
"""

from __future__ import annotations

import argparse
import html
import json
import re
import socket
import ssl
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


DEFAULT_SUBDOMAINS = [
    "www",
    "app",
    "api",
    "admin",
    "portal",
    "dashboard",
    "login",
    "auth",
    "sso",
    "id",
    "dev",
    "test",
    "staging",
    "stage",
    "beta",
    "qa",
    "docs",
    "help",
    "support",
]

DEFAULT_WEB_PORTS = "80,443,3000,5000,8000,8080,8081,8443,8888,9000"
DEFAULT_PATHS = "/robots.txt,/sitemap.xml,/.well-known/security.txt"
DEFAULT_NMAP_PORTS = (
    "21,22,25,53,80,110,143,443,445,587,993,995,1433,1521,2049,2375,2376,"
    "3000,3306,3389,5000,5432,5900,6379,8000,8080,8081,8443,8888,9000,"
    "9200,9300,11211,27017"
)
MAX_PORTS_WITHOUT_CONFIRM = 50
MAX_NMAP_PORTS_WITHOUT_CONFIRM = 256
USER_AGENT = "recon-combo-web/2.0 authorized-security-testing"
BANNER = r"""
  ____ ____  _____ _____ ____    _    ____  _  __  _____  _  _____  _    _       ____  _____ ____ ___  _   _
 / ___|  _ \| ____| ____|  _ \  / \  |  _ \| |/ / |  ___|/ \|_   _|/ \  | |     |  _ \| ____/ ___/ _ \| \ | |
| |  _| |_) |  _| |  _| | | | |/ _ \ | |_) | ' /  | |_  / _ \ | | / _ \ | |     | |_) |  _|| |  | | | |  \| |
| |_| |  _ <| |___| |___| |_| / ___ \|  _ <| . \  |  _|/ ___ \| |/ ___ \| |___  |  _ <| |__| |__| |_| | |\  |
 \____|_| \_\_____|_____|____/_/   \_\_| \_\_|\_\ |_| /_/   \_\_/_/   \_\_____| |_| \_\_____\____\___/|_| \_|
"""
TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_GENERATOR_RE = re.compile(
    rb"<meta[^>]+name=[\"']generator[\"'][^>]+content=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
TECH_HEADERS = {
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-runtime",
    "x-drupal-cache",
    "x-vercel-id",
    "x-amz-cf-id",
    "cf-ray",
}
SECURITY_HEADERS = {
    "content-security-policy": "Content Security Policy",
    "strict-transport-security": "HTTP Strict Transport Security",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        return None


@dataclass(frozen=True)
class HostResult:
    host: str
    addresses: list[str]


@dataclass(frozen=True)
class DnsRecord:
    query_type: str
    values: list[str]
    error: str | None = None


@dataclass(frozen=True)
class TlsResult:
    host: str
    port: int
    protocol: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    expires_in_days: int | None = None
    san_count: int = 0
    error: str | None = None


@dataclass(frozen=True)
class WebResult:
    url: str
    final_url: str
    status: int | None
    reason: str | None
    content_type: str | None
    content_length: str | None
    title: str | None
    meta_generator: str | None
    tech_headers: dict[str, str]
    security_headers_present: dict[str, str]
    security_headers_missing: list[str]
    redirects: list[str]
    error: str | None = None


@dataclass(frozen=True)
class PathResult:
    url: str
    status: int | None
    content_type: str | None
    interesting: bool
    notes: list[str]
    error: str | None = None


@dataclass(frozen=True)
class NmapPort:
    host: str
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None


@dataclass(frozen=True)
class NmapScriptFinding:
    host: str
    port: int | None
    script_id: str
    output: str


@dataclass(frozen=True)
class NmapResult:
    command: list[str]
    targets: list[str]
    ports: list[NmapPort]
    scripts: list[NmapScriptFinding]
    stderr: str | None = None
    error: str | None = None


def parse_ports(value: str) -> list[int]:
    ports: set[int] = set()

    for raw_part in value.split(","):
        part = raw_part.strip()
        if not part:
            continue

        if "-" in part:
            start_text, end_text = part.split("-", 1)
            start = parse_port_number(start_text)
            end = parse_port_number(end_text)
            if start > end:
                raise argparse.ArgumentTypeError(f"invalid port range: {part}")
            ports.update(range(start, end + 1))
        else:
            ports.add(parse_port_number(part))

    if not ports:
        raise argparse.ArgumentTypeError("at least one port is required")

    return sorted(ports)


def parse_port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid port: {value}") from exc

    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port out of range: {value}")
    return port


def parse_paths(value: str) -> list[str]:
    paths = []
    for raw_path in value.split(","):
        path = raw_path.strip()
        if not path:
            continue
        paths.append(path if path.startswith("/") else f"/{path}")
    return sorted(set(paths))


def normalize_target(value: str) -> tuple[str, str | None]:
    raw = value.strip()
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = parsed.hostname
    if not host or "." not in host:
        raise SystemExit("target should be a domain or URL, such as example.com or https://app.example.com")
    base_url = raw if "://" in raw else None
    return host.lower().strip("."), base_url


def load_subdomain_words(args: argparse.Namespace) -> list[str]:
    words: list[str] = []

    if args.wordlist:
        path = Path(args.wordlist)
        if not path.exists():
            raise SystemExit(f"wordlist not found: {path}")
        words.extend(
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )

    if args.subdomains:
        words.extend(word.strip() for word in args.subdomains.split(",") if word.strip())

    if not words:
        words.extend(DEFAULT_SUBDOMAINS)

    return sorted(set(normalize_label(word) for word in words if normalize_label(word)))


def normalize_label(value: str) -> str:
    label = value.strip().lower()
    if label.startswith("*."):
        label = label[2:]
    return label.strip(".")


def resolve_host(host: str, timeout: float) -> HostResult | None:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return None
    finally:
        socket.setdefaulttimeout(previous_timeout)

    addresses = sorted({info[4][0] for info in infos})
    return HostResult(host=host, addresses=addresses)


def enumerate_subdomains(domain: str, words: Iterable[str], timeout: float, workers: int) -> list[HostResult]:
    candidates = [f"{word}.{domain}" for word in words]
    found: list[HostResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(resolve_host, host, timeout): host for host in candidates}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda item: item.host)


def query_dns_record(domain: str, query_type: str, timeout: float) -> DnsRecord:
    try:
        completed = subprocess.run(
            ["nslookup", f"-type={query_type}", domain],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return DnsRecord(query_type=query_type, values=[], error=exc.__class__.__name__)

    values = []
    for line in completed.stdout.splitlines():
        clean = line.strip()
        if not clean or clean.lower().startswith(("server:", "address:", "non-authoritative")):
            continue
        if domain in clean or query_type.lower() in clean.lower() or "text =" in clean.lower():
            values.append(clean)

    if completed.returncode != 0 and not values:
        return DnsRecord(query_type=query_type, values=[], error="lookup failed")
    return DnsRecord(query_type=query_type, values=values[:20])


def candidate_urls(hosts: list[str], ports: list[int], base_url: str | None, https_only: bool, http_only: bool) -> list[str]:
    if base_url:
        return [base_url]

    urls = []
    for host in hosts:
        for port in ports:
            schemes = []
            if port in {443, 8443}:
                schemes.append("https")
            elif port in {80, 8080, 8081, 8000, 8888, 9000, 3000, 5000}:
                schemes.append("http")
            else:
                schemes.extend(["https", "http"])

            for scheme in schemes:
                if https_only and scheme != "https":
                    continue
                if http_only and scheme != "http":
                    continue
                default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
                netloc = host if default_port else f"{host}:{port}"
                urls.append(f"{scheme}://{netloc}/")
    return sorted(set(urls))


def fetch_url(url: str, timeout: float, max_body: int, max_redirects: int) -> WebResult:
    opener = build_opener(NoRedirectHandler)
    redirects: list[str] = []
    current_url = url

    for _ in range(max_redirects + 1):
        try:
            request = Request(
                current_url,
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Range": f"bytes=0-{max_body - 1}",
                },
            )
            response = opener.open(request, timeout=timeout)
            body = response.read(max_body)
            return build_web_result(url, current_url, response.status, response.reason, response.headers, body, redirects)
        except HTTPError as exc:
            location = exc.headers.get("Location")
            if exc.code in {301, 302, 303, 307, 308} and location:
                current_url = urljoin(current_url, location)
                redirects.append(f"{exc.code} -> {current_url}")
                continue
            body = exc.read(max_body)
            return build_web_result(url, current_url, exc.code, exc.reason, exc.headers, body, redirects)
        except (URLError, TimeoutError, OSError) as exc:
            return WebResult(
                url=url,
                final_url=current_url,
                status=None,
                reason=None,
                content_type=None,
                content_length=None,
                title=None,
                meta_generator=None,
                tech_headers={},
                security_headers_present={},
                security_headers_missing=[],
                redirects=redirects,
                error=exc.__class__.__name__,
            )

    return WebResult(
        url=url,
        final_url=current_url,
        status=None,
        reason=None,
        content_type=None,
        content_length=None,
        title=None,
        meta_generator=None,
        tech_headers={},
        security_headers_present={},
        security_headers_missing=[],
        redirects=redirects,
        error="too many redirects",
    )


def build_web_result(
    original_url: str,
    final_url: str,
    status: int,
    reason: str,
    headers,  # noqa: ANN001
    body: bytes,
    redirects: list[str],
) -> WebResult:
    lower_headers = {key.lower(): value for key, value in headers.items()}
    present = {
        SECURITY_HEADERS[name]: lower_headers[name]
        for name in SECURITY_HEADERS
        if name in lower_headers
    }
    missing = [label for name, label in SECURITY_HEADERS.items() if name not in lower_headers]
    tech = {
        name: lower_headers[name]
        for name in sorted(TECH_HEADERS)
        if name in lower_headers
    }

    return WebResult(
        url=original_url,
        final_url=final_url,
        status=status,
        reason=reason,
        content_type=headers.get("Content-Type"),
        content_length=headers.get("Content-Length"),
        title=extract_title(body),
        meta_generator=extract_meta_generator(body),
        tech_headers=tech,
        security_headers_present=present,
        security_headers_missing=missing,
        redirects=redirects,
    )


def fetch_path(base_url: str, path: str, timeout: float, max_body: int) -> PathResult:
    url = urljoin(base_url, path)
    try:
        request = Request(url, headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{max_body - 1}"})
        response = build_opener(NoRedirectHandler).open(request, timeout=timeout)
        body = response.read(max_body)
        notes = summarize_known_path(path, body)
        return PathResult(
            url=url,
            status=response.status,
            content_type=response.headers.get("Content-Type"),
            interesting=response.status < 400,
            notes=notes,
        )
    except HTTPError as exc:
        body = exc.read(max_body)
        notes = summarize_known_path(path, body) if exc.code < 400 else []
        return PathResult(
            url=url,
            status=exc.code,
            content_type=exc.headers.get("Content-Type"),
            interesting=exc.code < 400,
            notes=notes,
        )
    except (URLError, TimeoutError, OSError) as exc:
        return PathResult(url=url, status=None, content_type=None, interesting=False, notes=[], error=exc.__class__.__name__)


def summarize_known_path(path: str, body: bytes) -> list[str]:
    text = decode_body(body)
    notes: list[str] = []
    if path.endswith("robots.txt"):
        disallows = [line for line in text.splitlines() if line.lower().startswith("disallow:")]
        sitemaps = [line for line in text.splitlines() if line.lower().startswith("sitemap:")]
        notes.extend([f"{len(disallows)} disallow rule(s)", f"{len(sitemaps)} sitemap reference(s)"])
    elif path.endswith("sitemap.xml"):
        notes.append(f"{text.lower().count('<loc>')} URL location(s)")
    elif path.endswith("security.txt"):
        contacts = [line for line in text.splitlines() if line.lower().startswith("contact:")]
        expires = [line for line in text.splitlines() if line.lower().startswith("expires:")]
        notes.extend([f"{len(contacts)} contact field(s)", f"{len(expires)} expires field(s)"])
    return notes


def extract_title(body: bytes) -> str | None:
    match = TITLE_RE.search(body)
    if not match:
        return None
    title = re.sub(r"\s+", " ", decode_body(match.group(1))).strip()
    return html.unescape(title)[:160] if title else None


def extract_meta_generator(body: bytes) -> str | None:
    match = META_GENERATOR_RE.search(body)
    if not match:
        return None
    value = decode_body(match.group(1)).strip()
    return html.unescape(value)[:160] if value else None


def decode_body(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def inspect_tls(host: str, port: int, timeout: float) -> TlsResult:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=host) as tls_socket:
                cert = tls_socket.getpeercert()
                not_after = cert.get("notAfter")
                return TlsResult(
                    host=host,
                    port=port,
                    protocol=tls_socket.version(),
                    subject=first_cert_name(cert.get("subject", [])),
                    issuer=first_cert_name(cert.get("issuer", [])),
                    not_before=cert.get("notBefore"),
                    not_after=not_after,
                    expires_in_days=days_until_cert_expiry(not_after),
                    san_count=len(cert.get("subjectAltName", [])),
                )
    except (ssl.SSLError, TimeoutError, OSError) as exc:
        return TlsResult(host=host, port=port, error=exc.__class__.__name__)


def first_cert_name(parts: list[tuple[tuple[str, str], ...]]) -> str | None:
    for group in parts:
        for key, value in group:
            if key in {"commonName", "organizationName"}:
                return value
    return None


def days_until_cert_expiry(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (expires - datetime.now(timezone.utc)).days


def run_web_checks(urls: list[str], timeout: float, workers: int, max_body: int, max_redirects: int) -> list[WebResult]:
    results: list[WebResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(fetch_url, url, timeout, max_body, max_redirects): url
            for url in urls
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item.url)


def run_path_checks(web_results: list[WebResult], paths: list[str], timeout: float, workers: int, max_body: int) -> list[PathResult]:
    live_bases = [
        result.final_url
        for result in web_results
        if result.status is not None and result.status < 500 and result.error is None
    ]
    results: list[PathResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(fetch_path, base_url, path, timeout, max_body)
            for base_url in live_bases
            for path in paths
        ]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item.url)


def run_tls_checks(hosts: list[str], ports: list[int], timeout: float, workers: int) -> list[TlsResult]:
    tls_ports = [port for port in ports if port in {443, 8443}]
    results: list[TlsResult] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(inspect_tls, host, port, timeout)
            for host in hosts
            for port in tls_ports
        ]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: (item.host, item.port))


def run_nmap_scan(args: argparse.Namespace, hosts: list[str], nmap_ports: list[int]) -> NmapResult:
    targets = [args.domain]
    if args.nmap_include_subdomains:
        targets.extend(hosts)
    targets = sorted(set(targets))
    command = [
        args.nmap_path,
        "-oX",
        "-",
        "-Pn",
        "-n",
        "-sV",
        f"-T{args.nmap_timing}",
        "-p",
        ",".join(str(port) for port in nmap_ports),
    ]
    command.append("-sS" if args.nmap_stealth else "-sT")

    if args.nmap_vuln:
        command.extend(["--script", "vuln"])

    command.extend(targets)

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=args.nmap_timeout,
        )
    except FileNotFoundError:
        return NmapResult(command=command, targets=targets, ports=[], scripts=[], error="nmap not found")
    except subprocess.TimeoutExpired:
        return NmapResult(command=command, targets=targets, ports=[], scripts=[], error="nmap timed out")

    if completed.returncode != 0 and not completed.stdout.strip():
        return NmapResult(
            command=command,
            targets=targets,
            ports=[],
            scripts=[],
            stderr=trim_text(completed.stderr),
            error=f"nmap exited with status {completed.returncode}",
        )

    ports, scripts, parse_error = parse_nmap_xml(completed.stdout)
    return NmapResult(
        command=command,
        targets=targets,
        ports=ports,
        scripts=scripts,
        stderr=trim_text(completed.stderr) if completed.stderr.strip() else None,
        error=parse_error,
    )


def parse_nmap_xml(xml_text: str) -> tuple[list[NmapPort], list[NmapScriptFinding], str | None]:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return [], [], f"could not parse nmap XML: {exc}"

    ports: list[NmapPort] = []
    scripts: list[NmapScriptFinding] = []

    for host_node in root.findall("host"):
        host = nmap_host_label(host_node)
        hostscript = host_node.find("hostscript")
        if hostscript is not None:
            scripts.extend(parse_script_nodes(host, None, hostscript.findall("script")))

        for port_node in host_node.findall("./ports/port"):
            state_node = port_node.find("state")
            state = state_node.get("state") if state_node is not None else None
            if state != "open":
                continue

            port_id = int(port_node.get("portid", "0"))
            service_node = port_node.find("service")
            ports.append(
                NmapPort(
                    host=host,
                    port=port_id,
                    protocol=port_node.get("protocol", "tcp"),
                    state=state,
                    service=service_node.get("name") if service_node is not None else None,
                    product=service_node.get("product") if service_node is not None else None,
                    version=service_node.get("version") if service_node is not None else None,
                )
            )
            scripts.extend(parse_script_nodes(host, port_id, port_node.findall("script")))

    return (
        sorted(ports, key=lambda item: (item.host, item.port, item.protocol)),
        sorted(scripts, key=lambda item: (item.host, item.port or 0, item.script_id)),
        None,
    )


def nmap_host_label(host_node: ET.Element) -> str:
    hostname_node = host_node.find("./hostnames/hostname")
    if hostname_node is not None and hostname_node.get("name"):
        return hostname_node.get("name", "")
    address_node = host_node.find("address")
    if address_node is not None and address_node.get("addr"):
        return address_node.get("addr", "")
    return "unknown"


def parse_script_nodes(host: str, port: int | None, script_nodes: list[ET.Element]) -> list[NmapScriptFinding]:
    findings = []
    for script_node in script_nodes:
        output = trim_text(script_node.get("output", ""))
        if output:
            findings.append(
                NmapScriptFinding(
                    host=host,
                    port=port,
                    script_id=script_node.get("id", "unknown"),
                    output=output,
                )
            )
    return findings


def trim_text(value: str, limit: int = 2000) -> str:
    clean = re.sub(r"\s+", " ", value).strip()
    return clean[:limit] if len(clean) > limit else clean


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized web application recon: DNS, HTTP(S), headers, TLS, well-known files, and optional Nmap.",
        epilog="Only test web applications you own or have explicit permission to assess.",
    )
    parser.add_argument("target", help="Base domain or URL, such as example.com or https://app.example.com")
    parser.add_argument("--wordlist", help="File containing subdomain labels, one per line")
    parser.add_argument("--subdomains", help="Comma-separated subdomain labels, such as www,api,staging")
    parser.add_argument("--ports", default=DEFAULT_WEB_PORTS, help=f"Web ports to check. Default: {DEFAULT_WEB_PORTS}")
    parser.add_argument("--no-root", action="store_true", help="Do not include the root domain as a web host candidate")
    parser.add_argument("--https-only", action="store_true", help="Only request HTTPS URLs")
    parser.add_argument("--http-only", action="store_true", help="Only request HTTP URLs")
    parser.add_argument("--paths", default=DEFAULT_PATHS, help=f"Comma-separated well-known paths. Default: {DEFAULT_PATHS}")
    parser.add_argument("--timeout", type=float, default=4.0, help="Network timeout in seconds")
    parser.add_argument("--workers", type=int, default=20, help="Maximum concurrent workers")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay before HTTP checks, in seconds")
    parser.add_argument("--max-body", type=int, default=65536, help="Maximum response bytes to read per request")
    parser.add_argument("--max-redirects", type=int, default=5, help="Maximum redirects to follow")
    parser.add_argument("--allow-large-scan", action="store_true", help="Allow more than 50 web ports")
    parser.add_argument("--nmap", action="store_true", help="Run an optional Nmap service scan against the root target")
    parser.add_argument("--nmap-stealth", action="store_true", help="Use Nmap TCP SYN scan (-sS); may require admin/root")
    parser.add_argument("--nmap-vuln", action="store_true", help="Run Nmap vuln NSE scripts; implies --nmap")
    parser.add_argument("--nmap-include-subdomains", action="store_true", help="Include resolved subdomains in Nmap scope")
    parser.add_argument("--nmap-ports", default=DEFAULT_NMAP_PORTS, help=f"Nmap ports/ranges. Default: {DEFAULT_NMAP_PORTS}")
    parser.add_argument("--nmap-timing", type=int, default=3, help="Nmap timing template 0-5, default: 3")
    parser.add_argument("--nmap-timeout", type=float, default=300.0, help="Nmap process timeout in seconds")
    parser.add_argument("--nmap-path", default="nmap", help="Path to the nmap executable")
    parser.add_argument("--allow-large-nmap-scan", action="store_true", help="Allow more than 256 Nmap ports")
    parser.add_argument("--summary", action="store_true", help="Print only a compact report summary")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    parser.add_argument("--output", help="Write results to this file")
    return parser


def validate_args(args: argparse.Namespace) -> tuple[str, str | None, list[int], list[str], list[int]]:
    domain, base_url = normalize_target(args.target)
    args.domain = domain

    if args.timeout <= 0:
        raise SystemExit("--timeout must be greater than zero")
    if not 1 <= args.workers <= 100:
        raise SystemExit("--workers must be between 1 and 100")
    if args.delay < 0:
        raise SystemExit("--delay cannot be negative")
    if args.max_body < 1024:
        raise SystemExit("--max-body must be at least 1024")
    if args.max_redirects < 0:
        raise SystemExit("--max-redirects cannot be negative")
    if args.https_only and args.http_only:
        raise SystemExit("--https-only and --http-only cannot be used together")
    if not 0 <= args.nmap_timing <= 5:
        raise SystemExit("--nmap-timing must be between 0 and 5")
    if args.nmap_timeout <= 0:
        raise SystemExit("--nmap-timeout must be greater than zero")
    if args.nmap_vuln:
        args.nmap = True

    ports = parse_ports(args.ports)
    if len(ports) > MAX_PORTS_WITHOUT_CONFIRM and not args.allow_large_scan:
        raise SystemExit(
            f"refusing to check {len(ports)} web ports without --allow-large-scan "
            f"(limit is {MAX_PORTS_WITHOUT_CONFIRM})"
        )

    nmap_ports = parse_ports(args.nmap_ports)
    if len(nmap_ports) > MAX_NMAP_PORTS_WITHOUT_CONFIRM and not args.allow_large_nmap_scan:
        raise SystemExit(
            f"refusing to scan {len(nmap_ports)} Nmap ports without --allow-large-nmap-scan "
            f"(limit is {MAX_NMAP_PORTS_WITHOUT_CONFIRM})"
        )

    return domain, base_url, ports, parse_paths(args.paths), nmap_ports


def format_text(payload: dict) -> str:
    lines = [
        f"Target: {payload['target']}",
        f"Scope: web application recon only",
        "",
        "Summary:",
    ]
    lines.extend(format_summary_lines(payload["summary"], indent="  "))
    lines.extend([
        "",
        "Resolved hosts:",
    ])

    resolved_hosts = payload["resolved_hosts"]
    if resolved_hosts:
        for item in resolved_hosts:
            lines.append(f"  [FOUND] {item['host']} -> {', '.join(item['addresses'])}")
    else:
        lines.append("  [INFO] No hosts resolved.")

    lines.extend(["", "DNS records:"])
    for record in payload["dns_records"]:
        if record["values"]:
            lines.append(f"  [{record['query_type']}]")
            lines.extend(f"    {value}" for value in record["values"])
        elif record["error"]:
            lines.append(f"  [{record['query_type']}] {record['error']}")

    lines.extend(["", "Live web endpoints:"])
    web_results = [item for item in payload["web"] if item["status"] is not None]
    if web_results:
        for item in web_results:
            title = f" title={item['title']!r}" if item["title"] else ""
            lines.append(f"  [{item['status']}] {item['final_url']}{title}")
            if item["tech_headers"]:
                tech = ", ".join(f"{key}: {value}" for key, value in item["tech_headers"].items())
                lines.append(f"    tech headers: {tech}")
            if item["security_headers_missing"]:
                missing = ", ".join(item["security_headers_missing"])
                lines.append(f"    missing security headers: {missing}")
            if item["redirects"]:
                lines.append(f"    redirects: {'; '.join(item['redirects'])}")
    else:
        lines.append("  [INFO] No HTTP(S) endpoints responded in selected scope.")

    errors = [item for item in payload["web"] if item["error"]]
    if errors:
        lines.extend(["", "Web check errors:"])
        for item in errors[:20]:
            lines.append(f"  [ERROR] {item['url']} -> {item['error']}")

    lines.extend(["", "TLS certificates:"])
    tls_results = [item for item in payload["tls"] if not item["error"]]
    if tls_results:
        for item in tls_results:
            expiry = f", expires in {item['expires_in_days']} day(s)" if item["expires_in_days"] is not None else ""
            lines.append(f"  [TLS] {item['host']}:{item['port']} {item['protocol']}, subject={item['subject']!r}{expiry}")
    else:
        lines.append("  [INFO] No TLS certificate details collected.")

    interesting_paths = [item for item in payload["paths"] if item["interesting"]]
    lines.extend(["", "Well-known files:"])
    if interesting_paths:
        for item in interesting_paths:
            notes = f" ({'; '.join(item['notes'])})" if item["notes"] else ""
            lines.append(f"  [{item['status']}] {item['url']}{notes}")
    else:
        lines.append("  [INFO] No selected well-known files found.")

    if payload.get("nmap"):
        nmap = payload["nmap"]
        lines.extend(["", "Nmap scan:"])
        if nmap["command"]:
            lines.append(f"  command: {format_command(nmap['command'])}")
        if nmap["targets"]:
            lines.append(f"  targets: {', '.join(nmap['targets'])}")
        if nmap["error"]:
            lines.append(f"  [ERROR] {nmap['error']}")
        elif nmap["ports"]:
            lines.append("  Open ports:")
            for item in nmap["ports"]:
                service = item["service"] or "unknown"
                details = " ".join(part for part in [item["product"], item["version"]] if part)
                suffix = f" ({details})" if details else ""
                lines.append(f"    {item['host']}:{item['port']}/{item['protocol']} {service}{suffix}")
        else:
            lines.append("  [INFO] No open ports reported by Nmap.")

        if nmap["scripts"]:
            lines.append("  Script findings:")
            for item in nmap["scripts"][:30]:
                port = f":{item['port']}" if item["port"] is not None else ""
                lines.append(f"    [{item['script_id']}] {item['host']}{port} {item['output']}")
        if nmap["stderr"]:
            lines.append(f"  stderr: {nmap['stderr']}")

    return "\n".join(lines)


def build_summary(payload: dict) -> dict:
    live_web = [item for item in payload["web"] if item["status"] is not None]
    web_errors = [item for item in payload["web"] if item["error"]]
    tls_results = [item for item in payload["tls"] if not item["error"]]
    tls_errors = [item for item in payload["tls"] if item["error"]]
    tls_expiring_soon = [
        item
        for item in tls_results
        if item["expires_in_days"] is not None and item["expires_in_days"] <= 30
    ]
    interesting_paths = [item for item in payload["paths"] if item["interesting"]]
    status_counts: dict[str, int] = {}
    for item in live_web:
        status = str(item["status"])
        status_counts[status] = status_counts.get(status, 0) + 1

    nmap = payload.get("nmap") or {}
    return {
        "resolved_hosts": len(payload["resolved_hosts"]),
        "dns_record_types_with_values": sum(1 for item in payload["dns_records"] if item["values"]),
        "live_web_endpoints": len(live_web),
        "web_errors": len(web_errors),
        "status_counts": dict(sorted(status_counts.items())),
        "endpoints_missing_security_headers": sum(1 for item in live_web if item["security_headers_missing"]),
        "tls_certificates": len(tls_results),
        "tls_expiring_within_30_days": len(tls_expiring_soon),
        "tls_errors": len(tls_errors),
        "interesting_paths": len(interesting_paths),
        "nmap_open_ports": len(nmap.get("ports", [])),
        "nmap_script_findings": len(nmap.get("scripts", [])),
    }


def format_summary(summary: dict) -> str:
    return "\n".join(format_summary_lines(summary))


def format_summary_lines(summary: dict, indent: str = "") -> list[str]:
    status_counts = summary["status_counts"]
    status_text = ", ".join(f"{status}: {count}" for status, count in status_counts.items()) or "none"
    return [
        f"{indent}Resolved hosts: {summary['resolved_hosts']}",
        f"{indent}DNS record types with values: {summary['dns_record_types_with_values']}",
        f"{indent}Live web endpoints: {summary['live_web_endpoints']} ({status_text})",
        f"{indent}Web check errors: {summary['web_errors']}",
        f"{indent}Endpoints missing security headers: {summary['endpoints_missing_security_headers']}",
        f"{indent}TLS certificates: {summary['tls_certificates']}",
        f"{indent}TLS certificates expiring within 30 days: {summary['tls_expiring_within_30_days']}",
        f"{indent}TLS check errors: {summary['tls_errors']}",
        f"{indent}Interesting well-known files: {summary['interesting_paths']}",
        f"{indent}Nmap open ports: {summary['nmap_open_ports']}",
        f"{indent}Nmap script findings: {summary['nmap_script_findings']}",
    ]


def format_command(command: list[str]) -> str:
    return " ".join(quote_arg(part) for part in command)


def quote_arg(value: str) -> str:
    if re.search(r"\s", value):
        return f'"{value}"'
    return value


def main(argv: list[str] | None = None) -> int:
    print(BANNER, file=sys.stderr)
    parser = build_parser()
    args = parser.parse_args(argv)
    domain, base_url, ports, paths, nmap_ports = validate_args(args)
    words = load_subdomain_words(args)

    print("Use only against web applications you own or have explicit authorization to test.", file=sys.stderr)
    print(f"Resolving web host candidates for {domain}...", file=sys.stderr)

    resolved = enumerate_subdomains(domain, words, args.timeout, args.workers)
    if not args.no_root:
        root = resolve_host(domain, args.timeout)
        if root:
            resolved = [root, *resolved]

    hosts = sorted({item.host for item in resolved})
    urls = candidate_urls(hosts, ports, base_url, args.https_only, args.http_only)

    if args.delay > 0:
        time.sleep(args.delay)

    print(f"Checking {len(urls)} HTTP(S) endpoint candidate(s)...", file=sys.stderr)
    web_results = run_web_checks(urls, args.timeout, args.workers, args.max_body, args.max_redirects) if urls else []
    path_results = run_path_checks(web_results, paths, args.timeout, args.workers, args.max_body) if paths else []
    tls_results = run_tls_checks(hosts, ports, args.timeout, args.workers)
    dns_records = [
        query_dns_record(domain, "MX", args.timeout),
        query_dns_record(domain, "TXT", args.timeout),
    ]
    nmap_result = None
    if args.nmap:
        print("Running optional Nmap scan...", file=sys.stderr)
        nmap_result = run_nmap_scan(args, hosts, nmap_ports)

    payload = {
        "target": args.target,
        "domain": domain,
        "scope": "web application recon only",
        "resolved_hosts": [asdict(item) for item in resolved],
        "dns_records": [asdict(item) for item in dns_records],
        "web": [asdict(item) for item in web_results],
        "tls": [asdict(item) for item in tls_results],
        "paths": [asdict(item) for item in path_results],
        "nmap": asdict(nmap_result) if nmap_result else None,
    }
    payload["summary"] = build_summary(payload)

    if args.summary:
        output = json.dumps(payload["summary"], indent=2) if args.json else format_summary(payload["summary"])
    else:
        output = json.dumps(payload, indent=2) if args.json else format_text(payload)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
