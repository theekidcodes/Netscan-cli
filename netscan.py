#!/usr/bin/env python3
"""
NetScan CLI — Subnet Calculator & Port Scanner
===============================================
A command-line network utility combining IPv4 subnet analysis
and concurrent TCP port scanning.

Built on Python standard library only — no external dependencies.

Usage:
    python netscan.py subnet 192.168.1.0/24
    python netscan.py subnet 10.0.0.0/8
    python netscan.py scan 192.168.1.1
    python netscan.py scan 192.168.1.1 --ports 22,80,443,3306
    python netscan.py scan 192.168.1.1 --ports 1-1024
    python netscan.py scan google.com --ports 80,443

Author: Omobolaji Adejumo
        Computer Engineering, University of Lagos
"""

import argparse
import socket
import ipaddress
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── WELL-KNOWN SERVICE MAP ───────────────────────────────────────────────────
# Maps port numbers to common service names (OSI Layer 4 / Application layer)
SERVICES = {
    20:    "FTP-Data",     21:   "FTP",          22:   "SSH",
    23:    "Telnet",       25:   "SMTP",          53:   "DNS",
    67:    "DHCP-Server",  68:   "DHCP-Client",   69:   "TFTP",
    80:    "HTTP",         110:  "POP3",           119:  "NNTP",
    123:   "NTP",          143:  "IMAP",           161:  "SNMP",
    194:   "IRC",          443:  "HTTPS",          445:  "SMB",
    465:   "SMTPS",        587:  "SMTP-Subm",      993:  "IMAPS",
    995:   "POP3S",        1433: "MSSQL",          1521: "Oracle-DB",
    3306:  "MySQL",        3389: "RDP",            5432: "PostgreSQL",
    5900:  "VNC",          6379: "Redis",          8080: "HTTP-Alt",
    8443:  "HTTPS-Alt",    9200: "Elasticsearch",  27017: "MongoDB",
}

DEFAULT_PORTS = "21,22,25,53,80,110,143,443,445,3306,3389,5432,8080,8443"


# ─── SUBNET CALCULATOR ───────────────────────────────────────────────────────

def get_ip_class(ip_str: str) -> str:
    """Determine the IPv4 address class (A, B, C, D, or E)."""
    first_octet = int(ip_str.split(".")[0])
    if 1   <= first_octet <= 126: return "A"
    if 128 <= first_octet <= 191: return "B"
    if 192 <= first_octet <= 223: return "C"
    if 224 <= first_octet <= 239: return "D  (Multicast)"
    return "E  (Reserved / Experimental)"


def subnet_info(cidr: str):
    """
    Parse a CIDR-notation address and print a complete subnet breakdown.
    Covers: network address, broadcast, usable host range, subnet/wildcard
    masks, prefix length, IP class, and private/public classification.
    """
    try:
        # strict=False allows host bits to be set (e.g. 192.168.1.5/24 → 192.168.1.0/24)
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ValueError as e:
        print(f"[ERROR] Invalid CIDR: {e}")
        print("[HINT]  Example formats: 192.168.1.0/24  |  10.0.0.0/8  |  172.16.0.5/12")
        sys.exit(1)

    hosts = list(network.hosts())
    n_hosts = len(hosts)

    print()
    print("╔═══════════════════════════════════════════════════════╗")
    print(f"║  SUBNET ANALYSIS  —  {cidr:<33}║")
    print("╠═══════════════════════════════════════════════════════╣")
    print(f"║  Network Address    :  {str(network.network_address):<32}║")
    print(f"║  Subnet Mask        :  {str(network.netmask):<32}║")
    print(f"║  Wildcard Mask      :  {str(network.hostmask):<32}║")
    print(f"║  Broadcast Address  :  {str(network.broadcast_address):<32}║")
    print(f"║  Prefix Length      :  /{network.prefixlen:<31}║")

    if n_hosts >= 2:
        print(f"║  First Usable Host  :  {str(hosts[0]):<32}║")
        print(f"║  Last Usable Host   :  {str(hosts[-1]):<32}║")
    elif n_hosts == 0:
        print(f"║  Usable Hosts       :  None (point-to-point or loopback) ║")

    print(f"║  Total Addresses    :  {network.num_addresses:<32}║")
    print(f"║  Usable Hosts       :  {n_hosts:<32}║")
    print(f"║  IP Class           :  {get_ip_class(str(network.network_address)):<32}║")
    print(f"║  Private Range?     :  {'Yes' if network.is_private else 'No':<32}║")

    # Binary representation of the subnet mask
    mask_binary = ".".join(
        f"{int(o):08b}" for o in str(network.netmask).split(".")
    )
    print(f"║  Mask (binary)      :  {mask_binary:<32}║")
    print("╚═══════════════════════════════════════════════════════╝")
    print()


# ─── PORT SCANNER ─────────────────────────────────────────────────────────────

def scan_port(host: str, port: int, timeout: float = 0.75) -> tuple[int, bool]:
    """
    Attempt a TCP three-way handshake to host:port.
    Returns (port, True) if the connection succeeds (port is OPEN),
    (port, False) otherwise (CLOSED or filtered).
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return port, True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return port, False


def port_scan(host: str, ports: list[int]):
    """
    Scan a list of ports concurrently using a ThreadPoolExecutor.
    Uses up to 100 worker threads for I/O-bound parallelism.
    """
    # Resolve hostname → IP first
    try:
        resolved_ip = socket.gethostbyname(host)
    except socket.gaierror:
        print(f"\n[ERROR] Cannot resolve hostname: '{host}'")
        print("[HINT]  Check the address or your network connection.")
        sys.exit(1)

    print()
    print("╔══════════════════════════════════════════════════════════╗")
    print(f"║  PORT SCAN  —  {host}")
    if host != resolved_ip:
        print(f"║  Resolved   :  {resolved_ip}")
    print(f"║  Ports      :  {len(ports)} port(s) queued")
    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  {'PORT':<8} {'STATE':<10} {'SERVICE':<20}            ║")
    print("╠══════════════════════════════════════════════════════════╣")

    open_ports = []
    start_time = time.time()

    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = {
            executor.submit(scan_port, resolved_ip, p): p
            for p in ports
        }
        for future in as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    elapsed = time.time() - start_time
    open_ports.sort()

    if open_ports:
        for p in open_ports:
            service = SERVICES.get(p, "unknown")
            print(f"║  {p:<8} {'OPEN':<10} {service:<20}            ║")
    else:
        print("║  No open ports found in the scanned range.               ║")

    print("╠══════════════════════════════════════════════════════════╣")
    print(f"║  Scanned {len(ports)} ports in {elapsed:.2f}s  |  {len(open_ports)} open port(s) found   ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print()


# ─── PORT STRING PARSER ───────────────────────────────────────────────────────

def parse_ports(port_str: str) -> list[int]:
    """
    Parse a port specification string into a sorted list of unique ints.

    Supports:
        Single ports:   "80"
        Comma list:     "22,80,443"
        Ranges:         "1-1024"
        Mixed:          "22,80,100-200,443"
    """
    ports = []
    for segment in port_str.split(","):
        segment = segment.strip()
        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                print(f"[ERROR] Invalid range: '{segment}'")
                sys.exit(1)
            lo, hi = int(parts[0]), int(parts[1])
            if not (0 < lo <= hi <= 65535):
                print(f"[ERROR] Port range out of bounds: {lo}-{hi}")
                sys.exit(1)
            ports.extend(range(lo, hi + 1))
        else:
            p = int(segment)
            if not (0 < p <= 65535):
                print(f"[ERROR] Invalid port number: {p}")
                sys.exit(1)
            ports.append(p)

    return sorted(set(ports))


# ─── CLI INTERFACE ────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=(
            "NetScan CLI — Subnet Calculator & Port Scanner\n"
            "================================================\n"
            "A Python network utility for subnetting analysis and TCP port scanning.\n\n"
            "Examples:\n"
            "  python netscan.py subnet 192.168.1.0/24\n"
            "  python netscan.py scan 192.168.1.1 --ports 22,80,443\n"
            "  python netscan.py scan 10.0.0.1 --ports 1-1024"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ── subnet ──
    sub = subparsers.add_parser(
        "subnet",
        help="Analyse an IPv4 network in CIDR notation",
        description="Print a full subnet breakdown for a given CIDR address."
    )
    sub.add_argument(
        "cidr",
        help="CIDR notation, e.g. 192.168.1.0/24 or 10.0.0.0/8"
    )

    # ── scan ──
    sc = subparsers.add_parser(
        "scan",
        help="TCP port scan a host",
        description="Concurrently probe TCP ports on a target host."
    )
    sc.add_argument(
        "host",
        help="Target IP address or hostname"
    )
    sc.add_argument(
        "--ports",
        default=DEFAULT_PORTS,
        metavar="PORTS",
        help=(
            f"Ports to scan (default: {DEFAULT_PORTS})\n"
            "Formats: single '80', list '22,80,443', range '1-1024', mixed '22,80,100-200'"
        )
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "subnet":
        subnet_info(args.cidr)

    elif args.command == "scan":
        ports = parse_ports(args.ports)
        port_scan(args.host, ports)

    else:
        parser.print_help()
        sys.exit(0)


if __name__ == "__main__":
    main()
