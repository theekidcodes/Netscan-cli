# NetScan CLI — Subnet Calculator & Port Scanner

**Python | Networking | CLI Tool | No External Dependencies**

A command-line network utility combining **IPv4 subnet analysis** and **concurrent TCP port scanning**, built directly from Cisco NetAcad networking curriculum concepts — OSI model, TCP/IP, IPv4 addressing, CIDR notation, and transport-layer socket communication.

---

## Features

| Feature | Details |
|---|---|
| **Subnet Calculator** | Full IPv4 breakdown from any CIDR input |
| **Port Scanner** | Concurrent TCP scan with 100-thread pool |
| **Service Identification** | Maps open ports to 30+ known services |
| **Flexible Port Input** | Single, comma list, ranges, or mixed |
| **Hostname Resolution** | Accepts IPs or domain names |
| **Zero dependencies** | Standard library only (`socket`, `ipaddress`, `concurrent.futures`, `argparse`) |

---

## Usage

```bash
python netscan.py --help

# Subnet analysis
python netscan.py subnet 192.168.1.0/24
python netscan.py subnet 10.0.0.0/8
python netscan.py subnet 172.16.5.0/20

# Port scan — default ports (21,22,80,443,3306,3389...)
python netscan.py scan 192.168.1.1

# Port scan — specific ports
python netscan.py scan 192.168.1.1 --ports 22,80,443,3306

# Port scan — range
python netscan.py scan 10.0.0.1 --ports 1-1024

# Port scan — mixed
python netscan.py scan 192.168.1.1 --ports 22,80,100-200,443

# Scan a domain
python netscan.py scan example.com --ports 80,443
```

---

## Example Output

**Subnet analysis:**
```
╔═══════════════════════════════════════════════════════╗
║  SUBNET ANALYSIS  —  192.168.10.0/26                 ║
╠═══════════════════════════════════════════════════════╣
║  Network Address    :  192.168.10.0                   ║
║  Subnet Mask        :  255.255.255.192                ║
║  Wildcard Mask      :  0.0.0.63                       ║
║  Broadcast Address  :  192.168.10.63                  ║
║  Prefix Length      :  /26                            ║
║  First Usable Host  :  192.168.10.1                   ║
║  Last Usable Host   :  192.168.10.62                  ║
║  Total Addresses    :  64                             ║
║  Usable Hosts       :  62                             ║
║  IP Class           :  C                              ║
║  Private Range?     :  Yes                            ║
║  Mask (binary)      :  11111111.11111111.11111111.11000000 ║
╚═══════════════════════════════════════════════════════╝
```

**Port scan:**
```
╔══════════════════════════════════════════════════════════╗
║  PORT SCAN  —  192.168.1.1
║  Ports      :  14 port(s) queued
╠══════════════════════════════════════════════════════════╣
║  PORT     STATE      SERVICE                            ║
╠══════════════════════════════════════════════════════════╣
║  22       OPEN       SSH                               ║
║  80       OPEN       HTTP                              ║
║  443      OPEN       HTTPS                             ║
╠══════════════════════════════════════════════════════════╣
║  Scanned 14 ports in 0.83s  |  3 open port(s) found   ║
╚══════════════════════════════════════════════════════════╝
```

---

## Concepts Covered

| Concept | Where Applied |
|---|---|
| IPv4 addressing & CIDR | `ipaddress.IPv4Network` subnet breakdown |
| Subnet mask & wildcard mask | Displayed from `network.netmask` / `network.hostmask` |
| Network & broadcast addresses | `network.network_address`, `network.broadcast_address` |
| OSI Layer 3 (Network) | All subnet logic |
| OSI Layer 4 (Transport) | TCP socket connections in port scanner |
| TCP three-way handshake | `socket.create_connection()` |
| Concurrency / threading | `ThreadPoolExecutor` (100 workers) |
| CLI design | `argparse` with subcommands |

---

## Requirements

Python 3.10+ (uses standard library only — no `pip install` required)

---

## Relevant Companies

FAAN ICT Dept · Nigerian Ports Authority · NIMASA · NETCOM Africa · IHS Towers · NIIA (ICT/Systems Support) · NiRA · Ministry of Science & Technology Lagos · DATAFLEX Nigeria · Integrated Systems & Device Limited · GIIT

---

## Author

**Omobolaji Oluwanifemi Adejumo**  
Computer Engineering, University of Lagos  
[adejumoomobolaji218@gmail.com](mailto:adejumoomobolaji218@gmail.com)
