# Network Security

> Low-level network testing tools and reconnaissance references for authorized network security assessments. Covers host discovery, packet crafting, SYN flood simulation, and a curated cheat-sheet of standard network testing tools.

---

## Directory Structure

```
NetworkSecurity/
├── Tools/          — .NET SDK for network discovery and DoS simulation
└── Reconnaissance/ — Command reference for nmap, tcpdump, Wireshark, hping, and more
```

---

## Tools — .NET Network Testing SDK ([`Tools/`](Tools/))

A cross-platform **.NET** library and CLI for network security testing. Supports Windows and Linux via platform-specific raw socket implementations.

### Projects

| Project | Purpose |
|---------|---------|
| `LD.InfoSec.Network.Discovery` | ICMP ping sweep host discovery — single IP, range (`x.x.x.x-y.y.y.y`), or CIDR notation |
| `LD.InfoSec.Network.DoS` | SYN flood simulation for authorized load/resilience testing |
| `LD.InfoSec.Network.Shared` | Shared packet generation utilities and platform abstraction |
| `LD.InfoSec.Network.Win` | Windows raw socket implementation |
| `LD.InfoSec.Network.Linux` | Linux raw socket implementation |
| `LD.InfoSec.Network.Cli` | CLI entry point |

### Prerequisites

- .NET 8+ SDK
- On Linux: run as root or with `CAP_NET_RAW` capability (required for raw sockets)
- On Windows: run as Administrator

### Configure and run

Edit `Tools/LD.InfoSec.Network.Cli/Program.cs` to set your target and operation, then:

```bash
cd NetworkSecurity/Tools/LD.InfoSec.Network.Cli
dotnet run
```

**Ping sweep example** (discovers live hosts in a subnet):
```csharp
DiscoveryService discovery = new(new DiscoveryOptions
{
    DiscoveryType = DiscoveryType.PingSweep,
    IcmpType = IcmpType.EchoRequest,
    TargetIp = "192.168.1.0/24",   // CIDR, or "192.168.1.1-192.168.1.254" range
});
await discovery.Start();
```

**SYN flood example** (authorized stress testing only):
```csharp
DosAttack attack = new(new()
{
    DosType = DosType.SynFlood,
    TargetIp = "192.168.1.100",
    TargetPort = 80,
    SourceIp = "192.168.1.50",
    SourcePort = 60270,
    Size = 1,
});
await attack.Start();
```

> The SYN flood implementation sends raw TCP SYN packets with a spoofed source address. Only use against systems you own or have explicit written permission to test.

---

## Reconnaissance Reference ([`Reconnaissance/`](Reconnaissance/))

Command cheat-sheet for standard network reconnaissance and analysis tools.

### nmap — [nmap.org](https://nmap.org/)

```bash
nmap -sS 172.27.0.0/20          # SYN scan a subnet for live hosts
nmap -sV 192.168.86.150         # Service/version detection on a host
nmap -p 135 --script=msrpc-enum <TARGET_IP>  # Enumerate MSRPC (for overflow research)
nmap -A -T4 192.168.1.1         # Aggressive scan: OS detection, version, scripts, traceroute
```

### netstat (Windows)

```cmd
netstat -ab    # Show listening and established connections with owning process
netstat -an    # Numeric addresses, all connections
```

### hping3 — [kali.org/tools/hping3](https://www.kali.org/tools/hping3/)

```bash
hping3 -S -p 80 192.168.1.1        # SYN ping when ICMP is blocked
hping3 --traceroute -V -1 target   # ICMP traceroute
```

### nslookup / dig

```bash
nslookup www.example.com           # DNS lookup
dig @8.8.8.8 example.com ANY       # All record types via specific resolver
```

### tcpdump — [tcpdump.org](https://www.tcpdump.org/)

```bash
tcpdump -i eth0 "src host 10.1.0.100 and (dst port 53 or dst port 80)"
tcpdump -i eth0 -w capture.pcap    # Write to pcap for Wireshark analysis
tcpdump -r capture.pcap            # Read a captured file
```

### Wireshark — [wireshark.org](https://www.wireshark.org/)

GUI packet capture and analysis. Open a `.pcap` file or capture live traffic. Useful display filters:

```
tcp.flags.syn == 1 && tcp.flags.ack == 0    # SYN packets only
http.request                                  # HTTP requests
ip.addr == 192.168.1.100                     # Filter by host
```

### ettercap — [ettercap-project.org](https://www.ettercap-project.org/)

ARP poisoning and man-in-the-middle packet injection on a local network segment.

```bash
ettercap -T -q -M arp:remote /192.168.1.1// /192.168.1.100//
```

### tcpreplay — [linux.die.net/man/1/tcpreplay](https://linux.die.net/man/1/tcpreplay)

Replay a captured `.pcap` against a live interface:

```bash
tcpreplay -i eth0 capture.pcap
tcpreplay --multiplier=2.0 -i eth0 capture.pcap   # Replay at 2x speed
```

---

## References

- [nmap Book](https://nmap.org/book/man.html)
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [hping3 Manual](https://www.kali.org/tools/hping3/)
