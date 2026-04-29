# .NET Network Testing SDK

> A cross-platform .NET library and CLI for network security testing. Supports ICMP ping sweep host discovery and raw TCP SYN flood simulation for authorized network load testing.

---

## Project Structure

```
Tools/
├── LD.InfoSec.Network.Cli/         — CLI entry point (configure and run here)
├── LD.InfoSec.Network.Discovery/   — ICMP ping sweep implementation
├── LD.InfoSec.Network.DoS/         — SYN flood attack implementation
├── LD.InfoSec.Network.Shared/      — Packet generation, shared types
├── LD.InfoSec.Network.Win/         — Windows raw socket implementation
└── LD.InfoSec.Network.Linux/       — Linux raw socket implementation
```

---

## Prerequisites

- [.NET 8+ SDK](https://dotnet.microsoft.com/download)
- **Linux:** run as `root` or grant `CAP_NET_RAW` capability (required for raw sockets)
- **Windows:** run as Administrator

---

## Usage

Edit `LD.InfoSec.Network.Cli/Program.cs` to configure the operation, then run from the CLI project directory:

```bash
cd NetworkSecurity/Tools/LD.InfoSec.Network.Cli
dotnet run
```

---

## Host Discovery (Ping Sweep)

Sends ICMP Echo Request packets to enumerate live hosts on a subnet.

```csharp
DiscoveryService discovery = new(new DiscoveryOptions
{
    DiscoveryType = DiscoveryType.PingSweep,
    IcmpType = IcmpType.EchoRequest,
    TargetIp = "192.168.1.0/24",         // CIDR notation
    // or: TargetIp = "192.168.1.1-192.168.1.254",  // range
    // or: TargetIp = "192.168.1.100",               // single host
});
await discovery.Start();
```

Supported `TargetIp` formats:
- Single IP: `192.168.1.100`
- Range: `192.168.1.1-192.168.1.254`
- CIDR: `192.168.1.0/24`

---

## SYN Flood (Authorized DoS Simulation)

Sends raw TCP SYN packets with a configurable source address to simulate a SYN flood. Only use against systems you own or have explicit written permission to test.

```csharp
DosAttack attack = new(new AttackOptions
{
    DosType = DosType.SynFlood,
    TargetIp = "192.168.1.100",
    TargetPort = 80,
    SourceIp = "192.168.1.50",    // can be spoofed
    SourcePort = 60270,
    Size = 1,
});
await attack.Start();
```

The implementation delegates to `LD.InfoSec.Network.Linux.NetworkService.SendSynPackets` which constructs raw Ethernet/IP/TCP frames and injects them via a raw socket.

---

## Platform Architecture

The shared interface (`LD.InfoSec.Network.Shared.NetworkService`) abstracts raw socket operations. Platform-specific implementations in `LD.InfoSec.Network.Win` and `LD.InfoSec.Network.Linux` provide the actual socket calls for their respective OS. Switch between them by changing the `using` statement in the service implementations.

---

## References

- [Raw Sockets on Linux](https://man7.org/linux/man-pages/man7/raw.7.html)
- [ICMP — RFC 792](https://datatracker.ietf.org/doc/html/rfc792)
- [TCP SYN Flood — RFC 4987](https://datatracker.ietf.org/doc/html/rfc4987)
