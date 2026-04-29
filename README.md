```
 ██╗███╗   ██╗███████╗ ██████╗ ███████╗███████╗ ██████╗
 ██║████╗  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██╔════╝
 ██║██╔██╗ ██║█████╗  ██║   ██║███████╗█████╗  ██║
 ██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║██╔══╝  ██║
 ██║██║ ╚████║██║     ╚██████╔╝███████║███████╗╚██████╗
 ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
```

> **A collection of tools, code samples, and research spanning multiple information security domains.**
> Built for security professionals, pentesters, and researchers — for authorized use only.

---

## 🗺️ Repository Overview

This repository is organized by information security domain. Each section contains purpose-built tools, proof-of-concept code, and reference material for security research and authorized penetration testing.

```
infosec/
├── 🌐 WebSecurity/         — Web application security & API reconnaissance
├── 🔌 NetworkSecurity/     — Network testing & packet-level tooling
├── 💥 Exploits/            — Memory corruption & code vulnerability research
├── 🛡️  Antivirus/          — AV/EDR detection & evasion research
└── 🔐 Cryptography/        — Post-quantum cryptography tools & algorithm demos
```

---

## 🌐 Web Security

> Tools and techniques for testing and understanding web application vulnerabilities.

### 🔍 [AI API Scanner — Endpoint Recon & Risk Analyzer](https://github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance/api-tester)

An AI-powered, colorful console tool for API reconnaissance and pentest risk summarization, written in **Go**.

```
       .-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-.
      /   API SCANNER DRONE :: RECON MODE :: ONLINE          \
     /_________________________________________________________\
            \      ^__^      /
             \____(oo)______/      [GET] [POST] [PUT] [PATCH]
             /----(__)----\        [HEAD] [OPTIONS] [DELETE]
          .-'  /|::::|\  '-.
         /    /_|::::|_\    \
        |  []   /____\   []  |      >>> Sweeping endpoint space...
        |_____________________|      >>> Mapping docs + well-known paths
            /_/      \_\
```

**What it does:**
- 🕵️ Probes API endpoints using curated OWASP/PortSwigger-inspired wordlists
- 📖 Discovers additional routes by parsing live OpenAPI/Swagger/ReDoc documentation
- 🧪 Tests HTTP verbs (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS) per endpoint
- 🔍 Performs lightweight parameter probing (query params & JSON body fields)
- 🤖 Optionally generates an **AI-powered pentest risk summary** via OpenAI
- 🎨 Colorized output: green (2xx), yellow (401/403), red (other discovered)

**Quick start:**
```bash
go run . https://target.example.com --with-ai YOUR_OPENAI_API_KEY
```

---

### 📋 [Web Reconnaissance Reference](https://github.com/leedale1981/infosec/tree/master/WebSecurity/Reconnaissance)

Reference notes and techniques for web application reconnaissance including Burp Suite proxy setup, SQL injection discovery, and `whatweb` fingerprinting.

---

## 🔌 Network Security

> Low-level network tools for discovery, packet crafting, and authorized stress testing.

### 🛠️ [.NET Network Testing SDK](https://github.com/leedale1981/infosec/tree/master/NetworkSecurity/Tools)

A cross-platform **.NET** library and CLI for network security testing. Supports Windows and Linux via platform-specific network service implementations.

**Capabilities:**
| Module | Purpose |
|--------|---------|
| `LD.InfoSec.Network.Discovery` | 🔎 Network host discovery via ICMP ping sweeps |
| `LD.InfoSec.Network.DoS` | 💣 SYN flood and DoS simulation (authorized testing only) |
| `LD.InfoSec.Network.Shared` | 📦 Shared packet generation and network utilities |
| `LD.InfoSec.Network.Win` | 🪟 Windows-specific raw socket implementation |
| `LD.InfoSec.Network.Linux` | 🐧 Linux-specific raw socket implementation |
| `LD.InfoSec.Network.Cli` | ⌨️ CLI entry point |

---

### 📡 [Network Reconnaissance Reference](https://github.com/leedale1981/infosec/tree/master/NetworkSecurity/Reconnaissance)

Cheat-sheet and reference notes for tools including `nmap`, `tcpdump`, `Wireshark`, `hping`, `ettercap`, `tcpreplay`, and `netstat`.

---

## 💥 Exploits

> Proof-of-concept code for understanding memory corruption vulnerabilities.

### [Memory Corruption Research](https://github.com/leedale1981/infosec/tree/master/Exploits)

C/C++ and .NET proof-of-concept implementations demonstrating classic vulnerability classes. For educational and authorized red team use.

| Folder | Vulnerability Class |
|--------|-------------------|
| `buffer_overflows/` | 🧱 Stack-based buffer overflow exploitation |
| `format_string/` | 📝 Format string vulnerability exploitation |
| `heap_overflows/` | 🪣 Heap corruption and overflow techniques |

> 💡 Recommended companion tool: [SPIKE](https://www.kali.org/tools/spike/) for fuzzing COM/DCOM interfaces.

---

## 🛡️ Antivirus / EDR Research

> Research into AV/EDR detection mechanisms and evasion techniques, for defensive understanding and authorized red team assessments.

### 🪝 [DetoursHooker — API Hooking with Microsoft Detours](https://github.com/leedale1981/infosec/tree/master/Antivirus/evasion-techniques/hooking/hooker)

A C++ implementation using [Microsoft Detours](https://github.com/microsoft/Detours) to demonstrate API function hooking — redirecting Windows API calls at the IAT level. Includes a `DetoursSimulator` for safe testing of hooking behavior without live payloads.

---

### 🔗 [HookChain — Indirect Syscall EDR Bypass Research](https://github.com/leedale1981/infosec/tree/master/Antivirus/evasion-techniques/hooking/indirect_syscalls/hookchain)

An implementation of the **HookChain** technique as described in the academic paper *"HookChain: A new perspective for Bypassing EDR Solutions"* (Carvalho Junior, 2024).

**Technique overview:**
- 🔗 **IAT Hooking** — redirects execution at the Import Address Table level
- 🔢 **Dynamic SSN Resolution** — resolves System Service Numbers at runtime to avoid static signatures
- 📞 **Indirect System Calls** — bypasses EDR hooks placed on `Ntdll.dll` by calling the kernel directly

Includes enumeration results (`hookchain_finder64`) against major EDR vendors including CrowdStrike, SentinelOne, Defender ATP, Carbon Black, Cortex XDR, and more.

> 📄 White paper: [English v1.5](Antivirus/evasion-techniques/hooking/indirect_syscalls/hookchain/HookChain_en_v1.5.pdf)

---

### 🔍 [HookChain Finder](https://github.com/leedale1981/infosec/tree/master/Antivirus/evasion-techniques/hooking/hook_finder)

A standalone C utility (`hookchain_finder64`) that enumerates hooked functions in a running process — useful for auditing which EDR agents are hooking which Windows API calls.

---

## 🔐 Cryptography

> Post-quantum cryptography (PQC) tooling, classical algorithm demonstrations, and TLS experimentation.

### ⚛️ [QuantCrypt — Post-Quantum Cryptography Suite](https://github.com/leedale1981/infosec/tree/master/Cryptography/QuantCrypt)

A **.NET** suite for exploring and testing post-quantum cryptographic algorithms.

| Project | Purpose |
|---------|---------|
| `QuantCrypt.Core` | 🔢 Core PQC implementations — polynomial math operations (lattice-based crypto foundations), AES symmetric primitives |
| `QuantCrypt.Proxy` | 🔀 TLS proxy for observing and testing PQC-capable TLS handshakes |
| `QuantCrypt.Core.Tests` | 🧪 Unit tests for core mathematical operations |

---

### 🛠️ [PQC Support Tools](https://github.com/leedale1981/infosec/tree/master/Cryptography/PQCSupportTools)

Utilities for auditing Post-Quantum Cryptography support on a host system.

| Tool | Language | Purpose |
|------|----------|---------|
| `EnumProviders` | C++ | 🔍 Enumerate registered cryptographic providers on a Windows system |
| `PqcSupported` | C# / .NET | ✅ Check which PQC algorithms are supported by the current platform |

---

### 🗝️ [RSA Key Factorization Demo](https://github.com/leedale1981/infosec/tree/master/Cryptography/algorithms/keyfactor)

A **Go** program demonstrating RSA key pair generation, message encryption/decryption, and classical RSA key factorization attack simulation — illustrating why large key sizes matter and why RSA is vulnerable to quantum computers running Shor's algorithm.

```
Sender  ──[encrypt with public key]──► Ciphertext ──► Receiver (decrypts)
                                            │
                                            └──► Attacker (attempts factorization)
```

---

## ⚠️ Legal & Ethical Use

> All tools in this repository are provided **for authorized security testing, research, and educational purposes only**.
>
> - ✅ Use on systems you own or have explicit written permission to test
> - ✅ CTF competitions and lab environments
> - ✅ Defensive security research and EDR product development
> - ❌ Never use against systems without authorization
> - ❌ Never use for illegal, malicious, or destructive purposes
>
> The authors accept no liability for misuse of any code or techniques contained herein.

---

## 📚 References & Standards

- [OWASP](https://owasp.org/) — Web application security standards
- [NIST SSDF (SP 800-218)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf) — Secure Software Development Framework
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography) — Post-quantum algorithm standards
- [HookChain Paper (arXiv:2404.16856)](https://arxiv.org/abs/2404.16856) — HookChain EDR bypass research
- [Microsoft Detours](https://github.com/microsoft/Detours) — API hooking library
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Web vulnerability research

---

<div align="center">

*Built for defenders who think like attackers.*

</div>
