# Antivirus / EDR Research

> Research into how Endpoint Detection and Response (EDR) and Antivirus (AV) products detect malicious behaviour, and how those detection mechanisms can be understood and bypassed. All material here is for defensive security research, red team tooling development, and authorized penetration testing only.

---

## Directory Structure

```
Antivirus/
└── evasion-techniques/
    └── hooking/
        ├── hook_finder/        — Enumerate hooked functions in a live process
        ├── hooker/             — API hooking demo using Microsoft Detours
        └── indirect_syscalls/
            └── hookchain/      — IAT hooking + indirect syscalls EDR bypass technique
```

---

## Tools

### HookChain Finder — [`hooking/hook_finder/`](evasion-techniques/hooking/hook_finder/)

A C utility that enumerates which Windows API functions (Nt/Zw family) are currently hooked in a running process by inspecting the Import Address Table (IAT) against the live `ntdll.dll` export addresses.

**Use case:** Run this against a process on a machine with an EDR installed to see which syscall wrappers the EDR has placed hooks on.

**Prerequisites:** Windows x64, GCC (MinGW) or MSVC

**Build:**
```bash
gcc hookchain_finder64.c -o hookchain_finder64.exe -ldbghelp
```

**Run:**
```bash
# Enumerate hooks in the current process
hookchain_finder64.exe

# Load an additional DLL first, then enumerate (useful for testing injected hooks)
hookchain_finder64.exe path\to\some.dll
```

The tool prints every `Nt*` / `Zw*` function it finds, flags any that appear to be hooked (jump trampoline detected at the function prologue), and then walks all loaded modules checking for IAT discrepancies.

---

### DetoursHooker — [`hooking/hooker/`](evasion-techniques/hooking/hooker/)

A C++ demonstration of API function hooking using [Microsoft Detours](https://github.com/microsoft/Detours). The project intercepts the `Sleep()` Win32 API call at the IAT level and redirects it to a custom implementation.

**Projects in the Visual Studio solution (`EvasionTechniques.sln`):**

| Project | Purpose |
|---------|---------|
| `DetoursHooker` | A DLL that hooks `Sleep()` via Detours — inject into any process to intercept sleep calls |
| `DetoursSimulator` | A simple host exe that calls `Sleep(5000)` — used to demonstrate the hook in action |

**Prerequisites:** Visual Studio 2019+, Windows x64

**Build:** Open `EvasionTechniques/EvasionTechniques.sln` in Visual Studio and build the solution.

**Run:**
```cmd
# Use the Detours setdll tool to inject the hooker DLL into the simulator exe
setdll.exe /d:DetoursHooker.dll DetoursSimulator.exe

# Then run the simulator — the Sleep call will be intercepted by the hook
DetoursSimulator.exe
```

The hook prints a message before calling through to the original `Sleep`, demonstrating that EDRs use the same IAT-hooking mechanism to intercept API calls for inspection.

---

### HookChain — [`hooking/indirect_syscalls/hookchain/`](evasion-techniques/hooking/indirect_syscalls/hookchain/)

An implementation of the **HookChain** technique from the research paper *"HookChain: A new perspective for Bypassing EDR Solutions"* (Carvalho Junior, 2024 — [arXiv:2404.16856](https://arxiv.org/abs/2404.16856)).

The technique chains three evasion primitives together so that execution bypasses EDR hooks placed on `ntdll.dll`:

1. **IAT Hooking** — redirects execution at the Import Address Table before EDR hooks can intercept
2. **Dynamic SSN Resolution** — resolves System Service Numbers at runtime, avoiding static signatures
3. **Indirect System Calls** — calls the Windows kernel directly rather than via the hooked ntdll stubs

**White papers:** [English v1.5](evasion-techniques/hooking/indirect_syscalls/hookchain/HookChain_en_v1.5.pdf) | [Português v1.5](evasion-techniques/hooking/indirect_syscalls/hookchain/HookChain_pt_v1.5.pdf)

**Enumeration results** (`enum/results_enum/`) contain hookchain_finder64 output against major EDR vendors including CrowdStrike, SentinelOne, Defender ATP, Carbon Black, Cortex XDR, Elastic, Kaspersky, SentinelOne, Sophos, and more.

**Prerequisites:** Visual Studio 2022+, MASM (ml64), Windows x64

**Build:** Open `HookChain/HookChain_msg.sln` and build in x64 Debug or Release.

Pre-built binaries are in `HookChain/x64/Debug/`:
- `HookChain_msg.exe` — demonstrates the technique with a message box payload
- `HookChain_v.exe` — verbose variant showing syscall resolution steps
- `hookchain_finder64.exe` — the hook enumeration tool

---

## References

- [HookChain paper (arXiv:2404.16856)](https://arxiv.org/abs/2404.16856)
- [Microsoft Detours](https://github.com/microsoft/Detours)
- [Windows Internals — Syscall Mechanisms](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/system-service-dispatch-table)

---

> For authorized security research and red team use only. Do not deploy against systems without explicit written permission.
