# HookChain Finder — EDR Hook Enumerator

> A C utility (`hookchain_finder64`) that enumerates hooked Windows API functions in a running process. Useful for auditing which EDR/AV agents are hooking which Nt/Zw syscall wrappers, and for verifying that indirect syscall techniques successfully bypass those hooks.

---

## What it does

The tool performs two passes:

1. **Ntdll inventory** — walks `ntdll.dll`'s export table and records the in-memory address of every `Nt*` and `Zw*` function. It also checks each function prologue for a `JMP` instruction (byte `0xe9`), which is the tell-tale sign of an EDR inline hook.

2. **IAT scan** — takes a snapshot of all modules loaded in the current process and, for each one, compares the IAT entry for any ntdll import against the address recorded in step 1. A mismatch indicates that something has redirected the function pointer — i.e. an IAT hook placed by an EDR.

---

## Prerequisites

- Windows x64
- GCC (MinGW-w64) or MSVC

---

## Build

```bash
gcc hookchain_finder64.c -o hookchain_finder64.exe -ldbghelp
```

Or open/add to a Visual Studio project targeting x64.

---

## Run

```cmd
# Enumerate hooks in the current process
hookchain_finder64.exe

# Load an extra DLL first (e.g. an EDR's monitoring DLL), then enumerate
hookchain_finder64.exe C:\path\to\edr_agent.dll
```

The tool pauses after printing the ntdll function list so you can attach a debugger before the IAT walk begins. Press **Enter** to continue.

---

## Output

```
[+] Listing ntdll Nt/Zw functions
------------------------------------------
NtAllocateVirtualMemory is hooked          ← EDR inline hook detected
   [0] NtAllocateVirtualMemory 0x00007fff...
   [1] NtCreateFile 0x00007fff...
   ...
Mapped 461 functions

[*] Press enter to continue...

[+] Listing loaded modules
------------------------------------------
ntdll.dll is loaded at 0x00007fff...
kernel32.dll is loaded at 0x00007fff...
...

[+] Listing hooked modules
------------------------------------------
Checking ntdll.dll at myapp.exe IAT
  |-- myapp.exe IAT to ntdll.dll of function *NtAllocateVirtualMemory is hooked to 0x...
  +-- 1 hooked functions.
```

Functions marked with `*` are both IAT-hooked and have an inline `JMP` hook at the ntdll entry point — double-hooked by the EDR.

---

## Enumeration Results

The `enum/results_enum/` directory contains output captured on machines running various EDR products:

| File | EDR / Product |
|------|--------------|
| `crowdstrike.txt` | CrowdStrike Falcon |
| `sentinelone.txt` | SentinelOne |
| `defender_atp.txt` | Microsoft Defender for Endpoint (ATP) |
| `carbonblack.txt` | VMware Carbon Black |
| `cortex.txt` | Palo Alto Cortex XDR |
| `elastic.txt` | Elastic Security |
| `kaspersky.txt` | Kaspersky |
| `bitdefender.txt` | Bitdefender |
| `sophos.txt` | Sophos |
| `trellix.txt` | Trellix (McAfee) |
| `checkpoint.txt` | Check Point |
| `trend.txt` | Trend Micro Apex One |
| `malwarebytes.txt` | Malwarebytes |
| `eset.txt` | ESET |

A consolidated comparison spreadsheet is at `enum/results_enum/Result.xlsx`.

---

## References

- [HookChain paper (arXiv:2404.16856)](https://arxiv.org/abs/2404.16856)
- [Parent hookchain directory](../indirect_syscalls/hookchain/)
