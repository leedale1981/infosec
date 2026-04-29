# DetoursHooker — API Hooking with Microsoft Detours

> A C++ demonstration of Windows API function hooking using [Microsoft Detours](https://github.com/microsoft/Detours). Shows how EDR and AV products intercept Win32 API calls at the IAT (Import Address Table) level, and how the same mechanism can be used by red teamers.

---

## What it does

The `DetoursHooker` DLL intercepts the `Sleep()` Win32 API call by patching the target process's IAT so that calls to `Sleep` are redirected to a custom `TimedSleep` function. The custom function prints a message, then calls through to the real `Sleep`.

This is the same technique used by EDR products to intercept calls to sensitive APIs (e.g. `VirtualAlloc`, `NtWriteVirtualMemory`, `CreateRemoteThread`) for inspection before they reach the kernel.

---

## Projects

| Project | File | Description |
|---------|------|-------------|
| `DetoursHooker` | `Hooker.cpp` | A DLL that hooks `Sleep()` via Detours. Inject into any process. |
| `DetoursSimulator` | `DetoursSimulator.cpp` | A host exe that calls `Sleep(5000)` — used as the injection target. |

**Solution:** `EvasionTechniques/EvasionTechniques.sln`

---

## Prerequisites

- Visual Studio 2019 or later (with C++ Desktop workload)
- Windows x64

The Detours library source (`detours.cpp`, `detours.h`) is bundled directly in the project — no separate install needed.

---

## Build

1. Open `EvasionTechniques/EvasionTechniques.sln` in Visual Studio
2. Set configuration to `Debug | x64`
3. Build → Build Solution (`Ctrl+Shift+B`)

Outputs:
- `DetoursHooker/Hooker.dll` — the hook DLL
- `DetoursSimulator/DetoursSimulator.exe` — the target process

---

## Run

Use the bundled `setdll.exe` (Detours utility) to permanently inject the hook DLL into the simulator binary:

```cmd
cd EvasionTechniques\DetoursHooker

# Inject the hook DLL
setdll.exe /d:Hooker.dll ..\DetoursSimulator\DetoursSimulator.exe

# Run the simulator — Sleep() is now intercepted
..\DetoursSimulator\DetoursSimulator.exe
```

Expected output:
```
Oh no your not! Sleeping for 6000 milliseconds
```

The hook increments the sleep duration by 1000ms and prints before delegating to the real `Sleep`.

To remove the hook from the binary:
```cmd
setdll.exe /d: ..\DetoursSimulator\DetoursSimulator.exe
```

---

## How it works

```
Process calls Sleep(5000)
        │
        ▼
IAT entry for Sleep  ──(patched by Detours)──►  TimedSleep()
                                                      │
                                                      │  prints message
                                                      │
                                                      ▼
                                               TrueSleep(5000)  ──►  kernel32.Sleep
```

Detours patches the first few bytes of the target function with a `JMP` to the hook, saving the original bytes into a "trampoline" so the original can still be called through.

---

## References

- [Microsoft Detours](https://github.com/microsoft/Detours)
- [Detours Wiki](https://github.com/microsoft/Detours/wiki)
- [IAT Hooking Explained](https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking)
