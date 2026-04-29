# PQC Support Tools

> Two utilities for auditing Post-Quantum Cryptography (PQC) readiness on a host system — one for Windows CNG provider enumeration (C++), one for .NET ML-KEM support verification (C#).

---

## Tools

### EnumProviders — Windows CNG Provider Enumeration (`EnumProviders/`)

A C++ console application that calls `BCryptEnumRegisteredProviders` to list every cryptographic provider registered with the Windows Cryptography Next Generation (CNG) API.

Use this to check whether any post-quantum providers have been installed alongside the default Microsoft primitives, or to audit which algorithms are available on a given Windows build.

**Prerequisites:** Visual Studio 2019+, Windows (CNG is a Windows-only API)

**Build:**
```
Open EnumProviders/EnumProviders.sln in Visual Studio
Build → Build Solution (Ctrl+Shift+B)
```

**Run:**
```cmd
Debug\EnumProviders.exe
```

Sample output on a standard Windows 11 host:
```
Microsoft Primitive Provider
Microsoft Key Protection Provider
Microsoft Smart Card Key Storage Provider
Microsoft Platform Crypto Provider
```

---

### PqcSupported — ML-KEM Platform Check (`PqcSupported/`)

A C# / .NET program that:
1. Checks whether ML-KEM (CRYSTALS-Kyber, standardised as [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)) is supported by the current .NET runtime
2. If supported, performs a full ML-KEM-768 key encapsulation round-trip to verify correctness:
   - Generates a key pair
   - Encapsulates a shared secret with the public key (produces ciphertext)
   - Decapsulates the ciphertext with the private key
   - Verifies both sides derived the same shared secret

**Prerequisites:** [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0) (ML-KEM was introduced in .NET 10)

**Run:**
```bash
cd PQCSupportTools/PqcSupported
dotnet run
```

Expected output on a .NET 10+ host:
```
ML-KEM is supported :)
Testing ML-KEM 768...
Generating key pairs...
Generating shared secret as ciphertext...
Decrypting ciphertext with private key...
Checking shared secrets match...
Same answer, yay math! 4A3F...
```

Output on older runtimes:
```
ML-KEM isn't supported :(
```

---

## References

- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [.NET 10 Cryptography — ML-KEM](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/runtime#cryptography)
- [Windows CNG API — BCryptEnumRegisteredProviders](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptenumregisteredproviders)
