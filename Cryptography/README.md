# Cryptography

> Post-quantum cryptography (PQC) tooling, classical algorithm demonstrations, and TLS experimentation. The tools here explore the transition from classical public-key cryptography (RSA, ECC) to NIST-standardised post-quantum algorithms, and audit current platform support for PQC primitives.

---

## Directory Structure

```
Cryptography/
├── QuantCrypt/             — Solution root for the QuantCrypt .NET suite
├── QuantCrypt.Core/        — PQC math foundations (polynomial ops, AES)
├── QuantCrypt.Core.Tests/  — Unit tests for QuantCrypt.Core
├── QuantCrypt.Proxy/       — TLS proxy for observing PQC-capable handshakes
├── PQCSupportTools/
│   ├── EnumProviders/      — C++: list registered BCrypt providers on Windows
│   └── PqcSupported/       — C#: check ML-KEM support on the current platform
└── algorithms/
    └── keyfactor/          — Go: RSA demo + classical factorization attack simulation
```

---

## Tools

### QuantCrypt — PQC Suite (`QuantCrypt.Core`, `QuantCrypt.Proxy`)

A .NET suite for exploring post-quantum cryptography. Open `QuantCrypt/QuantCrypt.sln` in Visual Studio or Rider.

**Prerequisites:** .NET 10 SDK

**QuantCrypt.Core** implements the mathematical foundations used in lattice-based PQC:

| Namespace | Purpose |
|-----------|---------|
| `QuantCrypt.Core.Math` | Polynomial arithmetic over finite fields (Add, Subtract, Multiply with modular reduction) — the building blocks of MLWE/NTRU schemes |
| `QuantCrypt.Core.Symmetric` | AES symmetric cipher wrapper (stub, extensible) |

**Run the tests:**
```bash
cd Cryptography
dotnet test QuantCrypt.Core.Tests/QuantCrypt.Core.Tests.csproj
```

**QuantCrypt.Proxy** is a TCP listener that can be extended into a TLS inspection proxy for observing PQC-capable TLS 1.3 handshakes (e.g. X25519Kyber768 hybrid key exchange).

```bash
cd Cryptography/QuantCrypt.Proxy
dotnet run
```

---

### PQC Support Tools (`PQCSupportTools/`)

Two utilities for auditing PQC readiness on the current host.

#### EnumProviders (C++)

Lists all cryptographic providers registered with Windows CNG (`BCryptEnumRegisteredProviders`). Use this to see whether any post-quantum providers have been installed alongside the default Microsoft primitives.

**Prerequisites:** Visual Studio 2019+, Windows

**Build:** Open `PQCSupportTools/EnumProviders/EnumProviders.sln` and build.

**Run:**
```cmd
EnumProviders.exe
```

Sample output:
```
Microsoft Primitive Provider
Microsoft Key Protection Provider
```

#### PqcSupported (C# / .NET)

Checks whether ML-KEM (CRYSTALS-Kyber, NIST FIPS 203) is supported by the current .NET runtime, then demonstrates a full key encapsulation round-trip using ML-KEM-768.

**Prerequisites:** .NET 10 SDK (ML-KEM support was added in .NET 10)

**Run:**
```bash
cd Cryptography/PQCSupportTools/PqcSupported
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
Same answer, yay math! <hex-encoded shared secret>
```

---

### RSA Key Factorization Demo (`algorithms/keyfactor/`)

A Go program illustrating the classical RSA key factorization attack — the reason RSA is considered vulnerable to a sufficiently powerful quantum computer running Shor's algorithm.

**What it demonstrates:**
- RSA key-pair generation
- Message encryption with the public key (sender)
- Decryption with the private key (receiver)
- Classical factorization of the modulus to recover the private key (attacker)

**Execution flow:**
```
Sender  ──[encrypt with public key]──► Ciphertext ──► Receiver (decrypts with private key)
                                            │
                                            └──► Attacker (factorizes N to derive private key)
```

**Prerequisites:** Go 1.21+

**Run:**
```bash
cd Cryptography/algorithms/keyfactor
go run .
```

Expected output:
```
Original message =  Hello
Receiver decrypted message =  Hello
Attacker decrypted message =  Hello
```

The attacker recovers the plaintext by factorizing the small RSA modulus used in the demo, showing that classical RSA is breakable given a factorable key — and by extension, why post-quantum algorithms are necessary.

---

## References

- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST PQC Standardization Project](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [.NET 10 ML-KEM Support](https://learn.microsoft.com/en-us/dotnet/core/whats-new/dotnet-10/runtime)
- [Shor's Algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
