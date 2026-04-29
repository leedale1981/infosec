# RSA Key Factorization Demo

> A Go program that demonstrates RSA encryption/decryption and then simulates a classical factorization attack against a small RSA key — illustrating why RSA is theoretically vulnerable to quantum computers running Shor's algorithm, and why the migration to post-quantum algorithms matters.

---

## What it demonstrates

The program models three actors communicating over a network:

| Actor | Role |
|-------|------|
| **Sender** | Encrypts a plaintext message using the RSA public key |
| **Receiver** | Decrypts the ciphertext using the RSA private key |
| **Attacker** | Intercepts the ciphertext and factorizes the public key modulus `N` to derive the private key, then decrypts |

```
Sender  ──[encrypt with public key]──► Ciphertext ──► Receiver (decrypts with d)
                                            │
                                            └──► Attacker
                                                    │  factorize N = p × q
                                                    │  recover d from e, p, q
                                                    └──► decrypts successfully
```

With a small RSA modulus (as used here for demonstration), trial division or Pollard's rho can factor `N` in milliseconds. On a quantum computer, Shor's algorithm would factor cryptographically large keys (2048-bit, 4096-bit) in polynomial time, rendering classical RSA insecure.

---

## Project Structure

```
keyfactor/
├── main.go                   — Entry point: orchestrates sender, receiver, attacker
├── crypto/
│   └── rsa.go                — RSA key generation, encrypt, decrypt
├── components/
│   ├── sender.go             — Encrypts a message with the public key
│   ├── receiver.go           — Decrypts ciphertext with the private key
│   └── attacker.go           — Factorizes the modulus and recovers the private key
└── crackers/
    └── rsa_cracker.go        — Factorization algorithm implementation
```

---

## Prerequisites

- [Go 1.21+](https://go.dev/dl/)

---

## Run

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

All three strings match — the attacker successfully recovered the plaintext by factorizing the modulus, without ever having access to the private key.

---

## Build a binary

```bash
go build -o keyfactor .
./keyfactor
```

---

## Key concepts

- **RSA security assumption:** factoring `N = p × q` is computationally hard for large primes — this demo uses small primes to make the attack instant.
- **Shor's algorithm:** a quantum algorithm that factors integers in polynomial time (`O((log N)³)`), breaking RSA for any key size a quantum computer can address.
- **Post-quantum alternative:** ML-KEM (Kyber) and ML-DSA (Dilithium) — NIST-standardised algorithms based on lattice problems that are not known to be solvable efficiently by quantum computers.

---

## References

- [RSA cryptosystem](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
- [Shor's algorithm](https://en.wikipedia.org/wiki/Shor%27s_algorithm)
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
