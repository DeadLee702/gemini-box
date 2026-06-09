# Gemini Box

A Rust project for ed25519 signature generation and verification with ZIP archiving.

## Features

- **ed25519-dalek** for asymmetric cryptography
- OS-backed entropy for key generation
- ZIP archive support for job.evk and signatures
- Compile-time public key inclusion via `include_str!`
- Strict forgery detection

## Usage

### Generate Fixtures

Generate ed25519 keys and create signed fixtures:

```bash
cargo run --bin gen_fixtures
```

This will:
1. Generate a new ed25519 signing key using OS entropy
2. Save the public key to `test/pubkey.hex`
3. Sign `job.evk` content
4. Create `job.evk.zip` containing `job.evk` and `job.evk.sig`

### Verify Signatures

Verify the signature and detect forgeries:

```bash
cargo run --bin evk
```

This will:
1. Load the public key from `test/pubkey.hex` (embedded at compile time)
2. Extract `job.evk` and `job.evk.sig` from the ZIP
3. Verify the signature
4. Return "INVALID FORGERY DETECTED" alert if verification fails

## Dependencies

- `ed25519-dalek` - Ed25519 signature scheme
- `rand_core` - OS-backed random number generation
- `hex` - Hex encoding/decoding
- `zip` - ZIP archive support

## Related Projects
This is part of a three-layer deterministic verification stack:
- **[evk](https://github.com/DeadLee702/evk)** (Bundle validation & determinism)
- **[gemini-box](https://github.com/DeadLee702/gemini-box)** ← You are here (Cryptographic signing & verification)
- **[adversarial-compliance-matrix](https://github.com/DeadLee702/adversarial-compliance-matrix)** (12 incident detection tests)
