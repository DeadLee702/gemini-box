# gemini-box - Cryptographic Signing Layer

ed25519 signing for EVK Stack evidence bundles. Adds non-repudiation to deterministic `.evkp` artifacts.

## Core Function
1. **Sign**: Generate ed25519 keypair, sign bundle hash
2. **Verify**: Verify signature against public key 
3. **Fail-closed**: INVALID if signature missing/tampered

## Usage
```bash
cargo test --test signing -- tests/fixtures/sample.evkp
```

## EVK Stack Integration
`evk` → bundles → `gemini-box` → signs → `adversarial-compliance-matrix` → tests

## Role in the Z-12 platform

Gemini-Box is the **hardened execution / signing** layer of the Z-12 Sovereign
Security Platform. Each layer owns one responsibility:

| Component | Role |
|-----------|------|
| **[EVK](https://github.com/DeadLee702/evk)** | Deterministic identity/integrity verification **+ Kill Vector runtime enforcement** |
| **Gemini-Box** (this repo) | Hardened execution environment: ed25519 signing, non-repudiation, forensic (E01) analysis, **Ghost Matrix** containment |
| **[Adversarial Compliance Matrix](https://github.com/DeadLee702/adversarial-compliance-matrix)** | Continuous runtime validation |

Ed25519 signing here provides **non-repudiation** on top of EVK's deterministic
`.evkp` hashes. Note: signing is not yet fused into EVK's own `verify` path — it
remains a separate, composable layer. See [`docs/GHOST_MATRIX.md`](docs/GHOST_MATRIX.md)
for the containment concept.

MIT Licensed. Part of the Z-12 platform (EVK Stack).