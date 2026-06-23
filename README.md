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

MIT Licensed. Part of EVK Stack.