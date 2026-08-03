# Gemini-Box — Cryptographic Signing Layer
> ed25519 signing for the Z-12 EVK Stack. Adds non-repudiation to deterministic `.evkp` artifacts.
## Role in the Z-12 Platform
| Component | Role |
|-----------|------|
| EVK | Deterministic identity/integrity verification + Kill Vector runtime enforcement |
| Gemini-Box (this repo) | ed25519 signing, non-repudiation, forensic triage analysis |
| Adversarial Compliance Matrix | Continuous runtime validation |
---
## Summary
Gemini-Box signs `.evkp` bundles (ed25519) and provides triage analysis primitives. It exposes CLI binaries to generate fixtures, sign bundles, and perform triage analysis for incident bundles.
---
## Security & Key Management (IMPORTANT)
- Do NOT commit private keys to source control.
- Development: generate an ed25519 keypair locally with the helper script:
  - `scripts/generate_ed25519_keys.sh` (creates keys in $HOME/.z12/keystore)
- Production: use a secure keystore (HashiCorp Vault, Cloud KMS, or HSM/PKCS#11). Provide integration hooks so the CLI can read keys from Vault or system keyring.
- Public keys may be distributed with artifacts for verification, but private keys must remain protected.
---
## Library API (example)
```rust
use gemini_box::{analyze_incident, TriageAnalysis};

let analysis = analyze_incident("test/incident_7f3a.evkp")?;
println!("{}", analysis.to_json()?);
```
TriageAnalysis fields include file_path, status_code, incident_type, confidence, severity, recommended_action, chain_of_custody_valid.
---
## CLI Usage (examples)
```bash
# Generate a keypair (dev)
scripts/generate_ed25519_keys.sh
# Create signed fixture
cargo run --release --bin gen_fixtures
# Verify signed bundle
cargo run --release --bin evk job.evk.zip
# Analyze a signed incident bundle
cargo run --release --bin analyze test/incident_7f3a.evkp
# Run tests
cargo test --release
```
---
## Integration with EVK & ACM
- Workflow:
  - Gemini-Box signs a deterministic `.evkp` bundle.
  - EVK verifies the bundle integrity and signatures.
  - ACM evaluates evidence and returns a verdict (PURA/VIGLA/POLUITA).
- For E2E demos, make sure EVK and ACM are configured to find the Gemini public key (via a keystore path or environment variable).
---
## Container & CI notes
- Provide a Dockerfile for building and using Gemini-Box in the demo environment.
- CI should run:
  - cargo fmt/clippy/tests
  - sign/verify integration tests (use test keys stored in CI secrets or generated temporarily)
- Release workflow: build/push container images to GHCR on tags.
---
## Status codes reference (short)
| Code | Incident | Severity | Action |
|------|---------:|---------:|-------:|
| 0x0000 | Clean | LOW | allow |
| 0x0F2E | Handoff Conflict | HIGH | block |
| ... | ... | ... | ... |
(Full table in docs/status-codes.md if present.)
---
## Release & distribution
- Build signed artifacts and Docker images.
- Use tag-based releases (vX.Y.Z) to trigger image builds and signed artifact publishing.
---
## Honesty notes
- Gemini-Box provides signing and triage capabilities. For production, integrate a secure keystore and run sign/verify workflows in CI and release pipelines.
MIT Licensed (see LICENSE).
