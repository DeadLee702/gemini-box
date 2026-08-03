# Gemini-Box — Cryptographic Signing Layer

> ed25519 signing for the Z-12 EVK Stack. Adds non-repudiation to deterministic `.evkp` artifacts.

## Role in the Z-12 Platform

| Component | Role |
|-----------|------|
| **EVK** | Deterministic identity/integrity verification + Kill Vector runtime enforcement |
| **Gemini-Box** (this repo) | ed25519 signing, non-repudiation, forensic (E01) analysis |
| **Adversarial Compliance Matrix** | Continuous runtime validation, compliance engine |

## Architecture

```
EVK .evkp bundle → Gemini-Box signs (ed25519) → ACM evaluates compliance
```

## Library API

```rust
use gemini_box::{analyze_incident, TriageAnalysis};

let analysis = analyze_incident("test/incident_7f3a.evkp")?;
println!("{}", analysis.to_json()?);
```

### TriageAnalysis Fields
- `file_path`: Source file
- `status_code`: Hex status code (e.g. "0x0F2E")
- `incident_type`: Classification (e.g. "Handoff Conflict")
- `confidence`: Detection confidence (0.0-1.0)
- `severity`: LOW / MEDIUM / HIGH / CRITICAL
- `recommended_action`: allow / block / quarantine / escalate
- `chain_of_custody_valid`: bool

## CLI Usage

```bash
cargo run --release --bin gen_fixtures    # generate keypair + signed bundle
cargo run --release --bin evk job.evk.zip # verify ed25519 signature
cargo run --release --bin analyze test/incident_7f3a.evkp  # triage analysis (JSON)
cargo test --release                      # 25 tests
```

## Status Code Reference

| Code | Incident | Severity | Action |
|------|----------|----------|--------|
| 0x0000 | Clean | LOW | allow |
| 0x0F2E | Handoff Conflict | HIGH | block |
| 0x0E1A | Race Condition | HIGH | quarantine |
| 0x0D44 | Orphaned Step | MEDIUM | escalate |
| 0x1A4F | Transaction Replay | CRITICAL | block |
| 0x1B88 | Schema Mutation | MEDIUM | quarantine |
| 0x1C2B | Log Truncation | CRITICAL | escalate |
| 0x2A90 | Packet Modification | HIGH | block |
| 0x2B11 | Timestamp Drift | MEDIUM | escalate |
| 0x2C7F | API Spoofing | CRITICAL | block |
| 0x3A01 | Prompt Injection | HIGH | quarantine |
| 0x3B99 | Entropy Leakage | CRITICAL | escalate |
| 0x3C4D | Register Forgery | CRITICAL | block |

MIT Licensed. Part of the Z-12 platform.

---

## Production Readiness

Gemini-Box is part of the containerized Z-12 platform. It builds and runs inside the
Docker Compose demo alongside EVK and ACM, with ed25519 key management isolated from
the repository.

### Containerized demo

Gemini-Box runs as a service in the EVK `docker-compose.yml`:

```yaml
gemini:
  image: ${DOCKER_REGISTRY}/${DOCKER_NAMESPACE}/gemini-box:latest
  environment:
    - GEMINI_KEY_PATH=/opt/keystore/gemini_ed25519
  volumes:
    - ./keystore:/opt/keystore
```

### Key management

```bash
# From the EVK repo:
./scripts/generate_ed25519_keys.sh    # generates ed25519 keypair in $HOME/.z12/keystore
```

Keys are never stored in the repository. For production, use HashiCorp Vault, a cloud
KMS, or an HSM (PKCS#11). The `.gitignore` in each repo excludes `.env`, private keys,
and the keystore directory.

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GEMINI_KEY_PATH` | `$HOME/.z12/keystore/gemini_ed25519` | ed25519 private key file |
| `GEMINI_PUB_PATH` | `$HOME/.z12/keystore/gemini_ed25519.pub` | ed25519 public key file |
| `DOCKER_REGISTRY` | `ghcr.io` | Container registry for releases |
| `DOCKER_NAMESPACE` | `your-org-or-user` | Registry namespace |

### CI & releases

- Tagged releases (`v1.0.0`) trigger container image builds published to GHCR.
- CI runs `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit`, and
  `cargo test` on every push and pull request.
- Container scanning with Trivy (`trivy image --severity HIGH,CRITICAL`).

### Production checklist

1. **Key management** — external keystore (Vault/HSM/KMS); never commit keys.
2. **CI** — fmt, clippy, audit, unit + integration tests in containers.
3. **Releases** — signed container images via GHCR on tagged releases.
4. **Security review** — third-party audit required before production deployment.
