# Ghost Matrix (containment concept)

> **Status: CONCEPT / DOCUMENTATION ONLY.** No Ghost Matrix runtime service is
> implemented in this repository today. This document records the intended design
> so the concept is preserved as the platform evolves. Nothing here should be read
> as a shipped or tested capability.

## Purpose

Ghost Matrix is the **controlled-isolation** concept of the Z-12 platform. Where
Gemini-Box establishes a hardened, signed execution boundary, Ghost Matrix is the
place a suspicious workload is *observed* rather than trusted: a sandboxed, read-only
mirror of the runtime where behavior can be evaluated without granting it authority
over real resources.

## Responsibilities (intended)

- **Controlled isolation** — run a workload in a boundary with no write access to
  production state.
- **Runtime observation** — record syscalls / decisions for later analysis.
- **Incident analysis** — provide a safe environment to replay a captured incident.
- **Safe execution boundaries** — fail-closed: if isolation cannot be guaranteed,
  the workload does not run.

## Relationship to the rest of Z-12

```text
EVK verify ─▶ Gemini-Box sign/execute ─▶ (suspicious?) ─▶ Ghost Matrix (observe, isolate)
                                                             │
                                                             ▼
                                          ACM validation ─▶ ACM_DENY ─▶ EVK Kill Vector (terminate)
```

Ghost Matrix is the **observation/containment** step; the **enforcement** step
(process termination) lives in EVK's Kill Vector (`src/kill_vector`). Keeping the
two separate preserves the platform's layered-security principle: observation never
performs destructive action, and enforcement is only ever triggered by an explicit
ACM decision.

## Not implemented

- No sandbox/namespace/VM isolation backend is wired.
- No live syscall capture.
- No replay engine.

These are deliberately listed so the gap is explicit rather than implied.
