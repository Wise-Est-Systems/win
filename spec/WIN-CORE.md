# WIN — W.I.N Proof Protocol (Core)

**Status:** Draft (WIN-0.2)  
**Goal:** A smallest-possible, universal, deterministic integrity invariant for ANY digital artifact.

## Core invariant (protocol-level)

> If an artifact’s bytes change, verification MUST fail.

Formally:

- `H(bytes_now) == artifact_hash` → VERIFIED  
- `H(bytes_now) != artifact_hash` → TAMPERED

## Core rule

> An artifact is identified by a deterministic fingerprint of its exact bytes.

`artifact_hash = H(artifact_bytes)`

Where `H` is one of the allowed algorithms.

## Allowed algorithms

- `sha256` (default, REQUIRED)
- `sha512` (optional)
- `blake3` (optional)

Implementations MUST be deterministic and MUST hash raw bytes only (no metadata).

## Proof record (WIN-0.2)

A proof record is JSON with the following fields.

### Required
- `spec`: `"WIN-0.2"`
- `artifact_hash`: hex digest string
- `algorithm`: one of `sha256 | sha512 | blake3`
- `artifact_name`: basename string (informational)

### Recommended (informational only)
- `created_at`: ISO-8601 UTC
- `bytes`: integer file size
- `media_type`: string (e.g., `image/png`)
- `issuer`: freeform label (identity is OUT OF SCOPE for WIN Core)

## Verification procedure

1. Read artifact bytes.
2. Compute `H(bytes)` using `algorithm`.
3. Compare to `artifact_hash`.
4. Output binary result: VERIFIED / TAMPERED.

## What WIN Core does NOT solve (by design)

WIN Core does **not** prove identity, authorship, or intent.

Those require signatures + key management. WIN Core is the integrity layer that other systems can stack on.
