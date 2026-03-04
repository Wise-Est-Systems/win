# WIN Packet (Winstack) — v0.3.0

**Goal:** Make files self-verifying.

## Two commands

### 1) Create a WIN packet

```bash
winstack win myfile.pdf
```

Outputs a single portable packet:

- `myfile.pdf.win.zip`

### 2) Verify a WIN packet (anywhere)

```bash
winstack verify myfile.pdf.win.zip
```

Outputs:

- `VERIFIED` or `TAMPERED`

## What a WIN packet contains (implementation detail)

A `.win.zip` includes:
- the artifact (exact bytes)
- a proof JSON (WIN-CORE-0.2)
- `manifest.json` (WIN-PACKET-0.1)

## Invariant

If the bytes change, verification fails.
