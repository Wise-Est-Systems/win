# W.I.N
**Wise Independent Network**

WIN packets make files **self-verifying**.

If even one byte changes, verification fails.

---

## Quick Start

Create a WIN packet

winstack win contract.pdf

This produces

contract.pdf.win.zip

Verify anywhere

winstack verify contract.pdf.win.zip

Output

VERIFIED
or
TAMPERED

---

## Core Invariant

artifact → hash(bytes) → proof → verification

If the bytes change, verification fails.

---

## What W.I.N Is

W.I.N (Wise Independent Network) is a minimal protocol for portable artifact verification.

It allows any digital file to carry its own proof of integrity.

A WIN packet contains:

artifact bytes  
proof record  
manifest

---

## Why This Exists

The internet currently has no universal way to prove a file hasn't been modified.

W.I.N provides a simple portable verification protocol.

---

## Repository Structure

src/        reference implementation  
spec/       protocol specification  
examples/   demonstration artifacts  
tests/      verification tests  

---

## License

MIT
