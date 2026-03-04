# WIN Packet (Portable Proof Packet)

**Status:** Draft (WIN-PACKET-0.1)  
**Goal:** Proof must travel with the artifact.

## Packet format

A packet is a `.win.zip` containing:

- `<artifact>` (original file bytes)
- `<artifact>.proof.json` (WIN-0.2 proof)
- `manifest.json` (WIN-PACKET-0.1 manifest)

## Manifest (WIN-PACKET-0.1)

### Required fields
- `spec`: `"WIN-PACKET-0.1"`
- `packet_id`: recommended to equal `artifact_hash`
- `proof_path`: path to proof JSON in zip
- `artifact_path`: path to artifact in zip
- `created_at`: ISO-8601 UTC

## Packet verification

- read `manifest.json`
- read proof JSON
- hash the artifact bytes inside the zip
- compare against `artifact_hash`
- output VERIFIED / TAMPERED
