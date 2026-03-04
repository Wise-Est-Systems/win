from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Literal, Optional, Sequence
import zipfile


Alg = Literal["sha256", "sha512", "blake3"]


def fingerprint_file(path: Path, alg: Alg = "sha256", chunk_size: int = 1024 * 1024) -> str:
    """
    Deterministic fingerprint of EXACT FILE BYTES ONLY (no metadata).
    Streaming read for large artifacts.
    """
    h: Any
    if alg == "sha256":
        h = hashlib.sha256()
    elif alg == "sha512":
        h = hashlib.sha512()
    elif alg == "blake3":
        try:
            import blake3  # type: ignore
        except Exception as e:
            raise RuntimeError("blake3 selected but 'blake3' package is not installed. Install with: pip install blake3") from e
        h = blake3.blake3()
    else:
        raise ValueError(f"Unsupported algorithm: {alg}")

    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class AFPProof:
    """
    AFP-0.2 proof record (portable, minimal).
    Required fields:
      - spec: "WIN-CORE-0.2"
      - artifact_hash: hex digest of HASH(bytes)
      - algorithm: hash algorithm
      - artifact_name: original basename (informational)
    Recommended:
      - created_at: ISO8601 UTC (informational)
      - bytes: file size (informational)
      - media_type: MIME-like string (informational)
      - issuer: freeform string (informational; identity requires signatures, out of scope for AFP core)
    """
    spec: str
    artifact_hash: str
    algorithm: Alg
    artifact_name: str
    created_at: str
    bytes: int
    media_type: Optional[str] = None
    issuer: Optional[str] = None

    @staticmethod
    def create(artifact_path: Path, alg: Alg = "sha256", media_type: Optional[str] = None, issuer: Optional[str] = None) -> "AFPProof":
        fp = fingerprint_file(artifact_path, alg=alg)
        size = artifact_path.stat().st_size
        return AFPProof(
            spec="WIN-CORE-0.2",
            artifact_hash=fp,
            algorithm=alg,
            artifact_name=artifact_path.name,
            created_at=utc_now_iso(),
            bytes=size,
            media_type=media_type,
            issuer=issuer,
        )

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "spec": self.spec,
            "artifact_hash": self.artifact_hash,
            "algorithm": self.algorithm,
            "artifact_name": self.artifact_name,
            "created_at": self.created_at,
            "bytes": self.bytes,
        }
        if self.media_type:
            d["media_type"] = self.media_type
        if self.issuer:
            d["issuer"] = self.issuer
        return d

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AFPProof":
        return AFPProof(
            spec=str(d.get("spec", "")),
            artifact_hash=str(d["artifact_hash"]),
            algorithm=str(d["algorithm"]),  # type: ignore
            artifact_name=str(d.get("artifact_name", "")),
            created_at=str(d.get("created_at", "")),
            bytes=int(d.get("bytes", 0)),
            media_type=d.get("media_type"),
            issuer=d.get("issuer"),
        )


def write_json(obj: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def verify(artifact_path: Path, proof: AFPProof) -> bool:
    """
    Integrity verification: recompute hash and compare.
    """
    current = fingerprint_file(artifact_path, alg=proof.algorithm)
    return current == proof.artifact_hash


@dataclass(frozen=True)
class AFPPacketManifest:
    """
    AFP Packet Manifest (AFP-PACKET-0.1)
    Required:
      - spec
      - packet_id (recommended: same as artifact_hash)
      - proof_path
      - artifact_path
    """
    spec: str
    packet_id: str
    proof_path: str
    artifact_path: str
    created_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec": self.spec,
            "packet_id": self.packet_id,
            "proof_path": self.proof_path,
            "artifact_path": self.artifact_path,
            "created_at": self.created_at,
        }

    @staticmethod
    def create(packet_id: str, proof_path: str, artifact_path: str) -> "AFPPacketManifest":
        return AFPPacketManifest(
            spec="WIN-PACKET-0.1",
            packet_id=packet_id,
            proof_path=proof_path,
            artifact_path=artifact_path,
            created_at=utc_now_iso(),
        )

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "AFPPacketManifest":
        return AFPPacketManifest(
            spec=str(d.get("spec", "")),
            packet_id=str(d.get("packet_id", "")),
            proof_path=str(d.get("proof_path", "")),
            artifact_path=str(d.get("artifact_path", "")),
            created_at=str(d.get("created_at", "")),
        )


def pack(artifact_path: Path, out_zip: Path, alg: Alg = "sha256", media_type: Optional[str] = None, issuer: Optional[str] = None) -> Path:
    """
    Create a single portable .win.zip containing:
      - artifact (exact bytes)
      - proof.json
      - manifest.json
    """
    proof = AFPProof.create(artifact_path, alg=alg, media_type=media_type, issuer=issuer)
    proof_name = artifact_path.name + ".proof.json"
    manifest_name = "manifest.json"

    manifest = AFPPacketManifest.create(
        packet_id=proof.artifact_hash,
        proof_path=proof_name,
        artifact_path=artifact_path.name,
    )

    # write temp json in memory then zip
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.write(artifact_path, arcname=artifact_path.name)
        z.writestr(proof_name, json.dumps(proof.to_dict(), indent=2, sort_keys=True) + "\n")
        z.writestr(manifest_name, json.dumps(manifest.to_dict(), indent=2, sort_keys=True) + "\n")

    return out_zip


def verify_packet(packet_zip: Path) -> bool:
    """
    Verify an AFP packet without extracting to disk:
      - read manifest
      - read proof
      - hash artifact bytes inside zip
      - compare
    """
    with zipfile.ZipFile(packet_zip, "r") as z:
        manifest = AFPPacketManifest.from_dict(json.loads(z.read("manifest.json").decode("utf-8")))
        proof = AFPProof.from_dict(json.loads(z.read(manifest.proof_path).decode("utf-8")))

        # fingerprint bytes stream from zip
        # Use the same hashing logic as fingerprint_file but against bytes stream
        alg = proof.algorithm
        if alg == "sha256":
            h = hashlib.sha256()
        elif alg == "sha512":
            h = hashlib.sha512()
        elif alg == "blake3":
            try:
                import blake3  # type: ignore
            except Exception as e:
                raise RuntimeError("blake3 selected but 'blake3' package is not installed. Install with: pip install blake3") from e
            h = blake3.blake3()
        else:
            raise ValueError(f"Unsupported algorithm: {alg}")

        with z.open(manifest.artifact_path, "r") as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)

        return h.hexdigest() == proof.artifact_hash
