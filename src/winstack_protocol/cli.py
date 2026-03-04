from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .core import pack as _pack, verify_packet as _verify_packet


def _p(s: str) -> None:
    sys.stdout.write(s + "\n")


def _e(s: str) -> None:
    sys.stderr.write(s + "\n")


def cmd_win(args: argparse.Namespace) -> int:
    artifact = Path(args.file)
    if not artifact.exists():
        _e(f"ERROR: file not found: {artifact}")
        return 2
    out = Path(args.out) if args.out else Path(str(artifact) + ".win.zip")
    _pack(artifact, out, alg=args.alg, media_type=args.media_type, issuer=args.issuer)
    _p(str(out))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    pkt = Path(args.packet)
    if not pkt.exists():
        _e(f"ERROR: packet not found: {pkt}")
        return 2
    ok = _verify_packet(pkt)
    _p("VERIFIED" if ok else "TAMPERED")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="winstack",
        description="Winstack WIN packets: one-command proof, one-command verify.",
    )
    p.add_argument("--version", action="version", version="winstack-protocol 0.3.0 (WIN)")

    sub = p.add_subparsers(dest="cmd", required=True)

    p_win = sub.add_parser("win", help="Create a WIN packet: <file>.win.zip")
    p_win.add_argument("file")
    p_win.add_argument("--out", help="Output packet path (default: <file>.win.zip)")
    p_win.add_argument("--alg", default="sha256", choices=["sha256", "sha512", "blake3"])
    p_win.add_argument("--media-type", help="Optional MIME-like string (informational)")
    p_win.add_argument("--issuer", help="Optional issuer label (informational)")
    p_win.set_defaults(func=cmd_win)

    p_v = sub.add_parser("verify", help="Verify a WIN packet (.win.zip)")
    p_v.add_argument("packet")
    p_v.set_defaults(func=cmd_verify)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
