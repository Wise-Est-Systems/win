from pathlib import Path
from winstack_protocol.core import AFPProof, verify, pack, verify_packet

def test_proof_verify(tmp_path: Path):
    p = tmp_path / "a.txt"
    p.write_text("hello", encoding="utf-8")
    proof = AFPProof.create(p)
    assert verify(p, proof) is True
    p.write_text("hello!", encoding="utf-8")
    assert verify(p, proof) is False

def test_packet_verify(tmp_path: Path):
    p = tmp_path / "b.txt"
    p.write_text("hello", encoding="utf-8")
    pkt = tmp_path / "b.txt.win.zip"
    pack(p, pkt)
    assert verify_packet(pkt) is True
    # mutate by rewriting file then repack? Instead, verify_packet should detect if packet tampered,
    # so we'll tamper by editing the artifact inside the zip via rewriting a new zip with different artifact bytes.
    import zipfile, json
    from winstack_protocol.core import read_json
    tampered = tmp_path / "tampered.win.zip"
    with zipfile.ZipFile(pkt, "r") as z_in, zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as z_out:
        for info in z_in.infolist():
            data = z_in.read(info.filename)
            if info.filename == "b.txt":
                data = b"HELLO"  # change bytes
            z_out.writestr(info.filename, data)
    assert verify_packet(tampered) is False
