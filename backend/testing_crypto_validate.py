"""Run solely against CipherSetu's bundled fixture and generated replacement."""
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

from cryptography.hazmat.primitives.asymmetric import rsa

HYBRID_SUITE = "HPKE-MLKEM768-X25519-HKDFSHA256-AES256GCM"


def command(cli, *args):
    return subprocess.run(
        [str(cli), *map(str, args)],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True, timeout=25,
    ).stdout


def validate(cli, root):
    old_writer = runpy.run_path(str(root / "original.py"))["wrap_data_key"]
    patched = runpy.run_path(str(root / "patched.py"))
    write_key, read_key = patched["wrap_data_key"], patched["unwrap_data_key"]
    keys = root / "generated"
    command(cli, "keygen", "--dir", keys)
    hybrid_private = keys / "private.json"
    hybrid_public = keys / "public.json"
    legacy_private = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    # Fresh synthetic keys and wrapped records remain in this temporary directory.
    data_key = os.urandom(32)
    legacy_file = root / "legacy.wrapped"
    legacy_file.write_bytes(old_writer(legacy_private.public_key(), data_key))
    hybrid_file = root / "hybrid.wrapped"
    hybrid_file.write_bytes(write_key(hybrid_public, data_key, cli=cli))
    wrapped = hybrid_file.read_bytes()
    prefix = patched["HYBRID_PREFIX"]
    assert wrapped.startswith(prefix)
    payload = wrapped[len(prefix):]
    assert json.loads(payload)["suite"] == HYBRID_SUITE
    options = dict(cli=cli, hybrid_private_key=hybrid_private, legacy_private_key=legacy_private)
    assert read_key(legacy_file.read_bytes(), **options) == data_key
    assert read_key(wrapped, **options) == data_key
    envelope = json.loads(payload)
    envelope["ciphertext"] = ("A" if envelope["ciphertext"][0] != "A" else "B") + envelope["ciphertext"][1:]
    try:
        read_key(prefix + json.dumps(envelope).encode(), **options)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("tampered hybrid ciphertext was accepted")


if __name__ == "__main__":
    validate(Path(sys.argv[1]), Path(sys.argv[2]))
