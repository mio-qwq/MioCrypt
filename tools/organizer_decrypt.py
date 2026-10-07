#!/usr/bin/env python3
"""Organizer-only reference decryptor. This script requires the private key."""

from __future__ import annotations

import argparse
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


MAGIC = b"MIOCRYPT"
RSA_CIPHERTEXT_SIZE = 256


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encrypted_flag", type=Path)
    organizer_dir = Path(__file__).resolve().parents[1] / "local" / "organizer"
    parser.add_argument("--private-key", type=Path, default=organizer_dir / "miocrypt_private_key.pem")
    parser.add_argument("--output", type=Path, default=organizer_dir / "decrypted_flag.txt")
    args = parser.parse_args()

    encrypted = args.encrypted_flag.read_bytes()
    if not encrypted.startswith(MAGIC):
        raise SystemExit("Not a MioCrypt-encrypted flag.")
    wrapped_key = encrypted[len(MAGIC):len(MAGIC) + RSA_CIPHERTEXT_SIZE]
    ciphertext = encrypted[len(MAGIC) + RSA_CIPHERTEXT_SIZE:]
    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    session_key = private_key.decrypt(wrapped_key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    plaintext = bytes(value ^ session_key[index % len(session_key)] for index, value in enumerate(ciphertext))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(plaintext)
    print(f"Wrote {args.output}")


if __name__ == "__main__":
    main()
