#!/usr/bin/env python3
"""Package only the executable and encrypted flag, with optional debug symbols."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist-dir", type=Path, default=root / "dist")
    parser.add_argument("--output", type=Path, help="ZIP destination; defaults to DIST/MioCrypt-challenge.zip")
    parser.add_argument("--include-symbols", action="store_true", help="include MioCrypt.pdb")
    args = parser.parse_args()

    output = args.output if args.output is not None else args.dist_dir / "MioCrypt-challenge.zip"
    if output.suffix.lower() != ".zip":
        raise SystemExit("The output filename must end in .zip.")

    names = ["MioCrypt.exe", "flag"]
    if args.include_symbols:
        names.append("MioCrypt.pdb")
    for name in names:
        if not (args.dist_dir / name).is_file():
            raise SystemExit(f"Missing attachment: {args.dist_dir / name}")

    encrypted_flag = (args.dist_dir / "flag").read_bytes()
    if not encrypted_flag.startswith(b"MIOCRYPT") or len(encrypted_flag) <= 8 + 256:
        raise SystemExit("Refusing to package flag: expected MIOCRYPT header, RSA block, and XOR payload.")

    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name in names:
            archive.write(args.dist_dir / name, arcname=name)

    print(f"Wrote {output}")
    print(f"Contents: {', '.join(names)}")
    print(f"SHA256: {hashlib.sha256(output.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
