"""Write the chosen test flag as exact ASCII bytes, without a trailing newline."""

import argparse
from pathlib import Path


FLAG = b"PKWCTF{z4ko_z4ko_p4y_MioCh4n_1_KFC}"


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=root / "local" / "challenge" / "flag")
    destination = parser.parse_args().output
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(FLAG)
    print(f"Wrote {len(FLAG)} bytes to {destination}")


if __name__ == "__main__":
    main()
