#!/usr/bin/env python3
"""Write the EICAR test file — the industry-standard, HARMLESS antivirus test
string. Every real AV (including ClamAV) flags it as a virus, but it does
nothing. Use it to verify the scanner detects + quarantines correctly.

Usage:  python tests/make_eicar.py [dest_dir]
"""

import os
import sys

# Split so this source file itself isn't flagged by scanners.
EICAR = (r"X5O!P%@AP[4\PZX54(P^)7CC)7}"
         + "$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*")


def main() -> int:
    dest = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(dest, exist_ok=True)
    path = os.path.join(dest, "eicar_test.com")
    with open(path, "w", encoding="ascii") as fh:
        fh.write(EICAR)
    print(f"Wrote harmless EICAR test file: {path}")
    print("Scan its folder to confirm detection, e.g.:")
    print(f'  python cli.py scan "{os.path.abspath(dest)}" --no-quarantine')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
