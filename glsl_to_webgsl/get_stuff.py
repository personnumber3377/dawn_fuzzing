#!/usr/bin/env python3

import subprocess
import sys
import os
import re
from pathlib import Path

def run_fuzzer(fuzzer_path, input_file, output_dir):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [fuzzer_path, input_file],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        errors="replace",
    )

    stderr = proc.stderr.read()
    proc.wait()

    # Split on lines containing =====
    # This assumes blocks are wrapped like:
    # =====
    # <translated code>
    # =====
    blocks = re.split(r"=+\n", stderr)

    extracted = []
    for block in blocks:
        block = block.strip()
        if not block:
            continue

        # Heuristic: skip ANGLE error banners, keep code-like content
        if "ANGLE COMPILE FAILED" in block:
            continue

        extracted.append(block)

    if not extracted:
        return False

    base_name = Path(input_file).stem
    for i, content in enumerate(extracted):
        out_file = output_dir / f"{base_name}_translated_{i}.wgsl"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(content)

    return True


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <angle_translator_fuzzer> <input_file> <output_dir>")
        sys.exit(1)

    fuzzer = sys.argv[1]
    input_file = sys.argv[2]
    output_dir = sys.argv[3]

    success = run_fuzzer(fuzzer, input_file, output_dir)
    if success:
        print(f"[+] Extracted translation(s) from {input_file}")
    else:
        print(f"[-] No translation found in {input_file}")