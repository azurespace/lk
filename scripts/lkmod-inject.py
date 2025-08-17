#!/usr/bin/env python3
"""
Inject a binary blob (module .so) into a running QEMU guest via gdbstub.

Usage:
  ./scripts/lkmod-inject.py --file mods/hello_cpp/hello_cpp.so --addr 0x44000000 [--port 1234] [--gdb aarch64-elf-gdb]

Requires QEMU started with: scripts/run-lk-aarch64.sh --gdb [PORT]
"""
import argparse
import os
import shutil
import subprocess
import sys

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', required=True, help='Path to binary to inject')
    ap.add_argument('--addr', required=True, help='Hex or decimal guest address (e.g., 0x44000000)')
    ap.add_argument('--port', type=int, default=1234, help='QEMU gdb port (default 1234)')
    ap.add_argument('--gdb', default=None, help='gdb executable (default: aarch64-elf-gdb or gdb-multiarch)')
    args = ap.parse_args()

    path = os.path.abspath(args.file)
    if not os.path.exists(path):
        print(f"File not found: {path}", file=sys.stderr)
        return 2

    try:
        addr = int(args.addr, 0)
    except Exception:
        print(f"Invalid addr: {args.addr}", file=sys.stderr)
        return 2

    gdb = args.gdb
    if not gdb:
        gdb = shutil.which('aarch64-elf-gdb') or shutil.which('gdb-multiarch') or shutil.which('gdb')
    if not gdb:
        print("Could not find gdb. Install a cross gdb (aarch64-elf-gdb) or gdb-multiarch.", file=sys.stderr)
        return 2

    # Create a small gdb script
    gdb_cmds = f"""
set confirm off
target remote :{args.port}
restore {path} binary 0x{addr:x}
detach
quit
"""
    # Run gdb non-interactively
    print(f"Injecting {path} at 0x{addr:x} via {gdb} :{args.port}")
    p = subprocess.run([gdb, '-nx', '-batch', '-ex', f'target remote :{args.port}', '-ex', f'restore {path} binary 0x{addr:x}', '-ex', 'detach', '-ex', 'quit'])
    if p.returncode != 0:
        print(f"gdb failed with code {p.returncode}", file=sys.stderr)
        return p.returncode
    size = os.path.getsize(path)
    print(f"Injected {size} bytes. In guest shell, run: mod loadat 0x{addr:x} {size}")
    return 0

if __name__ == '__main__':
    sys.exit(main())
