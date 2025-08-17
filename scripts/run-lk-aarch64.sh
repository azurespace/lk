#!/usr/bin/env bash

set -euo pipefail

# Resolve repo root (this script lives in repo_root/scripts)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

ELF="${ROOT_DIR}/build-qemu-virt-arm64-test/lk.elf"
MEM_MB=512
SMP=1
CPU="cortex-a53"
ACCEL="auto"  # auto|hvf|none
GDB=""        # empty or tcp::PORT; when set, start paused (-S)

usage() {
  cat <<EOF
Usage: $(basename "$0") [options] [-- extra-qemu-args]

Options:
  --elf PATH         Path to lk.elf (default: ${ELF})
  -m, --mem MB       Memory size in MB (default: ${MEM_MB})
  -s, --smp N        Number of CPUs (default: ${SMP})
  --hvf              Force HVF acceleration (macOS only)
  --no-accel         Disable acceleration (TCG)
  --gdb [PORT]       Start QEMU gdb server (default 1234) and pause at reset
  -h, --help         Show this help

Notes:
  - Exit QEMU with Ctrl-a x (nographic mode).
EOF
}

ARGS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --elf)       ELF="$2"; shift 2 ;;
    -m|--mem)    MEM_MB="$2"; shift 2 ;;
    -s|--smp)    SMP="$2"; shift 2 ;;
    --hvf)       ACCEL="hvf"; shift ;;
    --no-accel)  ACCEL="none"; shift ;;
    --gdb)       if [[ $# -ge 2 && $2 != -* ]]; then GDB="tcp::$2"; shift 2; else GDB="tcp::1234"; shift; fi ;;
    -h|--help)   usage; exit 0 ;;
    --)          shift; ARGS+=("$@"); break ;;
    *)           ARGS+=("$1"); shift ;;
  esac
done

if ! command -v qemu-system-aarch64 >/dev/null 2>&1; then
  echo "qemu-system-aarch64 not found. Install QEMU (e.g., brew install qemu)." >&2
  exit 1
fi

if [[ ! -f "${ELF}" ]]; then
  echo "Kernel ELF not found at: ${ELF}" >&2
  echo "Build it with: make qemu-virt-arm64-test" >&2
  exit 1
fi

MACHINE_STR="virt"
ACCEL_ARGS=()

# Acceleration selection
if [[ "${ACCEL}" == "auto" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]] && qemu-system-aarch64 -accel help 2>/dev/null | grep -qi '\bhvf\b'; then
    ACCEL="hvf"
  else
    ACCEL="none"
  fi
fi

if [[ "${ACCEL}" == "hvf" ]]; then
  ACCEL_ARGS=("-accel" "hvf")
  MACHINE_STR+=",gic_version=2"
fi

echo "Launching QEMU..."
echo "  ELF: ${ELF}"
echo "  CPU: ${CPU}  SMP: ${SMP}  MEM: ${MEM_MB}MB  ACCEL: ${ACCEL}"

exec qemu-system-aarch64 \
  -cpu "${CPU}" \
  -smp "${SMP}" \
  -m "${MEM_MB}" \
  -machine "${MACHINE_STR}" \
  ${ACCEL_ARGS[@]+"${ACCEL_ARGS[@]}"} \
  ${GDB:+-S -gdb ${GDB}} \
  -nographic \
  -kernel "${ELF}" \
  ${ARGS[@]+"${ARGS[@]}"}
