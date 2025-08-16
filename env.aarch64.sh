#!/usr/bin/env bash
# Helper to set PATH for aarch64-elf toolchain and provide a QEMU runner.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}" )" && pwd)"

# Prefer the x86_64 toolchain (works via Rosetta on Apple Silicon).
# The arm64 toolchain currently depends on /opt/local/lib/libzstd.1.dylib.
TC_X64_BIN_DIR=$(ls -d "${ROOT_DIR}"/toolchain/aarch64-elf-*-Darwin-x86_64/bin 2>/dev/null | tail -n 1 || true)
TC_ARM64_BIN_DIR=$(ls -d "${ROOT_DIR}"/toolchain/aarch64-elf-*-Darwin-arm64/bin 2>/dev/null | tail -n 1 || true)

if [[ -n "${TC_X64_BIN_DIR}" && -d "${TC_X64_BIN_DIR}" ]]; then
  export PATH="${TC_X64_BIN_DIR}:$PATH"
elif [[ -n "${TC_ARM64_BIN_DIR}" && -d "${TC_ARM64_BIN_DIR}" ]]; then
  export PATH="${TC_ARM64_BIN_DIR}:$PATH"
else
  echo "No aarch64-elf toolchain found under ${ROOT_DIR}/toolchain" >&2
  echo "Run: python3.11 scripts/fetch-toolchains.py --prefix aarch64-elf" >&2
  return 1 2>/dev/null || exit 1
fi

echo "aarch64-elf-gcc: $(command -v aarch64-elf-gcc)"

# Convenience function to run QEMU with the built LK image.
run-qemu-arm64() {
  local elf="${ROOT_DIR}/build-qemu-virt-arm64-test/lk.elf"
  if [[ ! -f "${elf}" ]]; then
    echo "${elf} not found; build first: make qemu-virt-arm64-test" >&2
    return 1
  fi
  exec qemu-system-aarch64 -cpu cortex-a53 -machine virt -m 512 -smp 1 -nographic -kernel "${elf}" "$@"
}

echo "Use: source ./env.aarch64.sh; make qemu-virt-arm64-test; run-qemu-arm64"

