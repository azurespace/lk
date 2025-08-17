# Repository Guidelines

## Project Structure & Module Organization
- `app/`: Sample apps and shell commands. `docs/`: developer docs. `scripts/`: tooling and runners.
- `kernel/`, `arch/arm64/`, `platform/qemu-virt-arm/`: core kernel, AArch64 port, and QEMU virt platform.
- `lib/`: reusable libraries; each module has a `rules.mk`. `external/`: third‑party.
- `project/*.mk`: build targets (use `qemu-virt-arm64-test.mk`). Output goes to `build-qemu-virt-arm64-test/`.
- Local overrides: copy `lk_inc.mk.example` to `lk_inc.mk` to set `DEFAULT_PROJECT`, `TOOLCHAIN_PREFIX`, etc.

## Build, Test, and Development Commands
- Env: `source ./env.aarch64.sh` (adds `aarch64-elf-*` toolchain to `PATH`).
- Or fetch toolchain: `scripts/fetch-toolchains.py --prefix aarch64-elf` then `export PATH=$PWD/toolchain/aarch64-elf-*/bin:$PATH`.
- Build: `make qemu-virt-arm64-test -j$(nproc)` (top‑level `makefile` → `engine.mk`).
- Run: `scripts/run-lk-aarch64.sh` (uses `build-qemu-virt-arm64-test/lk.elf`).
  Example manual run: `qemu-system-aarch64 -cpu cortex-a53 -machine virt -m 512 -nographic -kernel build-qemu-virt-arm64-test/lk.elf`.
- Clean: `make clean` (in build dir). Static analysis: `scripts/do-cppcheck qemu-virt-arm64-test`.

## Runtime Modules (AArch64)
- Build C++ module: `make -C mods/hello_cpp CXX=aarch64-elf-g++`
- Inject blob into RAM at a known address (when QEMU started with `--gdb`):
  - `scripts/run-lk-aarch64.sh --gdb` then in another shell: `scripts/lkmod-inject.py --file mods/hello_cpp/hello_cpp.so --addr 0x44000000`
- In the LK console:
  - `mod loadat 0x44000000 <size>` loads the module from memory
  - `mod call hello_add 7 5` calls an exported function
  - `mod unload` unloads the last module; `mod free` frees a scratch buffer
- Constraints: modules are ET_DYN PIC shared objects; no external kernel symbol imports — use the provided API table (log/printf/alloc/free/ticks). Ensure no active users before unloading.

### Built-in module at boot
- The build embeds `mods/hello_cpp/hello_cpp.so` into the kernel image and auto-loads it at boot (LK init hook at `APPS`).
- No extra steps if you have the cross toolchain; the build will `make -C mods/hello_cpp` and objcopy the blob.
- On boot you will see a log line like: `lkmod: builtin loaded module@0x...` and a test `hello_add(2,3) = 5`.

## Coding Style & Naming Conventions
- Formatting: `scripts/codestyle` (astyle) — 4‑space indents, no tabs, Java‑style braces, align `*` to name.
- Linting: `.clang-tidy` is configured; run clang‑tidy locally where available.
- Naming: files/dirs lowercase; functions `lower_snake_case`; macros `UPPER_SNAKE_CASE`; types/structs concise and descriptive.
- Modules: add code under an appropriate `lib/<module>/` or subsystem and include a `rules.mk` mirroring neighbors.

## Testing Guidelines
- QEMU smoke tests: `python3 scripts/unittest.py` (expects `build-qemu-virt-arm64-test/lk.elf`).
- Unit tests live in `lib/unittest/`; add sources and register in `all_tests.c` when applicable.
- Prefer fast QEMU runs for validation; include sample console logs in PRs for new features.

## Commit & Pull Request Guidelines
- Commits: imperative, scoped by area, e.g. `lib: uefi: fix …` or `[lib][uefi] Add …`. Keep subjects concise; include rationale and user impact in body.
- PRs: clear description, linked issues, reproduction/run instructions, and updated docs if behavior changes.
- CI: GitHub Actions builds multiple targets; keep CI green. Note: `wip/**` and docs‑only changes are skipped per workflows.

## Security & Configuration Tips
- Do not commit toolchains, build outputs, or secrets. Prefer local `lk_inc.mk` for configuration.
- Set `lk_inc.mk` for AArch64, e.g.: `DEFAULT_PROJECT=qemu-virt-arm64-test` and `TOOLCHAIN_PREFIX=aarch64-elf-`.
- Architecture‑specific code belongs under `arch/arm64/`; board specifics under `platform/qemu-virt-arm/` and `project/*.mk`.
