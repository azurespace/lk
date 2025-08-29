Userspace Syscalls (AArch64)

Overview
- Exposes a minimal syscall ABI to EL0: `SYS_exit`, `SYS_write`, `SYS_yield`, `SYS_log`, `SYS_ticks`.
- See `kernel/include/kernel/syscalls.h` for numbers. Handler lives in `kernel/syscall/syscall.c`.

Usage from EL0
- Include `lib/uapi/lk_uapi.h` in userspace code.
- Call wrappers (AArch64 `svc #0`):
  - `sys_write(fd, buf, len)`: write bytes to console (fd=1 or 2).
  - `sys_log(buf, len)`: write bytes to kernel log (no fd).
  - `sys_ticks()`: query high‑resolution time (lk_bigtime_t).
  - `sys_yield()`, `sys_exit(code)`.
- Optional `u_printf` is provided if a `vsnprintf` is available in the EL0 image; it formats then calls `sys_write`.

Kernel‑side behavior
- `SYS_write`/`SYS_log` copy user buffers page‑safely via `arch_mmu_query` + `paddr_to_kvaddr` (no kernel address exposure).
- EL0 page faults are handled in `arch/arm64/exceptions_c.c`: user faults terminate only the current thread (`thread_exit(ERR_FAULT)`).

Notes
- Keep kernel memory unmapped in EL0; access kernel services via syscalls only.
- Extend the syscall set narrowly to what modules need (principle of least privilege).

