# mini-trace

A minimal, strace-like **syscall tracer** for Linux (x86_64), built directly on
`ptrace(2)` - no wrapping or shelling out to `strace`.

```
Usage: mini-trace [options] <command> [args...]
  --filter <name1,name2,...>   only show listed syscalls
  --summary                    print a syscall count table instead of a trace
  -h, --help                   show help
```

This is an explicitly **learning** tool that demonstrates syscall
interception fundamentals. It is **not** a security boundary, sandbox, or
anti-debugging mechanism.

---

## Build & Run

Requires: a Linux x86_64 system with `gcc` and `make`. No exotic dependencies.

```sh
make                 # builds ./mini-trace
./mini-trace ls -la
```

If `make` fails on `sys/user.h` or `sys/ptrace.h`: you are building on a
non-Linux host. This project is Linux-only (see *Requirements* below).

To work on the project you may also want to regenerate the syscall table
against your exact kernel (see *Generated syscall table*).

### Example output: Full trace

```
$ ./mini-trace ls /etc/passwd
 12345: syscall  59 (execve)( "/usr/bin/ls", ["ls", "/etc/passwd"], ... )
 12345:           execve = 0 /* new program image loaded */
 12345: syscall 257 (openat)( -1, "/etc/ld.so.cache", 0x0 )
 12345:           openat = 3
 12345: syscall 257 (openat)( -1, "/lib/x86_64-linux-gnu/libselinux.so.1", 0x0 )
 12345:           openat = 3
 12345: syscall   9 (mmap)( 0x0, 8192, 0x3, 0x22, -1, 0x0 )
 12345:             mmap = 140241511731200
 12345: syscall   3 (close)( 3 )
 12345:           close = 0
 ...
 12345: +++ exited with 0 +++
```

(The `-1` fd in `openat` is `AT_FDCWD` = "relative to the process's current
working directory"; `/proc/<pid>/fd/-1` doesn't exist, so the decoder shows
the raw value.)

### Example output: Filter

```
$ ./mini-trace --filter open,openat,connect ls /etc
 12346: syscall 257 (openat)( -1, "/etc/ld.so.cache", 0x0 )
 12346:           openat = 3
 12346: syscall 257 (openat)( -1, "/etc/localtime", 0x0 )
 12346:           openat = 3
 ...
```

### Example output:  Summary

```
$ ./mini-trace --summary find /tmp -maxdepth 1 -type f
    calls    errors      pct syscall
-------- -------- -------- --------
       36        0    42.86% newfstatat
       22        0    26.19% getdents64
       14        0    16.67% mmap
        5        0     5.95% close
        4        0     4.76% openat
       84        0   100.00% total
```

---

## How it works

### 1. `PTRACE_TRACEME` in the child

`mini-trace` `fork()`s. The child calls `ptrace(PTRACE_TRACEME, 0, ...)` so it
becomes traced by its parent, then raises `SIGSTOP` and waits. The parent
`waitpid`s for that stop, arms `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC`
via `PTRACE_SETOPTIONS`, and lets the child run with `PTRACE_CONT`. The child
then `execvp()`s the target command.

### 2. `PTRACE_SYSCALL`: two stops per syscall

The parent's main loop is:

```c
waitpid(pid, &status, 0);
PTRACE_GETREGS / PTRACE_GET_SYSCALL_INFO;   // classify the stop
print(...);
PTRACE_SYSCALL(pid, 0);                      // resume until next syscall stop
```

`PTRACE_SYSCALL` resumes the tracee and stops it again at the *next*
syscall boundary. Crucially, every syscall produces **two** stops:

| Stop             | When                                | Registers                                    |
|------------------|-------------------------------------|----------------------------------------------|
| **Syscall-enter stop** | just after the `syscall` instruction, **before** the kernel body runs | `orig_rax` = syscall number, `rdi/rsi/rdx/r10/r8/r9` = 6 args |
| **Syscall-exit stop**  | just before returning to userspace, after the kernel body ran | `rax` = return value, `orig_rax` = `-1` (on x86_64) |

So `mini-trace` alternates: **entry stop** → print `syscall( args )` →
**exit stop** → print `= retval`.

### 3. How entry and exit are told apart

Two mechanisms are implemented, selected automatically:

- **`PTRACE_GET_SYSCALL_INFO` (Linux ≥ 5.3, preferred).** This ptrace
  operation reports the stop phase (`PTRACE_SYSCALL_INFO_ENTRY` /
  `PTRACE_SYSCALL_INFO_EXIT`) plus a small struct whose *entry* branch
  carries the syscall number and six arguments and whose *exit* branch
  carries only the return value (`rval`) and an `is_error` flag — the
  kernel does **not** include the syscall number on the exit stop. This
  is the modern replacement for the `orig_rax == -1` heuristic, and it's
  what strace uses. Because the exit number is absent, mini-trace tracks
  the most recent entry number across stops to name and classify exit
  stops.

  **Subtlety:** the syscall's return value is the *number of bytes the
  kernel wrote into the struct* (padding excluded). `offsetof()` already
  measures from the top of the whole struct, so the end of the last field
  written is simply `offsetof(field) + sizeof(field)`. Entry stops report
  `offsetof(entry.args) + sizeof(entry.args)` = **80** bytes; exit stops
  report `offsetof(exit.is_error) + sizeof(exit.is_error)` = **33** bytes
  — *not* `sizeof(sci.exit)` = 40. Two classic mistakes:

  - `sizeof(sci.exit)` is 16 (7 bytes of trailing padding), so comparing
    against 40 silently rejects every exit stop, dropping it into the
    `orig_rax == -1` fallback and miscounting exits as *second entries*
    (doubled counts, all-zero errors).
  - Adding `offsetof(entry)` *and* `offsetof(entry.args)` double-counts
    the 24-byte union header (the nested offsetof already includes it),
    producing 104/57, which matches nothing either.

  mini-trace computes the field end with a single `offsetof(field) +
  sizeof(field)` — never `sizeof()` of the padded sub-struct, and never
  a second offset term — so the comparison is immune to ABI padding.
- **`orig_rax == -1` heuristic (fallback).** Before
  `PTRACE_GET_SYSCALL_INFO`, tracers read the register `orig_rax`:
  - entry stop: `orig_rax` holds the syscall number,
  - exit stop: the kernel has set `orig_rax = -1`.
  Arguments are then read from `rdi, rsi, rdx, r10, r8, r9`; the return value
  from `rax`.

`PTRACE_O_TRACESYSGOOD` makes syscall stops arrive as signal
`SIGTRAP|0x80` instead of plain `SIGTRAP`, so they cannot be confused with
exec traps or user-injected `SIGTRAP`s. `PTRACE_O_TRACEEXEC` additionally
replaces the exit stop of a successful `execve` with a `PTRACE_EVENT_EXEC`
stop and suppresses the redundant post-`exec` `SIGTRAP`.

### 4. Reading tracee memory

To print strings (`open("foo")`, `execve("/bin/ls", ...)`) the tracer must
read the tracee's address space while it is stopped:

- **`/proc/<pid>/mem` + `pread(2)`** — clean, portable, one call per read.
- **`PTRACE_PEEKDATA`** — classic word-at-a-time fallback if `/proc` is
  unavailable.

Both are implemented in `ptrace_wrapper.c`. Reads are *best-effort*: an
unreadable page prints `<unreadable@0x...>` instead of wedging the trace.

---

## File layout

```
mini-trace
├── Makefile                     # gcc, -Wall -Wextra, no deps
├── README.md                    # you are here
├── main.c                       # CLI + waitpid/PTRACE_SYSCALL loop
├── ptrace_wrapper.h/.c          # all raw ptrace(2)/waitpid(2) access
├── arg_decoder.h/.c             # per-syscall argument formatting
├── syscall_table.h              # GENERATED: nr -> name, incl. build note
└── tools/
    └── gen_syscall_table.sh     # regenerates syscall_table.h
```

Clean layering: `main.c` never calls `ptrace()` itself — the low-level calls
live only in `ptrace_wrapper.c`; argument decoding lives only in
`arg_decoder.c`; the syscall name table is a self-contained generated header.

### Generated syscall table (`syscall_table.h`)

`syscall_table.h` is checked in, and is generated once from the kernel's
official `arch/x86/entry/syscalls/syscall_64.tbl` (the same numbering as
`/usr/include/asm/unistd_64.h`) by `tools/gen_syscall_table.sh`. The header's
comment records exactly how it was produced. To regenerate against your
kernel:

```sh
make syscall-table        # uses /lib/modules/$(uname -r)/build/.../syscall_64.tbl
# or with an explicit path:
make syscall-table SYSCALL_TBL=/path/to/linux/arch/x86/entry/syscalls/syscall_64.tbl
```

---

## Multi-process / multi-threaded targets (documented limitation)

- `fork`/`vfork`/`clone`/`clone3` are **detected** and a note is printed
  to stderr — the process does not crash.
- Only the **initial child** is traced; forked children run untraced.
- Threads created with `CLONE_THREAD` are not followed, which can make
  syscall events appear interleaved or out of order.
- These are deliberate scope decisions; archiving full multi-process tracing
  would require a `waitpid(-1)` loop with per-pid state and is left as an
  exercise.

## Requirements & permissions

- **Linux, x86_64 (or a compat environment).** The syscall table, register
  layout (`user_regs_struct`), and `orig_rax` heuristic are x86_64-specific.
- `ptrace(2)` must be permitted. If you hit `EPERM` from
  `PTRACE_TRACEME`/`PTRACE_SETOPTIONS`:
  ```sh
  cat /proc/sys/kernel/yama/ptrace_scope
  # 0 = anyone may trace; 1 = only descendants (default, usually fine
  # for this tool since we trace our own child); 2,3 = stricter
  # Temporarily relax (root):
  echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
  ```
  Container policies / AppArmor / seccomp / setuid binaries can also cause
  `EPERM`.

---

## Why this matters: Connection to K-Guard

This tracer is the same mechanism that kernel-level monitoring and
sandboxing products use, just performed from userspace for learning:

1. **Syscall interception = the root of observation.** Every filesystem
   access, network connection, `exec`, and `mmap` ultimately flows through a
   syscall. Intercepting syscalls — as `mini-trace` does with
   `PTRACE_SYSCALL`, or as seccomp BPF / LSM hooks / eBPF programs
   (`tracepoint:sys_enter_*`) do inside the kernel — is the foundation for
   audit, behavioral detection, and policy enforcement. The stop-and-inspect
   pattern here is exactly what `strace`, `gdb`, and debuggers do.
2. **Entry/exit asymmetry is everywhere.** Kernel instrumentation has the
   same two-sided view: capture arguments before the call, capture the return
   value after. Understanding *why there are two stops per syscall* transfers
   directly to reading kernel `tracepoints`, `kprobes`, or seccomp user
   notifier code, where the same distinction exists.
3. **Userspace vs. kernel placement.** `mini-trace` sits between the app and
   the kernel using ptrace. A *K-Guard-style* monitor places the interception
   *in* the kernel (e.g., LSM hooks, seccomp, eBPF), which is lower-latency,
   harder to bypass, and survives the traced process crashing — at the cost of
   running privileged code. The ptrace approach trades that for a pure
   userspace implementation with zero kernel changes, which makes it the
   fastest way to learn the fundamental syscall interception contract.
4. **Same race conditions, same mitigations.** A tracer that reads tracee
   memory must do it while the tracee is stopped (this project does);
   kernel monitors must similarly be careful that the argument buffers they
   read are pinned and valid. Debugging this project is, literally,
   debugging the same category of bugs kernel developers debug.

In short: **`mini-trace` is the userspace "hello world" of syscall
interception** — the exact building block a K-Guard-style project would
reimplement in kernel space for real enforcement.