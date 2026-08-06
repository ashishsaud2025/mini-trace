/* ptrace_wrapper.h -- thin, error-checked wrappers around raw ptrace(2).
 *
 * This module is the ONLY place in mini-trace that calls ptrace(2)/waitpid(2)
 * directly, so the exact semantics of each stop are contained here.
 *
 * Design notes:
 *  - We enable PTRACE_O_TRACESYSGOOD on the tracee.  With that option,
 *    syscall stops are reported as signal SIGTRAP|0x80, which makes them
 *    trivial to tell apart from every other kind of stop.
 *  - Entry vs. exit classification: PTRACE_GET_SYSCALL_INFO (Linux >= 5.3)
 *    when available, otherwise the classic heuristic used by strace for
 *    decades: on x86_64 the kernel sets orig_rax = -1 at the exit stop,
 *    while at the entry stop orig_rax holds the syscall number.
 *  - Tracee memory is read via /proc/<pid>/mem (pread(2)) with a
 *    PTRACE_PEEKDATA fallback, so both documented techniques are
 *    demonstrated.
 *
 * All functions return -1 / NULL / false on error (setting errno) rather
 * than failing silently.
 */

#ifndef PTRACE_WRAPPER_H
#define PTRACE_WRAPPER_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/user.h>

#define MAX_SYSCALL_ARGS 6

/* One captured ptrace stop on the tracee. */
typedef struct {
    pid_t pid;
    bool  is_entry;                  /* true: syscall entry stop; false: exit stop */
    long  syscall_nr;                /* syscall number (entry: always; exit: via
                                        GET_SYSCALL_INFO, else -1 = unknown) */
    unsigned long args[MAX_SYSCALL_ARGS]; /* entry: raw args; exit: preserved regs */
    long  retval;                    /* exit: return value (negative errno if error) */
    struct user_regs_struct regs;    /* raw register snapshot at the stop */
} syscall_stop_t;

/* setup  */

/* Child side: PTRACE_TRACEME, then raise(SIGSTOP) and block until the
 * parent continues with ptrace_resume_cont().  On TRACEME failure prints a
 * hint to stderr (including the ptrace_scope tip) and _exit(2)s. */
void ptrace_child_begin(void);

/* Parent side: wait for the child's initial SIGSTOP after TRACEME.
 * Returns false if the child dies or the stop is unexpected. */
bool ptrace_wait_initial_stop(pid_t pid);

/* Arm TRACESYSGOOD so syscall stops carry SIGTRAP|0x80.  Returns 0 or -1. */
int ptrace_arm(pid_t pid);

/* continuations */

/* Resume with PTRACE_SYSCALL (next syscall entry/exit stop) injecting
 * `signal` (0 = no signal).  Returns 0 or -1. */
int ptrace_resume_syscall(pid_t pid, int signal);

/* Plain PTRACE_CONT, used exactly once right after the initial SIGSTOP. */
int ptrace_resume_cont(pid_t pid, int signal);

/* stop classification (feed it the raw waitpid status) */

bool ptrace_status_exited(int status, int *exit_code);
bool ptrace_status_signaled(int status, int *term_sig);
bool ptrace_status_syscall_stop(int status);                 /* SIGTRAP|0x80 */
bool ptrace_status_signal_stop(int status, int *sig_out);    /* other signal stop */

/* register capture */

/* Capture registers + entry/exit classification at a syscall stop. */
bool ptrace_fetch_stop(pid_t pid, syscall_stop_t *stop);

/* tracee memory access */

/* Read up to len bytes from tracee address space.  Returns bytes read
 * (may be less than len on a short read) or -1 on a hard fault. */
ssize_t ptrace_read_mem(pid_t pid, unsigned long addr, void *buf, size_t len);

/* Read a NUL-terminated string of at most max_len bytes.  Returns a
 * malloc'd, always NUL-terminated string, or NULL if the first byte
 * could not be read.  Caller frees. */
char *ptrace_read_string(pid_t pid, unsigned long addr, size_t max_len);

/* diagnostics */

/* Print "<what>(pid=N): <strerror>" plus a ptrace_scope hint on EPERM. */
void ptrace_perror(const char *what, pid_t pid);

#endif /* PTRACE_WRAPPER_H */