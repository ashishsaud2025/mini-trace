/* ptrace_wrapper.c -- implementation of the low-level ptrace wrappers.
 *
 * Everything directly touching ptrace(2), waitpid(2), /proc/<pid>/mem and
 * PTRACE_PEEKDATA lives here.  main.c only ever talks to this API, which
 * keeps the trace-loop logic readable and the raw errno/return-code
 * handling in exactly one place.
 */

#define _GNU_SOURCE

#include "ptrace_wrapper.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

/* diagnostics */

void ptrace_perror(const char *what, pid_t pid)
{
    int e = errno;
    fprintf(stderr, "mini-trace: %s(pid=%d): %s\n", what, pid, strerror(e));
    if (e == EPERM) {
        fprintf(stderr,
                "\nHINT: ptrace may be restricted on this system.\n"
                "  Check:  cat /proc/sys/kernel/yama/ptrace_scope\n"
                "  A value of 1 means you may only trace your own children\n"
                "  (which this tool does, so it usually works), and 2/3\n"
                "  restrict further.  As root you can temporarily relax it:\n"
                "    echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n"
                "  Container/AppArmor/setuid restrictions can also cause EPERM.\n");
    }
}

/* child side */

void ptrace_child_begin(void)
{
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        ptrace_perror("PTRACE_TRACEME", getpid());
        _exit(126);
    }
    /* Stop so the parent can attach options before we execute anything
     * (the exec trap would otherwise be the first thing the parent sees). */
    raise(SIGSTOP);
    /* Parent's PTRACE_CONT resumes us from here; fall through to execve. */
}

/* parent side: initial stop */

bool ptrace_wait_initial_stop(pid_t pid)
{
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ptrace_perror("waitpid(initial)", pid);
        return false;
    }
    if (WIFEXITED(status)) {
        fprintf(stderr,
                "mini-trace: child exited before reaching its initial stop "
                "(code %d)\n",
                WEXITSTATUS(status));
        return false;
    }
    if (!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP)) {
        fprintf(stderr,
                "mini-trace: unexpected initial stop status 0x%x "
                "(expected SIGSTOP)\n",
                status);
        return false;
    }
    return true;
}

int ptrace_arm(pid_t pid)
{
    /* TRACESYSGOOD: syscall stops are delivered as SIGTRAP|0x80 instead of
     * plain SIGTRAP, so they can never be confused with exec traps or
     * user-injected SIGTRAPs.
     * TRACEEXEC: a successful execve is reported as a PTRACE_EVENT_EXEC
     * stop instead of the exit syscall stop, and the redundant post-exec
     * SIGTRAP is suppressed. */
    unsigned long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)opts) == -1) {
        ptrace_perror("PTRACE_SETOPTIONS", pid);
        return -1;
    }
    return 0;
}

/* continuations */

int ptrace_resume_syscall(pid_t pid, int signal)
{
    if (ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(unsigned long)signal) == -1) {
        ptrace_perror("PTRACE_SYSCALL", pid);
        return -1;
    }
    return 0;
}

int ptrace_resume_cont(pid_t pid, int signal)
{
    if (ptrace(PTRACE_CONT, pid, NULL, (void *)(unsigned long)signal) == -1) {
        ptrace_perror("PTRACE_CONT", pid);
        return -1;
    }
    return 0;
}

/* wait status classification */

bool ptrace_status_exited(int status, int *exit_code)
{
    if (WIFEXITED(status)) {
        *exit_code = WEXITSTATUS(status);
        return true;
    }
    return false;
}

bool ptrace_status_signaled(int status, int *term_sig)
{
    if (WIFSIGNALED(status)) {
        *term_sig = WTERMSIG(status);
        return true;
    }
    return false;
}

bool ptrace_status_syscall_stop(int status)
{
    /* With PTRACE_O_TRACESYSGOOD armed, syscall stops appear as
     * (SIGTRAP | 0x80).  (Seccomp traps also appear this way; we do not
     * filter seccomp events and they are rare for the targets here, so
     * treat them as syscall stops.) */
    return WIFSTOPPED(status) && WSTOPSIG(status) == (SIGTRAP | 0x80);
}

bool ptrace_status_signal_stop(int status, int *sig_out)
{
    if (WIFSTOPPED(status) && WSTOPSIG(status) != (SIGTRAP | 0x80)) {
        *sig_out = WSTOPSIG(status);
        return true;
    }
    return false;
}

/* register capture */

static bool fetch_regs(pid_t pid, struct user_regs_struct *regs)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        ptrace_perror("PTRACE_GETREGS", pid);
        return false;
    }
    return true;
}

bool ptrace_fetch_stop(pid_t pid, syscall_stop_t *stop)
{
    memset(stop, 0, sizeof(*stop));
    stop->pid = pid;

    if (!fetch_regs(pid, &stop->regs))
        return false;

    /* entry vs exit classification 
     *
     * Preferred path: PTRACE_GET_SYSCALL_INFO (Linux >= 5.3) reports the
     * phase directly.  At the entry stop it gives us the syscall number
     * and the six arguments; at the exit stop it only gives us the return
     * value (the kernel's struct has no nr in the exit branch -- the name
     * is tracked across stops by main.c via pending entry numbers).
     * Fallback path (older kernels / reduced seccomp): the x86_64 kernel
     * sets orig_rax = -1 at the exit stop; at the entry stop orig_rax is
     * the syscall number.  This is the classic strace heuristic.
     */
#ifdef PTRACE_GET_SYSCALL_INFO
    struct ptrace_syscall_info sci;
    memset(&sci, 0, sizeof(sci));
    long r = ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(sci), &sci);

    /* The kernel returns only the bytes it actually wrote -- struct
     * padding is NOT included.  Entry stops write through entry.args:
     *   offsetof(entry) + offsetof(entry.args) + sizeof(entry.args)
     *   = 24 + 8 + 48 = 80 bytes.
     * Exit stops write through exit.is_error:
     *   offsetof(exit) + offsetof(exit.is_error) + sizeof(exit.is_error)
     *   = 24 + 8 + 1 = 33 bytes.
     * Note that sizeof(sci.exit) is 16 (7 bytes of trailing padding), so
     * comparing against it does NOT match the 33 bytes the kernel writes
     * -- every exit stop would fall through to the heuristic and be
     * miscounted as an additional entry (doubling counts and hiding
     * errors).  Compute the field end explicitly instead. */
    long entry_end =
        (long)offsetof(struct ptrace_syscall_info, entry) +
        (long)offsetof(struct ptrace_syscall_info, entry.args) +
        (long)sizeof(sci.entry.args);                       /* 80 */
    long exit_end  =
        (long)offsetof(struct ptrace_syscall_info, exit) +
        (long)offsetof(struct ptrace_syscall_info, exit.is_error) +
        (long)sizeof(sci.exit.is_error);                    /* 33 */
    if (r == entry_end || r == exit_end) {
        /* Modern path: PTRACE_GET_SYSCALL_INFO (Linux >= 5.3) reports the
         * phase directly along with the syscall number, args and retval. */
        if (sci.op == PTRACE_SYSCALL_INFO_ENTRY) {
            stop->is_entry = true;
            stop->syscall_nr = sci.entry.nr;
            for (int i = 0; i < MAX_SYSCALL_ARGS; i++)
                stop->args[i] = sci.entry.args[i];
            /* Mirror the syscall number into regs.orig_rax so later code
             * can rely on a uniform "regs.orig_rax==nr at entry" shape. */
            stop->regs.orig_rax = sci.entry.nr;
            return true;
        }
        if (sci.op == PTRACE_SYSCALL_INFO_EXIT) {
            /* The exit branch of ptrace_syscall_info has no `nr` member
             * (only rval/is_error); the caller tracks the syscall number
             * from the preceding entry stop.  is_error distinguishes real
             * errno-style failures from negative-but-valid return values. */
            stop->is_entry = false;
            stop->syscall_nr = -1;
            stop->retval = sci.exit.rval;
            stop->is_error = sci.exit.is_error != 0;
            /* Force the classic markers too, for uniformity. */
            stop->regs.orig_rax = -1;
            stop->regs.rax = (unsigned long)sci.exit.rval;
            return true;
        }
        /* seccomp / other unexpected info opcode: fall through to the
         * classic heuristic rather than failing the whole trace. */
    }
#endif /* PTRACE_GET_SYSCALL_INFO */

    /* Classic heuristic (also the fallback on kernels < 5.3, or on
     * builds whose headers lack PTRACE_GET_SYSCALL_INFO): the x86_64
     * kernel sets orig_rax = -1 at the exit stop; at the entry stop
     * orig_rax is the syscall number. */
    if ((long)stop->regs.orig_rax == -1) {
        stop->is_entry = false;
        stop->syscall_nr = -1;
        stop->retval = (long)stop->regs.rax;
        /* No is_error flag on this path; a negative retval is the closest
         * approximation (the kernel returns -errno on failure). */
        stop->is_error = stop->retval < 0;
    } else {
        stop->is_entry = true;
        stop->syscall_nr = (long)stop->regs.orig_rax;
        stop->args[0] = stop->regs.rdi;
        stop->args[1] = stop->regs.rsi;
        stop->args[2] = stop->regs.rdx;
        stop->args[3] = stop->regs.r10;
        stop->args[4] = stop->regs.r8;
        stop->args[5] = stop->regs.r9;
    }

    return true;
}

/* tracee memory */

ssize_t ptrace_read_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    /* Preferred: /proc/<pid>/mem, which lets us read an arbitrary byte
     * range in one pread(2) and is robust against page-boundary crossings. */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t n = pread(fd, buf, len, (off_t)addr);
        int saved = errno;
        close(fd);
        errno = saved;
        if (n >= 0)
            return n;
        /* Fall through to PEEKDATA on any pread failure. */
    }

    /* Fallback: PTRACE_PEEKDATA reads one machine word at a time. */
    unsigned char *out = buf;
    size_t got = 0;
    while (got < len) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, pid, (void *)addr + got, NULL);
        if (word == -1 && errno != 0) {
            if (got > 0)
                break; /* partial success: return what we have */
            return -1;
        }
        size_t chunk = sizeof(long);
        if (got + chunk > len)
            chunk = len - got;
        memcpy(out + got, &word, chunk);
        got += chunk;
    }
    return (ssize_t)got;
}

char *ptrace_read_string(pid_t pid, unsigned long addr, size_t max_len)
{
    char *buf = malloc(max_len + 1);
    if (!buf) {
        errno = ENOMEM;
        return NULL;
    }
    ssize_t n = ptrace_read_mem(pid, addr, buf, max_len);
    if (n < 0) {
        free(buf);
        return NULL;
    }
    /* The read is always NUL-terminated at position n; if the tracee's
     * string was shorter, an embedded NUL is already inside the buffer
     * and stops every consumer (all of which scan to the first NUL). */
    buf[n] = '\0';
    return buf;
}
