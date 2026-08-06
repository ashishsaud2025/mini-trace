/* main.c -- mini-trace CLI + PTRACE_SYSCALL trace loop.
 *
 * Usage:
 *   mini-trace <command> [args...]
 *   mini-trace -f <command> [args...]
 *   mini-trace --filter open,openat,connect <command> [args...]
 *   mini-trace --summary <command> [args...]
 *
 * Flow:
 *   fork(); child does PTRACE_TRACEME + SIGSTOP; parent arms
 *   PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC (+ TRACEFORK | TRACEVFORK |
 *   TRACECLONE when -f is given), then loops on waitpid(-1)/PTRACE_SYSCALL.
 *   Each syscall produces two stops (entry and exit); the entry stop shows
 *   the arguments, the exit stop shows the return value.  On a successful
 *   execve the exit stop is replaced by a PTRACE_EVENT_EXEC stop (which is
 *   why we arm TRACEEXEC: it prevents the separate, redundant exec SIGTRAP
 *   trap).  With -f, fork/vfork/clone similarly produce a PTRACE_EVENT_*
 *   stop on the parent instead of an ordinary syscall-exit stop; the new
 *   child is auto-attached and tracked in a per-pid table (tracee_state_t)
 *   alongside every other tracee, and the trace loop runs until all of
 *   them have exited.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include "arg_decoder.h"
#include "ptrace_wrapper.h"
#include "syscall_table.h"

#define FILTER_MAX_NR 512

/* Build metadata is injected by the Makefile; lets a binary identify the
 * exact commit it was built from (useful when chasing stale builds). */
#ifndef GIT_COMMIT
#define GIT_COMMIT "unknown"
#endif
#ifndef BUILD_DATE
#define BUILD_DATE "unknown"
#endif

static const char *mini_trace_version(void)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "mini-trace %s (built %s)", GIT_COMMIT,
             BUILD_DATE);
    return buf;
}

/* CLI state  */

typedef struct {
    bool summary;
    bool filter_enabled;
    bool follow_forks;   /* -f: also trace fork/vfork/clone children */
} options_t;

static bool filter_list[FILTER_MAX_NR];

static bool parse_filter_list(const char *csv)
{
    char *copy = strdup(csv);
    if (!copy)
        return false;

    char *save = NULL;
    int count = 0;
    for (char *tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        /* Trim spaces. */
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok == '\0')
            continue;

        /* Accept either a name or a numeric syscall number. */
        char *end = NULL;
        long num = strtol(tok, &end, 10);
        int nr;
        if (end != tok && *end == '\0') {
            nr = (int)num;
        } else {
            nr = -1;
            for (long i = 0; i < (long)SYSCALL_TABLE_SIZE; i++) {
                if (syscall_table[i] && strcmp(syscall_table[i], tok) == 0) {
                    nr = (int)i;
                    break;
                }
            }
            if (nr < 0) {
                fprintf(stderr,
                        "mini-trace: unknown syscall name '%s' in --filter\n",
                        tok);
                free(copy);
                return false;
            }
        }

        if (nr >= 0 && nr < FILTER_MAX_NR) {
            filter_list[nr] = true;
        } else {
            fprintf(stderr, "mini-trace: syscall number %d out of range\n", nr);
            free(copy);
            return false;
        }
        count++;
    }
    free(copy);
    return count > 0;
}

static void print_usage(FILE *out)
{
    fprintf(out,
            "Usage: mini-trace [options] <command> [args...]\n"
            "\n"
            "Trace syscalls of <command> using ptrace (PTRACE_SYSCALL).\n"
            "Linux x86_64 only.\n"
            "\n"
            "Options:\n"
            "  -f                           Follow fork/vfork/clone children\n"
            "                              (like strace -f) and trace them\n"
            "                              too, until every traced process\n"
            "                              has exited.\n"
            "  --filter <name1,name2,...>  Only show listed syscalls.\n"
            "                              Names or numbers; e.g.\n"
            "                              --filter open,openat,connect\n"
            "  --summary                   Print a syscall count table\n"
            "                              instead of the full trace.\n"
            "                              With -f, counts are combined\n"
            "                              across all traced processes.\n"
            "  -h, --help                  Show this help.\n"
            "\n"
            "Examples:\n"
            "  mini-trace ls -la\n"
            "  mini-trace --filter open,openat ls /etc\n"
            "  mini-trace --summary find /usr -name Makefile\n"
            "  mini-trace -f make -j4\n"
            "\n"
            "Notes:\n"
            "  If you get EPERM, check /proc/sys/kernel/yama/ptrace_scope.\n");
}

/* summary accounting */

static unsigned long long counts[FILTER_MAX_NR];
static unsigned long long error_counts[FILTER_MAX_NR];
static unsigned long long total_syscalls;
static unsigned long long total_errors;

static void summary_add(const syscall_stop_t *stop)
{
    long nr = stop->syscall_nr;
    if (nr >= 0 && nr < FILTER_MAX_NR)
        counts[nr]++;
    total_syscalls++;
}

/* Called at the exit stop: the syscall failed.  The failure is detected
 * via the kernel's is_error flag (modern PTRACE_GET_SYSCALL_INFO path) or
 * a negative return value (heuristic fallback).  Exit stops carry no
 * syscall number, so the error is attributed to the most recent entry
 * (pending_nr). */
static void summary_add_error(long nr)
{
    if (nr >= 0 && nr < FILTER_MAX_NR)
        error_counts[nr]++;
    total_errors++;
}

static void print_summary(void)
{
    printf("%9s %9s %9s %s\n", "calls", "errors", "pct", "syscall");
    printf("%9s %9s %9s %s\n", "--------", "--------", "--------", "--------");
    /* Sort by call count descending. */
    static int order[FILTER_MAX_NR];
    int n = 0;
    for (int i = 0; i < FILTER_MAX_NR; i++)
        if (counts[i] || error_counts[i])
            order[n++] = i;
    for (int i = 1; i < n; i++) {
        int key = order[i];
        int j = i - 1;
        while (j >= 0 && counts[order[j]] < counts[key]) {
            order[j + 1] = order[j];
            j--;
        }
        order[j + 1] = key;
    }
    for (int i = 0; i < n; i++) {
        int nr = order[i];
        double pct = total_syscalls ? 100.0 * (double)counts[nr] /
                                          (double)total_syscalls : 0.0;
        printf("%9llu %9llu %8.2f%% %s\n", counts[nr], error_counts[nr], pct,
               syscall_name(nr));
    }
    printf("%9llu %9llu %8s %s\n", total_syscalls, total_errors, "100.00%",
           "total");
}

/* trace loop */

/* Per-pid state.  With -f there can be many tracees alive at once, each at
 * its own point in its own entry/exit cycle, so pending_nr (the syscall
 * number seen at the most recent entry, needed to name/classify the
 * matching exit stop) has to live per-pid rather than in one global. */
typedef struct {
    pid_t pid;
    long  pending_nr;
    bool  in_use;
} tracee_state_t;

static tracee_state_t *tracees = NULL;
static size_t tracees_cap = 0;
static size_t active_count = 0; /* live tracees; loop ends when this hits 0 */

static tracee_state_t *tracee_lookup(pid_t pid)
{
    for (size_t i = 0; i < tracees_cap; i++)
        if (tracees[i].in_use && tracees[i].pid == pid)
            return &tracees[i];
    return NULL;
}

static tracee_state_t *tracee_register(pid_t pid)
{
    for (size_t i = 0; i < tracees_cap; i++) {
        if (!tracees[i].in_use) {
            tracees[i].pid = pid;
            tracees[i].pending_nr = -1;
            tracees[i].in_use = true;
            active_count++;
            return &tracees[i];
        }
    }
    size_t old_cap = tracees_cap;
    size_t new_cap = old_cap ? old_cap * 2 : 16;
    tracee_state_t *grown = realloc(tracees, new_cap * sizeof(*tracees));
    if (!grown) {
        fprintf(stderr, "mini-trace: out of memory tracking pid %d\n", pid);
        _exit(1);
    }
    for (size_t i = old_cap; i < new_cap; i++)
        grown[i].in_use = false;
    tracees = grown;
    tracees_cap = new_cap;
    /* Every slot below old_cap was already full (that's why we grew), so
     * the first newly-added slot is the correct place for this pid. */
    tracee_state_t *slot = &tracees[old_cap];
    slot->pid = pid;
    slot->pending_nr = -1;
    slot->in_use = true;
    active_count++;
    return slot;
}

static void tracee_unregister(pid_t pid)
{
    tracee_state_t *t = tracee_lookup(pid);
    if (t) {
        t->in_use = false;
        if (active_count)
            active_count--;
    }
}

/* The very first process we launch; its exit code/signal becomes
 * mini-trace's own exit status, and its "+++ exited +++" line is printed
 * inline (like plain strace) rather than as an attach/detach note. */
static pid_t leader_pid = -1;

/* Replayed as mini-trace's own exit status: the leader's exit code, or
 * 128+signal when it was killed by a signal. */
static int final_exit_code = 0;

static void handle_signal_stop(pid_t pid, int sig)
{
    /* Forward the signal and continue in syscall mode.  (The redundant
     * post-exec SIGTRAP that would otherwise appear here is suppressed by
     * PTRACE_O_TRACEEXEC, so the only SIGTRAP signal-stops remaining are
     * real ones raised by the tracee.) */
    if (ptrace_resume_syscall(pid, sig) == -1)
        _exit(1);
}

static void handle_fork_detected(pid_t pid, const syscall_stop_t *stop)
{
    fprintf(stderr,
            "mini-trace: note: pid %d invoked %s -- forked children are not "
            "traced (pass -f to also trace them)\n",
            pid, syscall_name(stop->syscall_nr));
}

/* Returns false if the trace loop must stop. */
static bool handle_syscall_stop(options_t *opts, syscall_stop_t *stop,
                                 tracee_state_t *ts)
{
    /* fork (57) / vfork (58) / clone (56) / clone3 (435) */
    if (stop->is_entry &&
        (stop->syscall_nr == 56 || stop->syscall_nr == 57 ||
         stop->syscall_nr == 58 || stop->syscall_nr == 435)) {
        /* Without -f this syscall's child is never attached, so warn once
         * here.  With -f, TRACEFORK/VFORK/CLONE deliver a much more
         * reliable PTRACE_EVENT_* stop with the real new pid (handled in
         * wait_and_handle), so nothing extra is needed at this entry. */
        if (!opts->follow_forks)
            handle_fork_detected(stop->pid, stop);
    }

    /* Record the most recent entry number regardless of mode/filtering:
     * exit stops never carry the syscall number (neither the
     * GET_SYSCALL_INFO exit branch nor the orig_rax==-1 heuristic provides
     * it), so pending_nr is the only way to name/classify an exit stop or
     * attribute its error.  This is tracked per-pid (ts) so interleaved
     * tracees under -f don't clobber each other's in-flight syscall. */
    if (stop->is_entry)
        ts->pending_nr = stop->syscall_nr;

    /* --filter applies in both --summary and full-trace mode: a filtered-
     * out syscall should neither be printed nor counted. */
    long nr = ts->pending_nr;
    bool show = !opts->filter_enabled ||
                (nr >= 0 && nr < FILTER_MAX_NR && filter_list[nr]);
    if (!show)
        return true;

    if (opts->summary) {
        if (stop->is_entry) {
            summary_add(stop);
        } else {
            /* x86_64 kernel convention: a syscall return value in the
             * range [-4095, -1] means "failed, and -retval is the errno"
             * (IS_ERR_VALUE).  Checking the raw retval directly is
             * robust on both the modern GET_SYSCALL_INFO path and the
             * orig_rax==-1 heuristic fallback. */
            long rv = stop->retval;
            if (rv < 0 && rv >= -4095)
                summary_add_error(ts->pending_nr);
        }
        return true;
    }

    if (stop->is_entry) {
        printf("%6d: syscall %3ld (%s)( %s )\n",
               stop->pid, stop->syscall_nr,
               syscall_name(stop->syscall_nr),
               arg_decode(stop->pid, stop->syscall_nr, stop->args));
        fflush(stdout);
    } else {
        printf("%6d: %14s = %s\n", stop->pid,
               nr >= 0 ? syscall_name(nr) : "?",
               arg_decode_retval(stop->retval));
        fflush(stdout);
    }
    return true;
}

static void handle_exec_event(options_t *opts, pid_t pid)
{
    /* PTRACE_EVENT_EXEC: execve succeeded.  The exit stop for execve is
     * replaced by this event (TRACEEXEC), so we have nothing to print from
     * the exit path for the syscall itself; note the new image. */
    if (opts->summary)
        return; /* the entry stop already counted execve */
    if (opts->filter_enabled && !filter_list[59]) /* 59 = execve */
        return;
    printf("%6d: %14s = 0 /* new program image loaded */\n", pid,
           "execve");
    fflush(stdout);
}

/* PTRACE_EVENT_FORK/VFORK/CLONE stop on `parent_pid`: a new tracee exists.
 * Only reached when opts->follow_forks is set (wait_and_handle gates it).
 *
 * This deliberately does nothing but look up and log the new pid.  The
 * kernel auto-attaches it the moment fork/vfork/clone runs, so no extra
 * ptrace call is needed to make that happen -- and empirically,
 * PTRACE_SETOPTIONS on it *here* fails with ESRCH (the tracer apparently
 * has to observe the new tracee via waitpid() at least once before most
 * ptrace(2) requests on it will succeed, regardless of whether it is
 * already stopped).  So registration/arming/resuming is left entirely to
 * the generic "freshly_seen" path in wait_and_handle(), which runs once
 * this pid's own first wait status actually arrives -- which happens
 * regardless of whether we've done anything with the pid in the meantime. */
static void handle_new_child(options_t *opts, pid_t parent_pid, int event)
{
    if (opts->summary)
        return;
    pid_t child_pid = ptrace_get_new_child(parent_pid);
    const char *kind = event == PTRACE_EVENT_VFORK   ? "vfork"
                        : event == PTRACE_EVENT_CLONE ? "clone"
                                                       : "fork";
    if (child_pid > 0)
        fprintf(stderr, "mini-trace: [pid %d] new child pid %d (via %s)\n",
                parent_pid, child_pid, kind);
    else
        fprintf(stderr, "mini-trace: [pid %d] new child (via %s)\n",
                parent_pid, kind);
}

static bool wait_and_handle(options_t *opts)
{
    int status;
    pid_t pid = waitpid(-1, &status, __WALL);
    if (pid == -1) {
        if (errno == ECHILD)
            return false; /* no tracees left */
        ptrace_perror("waitpid", -1);
        return false;
    }

    tracee_state_t *ts = tracee_lookup(pid);
    bool freshly_seen = false;
    if (!ts) {
        /* Only expected with -f: this pid's own first stop (typically a
         * synthetic SIGSTOP delivered by the auto-attach) raced ahead of
         * the parent's PTRACE_EVENT_FORK/VFORK/CLONE notification.  Arm
         * and register it now -- setting options twice on the same pid,
         * which can happen if handle_new_child() runs afterwards, is
         * harmless. */
        ts = tracee_register(pid);
        ptrace_arm(pid, opts->follow_forks);
        freshly_seen = true;
        if (!opts->summary)
            fprintf(stderr, "mini-trace: [pid %d] attached\n", pid);
    }

    int code;
    if (ptrace_status_exited(status, &code)) {
        if (!opts->summary) {
            if (pid == leader_pid)
                printf("%6d: +++ exited with %d +++\n", pid, code);
            else
                fprintf(stderr, "mini-trace: [pid %d] exited with %d\n", pid,
                        code);
        }
        if (pid == leader_pid)
            final_exit_code = code;
        tracee_unregister(pid);
        return active_count > 0;
    }

    int sig;
    if (ptrace_status_signaled(status, &sig)) {
        if (!opts->summary) {
            if (pid == leader_pid)
                printf("%6d: +++ killed by signal %d (%s) +++\n", pid, sig,
                       strsignal(sig));
            else
                fprintf(stderr,
                        "mini-trace: [pid %d] killed by signal %d (%s)\n",
                        pid, sig, strsignal(sig));
        }
        if (pid == leader_pid)
            final_exit_code = 128 + sig;
        tracee_unregister(pid);
        return active_count > 0;
    }

    if (freshly_seen) {
        /* Swallow this synthetic first stop exactly like the leader's own
         * post-TRACEME SIGSTOP is swallowed in main(): just start the
         * tracee running in syscall-trace mode. Forwarding the raw signal
         * (usually SIGSTOP) here would actually re-stop the tracee. */
        if (ptrace_resume_syscall(pid, 0) == -1)
            tracee_unregister(pid);
        return active_count > 0;
    }

    int event = ptrace_status_event(status);
    if (event == PTRACE_EVENT_EXEC) {
        handle_exec_event(opts, pid);
        if (ptrace_resume_syscall(pid, 0) == -1)
            tracee_unregister(pid);
        return active_count > 0;
    }
    if (opts->follow_forks &&
        (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
         event == PTRACE_EVENT_CLONE)) {
        handle_new_child(opts, pid, event);
        if (ptrace_resume_syscall(pid, 0) == -1)
            tracee_unregister(pid);
        return active_count > 0;
    }

    if (ptrace_status_syscall_stop(status)) {
        syscall_stop_t stop;
        if (!ptrace_fetch_stop(pid, &stop)) {
            tracee_unregister(pid);
            return active_count > 0;
        }
        /* Decode/print while the tracee is stopped: argument pointers are
         * only guaranteed valid (and only readable via PTRACE_PEEKDATA)
         * at this moment.  Only after handling do we resume it. */
        handle_syscall_stop(opts, &stop, ts);
        if (ptrace_resume_syscall(pid, 0) == -1)
            tracee_unregister(pid);
        return active_count > 0;
    }

    int osig;
    if (ptrace_status_signal_stop(status, &osig)) {
        handle_signal_stop(pid, osig);
        return active_count > 0;
    }

    fprintf(stderr, "mini-trace: unexpected wait status 0x%x for pid %d\n",
            status, pid);
    tracee_unregister(pid);
    return active_count > 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        print_usage(stderr);
        return 1;
    }

    options_t opts = {0};
    int argi = 1;
    bool after_dashdash = false;

    while (argi < argc) {
        const char *a = argv[argi];
        if (!after_dashdash && strcmp(a, "--") == 0) {
            after_dashdash = true;
            argi++;
            continue;
        }
        if (!after_dashdash &&
            (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)) {
            print_usage(stdout);
            return 0;
        }
        if (!after_dashdash &&
            (strcmp(a, "-V") == 0 || strcmp(a, "--version") == 0)) {
            printf("%s\n", mini_trace_version());
            return 0;
        }
        if (!after_dashdash && strcmp(a, "--summary") == 0) {
            opts.summary = true;
            argi++;
            continue;
        }
        if (!after_dashdash && strcmp(a, "-f") == 0) {
            opts.follow_forks = true;
            argi++;
            continue;
        }
        if (!after_dashdash && strcmp(a, "--filter") == 0 &&
            argi + 1 < argc) {
            if (!parse_filter_list(argv[argi + 1])) {
                fprintf(stderr, "mini-trace: malformed --filter\n");
                return 1;
            }
            opts.filter_enabled = true;
            argi += 2;
            continue;
        }
        if (!after_dashdash && strncmp(a, "--filter=", 9) == 0) {
            if (!parse_filter_list(a + 9)) {
                fprintf(stderr, "mini-trace: malformed --filter\n");
                return 1;
            }
            opts.filter_enabled = true;
            argi++;
            continue;
        }
        /* First non-option is the command. */
        break;
    }

    if (argi >= argc) {
        fprintf(stderr, "mini-trace: no command given\n");
        print_usage(stderr);
        return 1;
    }

    char **cmd = &argv[argi];

    pid_t pid = fork();
    if (pid == -1) {
        ptrace_perror("fork", 0);
        return 1;
    }

    if (pid == 0) {
        /* child */
        ptrace_child_begin();
        execvp(cmd[0], cmd);
        fprintf(stderr, "mini-trace: execvp(%s): %s\n", cmd[0],
                strerror(errno));
        _exit(127);
    }

    /* parent: tracer */
    leader_pid = pid;
    if (!ptrace_wait_initial_stop(pid))
        return 1;
    if (ptrace_arm(pid, opts.follow_forks) == -1)
        return 1;
    tracee_register(pid);
    if (ptrace_resume_cont(pid, 0) == -1)
        return 1;

    /* Main loop: PTRACE_CONT ran the leader to its first syscall entry;
     * every later resume is PTRACE_SYSCALL, alternating entry/exit stops.
     * With -f, waitpid(-1) inside wait_and_handle also picks up every
     * auto-attached fork/vfork/clone child; the loop keeps going until no
     * tracee (leader or child) is left alive. */
    while (wait_and_handle(&opts))
        ;

    if (opts.summary)
        print_summary();

    return final_exit_code;
}