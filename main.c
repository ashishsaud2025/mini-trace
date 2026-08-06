/* main.c -- mini-trace CLI + PTRACE_SYSCALL trace loop.
 *
 * Usage:
 *   mini-trace <command> [args...]
 *   mini-trace -f <command> [args...]
 *   mini-trace -T <command> [args...]
 *   mini-trace --filter open,openat,connect <command> [args...]
 *   mini-trace -e trace=network,file <command> [args...]
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
#include <time.h>
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
    bool timing;         /* -T: show time spent inside each syscall */
} options_t;

static bool filter_list[FILTER_MAX_NR];

/* -e trace=<category> syscall groups (x86_64 numbers, from syscall_table.h).
 * Deliberately curated, not exhaustive: enough of each family to make the
 * category useful, not a reimplementation of strace's much larger tables.
 *
 * file:    open/openat/close/read/write/stat family, path-based ops
 *          (rename, unlink, link, mkdir/rmdir, chmod/chown, readlink, ...)
 * network: socket(2) and everything that takes a socket fd
 * process: fork/vfork/clone/execve/exit/wait4/kill
 * memory:  mmap/mprotect/munmap */
static const int cat_file[] = {
    0, 1, 2, 3, 4, 5, 6, 8, 21, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85,
    86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 161, 217, 257, 258, 259, 260,
    262, 263, 264, 265, 266, 267, 268, 269, 280, 316,
};
static const int cat_network[] = {
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 288,
};
static const int cat_process[] = {56, 57, 58, 59, 60, 61, 62, 435};
static const int cat_memory[] = {9, 10, 11};

typedef struct {
    const char *name;
    const int *nrs;
    size_t count;
} category_t;

#define CAT(arr) arr, sizeof(arr) / sizeof(arr[0])
static const category_t categories[] = {
    {"file", CAT(cat_file)},
    {"network", CAT(cat_network)},
    {"process", CAT(cat_process)},
    {"memory", CAT(cat_memory)},
};
#undef CAT

/* Matches `name` (optionally "%"-prefixed, as strace also accepts) against
 * a known category and, on a hit, sets every syscall in it in filter_list.
 * Returns false if `name` isn't a known category (caller then tries it as
 * a plain syscall name/number instead). */
static bool apply_category(const char *name)
{
    if (name[0] == '%')
        name++;
    for (size_t i = 0; i < sizeof(categories) / sizeof(categories[0]); i++) {
        if (strcmp(name, categories[i].name) != 0)
            continue;
        for (size_t j = 0; j < categories[i].count; j++) {
            int nr = categories[i].nrs[j];
            if (nr >= 0 && nr < FILTER_MAX_NR)
                filter_list[nr] = true;
        }
        return true;
    }
    return false;
}

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

/* Parses the value of `-e trace=<...>`: a comma-separated list where each
 * token is either a category name (file, network, process, memory -- see
 * `categories[]` above) or, falling back, an individual syscall name/number
 * exactly like --filter accepts.  Both forms write into the same
 * filter_list[], so `-e trace=network,openat` and `--filter` compose
 * naturally if both are given. */
static bool parse_trace_expr(const char *csv)
{
    char *copy = strdup(csv);
    if (!copy)
        return false;

    char *save = NULL;
    int count = 0;
    bool ok = true;
    for (char *tok = strtok_r(copy, ",", &save); tok;
         tok = strtok_r(NULL, ",", &save)) {
        while (*tok == ' ' || *tok == '\t')
            tok++;
        if (*tok == '\0')
            continue;

        if (apply_category(tok)) {
            count++;
            continue;
        }

        /* Not a category: fall back to the same name/number lookup
         * --filter uses. */
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
                        "mini-trace: unknown category or syscall '%s' in "
                        "-e trace=\n",
                        tok);
                ok = false;
                break;
            }
        }
        if (nr >= 0 && nr < FILTER_MAX_NR) {
            filter_list[nr] = true;
        } else {
            fprintf(stderr, "mini-trace: syscall number %d out of range\n", nr);
            ok = false;
            break;
        }
        count++;
    }
    free(copy);
    return ok && count > 0;
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
            "  -T                           Also show time spent inside each\n"
            "                              syscall on the full trace, e.g.\n"
            "                              '= 3 <0.000041>'.  --summary\n"
            "                              always shows per-syscall timing\n"
            "                              (seconds, usecs/call) whether\n"
            "                              or not -T is given.\n"
            "  --filter <name1,name2,...>  Only show listed syscalls.\n"
            "                              Names or numbers; e.g.\n"
            "                              --filter open,openat,connect\n"
            "  -e trace=<group1,...>       Only show syscalls in the given\n"
            "                              categories: file, network,\n"
            "                              process, memory.  Category names\n"
            "                              and individual syscall\n"
            "                              names/numbers may be mixed, and\n"
            "                              this composes with --filter;\n"
            "                              e.g. -e trace=network,openat\n"
            "  --summary                   Print a syscall count table\n"
            "                              instead of the full trace.\n"
            "                              With -f, counts are combined\n"
            "                              across all traced processes.\n"
            "  -h, --help                  Show this help.\n"
            "\n"
            "Examples:\n"
            "  mini-trace ls -la\n"
            "  mini-trace --filter open,openat ls /etc\n"
            "  mini-trace -e trace=network curl example.com\n"
            "  mini-trace -T --summary find /usr -name Makefile\n"
            "  mini-trace -f make -j4\n"
            "\n"
            "Notes:\n"
            "  If you get EPERM, check /proc/sys/kernel/yama/ptrace_scope.\n");
}

/* summary accounting */

static unsigned long long counts[FILTER_MAX_NR];
static unsigned long long error_counts[FILTER_MAX_NR];
static double time_sec[FILTER_MAX_NR];       /* total time inside each nr */
static unsigned long long total_syscalls;
static unsigned long long total_errors;
static double total_time_sec;

static void summary_add(const syscall_stop_t *stop)
{
    long nr = stop->syscall_nr;
    if (nr >= 0 && nr < FILTER_MAX_NR)
        counts[nr]++;
    total_syscalls++;
}

/* Called at every exit stop in --summary mode, regardless of -T: unlike
 * the full trace line (which only shows timing when the user explicitly
 * asked for -T, since it's one more thing cluttering every line), the
 * summary table always has room for a "seconds"/"usecs/call" column and
 * the cost of a couple of extra clock_gettime() calls per syscall is
 * negligible next to everything else this tool already does per stop. */
static void summary_add_time(long nr, double elapsed)
{
    if (nr >= 0 && nr < FILTER_MAX_NR)
        time_sec[nr] += elapsed;
    total_time_sec += elapsed;
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
    printf("%9s %9s %11s %11s %9s %s\n", "calls", "errors", "seconds",
           "usecs/call", "pct", "syscall");
    printf("%9s %9s %11s %11s %9s %s\n", "--------", "--------",
           "-----------", "-----------", "--------", "--------");
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
        unsigned long long avg_usec =
            counts[nr] ? (unsigned long long)(time_sec[nr] * 1e6 /
                                                (double)counts[nr] + 0.5)
                       : 0;
        printf("%9llu %9llu %11.6f %11llu %8.2f%% %s\n", counts[nr],
               error_counts[nr], time_sec[nr], avg_usec, pct,
               syscall_name(nr));
    }
    unsigned long long total_avg_usec =
        total_syscalls ? (unsigned long long)(total_time_sec * 1e6 /
                                                (double)total_syscalls + 0.5)
                       : 0;
    printf("%9llu %9llu %11.6f %11llu %8s %s\n", total_syscalls,
           total_errors, total_time_sec, total_avg_usec, "100.00%", "total");
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
    struct timespec entry_time; /* CLOCK_MONOTONIC at the last entry stop,
                                    so the matching exit stop can report
                                    elapsed wall time. Only meaningful when
                                    entry_time_valid is true. */
    bool  entry_time_valid;     /* false until the first real entry stop
                                    this tracee has had. An exit-shaped
                                    stop can in principle be observed
                                    before any entry has been recorded for
                                    this pid (e.g. the transitional stop
                                    right after a PTRACE_EVENT_EXEC, before
                                    the exec'd program's first syscall has
                                    produced its own entry stop) -- without
                                    this flag, elapsed_since() would diff
                                    against the zero-initialized {0,0}
                                    sentinel and report a bogus multi-
                                    hundred-second "syscall time" equal to
                                    however long the machine has been up. */
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
            tracees[i].entry_time = (struct timespec){0};
            tracees[i].entry_time_valid = false;
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
    slot->entry_time = (struct timespec){0};
    slot->entry_time_valid = false;
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

/* Wall-clock seconds elapsed since `entry` (a CLOCK_MONOTONIC timestamp),
 * clamped to never go negative on a clock hiccup. Shared by --summary's
 * per-syscall time accumulation and -T's per-line display. */
static double elapsed_since(const struct timespec *entry)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    double e = (double)(now.tv_sec - entry->tv_sec) +
               (double)(now.tv_nsec - entry->tv_nsec) / 1e9;
    return e < 0 ? 0.0 : e;
}

/* Formats an elapsed duration the way strace's -T does: " <0.000041>",
 * leading space included so callers can just concatenate it onto the end
 * of the result line. Returns "" (not a bug: same static-buffer contract
 * as arg_decoder's helpers) when timing is disabled, so call sites don't
 * need an extra branch. */
static const char *format_elapsed(bool enabled, double secs)
{
    static char b[32];
    if (!enabled) {
        b[0] = '\0';
        return b;
    }
    snprintf(b, sizeof(b), " <%.6f>", secs);
    return b;
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
    if (stop->is_entry) {
        ts->pending_nr = stop->syscall_nr;
        /* Stamp the entry time now, before this stop is handled and the
         * tracee resumed, so the interval measured on the matching exit
         * stop covers the syscall's actual in-kernel time (plus whatever
         * scheduling delay exists before the exit stop is delivered back
         * to us -- the same wall-clock measurement strace's -T makes, not
         * a kernel-reported figure). Stamped unconditionally (not gated
         * on -T) because --summary always reports per-syscall timing now;
         * -T only controls whether the *full* per-line trace also prints
         * it. The clock_gettime() cost is negligible next to the ptrace
         * calls already happening on every single stop. */
        clock_gettime(CLOCK_MONOTONIC, &ts->entry_time);
        ts->entry_time_valid = true;
    }

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
            /* Skip time accounting entirely if we never saw this call's
             * entry stop (see entry_time_valid's comment) rather than
             * diffing against the zero sentinel and recording nonsense. */
            if (ts->entry_time_valid)
                summary_add_time(ts->pending_nr, elapsed_since(&ts->entry_time));
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
        double elapsed = (opts->timing && ts->entry_time_valid)
                              ? elapsed_since(&ts->entry_time)
                              : 0.0;
        printf("%6d: %14s = %s%s\n", stop->pid,
               nr >= 0 ? syscall_name(nr) : "?",
               arg_decode_retval(stop->retval),
               format_elapsed(opts->timing, elapsed));
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
        if (!after_dashdash && strcmp(a, "-T") == 0) {
            opts.timing = true;
            argi++;
            continue;
        }
        if (!after_dashdash && strcmp(a, "-e") == 0 && argi + 1 < argc) {
            const char *expr = argv[argi + 1];
            if (strncmp(expr, "trace=", 6) != 0) {
                fprintf(stderr,
                        "mini-trace: -e only supports 'trace=...' "
                        "(e.g. -e trace=network)\n");
                return 1;
            }
            if (!parse_trace_expr(expr + 6)) {
                fprintf(stderr, "mini-trace: malformed -e trace=...\n");
                return 1;
            }
            opts.filter_enabled = true;
            argi += 2;
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

    /* Main loop: PTRACE_CONT (not PTRACE_SYSCALL) ran the leader freely
     * until its first *event* stop -- since CONT alone doesn't arm
     * per-syscall stepping, any syscalls the leader makes before that
     * (e.g. execvp()'s internal PATH-search stat/access calls) run
     * unobserved, and the first stop we actually catch is the successful
     * execve's PTRACE_EVENT_EXEC (handled by handle_exec_event, not the
     * ordinary entry/exit path). Every later resume is PTRACE_SYSCALL, so
     * from there on stops alternate entry/exit as documented above --
     * except for one further wrinkle: the stop immediately following that
     * event switch to PTRACE_SYSCALL is itself sometimes already
     * exit-shaped, with no entry ever observed for it (see
     * entry_time_valid's comment on tracee_state_t for why this matters
     * for -T/--summary timing). With -f, waitpid(-1) inside
     * wait_and_handle also picks up every auto-attached fork/vfork/clone
     * child; the loop keeps going until no tracee (leader or child) is
     * left alive. */
    while (wait_and_handle(&opts))
        ;

    if (opts.summary)
        print_summary();

    return final_exit_code;
}