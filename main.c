/* main.c -- mini-trace CLI + PTRACE_SYSCALL trace loop.
 *
 * Usage:
 *   mini-trace <command> [args...]
 *   mini-trace --filter open,openat,connect <command> [args...]
 *   mini-trace --summary <command> [args...]
 *
 * Flow:
 *   fork(); child does PTRACE_TRACEME + SIGSTOP; parent arms
 *   PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC, then loops on
 *   waitpid/PTRACE_SYSCALL.  Each syscall produces two stops (entry and
 *   exit); the entry stop shows the arguments, the exit stop shows the
 *   return value.  On a successful execve the exit stop is replaced by a
 *   PTRACE_EVENT_EXEC stop (which is why we arm TRACEEXEC: it prevents
 *   the separate, redundant exec SIGTRAP trap).
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

/* CLI state  */

typedef struct {
    bool summary;
    bool filter_enabled;
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
            "  --filter <name1,name2,...>  Only show listed syscalls.\n"
            "                              Names or numbers; e.g.\n"
            "                              --filter open,openat,connect\n"
            "  --summary                   Print a syscall count table\n"
            "                              instead of the full trace.\n"
            "  -h, --help                  Show this help.\n"
            "\n"
            "Examples:\n"
            "  mini-trace ls -la\n"
            "  mini-trace --filter open,openat ls /etc\n"
            "  mini-trace --summary find /usr -name Makefile\n"
            "\n"
            "Notes:\n"
            "  If you get EPERM, check /proc/sys/kernel/yama/ptrace_scope.\n");
}

/* summary accounting */

static unsigned long long counts[FILTER_MAX_NR];
static unsigned long long total_syscalls;

static void summary_add(const syscall_stop_t *stop)
{
    long nr = stop->syscall_nr;
    if (nr >= 0 && nr < FILTER_MAX_NR)
        counts[nr]++;
    total_syscalls++;
}

static void print_summary(void)
{
    printf("%9s %9s %9s %s\n", "calls", "errors", "pct", "syscall");
    printf("%9s %9s %9s %s\n", "--------", "--------", "--------", "--------");
    /* Sort by call count descending. */
    static int order[FILTER_MAX_NR];
    int n = 0;
    for (int i = 0; i < FILTER_MAX_NR; i++)
        if (counts[i])
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
        printf("%9llu %9llu %8.2f%% %s\n", counts[nr], 0ULL, pct,
               syscall_name(nr));
    }
    printf("%9llu %9llu %8s %s\n", total_syscalls, 0ULL, "100.00%", "total");
}

/* trace loop */

/* Remember the syscall number seen at the most recent entry so that the
 * exit line can show the name even on the orig_rax==-1 fallback path. */
static long pending_nr = -1;

/* Replayed as mini-trace's own exit status: the tracee's exit code, or
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
            "traced (multi-process tracing is out of scope; see README)\n",
            pid, syscall_name(stop->syscall_nr));
}

/* Returns false if the trace loop must stop. */
static bool handle_syscall_stop(options_t *opts, syscall_stop_t *stop)
{
    /* fork (57) / vfork (58) / clone (56) / clone3 (435) */
    if (stop->is_entry &&
        (stop->syscall_nr == 56 || stop->syscall_nr == 57 ||
         stop->syscall_nr == 58 || stop->syscall_nr == 435)) {
        handle_fork_detected(stop->pid, stop);
    }

    if (opts->summary) {
        if (stop->is_entry)
            summary_add(stop);
        return true;
    }

    /* Record the most recent entry number regardless of filtering: exit
     * stops never carry the syscall number (neither the GET_SYSCALL_INFO
     * exit branch nor the orig_rax==-1 heuristic provides it), so
     * pending_nr is the only way to name/classify an exit stop. */
    if (stop->is_entry)
        pending_nr = stop->syscall_nr;

    long nr = pending_nr;
    bool show = !opts->filter_enabled ||
                (nr >= 0 && nr < FILTER_MAX_NR && filter_list[nr]);
    if (!show)
        return true;

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

static bool wait_and_handle(options_t *opts, pid_t pid)
{
    int status;
    if (waitpid(pid, &status, 0) == -1) {
        ptrace_perror("waitpid", pid);
        return false;
    }

    int code;
    if (ptrace_status_exited(status, &code)) {
        if (!opts->summary)
            printf("%6d: +++ exited with %d +++\n", pid, code);
        final_exit_code = code;
        return false;
    }

    int sig;
    if (ptrace_status_signaled(status, &sig)) {
        if (!opts->summary)
            printf("%6d: +++ killed by signal %d (%s) +++\n", pid, sig,
                   strsignal(sig));
        final_exit_code = 128 + sig;
        return false;
    }

    /* PTRACE_EVENT_* event stops (with TRACEEXEC, the successful-exec
     * exit-stop is delivered this way). */
    if (WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_EXEC) {
        handle_exec_event(opts, pid);
        if (ptrace_resume_syscall(pid, 0) == -1)
            return false;
        return true;
    }

    if (ptrace_status_syscall_stop(status)) {
        syscall_stop_t stop;
        if (!ptrace_fetch_stop(pid, &stop))
            return false;
        /* Decode/print while the tracee is stopped: argument pointers are
         * only guaranteed valid (and only readable via PTRACE_PEEKDATA)
         * at this moment.  Only after handling do we resume it. */
        bool cont = handle_syscall_stop(opts, &stop);
        if (ptrace_resume_syscall(pid, 0) == -1)
            return false;
        return cont;
    }

    int osig;
    if (ptrace_status_signal_stop(status, &osig)) {
        handle_signal_stop(pid, osig);
        return true;
    }

    fprintf(stderr, "mini-trace: unexpected wait status 0x%x\n", status);
    return false;
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
        if (!after_dashdash && strcmp(a, "--summary") == 0) {
            opts.summary = true;
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
    if (!ptrace_wait_initial_stop(pid))
        return 1;
    if (ptrace_arm(pid) == -1)
        return 1;
    if (ptrace_resume_cont(pid, 0) == -1)
        return 1;

    /* Main loop: PTRACE_CONT ran the child to its first syscall entry;
     * every later resume is PTRACE_SYSCALL, alternating entry/exit stops. */
    while (wait_and_handle(&opts, pid))
        ;

    if (opts.summary)
        print_summary();

    return final_exit_code;
}
