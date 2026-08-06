/* arg_decoder.c -- best-effort decoding of syscall arguments.
 *
 * We intentionally decode only a small set of syscalls deeply (pointer
 * strings, file descriptors, sockaddr structs).  Everything else degrades
 * to hex, because the goal of this project is to demonstrate the mechanism
 * -- not to reimplement strace's thousands of decoder lines.
 *
 * Reads of tracee memory go through ptrace_read_string / ptrace_read_mem.
 * A failed read never aborts the trace; we print a "<unreadable>" marker.
 */

#define _GNU_SOURCE

#include "arg_decoder.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_STR_LEN 128

/* Shared by every decoder; see header for lifetime rules. */
static char buf[ARG_BUF_SIZE];
static size_t pos;

static void reset_buf(void)
{
    pos = 0;
    buf[0] = '\0';
}

#if defined(__GNUC__)
__attribute__((format(printf, 1, 2)))
#endif
static void emit(const char *fmt, ...)
{
    if (pos >= sizeof(buf) - 1)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + pos, sizeof(buf) - pos, fmt, ap);
    va_end(ap);
    if (n > 0) {
        size_t adv = (size_t)n;
        if (adv > sizeof(buf) - pos - 1)
            adv = sizeof(buf) - pos - 1;
        pos += adv;
    }
}

/* helpers */

/* Print a C-escaped string.  `s` is always NUL-terminated. */
static void emit_escaped(const char *s)
{
    size_t i = 0;
    for (; i < MAX_STR_LEN && s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\\': emit("\\\\"); break;
        case '"':  emit("\\\""); break;
        case '\n': emit("\\n"); break;
        case '\t': emit("\\t"); break;
        case '\r': emit("\\r"); break;
        default:
            if (c < 0x20 || c == 0x7f)
                emit("\\x%02x", c);
            else
                emit("%c", c);
        }
    }
    if (i >= MAX_STR_LEN && s[i] != '\0')
        emit("...");
}

/* Resolve an fd to its file path via /proc/<pid>/fd (readlink follows the
 * symlink in the tracee's fd table).  Never fails the trace; returns NULL
 * if the path is not readable. */
static const char *fd_path(pid_t pid, int fd)
{
    static char fdbuf[320];
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);
    ssize_t n = readlink(path, fdbuf, sizeof(fdbuf) - 1);
    if (n < 0)
        return NULL;
    fdbuf[n] = '\0';
    return fdbuf;
}

static void emit_fd(pid_t pid, unsigned long raw)
{
    long fd = (long)raw;
    if (fd >= 0) {
        const char *p = fd_path(pid, (int)fd);
        if (p)
            emit("%ld<%s>", fd, p);
        else
            emit("%ld", fd);
    } else {
        emit("%ld", fd);
    }
}

static void emit_string(pid_t pid, unsigned long addr)
{
    if (addr == 0) {
        emit("NULL");
        return;
    }
    char *s = ptrace_read_string(pid, addr, MAX_STR_LEN);
    if (!s) {
        emit("<unreadable@0x%lx>", addr);
        return;
    }
    emit("\"");
    emit_escaped(s);
    emit("\"");
    free(s);
}

/* per-syscall decoders */

static void dec_open(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_string(pid, a[0]);
    emit(", 0x%lx", a[1]);
    if (a[1] & (O_CREAT | O_TMPFILE))
        emit(", 0%lo", a[2]); /* mode %o is what strace prints */
}

static void dec_openat(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_fd(pid, a[0]);
    emit(", ");
    emit_string(pid, a[1]);
    emit(", 0x%lx", a[2]);
    if (a[2] & (O_CREAT | O_TMPFILE))
        emit(", 0%lo", a[3]);
}

static void dec_read_write(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_fd(pid, a[0]);
    emit(", ");
    emit_string(pid, a[1]);
    emit(", %lu", a[2]);
}

static void dec_close(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_fd(pid, a[0]);
}

static void dec_mmap(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    (void)pid;
    emit("0x%lx, %lu, 0x%lx, 0x%lx, %ld, 0x%lx",
         a[0], a[1], a[2], a[3], (long)a[4], a[5]);
}

static void dec_execve(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_string(pid, a[0]);
    emit(", [");
    /* argv: walk the pointer array in the tracee (max 64 entries). */
    unsigned long p = a[1];
    unsigned long ptrs[64];
    size_t n = 0;
    for (size_t i = 0; i < 64; i++) {
        ssize_t r = ptrace_read_mem(pid, p + i * sizeof(unsigned long),
                                    &ptrs[i], sizeof(unsigned long));
        if (r != (ssize_t)sizeof(unsigned long) || ptrs[i] == 0)
            break;
        n++;
    }
    for (size_t i = 0; i < n; i++) {
        if (i)
            emit(", ");
        char *s = ptrace_read_string(pid, ptrs[i], MAX_STR_LEN);
        emit("\"");
        if (s)
            emit_escaped(s);
        else
            emit("?");
        emit("\"");
        free(s);
    }
    if (n == 0)
        emit("?");
    emit("], ...");
}

static void dec_sockaddr_common(pid_t pid, unsigned long addr, unsigned long len);

static void dec_sockfd_n_sockaddr(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    emit_fd(pid, a[0]);
    emit(", ");
    dec_sockaddr_common(pid, a[1], a[2]);
}

static void dec_socket(pid_t pid, const unsigned long a[MAX_SYSCALL_ARGS])
{
    (void)pid;
    emit("%lu, %lu, %lu /* domain, type, protocol */", a[0], a[1], a[2]);
}

static void dec_sockaddr_common(pid_t pid, unsigned long addr, unsigned long len)
{
    if (addr == 0) {
        emit("NULL");
        return;
    }
    if (len > 128) {
        emit("0x%lx", addr);
        return;
    }
    char raw[128];
    ssize_t r = ptrace_read_mem(pid, addr, raw, (size_t)len);
    if (r < 2) {
        emit("<unreadable@0x%lx>", addr);
        return;
    }
    unsigned short family;
    memcpy(&family, raw, 2);

    switch (family) {
    case AF_INET: {
        if (r >= 8) {
            char ip[INET_ADDRSTRLEN] = "?";
            inet_ntop(AF_INET, raw + 4, ip, sizeof(ip));
            unsigned short port;
            memcpy(&port, raw + 2, 2);
            emit("{AF_INET, port=%u, addr=%s}", ntohs(port), ip);
        } else {
            emit("{AF_INET, <truncated>}");
        }
        break;
    }
    case AF_INET6: {
        if (r >= 24) {
            char ip[INET6_ADDRSTRLEN] = "?";
            inet_ntop(AF_INET6, raw + 8, ip, sizeof(ip));
            unsigned short port;
            memcpy(&port, raw + 2, 2);
            emit("{AF_INET6, port=%u, addr=%s}", ntohs(port), ip);
        } else {
            emit("{AF_INET6, <truncated>}");
        }
        break;
    }
    case AF_UNIX:
        emit("{AF_UNIX, \"%.*s\"}", (int)(r > 2 ? r - 2 : 0), raw + 2);
        break;
    default:
        emit("{AF_%u, ...}", family);
        break;
    }
}

/* main entry */

const char *arg_decode(pid_t pid, long nr,
                       const unsigned long a[MAX_SYSCALL_ARGS])
{
    reset_buf();

    switch (nr) {
    case 0:  /* read */
    case 1:  /* write */
        dec_read_write(pid, a);
        return buf;
    case 2:  /* open */
        dec_open(pid, a);
        return buf;
    case 257: /* openat */
        dec_openat(pid, a);
        return buf;
    case 3:   /* close */
        dec_close(pid, a);
        return buf;
    case 9:   /* mmap */
    case 10:  /* mprotect */
        dec_mmap(pid, a);
        return buf;
    case 59:  /* execve */
        dec_execve(pid, a);
        return buf;
    case 41:  /* socket */
        dec_socket(pid, a);
        return buf;
    case 42:  /* connect */
    case 43:  /* accept */
    case 49:  /* bind */
    case 50:  /* listen */
        dec_sockfd_n_sockaddr(pid, a);
        return buf;
    default:
        break;
    }

    /* Fallback for everything else: raw hex. */
    emit("0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx",
         a[0], a[1], a[2], a[3], a[4], a[5]);
    return buf;
}

const char *arg_decode_retval(long ret)
{
    reset_buf();
    if (ret == 0) {
        emit("0");
    } else if (ret > 0) {
        emit("%ld", ret);
    } else {
        emit("-1 %s", strerror((int)(-ret)));
    }
    return buf;
}