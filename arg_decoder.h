/* arg_decoder.h -- format syscall arguments into a readable string.
 *
 * A small static buffer is reused for every decoding call, so the returned
 * pointer remains valid until the *next* call to arg_decode().  This is
 * intentional: the trace loop decodes, prints, then decodes the next stop,
 * and it avoids heap churn in the hot path.
 *
 * Decoding is best-effort: any failure (unreadable memory, unknown syscall)
 * falls back to a plain hex dump of the raw register value.  A tracer must
 * never crash or block the tracee because an argument could not be decoded.
 */

#ifndef ARG_DECODER_H
#define ARG_DECODER_H

#include "ptrace_wrapper.h"

#define ARG_BUF_SIZE 512

/* Format the arguments of the given syscall-entry stop.  The returned
 * string is valid until the next call to arg_decode, arg_decode_retval,
 * or arg_format_fd (which are the only writers). */
const char *arg_decode(pid_t pid, long syscall_nr,
                       const unsigned long args[MAX_SYSCALL_ARGS]);

/* Format a return value: "5", "-1 ENOENT (No such file or directory)",
 * "0x7f1234 (MAP_...)?" for pointers, etc.  Same buffer rules as above. */
const char *arg_decode_retval(long retval);

#endif /* ARG_DECODER_H */