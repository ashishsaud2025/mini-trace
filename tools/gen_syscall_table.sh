#!/usr/bin/env bash
# gen_syscall_table.sh -- regenerate syscall_table.h
#
# Usage:
#   ./tools/gen_syscall_table.sh <syscall_64.tbl>
#
# Source formats accepted:
#   1. Linux kernel: arch/x86/entry/syscalls/syscall_64.tbl
#        (lines: "<nr> <abi> <name> <entry point>")
#   2. glibc headers: /usr/include/asm/unistd_64.h
#        (lines: "#define __NR_<name> <nr>" and comment lines)
#
# Output is written to stdout; redirect into syscall_table.h when
# regenerating.  The header's "HOW PRODUCED" comment documents this script.
#
# Example on a distro with kernel headers installed:
#   ./tools/gen_syscall_table.sh \
#       /lib/modules/$(uname -r)/build/arch/x86/entry/syscalls/syscall_64.tbl \
#       > syscall_table.h

set -euo pipefail

src="${1:?usage: gen_syscall_table.sh <syscall_64.tbl|unistd_64.h>}"
skip_abi="x32"          # x32 ABI shares numbers with x86_64 on some rows; skip

ver=$(uname -r 2>/dev/null || echo unknown)

cat <<EOF
/* syscall_table.h -- GENERATED FILE, DO NOT EDIT BY HAND.
 *
 * x86_64 syscall-number -> name lookup for mini-trace.
 *
 * HOW PRODUCED: generated from $src
 * (kernel: $ver) by:
 *     tools/gen_syscall_table.sh $src
 * Re-run the script to refresh the table for newer kernels.
 * Rows without an entry (NULL) are rendered as "syscall_<nr>".
 * Unknown / older kernels: entries 335..423 are left empty; rows at
 * 424+ are only present on kernels that define them.
 */

#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

#include <stddef.h>
#include <stdio.h>

static const char *const syscall_table[] = {
EOF

case "$src" in
    *.tbl)
        # Format: nr abi name entry  (emit every x86_64 row, in order)
        awk -v skip="$skip_abi" '
            /^[[:space:]]*#/ { next }
            NF >= 4 && $2 != skip {
                # $1 nr, $2 abi, $3 name, $4 entry
                printf "\t[%s] = \"%s\",\n", $1, $3
            }
        ' "$src"
        ;;
    *)
        # Fall back to unistd_64.h format: "#define __NR_name nr"
        awk '
            /^[[:space:]]*#define[[:space:]]+__NR_/ {
                name = $2; sub(/^__NR_/, "", name)
                nr   = $3
                printf "\t[%s] = \"%s\",\n", nr, name
            }
        ' "$src"
        ;;
esac

cat <<EOF
};

#define SYSCALL_TABLE_SIZE (sizeof(syscall_table) / sizeof(syscall_table[0]))

/* Returns the name for a syscall number, or "syscall_<nr>" if unknown.
 * The returned pointer is only valid until the next call: copy it if
 * you need it to survive across two calls in one printf. */
static inline const char *syscall_name(long nr)
{
	static char buf[32];
	if (nr >= 0 && nr < (long)SYSCALL_TABLE_SIZE && syscall_table[nr])
		return syscall_table[nr];
	snprintf(buf, sizeof(buf), "syscall_%ld", nr);
	return buf;
}

#endif /* SYSCALL_TABLE_H */
EOF