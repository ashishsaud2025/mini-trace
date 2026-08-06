# mini-trace -- minimal strace-like syscall tracer (Linux, x86_64)
#
# Build:   make
# Clean:   make clean
#
# The project ships with a checked-in, generated syscall_table.h; the
# `syscall-table` target regenerates it from your system's kernel source
# when headers are available (see tools/gen_syscall_table.sh).

CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?=

# Embed build metadata so the running binary can self-identify (helps when
# debugging why a deployed binary behaves differently from the source).
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE := $(shell date -u +%Y%m%d 2>/dev/null || echo unknown)
CFLAGS += -DGIT_COMMIT=\"$(GIT_COMMIT)\" -DBUILD_DATE=\"$(BUILD_DATE)\"

TARGET  := mini-trace

SRCS := main.c ptrace_wrapper.c arg_decoder.c
HDRS := syscall_table.h ptrace_wrapper.h arg_decoder.h
OBJS := $(SRCS:.c=.o)

.PHONY: all clean syscall-table

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Regenerate syscall_table.h from a system-provided syscall table.
# Adjust $(SYSCALL_TBL) for your distro if the path differs.
SYSCALL_TBL ?= /lib/modules/$(shell uname -r 2>/dev/null)/build/arch/x86/entry/syscalls/syscall_64.tbl

syscall-table:
	@test -f $(SYSCALL_TBL) || { \
		echo "error: $(SYSCALL_TBL) not found."; \
		echo "Pass the path explicitly, e.g.:"; \
		echo "  make syscall-table SYSCALL_TBL=/path/to/syscall_64.tbl"; \
		exit 1; }
	./tools/gen_syscall_table.sh $(SYSCALL_TBL) > syscall_table.h

clean:
	rm -f $(TARGET) $(OBJS)