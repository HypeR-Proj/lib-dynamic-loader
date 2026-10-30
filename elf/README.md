<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# Internal ELF loading primitives

This private source library is compiled into its owning loader only. It has no installed DSO, heap, TLS, global state, filesystem
lookup or service endpoint. Its entry and image policy remain local to the loader.

`image.c` acquires content protection on one Native executable File before
reading its size or ELF headers, then installs its load segments as protected
file-backed private COW mappings. It closes the parser protection token after
mapping; live mappings retain independent protection references. An optional
exact interpreter name is an admission condition: `NULL` rejects `PT_INTERP`,
while the formal loader accepts
its architecture's canonical name. Neither path opens an interpreter file.
Mapping failure aborts the child. Once its threads stop, teardown releases
protected sources independently of any externally retained VMAR; ordinary
address-space ownership still controls final page reclamation.
Mapping and syscall-copy failures report status codes, including exhausted
memory or quota. Later hardware faults use bounded reclaim/refill retries;
an unresolved fault terminates the Process rather than returning an errno.

`launch.c` decodes the kernel's bounded bootstrap packet, validates tagged
handles and SDK launch data, and builds the LP64 application entry vector.
The caller explicitly supplies the runtime-linker bias and whether its loader
mapping will be retired. Static applications have `AT_BASE=0` and retire the
loader. Dynamic applications retain the loader for constructors and `dlopen`.
The common final-stack runtime always retires the temporary stack.

Both entry assemblies reserve 64 KiB above their C frames. A compile-time bound
covers the maximum packet, copied handles and entry vector; host tests exercise
the maximum valid packet. See the [owning loader](../README.md) for its entry policy.

## Address layout

Both architectures use the same initial userspace layout. Addresses below are
virtual addresses; ELF load bias accounts for each image's first load segment.

| Region | Range or policy | Owner |
| --- | --- | --- |
| Selected loader | Starts at `0x100000`; at most 1 MiB | Kernel prepares the caller-selected loader from a temporary internal stable image |
| Bootstrap stack | `[0x3df000, 0x3ff000)`, with a guard page at each end | Kernel; the upper 64 KiB holds launch records, the lower 64 KiB holds loader C frames |
| Main executable | `[0x400000, 0x10000000)` | Shared image mapper; PIE is biased to the beginning, fixed-address images must fit |
| Dynamic dependencies | Allocated from `0x20000000`, with separate VMARs | Formal dynamic loader |
| Final stack and heap | Chosen by the application's Native runtime | `libsystem`; outside the initial loader contract |

Static application startup retires the loader and bootstrap stack after copying
launch records and switching to the final stack. Dynamic startup retains the
formal loader and retires only the bootstrap stack. No continuation may return
into a retired region.
