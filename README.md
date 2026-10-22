<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# HypeR runtime linker

This component loads every formal-environment Native application, including
static executables. It is installed as `ld-hyper-aarch64.so` or
`ld-hyper-riscv64.so`; the system root keeps it in `/lib64/`, alongside
the architecture library directory. `ProcessBuilder` receives an explicit
`READ|EXECUTE` File capability naming this loader. The kernel maps it and enters
with a bootstrap-channel handle, exactly as for the smaller
[stage-1 loader](../../bootstrap/stage1/userspace-loader/README.md).

The loader self-relocates before accessing initialized state, then uses the
96-byte startup record to bind its ExecutionContext, ObjectFactory and SystemInfo
handles before any context-dependent operation. It uses the internal
[ELF loading primitives](elf/README.md) to map the application
once and construct its entry vector. A dynamic application's `PT_INTERP` must
name `/lib64/ld-hyper-<arch>.so`; this is validated metadata, not an instruction
to open or map another loader. The former stack-only interpreter entry is no
longer supported. There is no loader service or second loader rendezvous.
Dependency policy, symbol lookup, relocation, constructors, RELRO and runtime
loading remain userspace responsibilities; the kernel performs no Native
application relocation.

Library lookup is capability-relative: the loader receives a Directory
handle for the deployment's architecture library directory (normally
`/lib64/<arch>-hyper-hyper/`) and accepts exact relative object
names, never ambient search paths or other architecture directories.
The Directory must carry `READ|EXECUTE|PROTECT`; each library is opened with
those rights and protected before reading its size or headers. Mapped segments
retain content protection after the File and parser token are closed. Clean
pages may be reclaimed and read back from the protected file; relocations write
only private COW pages. No whole-file snapshot VMO reaches the loader.
Initial dependencies are global; `hyper_dlopen_at` additionally supports local
symbol scopes. Dependency resolution is eager and bounded, with `RELA` and `RELR`
support and no writable-executable mapping transition.

Symbol lookup uses the ELF `DT_HASH` buckets and collision chains, including for
`dlsym`, so each imported symbol does not rescan every exported Rust symbol.
The loader validates the complete table range and bounds total chain traversal
before admission; lookups also retain index and traversal bounds if an
application later modifies metadata in its own writable mappings. Hashing selects
candidates within one object; global and dependency-scope traversal retain
visibility filtering and strong-over-weak selection. The table follows the
[System V ELF hash format](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html#hash).

The Native [`ldd` command](../../docs/usage/applications/ldd.md)
inspects interpreter and dependency metadata against the standard library layout
without executing the target. It does not replace loader symbol or relocation
validation, nor can it infer a different library Directory delegated to a process.

`hyper_dlclose` currently releases a logical caller reference but deliberately
does not run destructors or reclaim mappings (and therefore does not release
their file-content protections). This conservative lifetime rule
avoids invalidating code while other threads may still execute it; unload will
require an explicit process-wide quiescence protocol.

## Runtime initialization

For dynamic applications the loader resolves `hyper_runtime_start` directly
in the relocated `libhyper.so` and passes the entry vector and a non-returning
continuation. That vector carries the same invocation capabilities to the shared
runtime. It binds them before initializing the heap, then creates the final main
stack, copies startup data, switches SP and releases the kernel bootstrap
stack. It retains this loader's mappings: constructors, its continuation and
later `dlopen` calls still use them. `AT_BASE` identifies this already mapped
loader. Its statically linked primitives never initialize a second heap.

Static applications skip dependency loading and enter their own CRT with
`AT_BASE=0`. The static CRT performs relative relocation and invokes its linked
runtime, which retires both the temporary stack and this loader. No loader
continuation or private object table is used after that transfer.

The runtime acknowledges startup after mapping, relocation and final-stack
setup, before constructors or `main`. A queued success remains valid when a
short-lived child exits immediately afterward. Loading failures report status
through the bootstrap channel. After the owner's threads stop, process
teardown releases file protection even if external VMAR handles retain the
dead address space's pages; those views can no longer refill from the file.

## Architecture contracts

AArch64 supports RELATIVE, ABS64, GLOB_DAT and JUMP_SLOT relocations. RV64
requires LP64D ELF flags and supports RELATIVE, 64 and JUMP_SLOT; its JUMP_SLOT
calculation ignores the addend as required by the RISC-V psABI. COPY, TLS and
resolver relocations are rejected. Both backends share loading and lifetime
policy; only entry assembly and machine relocation rules differ.

## Host verification

Run `sh sdk/toolchain/scripts/check-dynamic-loader.sh` from the repository root.
`check-userspace-loader.sh` additionally exercises both channel-entry policies,
the maximum startup packet, interpreter admission and static/dynamic retirement
metadata on both architectures.
The architecture probe checks machine flags and relocation formulas. A second
probe compiles the production `rtld.c` directly, supplies bounded in-memory ELF
views and records Native syscall effects. It covers malformed dynamic metadata,
file bounds, hash collisions and malformed chains, symbol scope and visibility,
symbol indices, writable relocation targets, RELR cursor/work
limits, mapping failure cleanup and restoration of a failed load transaction.
The transaction retains pre-existing references and visibility while discarding
new dependency mappings in reverse order. It does not promise to undo arbitrary
constructor side effects.

Both ELF architectures run under UBSan; Linux CI also enables ASan. These tests
do not emulate page tables or prove the executable mapping/constructor path:
the Native dynamic-loading QEMU acceptance tests remain required.

## Service residency

The loader creates ordinary protected, reclaimable file mappings. A service
with explicit `LOCK_MEMORY` authority may populate and lock its own current
mappings before accepting work. `mlock` belongs to the VMAR contract, not loader
environment policy; it does not cover future mappings or later `dlopen` calls.
Services that must not fault into their own filesystem must establish residency
before readiness and lock any later file-backed additions explicitly. Unmap,
explicit unlock, and process teardown release their residency claims.
