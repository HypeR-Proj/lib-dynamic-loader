<!--
SPDX-FileCopyrightText: 2026 roolrz
SPDX-License-Identifier: Apache-2.0
-->

# Application I/O and authority

## Interactive transport

Physical byte transport belongs to `console-raw`; formal line discipline belongs
to `terminal-service`. Session-manager supervises the terminal and shell, without
relaying input or output. The shell gives a scoped terminal lease to a command
with unredirected terminal stdin; in a pipeline this is the first stage.
It becomes active only after its Process observer is bound; termination restores
the parent settings and preserves unconsumed typeahead. File redirections and
pipeline edges remain separate binary streams.

Terminal stdin uses a connector and one private request/response connection per
process. Ordinary `Read` requests only the caller's byte count instead of
prefetching terminal input into Rust's global stdin buffer. The generic runtime
does not interpret CR or Ctrl-D: canonical EOF, conversion, raw binary handling
and read timing are implemented by the formal terminal. `top` and `vmm console`
select raw mode and use the same runtime input owner as `std::io`.
See [Native terminals](https://hyper-proj.github.io/terminal-service/docs/terminal.html) and the
[runtime contract](https://github.com/HypeR-Proj/lib-system/blob/main/README.md).

`make test-console ARCH=aarch64` checks interactive shell typeahead, EOF,
std child inheritance, binary pipes, paced input, idle wakeups and return from
full-screen/VM clients. `make test-terminal ARCH=aarch64` additionally checks
terminal metadata, read timeouts, canonical EOF, all 256 raw byte values and
restoration after a raw-mode child exits. `terminal-probe` is included only in
development images. `QEMU_CPUS` selects the CPU count;
`CONSOLE_TYPED_ROUNDS` overrides the default 40 paced commands.


## Command authority

The session delegates process-construction authority to the shell. Commands
inherit attenuated root and cwd Directory capabilities, standard streams and
authorized process resources; path traversal is bounded by the delegated root,
not the initial cwd. Inspector delegation depends on the resolved executable
path: `/bin/ps` receives task inspection, `/bin/free` and `/bin/memstat` memory
inspection, and `/bin/top` task, memory and CPU inspection.
`/bin/perf` alone receives CPU profiling control and call-chain inspection.
`/bin/handle` receives object
inspection including privileged details, plus task inspection for process
lookup. Copying or
renaming a tool to another path does not acquire those grants.
The trusted `/bin/sh` path receives the shell's delegatable diagnostic
and control capabilities, so nested shells keep the same tool access. Every
formal child uses the system dynamic loader, including static executables; the
shell retains no bootstrap loader or archive directory.
