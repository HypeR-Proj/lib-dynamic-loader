/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
/* Formal-environment entry: the kernel already mapped this loader. */
#include "launch.h"
#include <hyper/relocate.h>
#include <hyper/invocation.h>

#if defined(__aarch64__)
#define INTERPRETER "/lib64/ld-hyper-aarch64.so"
#elif defined(__riscv) && __riscv_xlen == 64
#define INTERPRETER "/lib64/ld-hyper-riscv64.so"
#else
#error Unsupported Native loader architecture
#endif

extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));
extern _Noreturn void __hyper_rtld_enter(uintptr_t stack, uintptr_t entry);
extern _Noreturn __attribute__((visibility("hidden"))) void
__hyper_rtld_link(const ElfImage *image, const ElfLaunch *launch, hyper_native_handle_t channel);

_Noreturn void __hyper_rtld_start(hyper_native_handle_t channel, uintptr_t stack_top)
{
	/* Do not access writable globals, external data or GOT pointers before this. */
	if (!hyper_elf_self_relocate(&__ehdr_start))
		__builtin_trap();
	ElfLaunch launch;
	hyper_native_status_t status = elf_launch_receive(&launch, channel, stack_top);
	if (status)
		elf_launch_fail(channel, launch.boot ? launch.boot->execution_context : 0, status);
	status = hyper_native_bind_invocation_handles(launch.boot->execution_context,
						      launch.boot->object_factory,
						      launch.boot->system_info);
	if (status)
		elf_launch_fail(channel, launch.boot->execution_context, status);
	ElfImage main;
	status = elf_image_load(&main, launch.boot->root_vmar, launch.boot->executable, 0x400000,
				0x10000000, INTERPRETER);
	(void)hyper_handle_close(launch.boot->executable);
	if (status)
		elf_launch_fail(channel, launch.boot->execution_context, status);
	if (!main.interpreter[0]) {
		/* AT_BASE=0 keeps static CRT self relocation enabled. Its runtime retires
		 * this loader after switching stacks; no loader continuation survives. */
		uintptr_t stack = elf_launch_stack(&launch, &main, channel, 0, 1);
		__hyper_rtld_enter(stack, main.entry);
	}
	__hyper_rtld_link(&main, &launch, channel);
}
