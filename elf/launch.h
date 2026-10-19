/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef HYPER_ELF_LOADER_LAUNCH_H
#define HYPER_ELF_LOADER_LAUNCH_H
#include "image.h"
#include <hyper/launch.h>

#define MESSAGE_BYTES                                                                              \
	(sizeof(hyper_native_loader_startup_t) + 256 * 16 +                                        \
	 HYPER_NATIVE_PROCESS_STARTUP_DATA_MAX_BYTES)

typedef struct {
	hyper_native_loader_startup_t *boot;
	hyper_native_startup_handle_t *handles;
	hyper_launch_data_t *data;
} ElfLaunch;

/* Only accepted messages expose these child-owned handles to either loader. */
hyper_native_status_t elf_launch_receive(ElfLaunch *launch, hyper_native_handle_t channel,
					 uintptr_t stack_top);
/* This loader option affects only the child's quota-charged mappings. */
uintptr_t elf_launch_stack(const ElfLaunch *launch, const ElfImage *main,
			   hyper_native_handle_t channel, uintptr_t linker_base, int retire_loader);
_Noreturn void elf_launch_fail(hyper_native_handle_t channel, hyper_native_handle_t execution,
			       hyper_native_status_t status);
#endif
