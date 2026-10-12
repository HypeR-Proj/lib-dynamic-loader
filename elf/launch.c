/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
/* Shared Native loader protocol; no heap, TLS, global state or filesystem lookup. */
#include "launch.h"
#include <string.h>

#define AUXILIARY_COUNT 16
#define VECTOR_WORDS                                                                               \
	(1 + HYPER_LAUNCH_MAX_ARGUMENTS + 1 + HYPER_LAUNCH_MAX_ENVIRONMENT + 1 +                   \
	 AUXILIARY_COUNT * 2)
_Static_assert(MESSAGE_BYTES + HYPER_NATIVE_STARTUP_MAX_HANDLES * 16 +
			       VECTOR_WORDS * sizeof(uintptr_t) + 31 <
		       65536,
	       "startup packet and vector must fit the assembly scratch partition");

_Noreturn void elf_launch_fail(hyper_native_handle_t channel, hyper_native_status_t status)
{
	hyper_launch_result_t result = {.status = status};
	(void)hyper_byte_channel_write(channel, &result, sizeof(result));
	hyper_process_exit(status);
}

static int launch_data_valid(const hyper_launch_data_t *data, size_t size)
{
	if (size < sizeof(*data) || !data->argument_count ||
	    data->argument_count > HYPER_LAUNCH_MAX_ARGUMENTS ||
	    data->environment_count > HYPER_LAUNCH_MAX_ENVIRONMENT)
		return 0;
	size_t count = data->argument_count + data->environment_count;
	size_t first = sizeof(*data) + count * sizeof(uint32_t);
	if (first > size)
		return 0;
	const uint32_t *offsets = (const uint32_t *)(data + 1);
	for (size_t i = 0; i < count; ++i) {
		if (offsets[i] < first || offsets[i] >= size)
			return 0;
		const char *string = (const char *)data + offsets[i];
		size_t remaining = size - offsets[i];
		if (remaining > HYPER_LAUNCH_MAX_STRING_BYTES + 1)
			remaining = HYPER_LAUNCH_MAX_STRING_BYTES + 1;
		const char *end = memchr(string, 0, remaining);
		if (!end)
			return 0;
		if (i >= data->argument_count) {
			const char *equals = memchr(string, '=', (size_t)(end - string));
			if (!equals || equals == string)
				return 0;
		}
	}
	return 1;
}

/* Assembly reserves the upper 64 KiB for these records. All C frames stay
 * below that partition until the final one-way transfer. */
hyper_native_status_t elf_launch_receive(ElfLaunch *launch, hyper_native_handle_t channel,
					 uintptr_t stack_top)
{
	unsigned char *message = (void *)((stack_top - MESSAGE_BYTES) & ~(uintptr_t)15);
	hyper_call_result_t received = hyper_byte_channel_read(channel, message, MESSAGE_BYTES);
	if (received.status)
		return received.status;
	hyper_native_loader_startup_t *boot = (void *)message;
	if (received.value0 < sizeof(*boot) || boot->size != sizeof(*boot) ||
	    boot->handle_count > HYPER_NATIVE_STARTUP_MAX_HANDLES - 2 || !boot->executable ||
	    !boot->root_vmar || !boot->stack_vmar ||
	    boot->data_size > HYPER_NATIVE_PROCESS_STARTUP_DATA_MAX_BYTES ||
	    boot->flags & ~HYPER_NATIVE_LOADER_STARTUP_REPLY ||
	    received.value0 != sizeof(*boot) + boot->handle_count * 16 + boot->data_size ||
	    boot->stack_size < 128 * 1024 || boot->stack_base > UINTPTR_MAX - boot->stack_size ||
	    boot->stack_base + boot->stack_size != stack_top || boot->stack_base < IMAGE_PAGE)
		return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
	hyper_native_startup_handle_t *source = (void *)(boot + 1);
	hyper_launch_data_t *data = (void *)(source + boot->handle_count);
	if (boot->data_size && !launch_data_valid(data, boot->data_size))
		return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
	/* Root/stack handles are supplied separately by the kernel, not accepted
	 * from user-tagged input. Reject duplicate roles before runtime adoption. */
	hyper_native_startup_handle_t *handles = (void *)(message - (boot->handle_count + 2) * 16);
	for (size_t i = 0; i < boot->handle_count; ++i) {
		if (!source[i].purpose || source[i].flags || !source[i].handle ||
		    source[i].purpose == HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_ROOT_VMAR ||
		    source[i].purpose == HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_INITIAL_STACK_VMAR)
			return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
		for (size_t j = 0; j < i; ++j)
			if (source[i].purpose == source[j].purpose)
				return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
		handles[i] = source[i];
	}
	handles[boot->handle_count] = (hyper_native_startup_handle_t){
		.purpose = HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_ROOT_VMAR,
		.handle = boot->root_vmar};
	handles[boot->handle_count + 1] = (hyper_native_startup_handle_t){
		.purpose = HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_INITIAL_STACK_VMAR,
		.handle = boot->stack_vmar};
	*launch = (ElfLaunch){.boot = boot, .handles = handles, .data = data};
	return HYPER_NATIVE_STATUS_OK;
}

uintptr_t elf_launch_stack(const ElfLaunch *launch, const ElfImage *main,
			   hyper_native_handle_t channel, uintptr_t linker_base, int retire_loader)
{
	const hyper_native_loader_startup_t *boot = launch->boot;
	const hyper_launch_data_t *data = launch->data;
	hyper_native_startup_handle_t *handles = launch->handles;
	size_t argc = boot->data_size ? data->argument_count : 1;
	size_t envc = boot->data_size ? data->environment_count : 0;
	size_t words = 1 + argc + 1 + envc + 1 + AUXILIARY_COUNT * 2;
	uintptr_t sp = ((uintptr_t)handles - words * sizeof(uintptr_t)) & ~(uintptr_t)15;
	uintptr_t *out = (void *)sp;
	const uint32_t *offsets = (const void *)(data + 1);
	*out++ = argc;
	for (size_t i = 0; i < argc; ++i)
		*out++ = boot->data_size ? (uintptr_t)data + offsets[i] : (uintptr_t)"/init";
	*out++ = 0;
	for (size_t i = 0; i < envc; ++i)
		*out++ = (uintptr_t)data + offsets[argc + i];
	*out++ = 0;
#define AUX(key, value)                                                                            \
	do {                                                                                       \
		*out++ = (key);                                                                    \
		*out++ = (value);                                                                  \
	} while (0)
	AUX(3, main->program_headers);
	AUX(4, sizeof(Elf64_Phdr));
	AUX(5, main->header.phnum);
	AUX(6, IMAGE_PAGE);
	AUX(7, linker_base);
	AUX(9, main->entry);
	AUX(HYPER_AUXV_STARTUP_HANDLES, (uintptr_t)handles);
	AUX(HYPER_AUXV_STARTUP_HANDLE_COUNT, boot->handle_count + 2);
	AUX(HYPER_AUXV_INITIAL_STACK_BASE, boot->stack_base - IMAGE_PAGE);
	AUX(HYPER_AUXV_INITIAL_STACK_CAPACITY, boot->stack_size);
	AUX(HYPER_AUXV_INITIAL_STACK_SIZE, boot->stack_size);
	AUX(HYPER_AUXV_MAIN_STACK_SIZE, main->stack_size);
	AUX(HYPER_AUXV_LOADER_BASE, retire_loader ? boot->loader_base : 0);
	AUX(HYPER_AUXV_LOADER_SIZE, retire_loader ? boot->loader_size : 0);
	AUX(HYPER_AUXV_STARTUP_CHANNEL,
	    boot->flags & HYPER_NATIVE_LOADER_STARTUP_REPLY ? channel : 0);
	AUX(0, 0);
#undef AUX
	if (!(boot->flags & HYPER_NATIVE_LOADER_STARTUP_REPLY))
		(void)hyper_handle_close(channel);
	return sp;
}
