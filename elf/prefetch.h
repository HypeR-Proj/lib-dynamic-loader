/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef HYPER_ELF_LOADER_PREFETCH_H
#define HYPER_ELF_LOADER_PREFETCH_H
#include <hyper/elf.h>
#include <hyper/syscall.h>

/* Prepare the required header page without advancing the sequential predictor.
 * Header/PHDR reads then hit cache instead of starting a competing guessed
 * window before the loader can supply its validated range plan. */
static void elf_prefetch_header(hyper_native_handle_t file, uint64_t file_size)
{
	if (file_size < sizeof(Elf64_Ehdr))
		return;
	uint64_t length = file_size < 4096 ? file_size : 4096;
	(void)hyper_file_prefetch(file, 0, length);
}

/* Call only after validating every PT_LOAD and acquiring content protection.
 * File order is independent of PHDR order and virtual permissions. Merge only
 * overlapping/adjacent file pages; BSS and holes require no speculative I/O.
 * Bound preparation per image so a large object cannot churn the whole cache
 * before mapping begins. Remaining data uses ordinary bounded demand batches. */
static void elf_prefetch_loads(hyper_native_handle_t file, uint64_t file_size,
			       const Elf64_Phdr *phdr, size_t count)
{
	const uint64_t page = 4096;
	uint64_t cursor = 0, budget = HYPER_NATIVE_FILE_MAX_PREFETCH_BYTES;
	for (size_t i = 0; i < count; ++i) {
		const Elf64_Phdr *p = &phdr[i];
		if (p->type == 1 && p->memsz && p->filesz &&
		    (p->offset > file_size || p->filesz > file_size - p->offset))
			return;
	}
	while (budget) {
		uint64_t start = UINT64_MAX, end = 0;
		for (size_t i = 0; i < count; ++i) {
			const Elf64_Phdr *p = &phdr[i];
			if (p->type != 1 || !p->memsz || !p->filesz)
				continue;
			uint64_t low = p->offset - p->offset % page;
			uint64_t high = p->offset + p->filesz;
			uint64_t padding = (page - high % page) % page;
			high += padding < file_size - high ? padding : file_size - high;
			if (high <= cursor)
				continue;
			if (low < cursor)
				low = cursor;
			if (low < start) {
				start = low;
				end = high;
			}
		}
		if (start == UINT64_MAX)
			return;
		/* Unsorted headers can reveal a bridge only after another extension. */
		uint64_t previous;
		do {
			previous = end;
			for (size_t i = 0; i < count; ++i) {
				const Elf64_Phdr *p = &phdr[i];
				if (p->type != 1 || !p->memsz || !p->filesz)
					continue;
				uint64_t low = p->offset - p->offset % page;
				uint64_t high = p->offset + p->filesz;
				uint64_t padding = (page - high % page) % page;
				high += padding < file_size - high ? padding : file_size - high;
				if (low <= end && high > end)
					end = high;
			}
		} while (end != previous);
		uint64_t length = end - start;
		if (length > budget)
			length = budget;
		hyper_call_result_t result = hyper_file_prefetch(file, start, length);
		/* A hint never substitutes for demand validation or successful mapping. */
		if (result.status || result.value0 != length)
			return;
		cursor = start + length;
		budget -= length;
	}
}
#endif
