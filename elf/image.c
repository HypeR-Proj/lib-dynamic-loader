/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
#include "image.h"
#include "prefetch.h"
#include <string.h>

#define BAD_IMAGE HYPER_NATIVE_STATUS_INVALID_ARGUMENT
#define PT_LOAD 1
#define PT_INTERP 3
#define PT_TLS 7
#define PT_GNU_STACK UINT32_C(0x6474e551)

static uintptr_t down(uintptr_t value)
{
	return value & ~(uintptr_t)(IMAGE_PAGE - 1);
}

static uintptr_t up(uintptr_t value)
{
	return (value + IMAGE_PAGE - 1) & ~(uintptr_t)(IMAGE_PAGE - 1);
}

static hyper_native_status_t read_image(hyper_native_handle_t file, uint64_t size, uint64_t offset,
					void *output, size_t count)
{
	if (offset > size || count > size - offset)
		return BAD_IMAGE;
	while (count) {
		hyper_call_result_t read = hyper_file_read_at(file, offset, output, count);
		if (read.status)
			return read.status;
		if (!read.value0 || read.value0 > count)
			return BAD_IMAGE;
		output = (unsigned char *)output + read.value0;
		offset += read.value0;
		count -= read.value0;
	}
	return HYPER_NATIVE_STATUS_OK;
}

static int header_valid(const Elf64_Ehdr *header)
{
	const unsigned char identity[] = {127, 'E', 'L', 'F', 2, 1, 1, 63};
	if (memcmp(header->ident, identity, sizeof(identity)) || header->ident[8] ||
	    (header->type != 2 && header->type != 3) || header->version != 1 ||
	    header->ehsize != sizeof(*header) || header->phentsize != sizeof(Elf64_Phdr) ||
	    !header->phnum || header->phnum > IMAGE_MAX_PHDR || header->phoff < sizeof(*header))
		return 0;
#if defined(__aarch64__)
	return header->machine == 183 && header->flags == 0 && !(header->entry % 4);
#elif defined(__riscv) && __riscv_xlen == 64
	return header->machine == 243 && (header->flags & ~1u) == 4 && !(header->entry % 2);
#else
#error Unsupported Native userspace-loader architecture
#endif
}

/* Validate all ranges before creating mappings. In particular, page-rounded
 * overlap would make segment permissions and zero-fill order-dependent. */
static hyper_native_status_t inspect(ElfImage *image, hyper_native_handle_t file,
				     uint64_t file_size, uintptr_t start, uintptr_t limit,
				     const char *interpreter)
{
	uintptr_t minimum = UINTPTR_MAX, maximum = 0;
	unsigned saw_interpreter = 0, saw_stack = 0;
	for (size_t i = 0; i < image->header.phnum; ++i) {
		const Elf64_Phdr *p = &image->phdr[i];
		if (p->type == PT_TLS && p->memsz)
			return HYPER_NATIVE_STATUS_NOT_SUPPORTED;
		if (p->type == PT_GNU_STACK) {
			if (saw_stack++ || (p->flags & 1))
				return BAD_IMAGE;
			image->stack_size = p->memsz;
		}
		if (p->type == PT_INTERP) {
			if (saw_interpreter++ || p->filesz < 2 ||
			    p->filesz > sizeof(image->interpreter))
				return BAD_IMAGE;
			hyper_native_status_t status = read_image(file, file_size, p->offset,
								  image->interpreter, p->filesz);
			if (status)
				return status;
			if (image->interpreter[p->filesz - 1] ||
			    memchr(image->interpreter, 0, p->filesz - 1))
				return BAD_IMAGE;
			if (!interpreter || strcmp(image->interpreter, interpreter))
				return HYPER_NATIVE_STATUS_NOT_SUPPORTED;
		}
		if (p->type != PT_LOAD)
			continue;
		if (!p->memsz) {
			if (p->filesz)
				return BAD_IMAGE;
			continue;
		}
		if ((p->flags & ~7u) || !(p->flags & 4) || (p->flags & 3) == 3 ||
		    p->filesz > p->memsz || p->offset > file_size ||
		    p->filesz > file_size - p->offset || p->vaddr >= limit ||
		    p->memsz > limit - p->vaddr ||
		    p->vaddr % IMAGE_PAGE != p->offset % IMAGE_PAGE ||
		    (p->align > 1 && (p->align > IMAGE_PAGE || (p->align & (p->align - 1)))))
			return BAD_IMAGE;
		uintptr_t first = down(p->vaddr), end = up(p->vaddr + p->memsz);
		for (size_t j = 0; j < i; ++j) {
			const Elf64_Phdr *q = &image->phdr[j];
			if (q->type == PT_LOAD && q->memsz && first < up(q->vaddr + q->memsz) &&
			    down(q->vaddr) < end)
				return BAD_IMAGE;
		}
		if (first < minimum)
			minimum = first;
		if (end > maximum)
			maximum = end;
	}
	if (minimum == UINTPTR_MAX || maximum <= minimum || maximum - minimum > 64 * 1024 * 1024)
		return BAD_IMAGE;
	if (image->header.type == 3) {
		if (minimum > start)
			return BAD_IMAGE;
		image->base = start - minimum;
	} else if (minimum < start) {
		return BAD_IMAGE;
	}
	if (maximum > limit - image->base || image->header.entry > UINTPTR_MAX - image->base)
		return BAD_IMAGE;
	image->end = image->base + maximum;
	image->entry = image->base + image->header.entry;
	int entry_valid = 0;
	for (size_t i = 0; i < image->header.phnum; ++i) {
		const Elf64_Phdr *p = &image->phdr[i];
		if (p->type != PT_LOAD)
			continue;
		if ((p->flags & 1) && image->header.entry >= p->vaddr &&
		    image->header.entry - p->vaddr < p->filesz)
			entry_valid = 1;
		uint64_t phsize = image->header.phnum * sizeof(Elf64_Phdr);
		if (image->header.phoff >= p->offset &&
		    image->header.phoff - p->offset <= p->filesz &&
		    phsize <= p->filesz - (image->header.phoff - p->offset))
			image->program_headers =
				image->base + p->vaddr + image->header.phoff - p->offset;
	}
	return entry_valid && image->program_headers ? 0 : BAD_IMAGE;
}

static hyper_native_status_t load_protected_image(ElfImage *image, hyper_native_handle_t root,
						  hyper_native_handle_t file,
						  hyper_native_handle_t protection,
						  uint64_t file_size, uintptr_t start,
						  uintptr_t limit, const char *interpreter)
{
	memset(image, 0, sizeof(*image));
	elf_prefetch_header(file, file_size);
	hyper_native_status_t status =
		read_image(file, file_size, 0, &image->header, sizeof(image->header));
	if (status)
		return status;
	if (!header_valid(&image->header))
		return BAD_IMAGE;
	status = read_image(file, file_size, image->header.phoff, image->phdr,
			    image->header.phnum * sizeof(Elf64_Phdr));
	if (status)
		return status;
	status = inspect(image, file, file_size, start, limit, interpreter);
	if (status)
		return status;
	elf_prefetch_loads(file, file_size, image->phdr, image->header.phnum);
	/* The main image uses root mappings. The runtime linker seals its RELRO
	 * through ROOT_VMAR; dependency images have separate VMARs owned by that
	 * linker. Admission above separates the application and loader ranges. */
	for (size_t i = 0; i < image->header.phnum; ++i) {
		const Elf64_Phdr *p = &image->phdr[i];
		if (p->type != PT_LOAD || !p->memsz)
			continue;
		uint32_t permissions = HYPER_NATIVE_VMAR_PERMISSION_READ;
		if (p->flags & 1)
			permissions |= HYPER_NATIVE_VMAR_PERMISSION_EXECUTE;
		if (p->flags & 2)
			permissions |= HYPER_NATIVE_VMAR_PERMISSION_WRITE;
		hyper_native_private_mapping_t mapping = {
			.source_offset = down(p->offset),
			.source_length = p->filesz,
			.address = down(image->base + p->vaddr),
			.size = up(p->vaddr % IMAGE_PAGE + p->memsz),
			.data_offset = p->vaddr % IMAGE_PAGE,
			.permissions = permissions,
			.mode = HYPER_NATIVE_PRIVATE_MAPPING_COPY_ON_WRITE,
		};
		status = hyper_vmar_map_file(root, file, protection, &mapping, sizeof(mapping));
		if (status)
			break;
	}
	return status;
}

/* Acquire before the first metadata or content read. A successful file mapping
 * keeps its own protection reference; closing this parser token is always safe. */
hyper_native_status_t elf_image_load(ElfImage *image, hyper_native_handle_t root,
				     hyper_native_handle_t file, uintptr_t start, uintptr_t limit,
				     const char *interpreter)
{
	hyper_call_result_t protection = hyper_file_protect(file);
	if (protection.status)
		return protection.status;
	hyper_native_status_t status = load_protected_image(
		image, root, file, protection.value0, protection.value1, start, limit, interpreter);
	(void)hyper_handle_close(protection.value0);
	return status;
}
