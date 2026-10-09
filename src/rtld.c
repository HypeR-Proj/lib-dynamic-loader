/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */

/*
 * Bounded HypeR Native runtime linker.
 *
 * The userspace loader maps the main image and this interpreter. This file owns all
 * dependency lookup and symbol policy. It intentionally supports only eager
 * Native RELA/RELR relocation and capability-relative library lookup.
 */

#include <hyper/launch.h>
#include <hyper/relocate.h>
#include <hyper/dlfcn.h>
#include <hyper/syscall.h>
#include <stddef.h>
#include <stdint.h>

#define EI_NIDENT 16
#define ET_DYN 3
#include "arch.h"
#define PT_LOAD 1
#define PT_DYNAMIC 2
#define PT_PHDR 6
#define PT_TLS 7
#define PT_GNU_STACK UINT32_C(0x6474e551)
#define PT_GNU_RELRO UINT32_C(0x6474e552)
#define PF_X 1
#define PF_W 2
#define PF_R 4
#define DT_NULL 0
#define DT_NEEDED 1
#define DT_HASH 4
#define DT_STRTAB 5
#define DT_SYMTAB 6
#define DT_RELA 7
#define DT_RELASZ 8
#define DT_RELAENT 9
#define DT_STRSZ 10
#define DT_SYMENT 11
#define DT_INIT 12
#define DT_REL 17
#define DT_RELSZ 18
#define DT_RELENT 19
#define DT_INIT_ARRAY 25
#define DT_INIT_ARRAYSZ 27
#define DT_TEXTREL 22
#define DT_FLAGS 30
#define DT_PLTREL 20
#define DT_JMPREL 23
#define DT_PLTRELSZ 2
#define DT_RELR 36
#define DT_RELRSZ 35
#define DT_RELRENT 37
#define DF_TEXTREL UINT64_C(0x4)
#define STB_LOCAL 0
#define STB_WEAK 2
#define STV_DEFAULT 0
#define STV_PROTECTED 3
#define SHN_UNDEF 0
#define SHN_ABS UINT16_C(0xfff1)
#define PAGE_SIZE UINT64_C(4096)
#define MAX_OBJECTS 16
#define MAX_PROGRAM_HEADERS 32
#define MAX_NEEDED 16
#define MAX_NAME_BYTES 127
#define MAX_RELOCATIONS 1048576
#define LIBRARY_BASE UINT64_C(0x20000000)
#define LIBRARY_LIMIT UINT64_C(0xe0000000)
#define AT_NULL 0
#define AT_PHDR 3
#define AT_PHENT 4
#define AT_PHNUM 5
#define AT_BASE 7
#define AT_ENTRY 9

typedef struct {
	const char *strings;
	uint64_t string_size;
	const Elf64_Sym *symbols;
	uint64_t symbol_count;
	const uint32_t *buckets;
	const uint32_t *chains;
	uint32_t bucket_count;
	const Elf64_Rela *rela;
	uint64_t rela_count;
	const Elf64_Rela *plt_rela;
	uint64_t plt_rela_count;
	const uint64_t *relr;
	uint64_t relr_count;
	uint64_t needed[MAX_NEEDED];
	size_t needed_count;
	uintptr_t init;
	const uintptr_t *init_array;
	size_t init_array_count;
} DynamicInfo;

typedef struct Object {
	char name[MAX_NAME_BYTES + 1];
	uintptr_t base;
	uintptr_t map_start;
	uintptr_t map_end;
	hyper_native_handle_t vmar;
	const Elf64_Phdr *phdr;
	size_t phnum;
	Elf64_Phdr owned_phdr[MAX_PROGRAM_HEADERS];
	DynamicInfo dynamic;
	struct Object *dependencies[MAX_NEEDED];
	uint32_t references;
	uint32_t flags;
	unsigned relocated : 1;
	unsigned initialized : 1;
} Object;

static Object objects[MAX_OBJECTS];
static size_t object_count;
static uintptr_t next_library_address = LIBRARY_BASE;
static hyper_native_handle_t library_directory;
static hyper_native_handle_t root_vmar;
static hyper_native_handle_t diagnostic_console;
static const char *last_error;
static unsigned char loader_lock;

static size_t string_length(const char *value, size_t maximum);

static void report_startup_failure(void)
{
	static const char prefix[] = "HypeR dynamic-loader: ";
	static const char fallback[] = "startup failed";
	char output[sizeof(prefix) + MAX_NAME_BYTES + 1];
	if (diagnostic_console == 0) {
		return;
	}
	const char *message = last_error == NULL ? fallback : last_error;
	size_t position = 0;
	for (size_t index = 0; index < sizeof(prefix) - 1; ++index) {
		output[position++] = prefix[index];
	}
	size_t message_length = string_length(message, MAX_NAME_BYTES);
	for (size_t index = 0; index < message_length; ++index) {
		output[position++] = message[index];
	}
	output[position++] = '\n';
	(void)hyper_console_write(diagnostic_console, output, position);
}

static uintptr_t align_down(uintptr_t value)
{
	return value & ~(PAGE_SIZE - 1);
}

static uintptr_t align_up(uintptr_t value)
{
	if (value > UINTPTR_MAX - (PAGE_SIZE - 1)) {
		return 0;
	}
	return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
}

static int add_unsigned(uintptr_t base, uint64_t offset, uintptr_t *result)
{
	if (offset > UINTPTR_MAX - base) {
		return 0;
	}
	*result = base + (uintptr_t)offset;
	return 1;
}

static int add_signed(uintptr_t base, int64_t offset, uintptr_t *result)
{
	if (offset >= 0) {
		return add_unsigned(base, (uint64_t)offset, result);
	}
	uint64_t magnitude = (uint64_t)(-(offset + 1)) + 1;
	if (magnitude > base) {
		return 0;
	}
	*result = base - (uintptr_t)magnitude;
	return 1;
}

static size_t string_length(const char *value, size_t maximum)
{
	size_t length = 0;
	while (length < maximum && value[length] != '\0') {
		++length;
	}
	return length;
}

static int string_equal(const char *left, const char *right)
{
	size_t index = 0;
	while (left[index] == right[index]) {
		if (left[index] == '\0') {
			return 1;
		}
		++index;
	}
	return 0;
}

static void copy_name(char *destination, const char *source)
{
	size_t length = string_length(source, MAX_NAME_BYTES);
	for (size_t index = 0; index < length; ++index) {
		destination[index] = source[index];
	}
	destination[length] = '\0';
}

static void lock_loader(void)
{
	while (__atomic_test_and_set(&loader_lock, __ATOMIC_ACQUIRE)) {
		(void)hyper_native_call6(HYPER_NATIVE_SYS_THREAD_YIELD, 0, 0, 0, 0, 0, 0);
	}
}

static void unlock_loader(void)
{
	__atomic_clear(&loader_lock, __ATOMIC_RELEASE);
}

static int address_in_object(const Object *object, uintptr_t address, size_t length, uint32_t flags)
{
	if (length > UINTPTR_MAX - address) {
		return 0;
	}
	uintptr_t end = address + length;
	for (size_t index = 0; index < object->phnum; ++index) {
		const Elf64_Phdr *segment = &object->phdr[index];
		if (segment->type != PT_LOAD || (segment->flags & flags) != flags) {
			continue;
		}
		uintptr_t start = 0;
		if (add_unsigned(object->base, segment->vaddr, &start) &&
		    segment->memsz <= UINTPTR_MAX - start && start <= address &&
		    end <= start + segment->memsz) {
			return 1;
		}
	}
	return 0;
}

static void *object_pointer(const Object *object, uint64_t value, size_t length)
{
	if (value > UINTPTR_MAX - object->base) {
		return NULL;
	}
	uintptr_t address = object->base + value;
	return address_in_object(object, address, length, PF_R) ? (void *)address : NULL;
}

static int pointer_aligned(const void *pointer, size_t alignment)
{
	return ((uintptr_t)pointer & (alignment - 1)) == 0;
}

static int read_exact(hyper_native_handle_t snapshot, uint64_t byte_size, uint64_t offset,
		      void *output, size_t length)
{
	if (offset > byte_size || length > byte_size - offset) {
		return 0;
	}
	return hyper_vmo_read(snapshot, offset, output, length) == HYPER_NATIVE_STATUS_OK;
}

static int parse_symbol_hash(Object *object, uint64_t address)
{
	const uint32_t *header = object_pointer(object, address, 2 * sizeof(uint32_t));
	if (header == NULL || !pointer_aligned(header, _Alignof(uint32_t)) || header[0] == 0 ||
	    header[1] == 0) {
		last_error = "invalid symbol hash";
		return 0;
	}
	uint32_t bucket_count = header[0];
	uint32_t symbol_count = header[1];
	uint64_t words = UINT64_C(2) + bucket_count + symbol_count;
	if (words > SIZE_MAX / sizeof(uint32_t) ||
	    object_pointer(object, address, (size_t)words * sizeof(uint32_t)) == NULL) {
		last_error = "symbol hash outside image";
		return 0;
	}
	const uint32_t *buckets = header + 2;
	const uint32_t *chains = buckets + bucket_count;
	/* Every reachable symbol belongs to one bucket. A single table-wide
	 * budget bounds validation even for cyclic or overlapping hostile chains. */
	uint32_t remaining = symbol_count - 1;
	for (uint32_t bucket = 0; bucket < bucket_count; ++bucket) {
		for (uint32_t index = buckets[bucket]; index != 0; index = chains[index]) {
			if (index >= symbol_count || remaining == 0) {
				last_error = "invalid symbol hash chain";
				return 0;
			}
			--remaining;
		}
	}
	object->dynamic.buckets = buckets;
	object->dynamic.chains = chains;
	object->dynamic.bucket_count = bucket_count;
	object->dynamic.symbol_count = symbol_count;
	return 1;
}

static int parse_dynamic(Object *object)
{
	const Elf64_Dyn *table = NULL;
	size_t table_count = 0;
	for (size_t index = 0; index < object->phnum; ++index) {
		const Elf64_Phdr *segment = &object->phdr[index];
		if (segment->type == PT_DYNAMIC) {
			if (segment->memsz % sizeof(*table) != 0) {
				last_error = "misaligned dynamic table size";
				return 0;
			}
			table = object_pointer(object, segment->vaddr, (size_t)segment->memsz);
			if (table != NULL && !pointer_aligned(table, _Alignof(Elf64_Dyn))) {
				last_error = "misaligned dynamic table";
				return 0;
			}
			table_count = (size_t)(segment->memsz / sizeof(*table));
			break;
		}
	}
	if (table == NULL || table_count == 0) {
		last_error = "missing dynamic table";
		return 0;
	}

	uint64_t hash = 0;
	uint64_t strings = 0;
	uint64_t symbols = 0;
	uint64_t rela = 0;
	uint64_t rela_size = 0;
	uint64_t rela_entry = 0;
	uint64_t plt_rela = 0;
	uint64_t plt_rela_size = 0;
	uint64_t plt_kind = 0;
	uint64_t relr = 0;
	uint64_t relr_size = 0;
	uint64_t relr_entry = 0;
	uint64_t init_array = 0;
	uint64_t init_array_size = 0;
	int terminated = 0;
	for (size_t index = 0; index < table_count; ++index) {
		uint64_t value = table[index].value;
		switch (table[index].tag) {
		case DT_NULL:
			terminated = 1;
			index = table_count;
			break;
		case DT_NEEDED:
			if (object->dynamic.needed_count == MAX_NEEDED) {
				last_error = "too many dependencies";
				return 0;
			}
			object->dynamic.needed[object->dynamic.needed_count++] = value;
			break;
		case DT_HASH:
			hash = value;
			break;
		case DT_STRTAB:
			strings = value;
			break;
		case DT_STRSZ:
			object->dynamic.string_size = value;
			break;
		case DT_SYMTAB:
			symbols = value;
			break;
		case DT_SYMENT:
			if (value != sizeof(Elf64_Sym)) {
				last_error = "invalid symbol entry";
				return 0;
			}
			break;
		case DT_RELA:
			rela = value;
			break;
		case DT_RELASZ:
			rela_size = value;
			break;
		case DT_RELAENT:
			rela_entry = value;
			break;
		case DT_REL:
		case DT_RELSZ:
		case DT_RELENT:
			last_error = "REL relocations are unsupported";
			return 0;
		case DT_JMPREL:
			plt_rela = value;
			break;
		case DT_PLTRELSZ:
			plt_rela_size = value;
			break;
		case DT_PLTREL:
			plt_kind = value;
			break;
		case DT_RELR:
			relr = value;
			break;
		case DT_RELRSZ:
			relr_size = value;
			break;
		case DT_RELRENT:
			relr_entry = value;
			break;
		case DT_INIT:
			if (!add_unsigned(object->base, value, &object->dynamic.init)) {
				last_error = "initialization function overflow";
				return 0;
			}
			break;
		case DT_INIT_ARRAY:
			init_array = value;
			break;
		case DT_INIT_ARRAYSZ:
			init_array_size = value;
			break;
		case DT_TEXTREL:
			last_error = "text relocations are unsupported";
			return 0;
		case DT_FLAGS:
			if ((value & DF_TEXTREL) != 0) {
				last_error = "text relocations are unsupported";
				return 0;
			}
			break;
		default:
			break;
		}
	}
	if (!terminated || hash == 0 || strings == 0 || symbols == 0 ||
	    object->dynamic.string_size == 0) {
		last_error = "incomplete dynamic metadata";
		return 0;
	}
	if (!parse_symbol_hash(object, hash)) {
		return 0;
	}
	if (object->dynamic.symbol_count > SIZE_MAX / sizeof(Elf64_Sym)) {
		last_error = "symbol table size overflow";
		return 0;
	}
	object->dynamic.strings =
		object_pointer(object, strings, (size_t)object->dynamic.string_size);
	object->dynamic.symbols = object_pointer(
		object, symbols, (size_t)object->dynamic.symbol_count * sizeof(Elf64_Sym));
	if (object->dynamic.strings == NULL || object->dynamic.symbols == NULL) {
		last_error = "symbol table outside image";
		return 0;
	}
	if (!pointer_aligned(object->dynamic.symbols, _Alignof(Elf64_Sym))) {
		last_error = "misaligned symbol table";
		return 0;
	}
	if (rela_size != 0) {
		if (rela_entry != sizeof(Elf64_Rela) || rela_size % sizeof(Elf64_Rela) != 0) {
			last_error = "invalid RELA table";
			return 0;
		}
		object->dynamic.rela = object_pointer(object, rela, (size_t)rela_size);
		object->dynamic.rela_count = (size_t)(rela_size / sizeof(Elf64_Rela));
		if (object->dynamic.rela != NULL &&
		    !pointer_aligned(object->dynamic.rela, _Alignof(Elf64_Rela))) {
			last_error = "misaligned RELA table";
			return 0;
		}
	}
	if (plt_rela_size != 0) {
		if (plt_kind != DT_RELA || plt_rela_size % sizeof(Elf64_Rela) != 0) {
			last_error = "unsupported PLT relocation";
			return 0;
		}
		object->dynamic.plt_rela = object_pointer(object, plt_rela, (size_t)plt_rela_size);
		object->dynamic.plt_rela_count = (size_t)(plt_rela_size / sizeof(Elf64_Rela));
		if (object->dynamic.plt_rela != NULL &&
		    !pointer_aligned(object->dynamic.plt_rela, _Alignof(Elf64_Rela))) {
			last_error = "misaligned PLT relocation table";
			return 0;
		}
	}
	if (relr_size != 0) {
		if (relr_entry != sizeof(uint64_t) || relr_size % sizeof(uint64_t) != 0) {
			last_error = "invalid RELR table";
			return 0;
		}
		object->dynamic.relr = object_pointer(object, relr, (size_t)relr_size);
		object->dynamic.relr_count = (size_t)(relr_size / sizeof(uint64_t));
		if (object->dynamic.relr != NULL &&
		    !pointer_aligned(object->dynamic.relr, _Alignof(uint64_t))) {
			last_error = "misaligned RELR table";
			return 0;
		}
	}
	if ((object->dynamic.rela_count != 0 && object->dynamic.rela == NULL) ||
	    (object->dynamic.plt_rela_count != 0 && object->dynamic.plt_rela == NULL) ||
	    (object->dynamic.relr_count != 0 && object->dynamic.relr == NULL)) {
		last_error = "relocation table outside image";
		return 0;
	}
	if (init_array_size != 0) {
		if (init_array_size % sizeof(uintptr_t) != 0) {
			last_error = "invalid initialization array";
			return 0;
		}
		object->dynamic.init_array =
			object_pointer(object, init_array, (size_t)init_array_size);
		object->dynamic.init_array_count = (size_t)(init_array_size / sizeof(uintptr_t));
		if (object->dynamic.init_array == NULL ||
		    !pointer_aligned(object->dynamic.init_array, _Alignof(uintptr_t))) {
			last_error = "initialization array outside image";
			return 0;
		}
	}
	return 1;
}

static const char *dynamic_string(const Object *object, uint64_t offset)
{
	if (offset >= object->dynamic.string_size) {
		return NULL;
	}
	const char *value = object->dynamic.strings + offset;
	size_t maximum = (size_t)(object->dynamic.string_size - offset);
	return string_length(value, maximum) < maximum ? value : NULL;
}

static Object *find_object(const char *name)
{
	for (size_t index = 0; index < object_count; ++index) {
		if (string_equal(objects[index].name, name)) {
			return &objects[index];
		}
	}
	return NULL;
}

static Object *object_from_handle(void *handle)
{
	uintptr_t value = (uintptr_t)handle;
	uintptr_t first = (uintptr_t)&objects[0];
	uintptr_t limit = (uintptr_t)&objects[object_count];
	if (value < first || value >= limit || (value - first) % sizeof(Object) != 0) {
		return NULL;
	}
	return &objects[(value - first) / sizeof(Object)];
}

static uint32_t symbol_hash(const char *name)
{
	uint32_t hash = 0;
	for (const unsigned char *cursor = (const unsigned char *)name; *cursor != 0; ++cursor) {
		hash = (hash << 4) + *cursor;
		uint32_t high = hash & UINT32_C(0xf0000000);
		hash = (hash ^ (high >> 24)) & ~high;
	}
	return hash;
}

static void *find_symbol_in(const Object *object, const char *name, int *weak)
{
	const DynamicInfo *dynamic = &object->dynamic;
	uint32_t index = dynamic->buckets[symbol_hash(name) % dynamic->bucket_count];
	/* Dynamic metadata may live in writable application mappings. Retain
	 * lookup bounds even after the complete hash was validated at admission. */
	for (uint64_t remaining = dynamic->symbol_count; index != 0;
	     index = dynamic->chains[index], --remaining) {
		if (index >= dynamic->symbol_count || remaining == 0) {
			last_error = "invalid symbol hash chain";
			return NULL;
		}
		const Elf64_Sym *symbol = &object->dynamic.symbols[index];
		if (symbol->section == SHN_UNDEF || symbol->name >= object->dynamic.string_size) {
			continue;
		}
		unsigned binding = symbol->info >> 4;
		unsigned visibility = symbol->other & 3;
		const char *symbol_name = dynamic_string(object, symbol->name);
		if (binding == STB_LOCAL ||
		    (visibility != STV_DEFAULT && visibility != STV_PROTECTED) ||
		    symbol_name == NULL || !string_equal(symbol_name, name)) {
			continue;
		}
		uintptr_t value = 0;
		if (symbol->section == SHN_ABS) {
			value = symbol->value;
		} else if (!add_unsigned(object->base, symbol->value, &value) ||
			   !address_in_object(object, value,
					      symbol->size == 0 ? 1 : (size_t)symbol->size, 0)) {
			continue;
		}
		*weak = binding == STB_WEAK;
		return (void *)value;
	}
	return NULL;
}

static void *find_global_symbol(const char *name, int *weak)
{
	void *weak_value = NULL;
	for (size_t index = 0; index < object_count; ++index) {
		if ((objects[index].flags & HYPER_RTLD_GLOBAL) == 0) {
			continue;
		}
		int candidate_weak = 0;
		void *value = find_symbol_in(&objects[index], name, &candidate_weak);
		if (value != NULL && !candidate_weak) {
			*weak = 0;
			return value;
		}
		if (value != NULL && weak_value == NULL) {
			weak_value = value;
		}
	}
	*weak = weak_value != NULL;
	return weak_value;
}

static void *find_dependency_symbol(const Object *object, const char *name, uint32_t *visited,
				    int *weak)
{
	size_t object_index = (size_t)(object - objects);
	uint32_t mask = UINT32_C(1) << object_index;
	if ((*visited & mask) != 0) {
		return NULL;
	}
	*visited |= mask;

	int candidate_weak = 0;
	void *weak_value = NULL;
	void *value = find_symbol_in(object, name, &candidate_weak);
	if (value != NULL && !candidate_weak) {
		*weak = 0;
		return value;
	}
	if (value != NULL) {
		weak_value = value;
	}
	for (size_t index = 0; index < object->dynamic.needed_count; ++index) {
		const Object *dependency = object->dependencies[index];
		if (dependency == NULL) {
			continue;
		}
		candidate_weak = 0;
		value = find_dependency_symbol(dependency, name, visited, &candidate_weak);
		if (value != NULL && !candidate_weak) {
			*weak = 0;
			return value;
		}
		if (value != NULL && weak_value == NULL) {
			weak_value = value;
		}
	}
	*weak = weak_value != NULL;
	return weak_value;
}

static void *find_symbol_for(const Object *object, const char *name, int *weak)
{
	void *global = find_global_symbol(name, weak);
	if (global != NULL && !*weak) {
		return global;
	}
	uint32_t visited = 0;
	int local_weak = 0;
	void *local = find_dependency_symbol(object, name, &visited, &local_weak);
	if (local != NULL && !local_weak) {
		*weak = 0;
		return local;
	}
	if (global != NULL) {
		*weak = 1;
		return global;
	}
	*weak = local != NULL;
	return local;
}

static int resolve_symbol(const Object *object, uint64_t index, uintptr_t *value)
{
	if (index >= object->dynamic.symbol_count) {
		last_error = "relocation symbol outside table";
		return 0;
	}
	const Elf64_Sym *symbol = &object->dynamic.symbols[index];
	if (symbol->section != SHN_UNDEF) {
		if (symbol->section == SHN_ABS) {
			*value = symbol->value;
			return 1;
		}
		if (add_unsigned(object->base, symbol->value, value) &&
		    address_in_object(object, *value, 1, 0)) {
			return 1;
		}
		last_error = "defined symbol outside image";
		return 0;
	}
	const char *name = dynamic_string(object, symbol->name);
	if (name == NULL) {
		last_error = "invalid relocation symbol name";
		return 0;
	}
	int weak = 0;
	void *resolved = find_symbol_for(object, name, &weak);
	if (resolved == NULL && (symbol->info >> 4) != STB_WEAK) {
		last_error = "unresolved symbol";
		return 0;
	}
	*value = (uintptr_t)resolved;
	return 1;
}

static int apply_rela(Object *object, const Elf64_Rela *table, size_t count)
{
	if (count > MAX_RELOCATIONS) {
		last_error = "too many relocations";
		return 0;
	}
	for (size_t index = 0; index < count; ++index) {
		const Elf64_Rela *relocation = &table[index];
		uint32_t kind = (uint32_t)relocation->info;
		uint64_t symbol = relocation->info >> 32;
		uintptr_t target_address = 0;
		if (!add_unsigned(object->base, relocation->offset, &target_address) ||
		    !pointer_aligned((const void *)target_address, _Alignof(uintptr_t)) ||
		    !address_in_object(object, target_address, sizeof(uintptr_t), PF_W)) {
			last_error = "relocation target is not writable";
			return 0;
		}
		uintptr_t value = 0;
		if (kind == HYPER_RELOC_RELATIVE && symbol == 0) {
			if (!add_signed(object->base, relocation->addend, &value)) {
				last_error = "relative relocation overflow";
				return 0;
			}
		} else if (hyper_symbol_relocation(kind)) {
			if (!resolve_symbol(object, symbol, &value)) {
				return 0;
			}
			if (!add_signed(value, hyper_symbol_addend(kind, relocation->addend),
					&value)) {
				last_error = "symbol relocation overflow";
				return 0;
			}
		} else {
			last_error = "unsupported Native relocation";
			return 0;
		}
		*(uintptr_t *)target_address = value;
	}
	return 1;
}

static int apply_relr(Object *object)
{
	uintptr_t cursor = 0;
	size_t expanded = 0;
	int has_cursor = 0;
	for (size_t index = 0; index < object->dynamic.relr_count; ++index) {
		uint64_t entry = object->dynamic.relr[index];
		if ((entry & 1) == 0) {
			if (expanded == MAX_RELOCATIONS) {
				last_error = "too many RELR relocations";
				return 0;
			}
			if (!add_unsigned(object->base, entry, &cursor) ||
			    !pointer_aligned((const void *)cursor, _Alignof(uintptr_t)) ||
			    !address_in_object(object, cursor, sizeof(uintptr_t), PF_W)) {
				last_error = "RELR target is not writable";
				return 0;
			}
			if (*(uintptr_t *)cursor > UINTPTR_MAX - object->base) {
				last_error = "RELR value overflow";
				return 0;
			}
			*(uintptr_t *)cursor += object->base;
			if (cursor > UINTPTR_MAX - sizeof(uintptr_t)) {
				last_error = "RELR cursor overflow";
				return 0;
			}
			cursor += sizeof(uintptr_t);
			++expanded;
			has_cursor = 1;
			continue;
		}
		if (!has_cursor) {
			last_error = "RELR bitmap without an address";
			return 0;
		}
		for (unsigned bit = 1; bit < 64; ++bit) {
			if ((entry & (UINT64_C(1) << bit)) == 0) {
				continue;
			}
			if (expanded == MAX_RELOCATIONS) {
				last_error = "too many RELR relocations";
				return 0;
			}
			uintptr_t delta = (bit - 1) * sizeof(uintptr_t);
			uintptr_t target = 0;
			if (!add_unsigned(cursor, delta, &target) ||
			    !pointer_aligned((const void *)target, _Alignof(uintptr_t)) ||
			    !address_in_object(object, target, sizeof(uintptr_t), PF_W)) {
				last_error = "RELR bitmap target is not writable";
				return 0;
			}
			if (*(uintptr_t *)target > UINTPTR_MAX - object->base) {
				last_error = "RELR value overflow";
				return 0;
			}
			*(uintptr_t *)target += object->base;
			++expanded;
		}
		if (!add_unsigned(cursor, 63 * sizeof(uintptr_t), &cursor)) {
			last_error = "RELR cursor overflow";
			return 0;
		}
	}
	return 1;
}

static int protect_relro(Object *object)
{
	for (size_t index = 0; index < object->phnum; ++index) {
		const Elf64_Phdr *segment = &object->phdr[index];
		if (segment->type != PT_GNU_RELRO || segment->memsz == 0) {
			continue;
		}
		uintptr_t address = 0;
		uintptr_t unaligned_end = 0;
		if (!add_unsigned(object->base, segment->vaddr, &address) ||
		    !add_unsigned(address, segment->memsz, &unaligned_end)) {
			last_error = "RELRO range overflow";
			return 0;
		}
		uintptr_t start = align_down(address);
		uintptr_t end = align_up(unaligned_end);
		if (end == 0 || hyper_vmar_protect(object->vmar, start, end - start,
						   HYPER_NATIVE_VMAR_PERMISSION_READ) !=
					HYPER_NATIVE_STATUS_OK) {
			last_error = "could not seal RELRO";
			return 0;
		}
	}
	return 1;
}

static int relocate_object(Object *object)
{
	if (object->relocated) {
		return 1;
	}
	if (!apply_rela(object, object->dynamic.rela, object->dynamic.rela_count) ||
	    !apply_rela(object, object->dynamic.plt_rela, object->dynamic.plt_rela_count) ||
	    !apply_relr(object) || !protect_relro(object)) {
		return 0;
	}
	object->relocated = 1;
	return 1;
}

static int validate_header(const Elf64_Ehdr *header)
{
	return header->ident[0] == 0x7f && header->ident[1] == 'E' && header->ident[2] == 'L' &&
	       header->ident[3] == 'F' && header->ident[4] == 2 && header->ident[5] == 1 &&
	       header->ident[6] == 1 && header->ident[7] == HYPER_NATIVE_ELF_OSABI &&
	       header->ident[8] == HYPER_NATIVE_ELF_ABI_VERSION && header->type == ET_DYN &&
	       header->machine == HYPER_ELF_MACHINE && header->version == 1 &&
	       hyper_elf_flags_valid(header->flags) && header->ehsize == sizeof(*header) &&
	       header->phentsize == sizeof(Elf64_Phdr) && header->phnum != 0 &&
	       header->phnum <= MAX_PROGRAM_HEADERS;
}

static void promote_global(Object *object, uint32_t *visited)
{
	size_t object_index = (size_t)(object - objects);
	uint32_t mask = UINT32_C(1) << object_index;
	if ((*visited & mask) != 0) {
		return;
	}
	*visited |= mask;
	object->flags |= HYPER_RTLD_GLOBAL;
	for (size_t index = 0; index < object->dynamic.needed_count; ++index) {
		if (object->dependencies[index] != NULL) {
			promote_global(object->dependencies[index], visited);
		}
	}
}

static Object *load_object(hyper_native_handle_t directory, const char *name, uint32_t flags)
{
	Object *present = find_object(name);
	if (present != NULL) {
		if (present->references == UINT32_MAX) {
			last_error = "shared-object reference overflow";
			return NULL;
		}
		++present->references;
		if ((flags & HYPER_RTLD_GLOBAL) != 0) {
			uint32_t visited = 0;
			promote_global(present, &visited);
		}
		return present;
	}
	size_t name_length = string_length(name, MAX_NAME_BYTES + 1);
	if (name_length == 0 || name_length > MAX_NAME_BYTES || object_count == MAX_OBJECTS) {
		last_error = "invalid or excessive library name";
		return NULL;
	}
	if (string_equal(name, ".") || string_equal(name, "..")) {
		last_error = "library name must be a regular path component";
		return NULL;
	}
	for (size_t index = 0; index < name_length; ++index) {
		if (name[index] == '/') {
			last_error = "library name must be relative to its capability";
			return NULL;
		}
	}
	hyper_call_result_t opened = hyper_directory_open_file(
		directory, name, name_length, HYPER_NATIVE_RIGHT_READ | HYPER_NATIVE_RIGHT_EXECUTE);
	if (opened.status != HYPER_NATIVE_STATUS_OK) {
		last_error = "library open failed";
		return NULL;
	}
	hyper_native_handle_t file = opened.value0;
	hyper_native_handle_t file_vmo = 0;
	hyper_call_result_t file_vmo_result = hyper_file_create_executable_vmo(file);
	if (file_vmo_result.status != HYPER_NATIVE_STATUS_OK) {
		last_error = "executable VMO creation failed";
		goto fail;
	}
	file_vmo = file_vmo_result.value0;
	uint64_t file_size = file_vmo_result.value1;
	(void)hyper_handle_close(file);
	file = 0;
	Elf64_Ehdr header;
	if (!read_exact(file_vmo, file_size, 0, &header, sizeof(header)) ||
	    !validate_header(&header)) {
		last_error = "invalid shared object header";
		goto fail;
	}
	Object *object = &objects[object_count];
	for (size_t index = 0; index < sizeof(*object); ++index) {
		((unsigned char *)object)[index] = 0;
	}
	size_t program_header_bytes = (size_t)header.phnum * sizeof(Elf64_Phdr);
	if (header.phoff > UINT64_MAX - program_header_bytes ||
	    !read_exact(file_vmo, file_size, header.phoff, object->owned_phdr,
			program_header_bytes)) {
		last_error = "truncated program headers";
		goto fail;
	}
	uintptr_t minimum = UINTPTR_MAX;
	uintptr_t maximum = 0;
	size_t dynamic_segments = 0;
	for (size_t index = 0; index < header.phnum; ++index) {
		const Elf64_Phdr *segment = &object->owned_phdr[index];
		if (segment->type == PT_DYNAMIC) {
			if (++dynamic_segments != 1) {
				last_error = "multiple dynamic tables";
				goto fail;
			}
		}
		if (segment->type == PT_TLS && segment->memsz != 0) {
			last_error = "thread-local storage is unsupported";
			goto fail;
		}
		if (segment->type == PT_GNU_STACK && (segment->flags & PF_X) != 0) {
			last_error = "executable stack requested";
			goto fail;
		}
		if (segment->type != PT_LOAD) {
			continue;
		}
		if (segment->memsz == 0) {
			continue;
		}
		if ((segment->flags & PF_R) == 0 ||
		    (segment->flags & PF_W && segment->flags & PF_X) ||
		    segment->filesz > segment->memsz ||
		    segment->vaddr > UINTPTR_MAX - segment->memsz || segment->offset > file_size ||
		    segment->filesz > file_size - segment->offset ||
		    (segment->align > 1 && (segment->align > PAGE_SIZE ||
					    (segment->align & (segment->align - 1)) != 0)) ||
		    (segment->vaddr & (PAGE_SIZE - 1)) != (segment->offset & (PAGE_SIZE - 1))) {
			last_error = "invalid load segment";
			goto fail;
		}
		uintptr_t start = align_down(segment->vaddr);
		uintptr_t end = align_up(segment->vaddr + segment->memsz);
		if (end == 0) {
			last_error = "invalid load segment range";
			goto fail;
		}
		if (start < minimum)
			minimum = start;
		if (end > maximum)
			maximum = end;
		for (size_t previous = 0; previous < index; ++previous) {
			const Elf64_Phdr *other = &object->owned_phdr[previous];
			if (other->type != PT_LOAD || other->memsz == 0) {
				continue;
			}
			uintptr_t other_start = align_down(other->vaddr);
			uintptr_t other_end = align_up(other->vaddr + other->memsz);
			if (other_end == 0 || (start < other_end && other_start < end)) {
				last_error = "overlapping load segments";
				goto fail;
			}
		}
	}
	uintptr_t span = minimum == UINTPTR_MAX ? 0 : maximum - minimum;
	uintptr_t mapped_start = align_up(next_library_address);
	if (minimum == UINTPTR_MAX || span == 0 || span > LIBRARY_LIMIT || dynamic_segments != 1 ||
	    mapped_start == 0 || minimum > mapped_start || mapped_start > LIBRARY_LIMIT - span ||
	    mapped_start + span > LIBRARY_LIMIT - PAGE_SIZE) {
		last_error = "shared-object address space exhausted";
		goto fail;
	}
	hyper_call_result_t area = hyper_vmar_allocate(root_vmar, mapped_start, span,
						       HYPER_NATIVE_VMAR_ALLOCATE_EXACT);
	if (area.status != HYPER_NATIVE_STATUS_OK) {
		last_error = "shared-object VMAR allocation failed";
		goto fail;
	}
	object->vmar = area.value0;
	object->base = mapped_start - minimum;
	object->map_start = mapped_start;
	object->map_end = mapped_start + span;
	object->phdr = object->owned_phdr;
	object->phnum = header.phnum;
	object->references = 1;
	object->flags = flags & (HYPER_RTLD_LOCAL | HYPER_RTLD_GLOBAL);
	copy_name(object->name, name);
	++object_count;
	next_library_address = mapped_start + span + PAGE_SIZE;

	for (size_t index = 0; index < object->phnum; ++index) {
		const Elf64_Phdr *segment = &object->phdr[index];
		if (segment->type != PT_LOAD || segment->memsz == 0)
			continue;
		uintptr_t segment_address = 0;
		if (!add_unsigned(object->base, segment->vaddr, &segment_address)) {
			last_error = "load address overflow";
			goto fail;
		}
		uintptr_t address = align_down(segment_address);
		uint64_t delta = segment->vaddr & (PAGE_SIZE - 1);
		uintptr_t unaligned_map_size = 0;
		if (!add_unsigned(delta, segment->memsz, &unaligned_map_size)) {
			last_error = "load mapping overflow";
			goto fail;
		}
		uint64_t map_size = align_up(unaligned_map_size);
		if (map_size == 0) {
			last_error = "load mapping overflow";
			goto fail;
		}
		uint32_t permissions = HYPER_NATIVE_VMAR_PERMISSION_READ;
		if (segment->flags & PF_X)
			permissions |= HYPER_NATIVE_VMAR_PERMISSION_EXECUTE;
		if (segment->flags & PF_W)
			permissions |= HYPER_NATIVE_VMAR_PERMISSION_WRITE;
		hyper_native_private_mapping_t mapping = {
			.source_offset = align_down(segment->offset),
			.source_length = segment->filesz,
			.address = address,
			.size = map_size,
			.data_offset = delta,
			.permissions = permissions,
			.mode = HYPER_NATIVE_PRIVATE_MAPPING_COPY_ON_WRITE,
		};
		hyper_native_status_t status =
			hyper_vmar_map_private(object->vmar, file_vmo, &mapping, sizeof(mapping));
		if (status != HYPER_NATIVE_STATUS_OK) {
			if ((segment->flags & PF_X) != 0) {
				last_error = "executable shared-object mapping failed";
			} else if ((segment->flags & PF_W) != 0) {
				last_error = "writable shared-object mapping failed";
			} else {
				last_error = "read-only shared-object mapping failed";
			}
			goto fail;
		}
	}
	(void)hyper_handle_close(file_vmo);
	file_vmo = 0;
	if (!parse_dynamic(object)) {
		return NULL;
	}
	for (size_t index = 0; index < object->dynamic.needed_count; ++index) {
		const char *dependency = dynamic_string(object, object->dynamic.needed[index]);
		uint32_t dependency_flags =
			(flags & HYPER_RTLD_GLOBAL) != 0 ? HYPER_RTLD_GLOBAL : HYPER_RTLD_LOCAL;
		Object *loaded = dependency == NULL
					 ? NULL
					 : load_object(directory, dependency, dependency_flags);
		if (loaded == NULL) {
			return NULL;
		}
		object->dependencies[index] = loaded;
	}
	return object;

fail:
	if (file_vmo != 0)
		(void)hyper_handle_close(file_vmo);
	if (file != 0)
		(void)hyper_handle_close(file);
	return NULL;
}

static int address_is_executable(uintptr_t address)
{
	for (size_t index = 0; index < object_count; ++index) {
		if (address_in_object(&objects[index], address, 1, PF_X)) {
			return 1;
		}
	}
	return 0;
}

static int initialize_object(Object *object)
{
	if (object->initialized)
		return 1;
	object->initialized = 1;
	if (object->dynamic.init != 0) {
		if (!address_is_executable(object->dynamic.init)) {
			last_error = "initialization function is not executable";
			return 0;
		}
		((void (*)(void))object->dynamic.init)();
	}
	for (size_t index = 0; index < object->dynamic.init_array_count; ++index) {
		uintptr_t function = object->dynamic.init_array[index];
		if (function == 0 || function == UINTPTR_MAX) {
			continue;
		}
		if (!address_is_executable(function)) {
			last_error = "initialization array target is not executable";
			return 0;
		}
		((void (*)(void))function)();
	}
	return 1;
}

static void rollback_objects(size_t first, uintptr_t saved_next_address)
{
	while (object_count > first) {
		Object *object = &objects[object_count - 1];
		if (object->vmar != 0 && object->vmar != root_vmar) {
			uintptr_t size = object->map_end - object->map_start;
			if (size != 0) {
				(void)hyper_vmar_unmap(object->vmar, object->map_start, size);
			}
			if (hyper_vmar_destroy(object->vmar) != HYPER_NATIVE_STATUS_OK) {
				(void)hyper_handle_close(object->vmar);
			}
		}
		for (size_t index = 0; index < sizeof(*object); ++index) {
			((unsigned char *)object)[index] = 0;
		}
		--object_count;
	}
	next_library_address = saved_next_address;
}

static int register_interpreter(uintptr_t base)
{
	if (object_count == MAX_OBJECTS || base > UINTPTR_MAX - sizeof(Elf64_Ehdr)) {
		return 0;
	}
	const Elf64_Ehdr *header = (const void *)base;
	if (!validate_header(header)) {
		last_error = "invalid interpreter header";
		return 0;
	}
	uintptr_t program_headers = 0;
	size_t program_header_bytes = (size_t)header->phnum * sizeof(Elf64_Phdr);
	if (!add_unsigned(base, header->phoff, &program_headers) ||
	    program_header_bytes > UINTPTR_MAX - program_headers ||
	    !pointer_aligned((const void *)program_headers, _Alignof(Elf64_Phdr))) {
		last_error = "invalid interpreter program headers";
		return 0;
	}
	Object *interpreter = &objects[object_count];
	for (size_t index = 0; index < sizeof(*interpreter); ++index) {
		((unsigned char *)interpreter)[index] = 0;
	}
	const Elf64_Phdr *source = (const void *)program_headers;
	for (size_t index = 0; index < header->phnum; ++index) {
		interpreter->owned_phdr[index] = source[index];
	}
	copy_name(interpreter->name, HYPER_DYNAMIC_LOADER_NAME);
	interpreter->base = base;
	interpreter->vmar = root_vmar;
	interpreter->phdr = interpreter->owned_phdr;
	interpreter->phnum = header->phnum;
	interpreter->references = 1;
	interpreter->flags = HYPER_RTLD_GLOBAL;
	interpreter->relocated = 1;
	interpreter->initialized = 1;
	++object_count;
	if (!parse_dynamic(interpreter)) {
		--object_count;
		return 0;
	}
	return 1;
}

static int initialize_main(const uintptr_t *stack)
{
	uintptr_t argc = stack[0];
	if (argc > 4096) {
		last_error = "invalid argument vector";
		return 0;
	}
	const uintptr_t *cursor = stack + 1 + argc;
	if (*cursor++ != 0) {
		last_error = "unterminated argument vector";
		return 0;
	}
	while (*cursor != 0)
		++cursor;
	++cursor;
	uintptr_t phdr = 0;
	uintptr_t phent = 0;
	uintptr_t phnum = 0;
	uintptr_t base = 0;
	uintptr_t entry = 0;
	uintptr_t handles = 0;
	uintptr_t handle_count = 0;
	while (cursor[0] != AT_NULL) {
		switch (cursor[0]) {
		case AT_PHDR:
			phdr = cursor[1];
			break;
		case AT_PHENT:
			phent = cursor[1];
			break;
		case AT_PHNUM:
			phnum = cursor[1];
			break;
		case AT_BASE:
			base = cursor[1];
			break;
		case AT_ENTRY:
			entry = cursor[1];
			break;
		case HYPER_AUXV_STARTUP_HANDLES:
			handles = cursor[1];
			break;
		case HYPER_AUXV_STARTUP_HANDLE_COUNT:
			handle_count = cursor[1];
			break;
		default:
			break;
		}
		cursor += 2;
	}
	if (phdr == 0 || phent != sizeof(Elf64_Phdr) || phnum == 0 || phnum > MAX_PROGRAM_HEADERS ||
	    base == 0 || entry == 0 || handles == 0 ||
	    !pointer_aligned((const void *)phdr, _Alignof(Elf64_Phdr)) ||
	    !pointer_aligned((const void *)handles, _Alignof(hyper_native_startup_handle_t)) ||
	    handle_count > HYPER_NATIVE_STARTUP_MAX_HANDLES) {
		last_error = "invalid startup auxiliary vector";
		return 0;
	}
	const hyper_native_startup_handle_t *records = (const void *)handles;
	for (size_t index = 0; index < handle_count; ++index) {
		if (records[index].purpose == HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_ROOT_VMAR) {
			root_vmar = records[index].handle;
		} else if (records[index].purpose == HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_CONSOLE) {
			diagnostic_console = records[index].handle;
		} else if (records[index].purpose ==
			   HYPER_NATIVE_STARTUP_HANDLE_PURPOSE_DYNAMIC_LIBRARY_DIRECTORY) {
			library_directory = records[index].handle;
		}
	}
	if (root_vmar == 0 || library_directory == 0) {
		last_error = "missing loader startup capability";
		return 0;
	}
	Object *main = &objects[0];
	for (size_t index = 0; index < sizeof(*main); ++index)
		((unsigned char *)main)[index] = 0;
	copy_name(main->name, "<main>");
	main->phdr = (const void *)phdr;
	main->phnum = phnum;
	main->vmar = root_vmar;
	main->references = 1;
	main->flags = HYPER_RTLD_GLOBAL;
	for (size_t index = 0; index < main->phnum; ++index) {
		if (main->phdr[index].type == PT_PHDR) {
			if (phdr < main->phdr[index].vaddr) {
				last_error = "main image load bias underflow";
				return 0;
			}
			main->base = phdr - main->phdr[index].vaddr;
			break;
		}
	}
	if (main->base == 0) {
		last_error = "main image has no program-header mapping";
		return 0;
	}
	object_count = 1;
	if (!parse_dynamic(main))
		return 0;
	if (!register_interpreter(base))
		return 0;
	for (size_t index = 0; index < main->dynamic.needed_count; ++index) {
		const char *dependency = dynamic_string(main, main->dynamic.needed[index]);
		Object *loaded = dependency == NULL ? NULL
						    : load_object(library_directory, dependency,
								  HYPER_RTLD_GLOBAL);
		if (loaded == NULL) {
			return 0;
		}
		main->dependencies[index] = loaded;
	}
	for (size_t index = object_count; index > 0; --index) {
		if (!relocate_object(&objects[index - 1]))
			return 0;
	}
	return 1;
}

extern _Noreturn void __hyper_rtld_enter(uintptr_t stack, uintptr_t entry);

static _Noreturn void enter_application(const uintptr_t *stack)
{
	/* Runtime initialization and bootstrap-stack retirement have completed.
	 * Constructors execute exclusively on the final app stack. */
	for (size_t index = object_count; index > 1; --index) {
		if (!initialize_object(&objects[index - 1]))
			hyper_process_exit(HYPER_NATIVE_STATUS_BAD_STATE);
	}
	if (!initialize_object(&objects[0]))
		hyper_process_exit(HYPER_NATIVE_STATUS_BAD_STATE);
	const uintptr_t *cursor = stack + 1 + stack[0];
	++cursor;
	while (*cursor++ != 0) {
	}
	while (cursor[0] != AT_NULL) {
		if (cursor[0] == AT_ENTRY)
			__hyper_rtld_enter((uintptr_t)stack, cursor[1]);
		cursor += 2;
	}
	hyper_process_exit(HYPER_NATIVE_STATUS_BAD_STATE);
}

extern const Elf64_Ehdr __ehdr_start __attribute__((visibility("hidden")));

_Noreturn void __hyper_rtld_start(const uintptr_t *stack)
{
	if (!hyper_elf_self_relocate(&__ehdr_start))
		hyper_process_exit(HYPER_NATIVE_STATUS_NOT_SUPPORTED);
	if (!initialize_main(stack)) {
		report_startup_failure();
		hyper_process_exit(HYPER_NATIVE_STATUS_NOT_SUPPORTED);
	}
	/* Resolve in the relocated shared runtime, never the interpreter's static
	 * primitives or an interposing app. This call abandons our bootstrap frames. */
	Object *runtime = find_object("libhyper.so");
	int weak = 0;
	void *hook = runtime ? find_symbol_in(runtime, "hyper_runtime_start", &weak) : NULL;
	if (!hook) {
		last_error = "missing Native runtime startup handoff";
		report_startup_failure();
		hyper_process_exit(HYPER_NATIVE_STATUS_NOT_SUPPORTED);
	}
	((void (*)(const uintptr_t *, void (*)(const uintptr_t *)))hook)(stack, enter_application);
	hyper_process_exit(HYPER_NATIVE_STATUS_INTERNAL);
}

/* A failed dependency load must restore existing objects as well as discard
 * newly mapped objects. This snapshot is owned by the locked dlopen operation;
 * constructors run only after all load/relocation checks complete. */
typedef struct {
	size_t first;
	uintptr_t next_address;
	uint32_t references[MAX_OBJECTS];
	uint32_t flags[MAX_OBJECTS];
} LoadTransaction;

static LoadTransaction begin_load_transaction(void)
{
	LoadTransaction transaction = {
		.first = object_count,
		.next_address = next_library_address,
	};
	for (size_t index = 0; index < transaction.first; ++index) {
		transaction.references[index] = objects[index].references;
		transaction.flags[index] = objects[index].flags;
	}
	return transaction;
}

static void rollback_load_transaction(const LoadTransaction *transaction)
{
	rollback_objects(transaction->first, transaction->next_address);
	for (size_t index = 0; index < transaction->first; ++index) {
		objects[index].references = transaction->references[index];
		objects[index].flags = transaction->flags[index];
	}
}

void *hyper_dlopen_at(hyper_native_handle_t directory, const char *name, uint32_t flags)
{
	lock_loader();
	if (directory == 0 || name == NULL || (flags & HYPER_RTLD_NOW) == 0 ||
	    (flags & ~(HYPER_RTLD_NOW | HYPER_RTLD_LOCAL | HYPER_RTLD_GLOBAL)) != 0 ||
	    ((flags & HYPER_RTLD_LOCAL) != 0 && (flags & HYPER_RTLD_GLOBAL) != 0)) {
		last_error = "invalid dlopen arguments";
		unlock_loader();
		return NULL;
	}
	const LoadTransaction transaction = begin_load_transaction();
	Object *object = load_object(directory, name, flags);
	if (object != NULL) {
		for (size_t index = object_count; index > transaction.first; --index) {
			if (!relocate_object(&objects[index - 1])) {
				object = NULL;
				break;
			}
		}
	}
	if (object != NULL && !relocate_object(object))
		object = NULL;
	if (object != NULL) {
		for (size_t index = object_count; index > transaction.first; --index) {
			if (!initialize_object(&objects[index - 1])) {
				object = NULL;
				break;
			}
		}
		if (object != NULL && !initialize_object(object))
			object = NULL;
	}
	if (object == NULL) {
		rollback_load_transaction(&transaction);
	}
	unlock_loader();
	return object;
}

void *hyper_dlsym(void *handle, const char *name)
{
	lock_loader();
	if (name == NULL) {
		last_error = "invalid symbol name";
		unlock_loader();
		return NULL;
	}
	Object *object = handle == NULL ? NULL : object_from_handle(handle);
	if (handle != NULL && object == NULL) {
		last_error = "invalid shared-object handle";
		unlock_loader();
		return NULL;
	}
	int weak = 0;
	uint32_t visited = 0;
	void *value = handle == NULL ? find_global_symbol(name, &weak)
				     : find_dependency_symbol(object, name, &visited, &weak);
	if (value == NULL)
		last_error = "symbol not found";
	unlock_loader();
	return value;
}

hyper_native_status_t hyper_dlclose(void *handle)
{
	if (handle == NULL)
		return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
	lock_loader();
	Object *object = object_from_handle(handle);
	if (object == NULL || object->references == 0) {
		unlock_loader();
		return HYPER_NATIVE_STATUS_INVALID_ARGUMENT;
	}
	--object->references;
	unlock_loader();
	return HYPER_NATIVE_STATUS_OK;
}

const char *hyper_dlerror(void)
{
	lock_loader();
	const char *error = last_error;
	last_error = NULL;
	unlock_loader();
	return error;
}
