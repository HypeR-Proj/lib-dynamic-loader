/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
/* Header-only architecture contracts run on the host without system headers
 * so defining a target ISA cannot change the host C library's type layout. */
typedef unsigned int uint32_t;
typedef long long int64_t;
#include "../src/arch.h"

int main(void)
{
#if defined(__riscv)
	if (HYPER_ELF_MACHINE != 243 || HYPER_RELOC_RELATIVE != 3)
		return 1;
	if (!hyper_symbol_relocation(2) || !hyper_symbol_relocation(5))
		return 2;
	if (hyper_symbol_relocation(4) || hyper_symbol_relocation(58))
		return 3;
	if (hyper_symbol_addend(5, 123) != 0 || hyper_symbol_addend(5, -123) != 0)
		return 4;
	if (hyper_symbol_addend(2, -123) != -123)
		return 5;
	if (!hyper_elf_flags_valid(4) || !hyper_elf_flags_valid(5))
		return 6;
	if (hyper_elf_flags_valid(0) || hyper_elf_flags_valid(12))
		return 7;
#else
	if (HYPER_ELF_MACHINE != 183 || HYPER_RELOC_RELATIVE != 1027)
		return 1;
	if (!hyper_symbol_relocation(257) || !hyper_symbol_relocation(1026))
		return 2;
	if (hyper_symbol_relocation(5))
		return 3;
	if (hyper_symbol_addend(1026, 123) != 123)
		return 4;
	if (!hyper_elf_flags_valid(0) || hyper_elf_flags_valid(4))
		return 5;
#endif
	return 0;
}
