/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef HYPER_LOADER_ARCH_H
#define HYPER_LOADER_ARCH_H

#if defined(__aarch64__)
#define HYPER_ELF_MACHINE 183
#define HYPER_RELOC_RELATIVE 1027
#define HYPER_DYNAMIC_LOADER_NAME "ld-hyper-aarch64.so"

static int hyper_symbol_relocation(uint32_t kind)
{
	return kind == 257 || kind == 1025 || kind == 1026;
}

static int64_t hyper_symbol_addend(uint32_t kind, int64_t addend)
{
	(void)kind;
	return addend;
}

static int hyper_elf_flags_valid(uint32_t flags)
{
	return flags == 0;
}
#elif defined(__riscv) && __riscv_xlen == 64
#define HYPER_ELF_MACHINE 243
#define HYPER_RELOC_RELATIVE 3
#define HYPER_DYNAMIC_LOADER_NAME "ld-hyper-riscv64.so"

/* R_RISCV_64 and R_RISCV_JUMP_SLOT; RV64 has no GLOB_DAT relocation. */
static int hyper_symbol_relocation(uint32_t kind)
{
	return kind == 2 || kind == 5;
}

/* The RISC-V psABI defines JUMP_SLOT as S, not S + A. */
static int64_t hyper_symbol_addend(uint32_t kind, int64_t addend)
{
	return kind == 5 ? 0 : addend;
}

/* LP64D is mandatory; compressed instructions are optional. Reject RVE,
 * TSO, other float ABIs and all reserved flags. */
static int hyper_elf_flags_valid(uint32_t flags)
{
	return (flags & ~1u) == 4;
}
#else
#error Unsupported Native loader architecture
#endif
#endif
