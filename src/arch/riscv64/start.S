/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */

.section .text._start, "ax", @progbits
.p2align 2
.global _start
.type _start, @function
_start:
    mv a0, sp
    tail __hyper_rtld_start
.size _start, . - _start
.global __hyper_rtld_enter
.hidden __hyper_rtld_enter
.type __hyper_rtld_enter, @function
__hyper_rtld_enter:
    mv sp, a0
    li s0, 0
    li ra, 0
    jr a1
.size __hyper_rtld_enter, . - __hyper_rtld_enter

.section .note.GNU-stack, "", @progbits
