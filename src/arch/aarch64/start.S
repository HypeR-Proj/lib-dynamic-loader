/* SPDX-FileCopyrightText: 2026 roolrz
 * SPDX-License-Identifier: Apache-2.0
 */

.section .text._start, "ax", %progbits
.p2align 2
.global _start
.type _start, %function
_start:
    mov x0, sp
    b __hyper_rtld_start
.size _start, . - _start

.global __hyper_rtld_enter
.hidden __hyper_rtld_enter
.type __hyper_rtld_enter, %function
__hyper_rtld_enter:
    mov sp, x0
    mov x29, xzr
    mov x30, xzr
    br x1
.size __hyper_rtld_enter, . - __hyper_rtld_enter

.section .note.GNU-stack, "", %progbits
