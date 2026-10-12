# SPDX-FileCopyrightText: 2026 roolrz
# SPDX-License-Identifier: Apache-2.0

# Internal source library: each bootstrap carries these freestanding primitives.
# It is never installed as a DSO or exposed as an application SDK dependency.
function(hyper_add_elf_loader target)
    target_sources(${target} PRIVATE
        ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/image.c
        ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/launch.c
    )
    target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_FUNCTION_LIST_DIR})
endfunction()
