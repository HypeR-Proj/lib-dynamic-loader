# SPDX-FileCopyrightText: 2026 roolrz
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.25)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
project(HypeRDynamicLoader VERSION 0.0.0 LANGUAGES C ASM)

if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "HypeR dynamic-loader requires Clang")
endif()
if(NOT HYPER_ARCH MATCHES "^(aarch64|riscv64)$")
    message(FATAL_ERROR "HypeR dynamic linking requires a supported Native architecture")
endif()
if(NOT EXISTS "${HYPER_SYSROOT}/include/hyper/native.h")
    message(FATAL_ERROR "HYPER_SYSROOT must name a complete HypeR sysroot")
endif()

add_executable(hyper_dynamic_loader
    src/arch/${HYPER_ARCH}/start.S
    src/rtld.c
)
target_compile_features(hyper_dynamic_loader PRIVATE c_std_17)
target_compile_options(hyper_dynamic_loader PRIVATE
    $<$<COMPILE_LANGUAGE:C>:-ffreestanding;-fno-builtin;-fPIE;-fno-stack-protector;-Wall;-Wextra;-Werror>
)
target_include_directories(hyper_dynamic_loader PRIVATE
    ${HYPER_SYSROOT}/include
)
target_link_options(hyper_dynamic_loader PRIVATE
    --ld-path=${HYPER_LD}
    -nostdlib
    -Wl,-shared,--no-dynamic-linker,--no-undefined,--fatal-warnings
    -Wl,-Bsymbolic,-z,text,--entry=_start
    -Wl,--export-dynamic-symbol=hyper_dlopen_at
    -Wl,--export-dynamic-symbol=hyper_dlsym
    -Wl,--export-dynamic-symbol=hyper_dlclose
    -Wl,--export-dynamic-symbol=hyper_dlerror
    -Wl,--build-id=none,--gc-sections,-z,noexecstack,-z,max-page-size=4096
    -Wl,--hash-style=sysv,-soname,ld-hyper-${HYPER_ARCH}.so
    -Wl,-T,${HYPER_SYSROOT}/lib/hyper/${HYPER_ARCH}/hyper-native.ld
    ${HYPER_SYSROOT}/lib/libhyper.a
)
set_target_properties(hyper_dynamic_loader PROPERTIES
    OUTPUT_NAME ld-hyper-${HYPER_ARCH}.so
    SUFFIX ""
)

install(TARGETS hyper_dynamic_loader RUNTIME DESTINATION lib64)
