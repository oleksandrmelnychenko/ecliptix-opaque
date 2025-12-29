# =============================================================================
# CodeProtection.cmake - Native Code Obfuscation & Protection
# =============================================================================
# This module provides integration with various code protection tools for
# native C/C++ binaries. It supports both commercial and open-source solutions.
#
# Supported Protection Tools:
# 1. VMProtect (Commercial) - Industry-leading code virtualization
# 2. Themida (Commercial) - Advanced code protection
# 3. LLVM Obfuscator (Open Source) - Compile-time obfuscation
# 4. Compile-time hardening (Built-in) - Security flags
#
# Usage:
#   include(CodeProtection)
#   enable_code_protection(target_name)
#
# Options:
#   -DENABLE_CODE_PROTECTION=ON        Enable protection (default: ON for Release)
#   -DPROTECTION_LEVEL=standard        Protection level: minimal, standard, maximum
#   -DVMPROTECT_PATH=/path/to/vmp      Path to VMProtect CLI
#   -DTHEMIDA_PATH=/path/to/themida    Path to Themida CLI
#   -DUSE_LLVM_OBFUSCATOR=ON           Use LLVM-based obfuscation
# =============================================================================

cmake_minimum_required(VERSION 3.20)

option(ENABLE_CODE_PROTECTION "Enable code protection/obfuscation" ON)
option(USE_LLVM_OBFUSCATOR "Use LLVM-based compile-time obfuscation" OFF)
set(PROTECTION_LEVEL "standard" CACHE STRING "Protection level: minimal, standard, maximum")
set_property(CACHE PROTECTION_LEVEL PROPERTY STRINGS minimal standard maximum)

# VMProtect and Themida paths
set(VMPROTECT_PATH "" CACHE FILEPATH "Path to VMProtect CLI executable")
set(THEMIDA_PATH "" CACHE FILEPATH "Path to Themida CLI executable")

# =============================================================================
# Compile-Time Hardening (Always Applied)
# =============================================================================
function(apply_compile_hardening target)
    message(STATUS "[Protection] Applying compile-time hardening to ${target}")

    # GNU/Clang compiler hardening
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            # Stack protection
            -fstack-protector-strong
            -fstack-clash-protection

            # Position Independent Code
            -fPIC

            # Fortify Source (buffer overflow protection)
            -D_FORTIFY_SOURCE=2

            # Control Flow Integrity (Clang only)
            $<$<CXX_COMPILER_ID:Clang>:-fsanitize=cfi>
            $<$<CXX_COMPILER_ID:Clang>:-fvisibility=hidden>

            # No executable stack
            -Wl,-z,noexecstack

            # Strip symbols in Release
            $<$<CONFIG:Release>:-s>
        )

        # Linker hardening
        target_link_options(${target} PRIVATE
            # Full RELRO (relocations read-only)
            -Wl,-z,relro,-z,now

            # No executable stack
            -Wl,-z,noexecstack

            # Bind functions at load time
            -Wl,-z,now
        )
    endif()

    # MSVC hardening
    if(MSVC)
        target_compile_options(${target} PRIVATE
            # Buffer security check
            /GS

            # SDL checks
            /sdl

            # Control Flow Guard
            /guard:cf

            # Spectre mitigation
            /Qspectre
        )

        target_link_options(${target} PRIVATE
            # ASLR
            /DYNAMICBASE

            # DEP (Data Execution Prevention)
            /NXCOMPAT

            # Control Flow Guard
            /guard:cf

            # High entropy ASLR (64-bit)
            $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>:/HIGHENTROPYVA>
        )
    endif()
endfunction()

# =============================================================================
# LLVM Obfuscator Integration (Open Source)
# =============================================================================
# Supports: ollvm, Hikari, obfuscator-llvm
# These provide compile-time obfuscation via LLVM passes
function(apply_llvm_obfuscation target level)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "[Protection] LLVM obfuscation requires Clang compiler")
        return()
    endif()

    message(STATUS "[Protection] Applying LLVM obfuscation (level: ${level}) to ${target}")

    set(OBFUSCATION_FLAGS "")

    if(level STREQUAL "minimal")
        # Basic obfuscation
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub           # Instruction substitution
            -mllvm -bcf_prob=30   # Low bogus control flow probability
        )
    elseif(level STREQUAL "standard")
        # Standard obfuscation
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub           # Instruction substitution
            -mllvm -bcf           # Bogus control flow
            -mllvm -bcf_prob=50   # 50% probability
            -mllvm -fla           # Control flow flattening
            -mllvm -split         # Basic block splitting
            -mllvm -split_num=3   # Split into 3 blocks
        )
    elseif(level STREQUAL "maximum")
        # Maximum obfuscation (slower compilation & runtime)
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub           # Instruction substitution
            -mllvm -sub_loop=3    # 3 substitution passes
            -mllvm -bcf           # Bogus control flow
            -mllvm -bcf_prob=80   # 80% probability
            -mllvm -bcf_loop=3    # 3 BCF passes
            -mllvm -fla           # Control flow flattening
            -mllvm -split         # Basic block splitting
            -mllvm -split_num=5   # Split into 5 blocks
            -mllvm -sobf          # String obfuscation
        )
    endif()

    target_compile_options(${target} PRIVATE ${OBFUSCATION_FLAGS})
endfunction()

# =============================================================================
# String Encryption (Custom Implementation)
# =============================================================================
# Encrypts string literals at compile time, decrypts at runtime
function(enable_string_encryption target)
    message(STATUS "[Protection] Enabling string encryption for ${target}")

    # Add string encryption header
    target_compile_definitions(${target} PRIVATE
        ECLIPTIX_ENABLE_STRING_ENCRYPTION=1
    )

    # Use constexpr encryption if C++20 available
    if(CMAKE_CXX_STANDARD GREATER_EQUAL 20)
        target_compile_definitions(${target} PRIVATE
            ECLIPTIX_USE_CONSTEXPR_ENCRYPTION=1
        )
    endif()
endfunction()

# =============================================================================
# Anti-Debug & Anti-Tamper (Custom Implementation)
# =============================================================================
function(enable_anti_debug target)
    message(STATUS "[Protection] Enabling anti-debug for ${target}")

    target_compile_definitions(${target} PRIVATE
        ECLIPTIX_ENABLE_ANTI_DEBUG=1
        ECLIPTIX_ENABLE_ANTI_TAMPER=1
    )
endfunction()

# =============================================================================
# VMProtect Post-Build Integration
# =============================================================================
function(apply_vmprotect target vmp_path level)
    if(NOT EXISTS "${vmp_path}")
        message(WARNING "[Protection] VMProtect not found at: ${vmp_path}")
        return()
    endif()

    message(STATUS "[Protection] Configuring VMProtect for ${target}")

    # Determine protection options based on level
    set(VMP_OPTIONS "")
    if(level STREQUAL "minimal")
        set(VMP_OPTIONS "--mutation-level=low --vm-code-level=low")
    elseif(level STREQUAL "standard")
        set(VMP_OPTIONS "--mutation-level=medium --vm-code-level=medium --anti-debug")
    elseif(level STREQUAL "maximum")
        set(VMP_OPTIONS "--mutation-level=ultra --vm-code-level=ultra --anti-debug --anti-vm --pack-resources")
    endif()

    # Add post-build command
    add_custom_command(TARGET ${target} POST_BUILD
        COMMAND ${vmp_path}
            "$<TARGET_FILE:${target}>"
            "$<TARGET_FILE:${target}>.protected"
            ${VMP_OPTIONS}
        COMMAND ${CMAKE_COMMAND} -E copy
            "$<TARGET_FILE:${target}>.protected"
            "$<TARGET_FILE:${target}>"
        COMMAND ${CMAKE_COMMAND} -E remove "$<TARGET_FILE:${target}>.protected"
        COMMENT "[Protection] Applying VMProtect to ${target}"
        VERBATIM
    )
endfunction()

# =============================================================================
# Themida Post-Build Integration
# =============================================================================
function(apply_themida target themida_path level)
    if(NOT EXISTS "${themida_path}")
        message(WARNING "[Protection] Themida not found at: ${themida_path}")
        return()
    endif()

    message(STATUS "[Protection] Configuring Themida for ${target}")

    # Determine protection options based on level
    set(THEMIDA_VM "FISH_WHITE")  # Default VM
    if(level STREQUAL "minimal")
        set(THEMIDA_VM "FISH_LITE")
    elseif(level STREQUAL "maximum")
        set(THEMIDA_VM "TIGER_BLACK")
    endif()

    # Add post-build command (Windows only)
    if(WIN32)
        add_custom_command(TARGET ${target} POST_BUILD
            COMMAND ${themida_path}
                /protect "$<TARGET_FILE:${target}>"
                /output "$<TARGET_FILE:${target}>.protected"
                /virtualmachine ${THEMIDA_VM}
                /antidebug CHECK_DEBUGGER
                /compression ON
            COMMAND ${CMAKE_COMMAND} -E copy
                "$<TARGET_FILE:${target}>.protected"
                "$<TARGET_FILE:${target}>"
            COMMAND ${CMAKE_COMMAND} -E remove "$<TARGET_FILE:${target}>.protected"
            COMMENT "[Protection] Applying Themida to ${target}"
            VERBATIM
        )
    endif()
endfunction()

# =============================================================================
# Main Protection Function
# =============================================================================
function(enable_code_protection target)
    if(NOT ENABLE_CODE_PROTECTION)
        message(STATUS "[Protection] Code protection disabled for ${target}")
        return()
    endif()

    message(STATUS "============================================")
    message(STATUS "[Protection] Configuring protection for: ${target}")
    message(STATUS "[Protection] Level: ${PROTECTION_LEVEL}")
    message(STATUS "============================================")

    # Always apply compile-time hardening
    apply_compile_hardening(${target})

    # Apply LLVM obfuscation if enabled and using Clang
    if(USE_LLVM_OBFUSCATOR AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        apply_llvm_obfuscation(${target} ${PROTECTION_LEVEL})
    endif()

    # Apply string encryption for standard+ levels
    if(NOT PROTECTION_LEVEL STREQUAL "minimal")
        enable_string_encryption(${target})
    endif()

    # Apply anti-debug for maximum level
    if(PROTECTION_LEVEL STREQUAL "maximum")
        enable_anti_debug(${target})
    endif()

    # Apply VMProtect if available (Windows/Linux)
    if(VMPROTECT_PATH AND EXISTS "${VMPROTECT_PATH}")
        apply_vmprotect(${target} "${VMPROTECT_PATH}" ${PROTECTION_LEVEL})
    endif()

    # Apply Themida if available (Windows only)
    if(WIN32 AND THEMIDA_PATH AND EXISTS "${THEMIDA_PATH}")
        apply_themida(${target} "${THEMIDA_PATH}" ${PROTECTION_LEVEL})
    endif()

    # Strip symbols in Release builds
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${target}>" || true
                COMMENT "[Protection] Stripping symbols from ${target}"
            )
        endif()
    endif()
endfunction()

# =============================================================================
# Generate Protection Report
# =============================================================================
function(generate_protection_report)
    message(STATUS "")
    message(STATUS "============================================")
    message(STATUS "       CODE PROTECTION CONFIGURATION")
    message(STATUS "============================================")
    message(STATUS "Protection Enabled:    ${ENABLE_CODE_PROTECTION}")
    message(STATUS "Protection Level:      ${PROTECTION_LEVEL}")
    message(STATUS "LLVM Obfuscator:       ${USE_LLVM_OBFUSCATOR}")
    message(STATUS "VMProtect Path:        ${VMPROTECT_PATH}")
    message(STATUS "Themida Path:          ${THEMIDA_PATH}")
    message(STATUS "Compiler:              ${CMAKE_CXX_COMPILER_ID}")
    message(STATUS "Build Type:            ${CMAKE_BUILD_TYPE}")
    message(STATUS "============================================")
    message(STATUS "")
endfunction()
