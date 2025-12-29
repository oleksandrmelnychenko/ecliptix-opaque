# =============================================================================
# LLVMObfuscator.cmake - Free LLVM-Based Code Obfuscation
# =============================================================================
# Integrates with Hikari or obfuscator-llvm for compile-time obfuscation.
# Requires Clang compiler with obfuscation passes.
#
# Installation (Hikari - recommended):
#   macOS:   brew install hikari
#   Linux:   Build from https://github.com/HikariObfuscator/Hikari
#
# Usage:
#   cmake -DENABLE_OBFUSCATION=ON -DOBFUSCATION_LEVEL=standard ..
# =============================================================================

cmake_minimum_required(VERSION 3.20)

option(ENABLE_OBFUSCATION "Enable LLVM-based code obfuscation" OFF)
set(OBFUSCATION_LEVEL "standard" CACHE STRING "Obfuscation level: light, standard, aggressive")
set_property(CACHE OBFUSCATION_LEVEL PROPERTY STRINGS light standard aggressive)

# Check if using Clang
function(check_llvm_obfuscator_support)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "[Obfuscation] LLVM obfuscation requires Clang compiler. Current: ${CMAKE_CXX_COMPILER_ID}")
        set(LLVM_OBFUSCATOR_SUPPORTED FALSE PARENT_SCOPE)
        return()
    endif()

    # Test if obfuscation flags are supported
    include(CheckCXXCompilerFlag)
    check_cxx_compiler_flag("-mllvm -sub" HAS_INSTRUCTION_SUB)

    if(HAS_INSTRUCTION_SUB)
        message(STATUS "[Obfuscation] LLVM obfuscator passes detected")
        set(LLVM_OBFUSCATOR_SUPPORTED TRUE PARENT_SCOPE)
    else()
        message(STATUS "[Obfuscation] Standard Clang detected (no obfuscator passes)")
        message(STATUS "[Obfuscation] Install Hikari for full obfuscation support")
        set(LLVM_OBFUSCATOR_SUPPORTED FALSE PARENT_SCOPE)
    endif()
endfunction()

# =============================================================================
# Apply obfuscation to a target
# =============================================================================
function(apply_llvm_obfuscation target)
    if(NOT ENABLE_OBFUSCATION)
        return()
    endif()

    check_llvm_obfuscator_support()

    if(NOT LLVM_OBFUSCATOR_SUPPORTED)
        message(STATUS "[Obfuscation] Applying fallback hardening for ${target}")
        apply_fallback_hardening(${target})
        return()
    endif()

    message(STATUS "[Obfuscation] Applying ${OBFUSCATION_LEVEL} obfuscation to ${target}")

    set(OBF_FLAGS "")

    if(OBFUSCATION_LEVEL STREQUAL "light")
        # Light obfuscation - minimal performance impact
        list(APPEND OBF_FLAGS
            -mllvm -sub                    # Instruction substitution
            -mllvm -sub_loop=1             # Single pass
        )
    elseif(OBFUSCATION_LEVEL STREQUAL "standard")
        # Standard obfuscation - balanced protection/performance
        list(APPEND OBF_FLAGS
            -mllvm -sub                    # Instruction substitution
            -mllvm -sub_loop=2             # Two passes
            -mllvm -bcf                    # Bogus control flow
            -mllvm -bcf_prob=40            # 40% probability
            -mllvm -fla                    # Control flow flattening
            -mllvm -split                  # Basic block splitting
            -mllvm -split_num=3            # Split into 3 blocks
        )
    elseif(OBFUSCATION_LEVEL STREQUAL "aggressive")
        # Aggressive obfuscation - maximum protection
        list(APPEND OBF_FLAGS
            -mllvm -sub                    # Instruction substitution
            -mllvm -sub_loop=3             # Three passes
            -mllvm -bcf                    # Bogus control flow
            -mllvm -bcf_prob=80            # 80% probability
            -mllvm -bcf_loop=2             # Two BCF passes
            -mllvm -fla                    # Control flow flattening
            -mllvm -split                  # Basic block splitting
            -mllvm -split_num=5            # Split into 5 blocks
            -mllvm -sobf                   # String obfuscation
        )
    endif()

    target_compile_options(${target} PRIVATE ${OBF_FLAGS})

    # Always strip symbols in Release
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(${target} PRIVATE -s)
    endif()
endfunction()

# =============================================================================
# Fallback hardening when obfuscator not available
# =============================================================================
function(apply_fallback_hardening target)
    message(STATUS "[Obfuscation] Applying compile-time hardening to ${target}")

    # Security hardening flags (always available)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -fstack-protector-strong
            -fPIC
            -D_FORTIFY_SOURCE=2
            -fvisibility=hidden
            -fvisibility-inlines-hidden
        )

        target_link_options(${target} PRIVATE
            -Wl,-z,relro,-z,now
            -Wl,-z,noexecstack
        )

        # Strip in Release
        if(CMAKE_BUILD_TYPE STREQUAL "Release")
            target_link_options(${target} PRIVATE -s)
        endif()
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE
            /GS /sdl /guard:cf /Qspectre
        )
        target_link_options(${target} PRIVATE
            /DYNAMICBASE /NXCOMPAT /guard:cf
        )
    endif()
endfunction()

# =============================================================================
# Convenience function to enable obfuscation on target
# =============================================================================
function(target_enable_obfuscation target)
    apply_llvm_obfuscation(${target})
endfunction()
