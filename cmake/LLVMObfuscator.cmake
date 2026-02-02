cmake_minimum_required(VERSION 3.20)

option(ENABLE_OBFUSCATION "Enable LLVM-based code obfuscation" OFF)
set(OBFUSCATION_LEVEL "standard" CACHE STRING "Obfuscation level: light, standard, aggressive")
set_property(CACHE OBFUSCATION_LEVEL PROPERTY STRINGS light standard aggressive)

function(check_llvm_obfuscator_support)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "[Obfuscation] LLVM obfuscation requires Clang compiler. Current: ${CMAKE_CXX_COMPILER_ID}")
        set(LLVM_OBFUSCATOR_SUPPORTED FALSE PARENT_SCOPE)
        return()
    endif()

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
        list(APPEND OBF_FLAGS
            -mllvm -sub
            -mllvm -sub_loop=1
        )
    elseif(OBFUSCATION_LEVEL STREQUAL "standard")
        list(APPEND OBF_FLAGS
            -mllvm -sub
            -mllvm -sub_loop=2
            -mllvm -bcf
            -mllvm -bcf_prob=40
            -mllvm -fla
            -mllvm -split
            -mllvm -split_num=3
        )
    elseif(OBFUSCATION_LEVEL STREQUAL "aggressive")
        list(APPEND OBF_FLAGS
            -mllvm -sub
            -mllvm -sub_loop=3
            -mllvm -bcf
            -mllvm -bcf_prob=80
            -mllvm -bcf_loop=2
            -mllvm -fla
            -mllvm -split
            -mllvm -split_num=5
            -mllvm -sobf
        )
    endif()

    target_compile_options(${target} PRIVATE ${OBF_FLAGS})

    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        target_link_options(${target} PRIVATE -s)
    endif()
endfunction()

function(apply_fallback_hardening target)
    message(STATUS "[Obfuscation] Applying compile-time hardening to ${target}")

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

function(target_enable_obfuscation target)
    apply_llvm_obfuscation(${target})
endfunction()
