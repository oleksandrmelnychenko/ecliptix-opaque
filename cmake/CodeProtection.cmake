cmake_minimum_required(VERSION 3.20)

option(ENABLE_CODE_PROTECTION "Enable code protection/obfuscation" ON)
option(USE_LLVM_OBFUSCATOR "Use LLVM-based compile-time obfuscation" OFF)
set(PROTECTION_LEVEL "standard" CACHE STRING "Protection level: minimal, standard, maximum")
set_property(CACHE PROTECTION_LEVEL PROPERTY STRINGS minimal standard maximum)

set(VMPROTECT_PATH "" CACHE FILEPATH "Path to VMProtect CLI executable")
set(THEMIDA_PATH "" CACHE FILEPATH "Path to Themida CLI executable")

function(apply_compile_hardening target)
    message(STATUS "[Protection] Applying compile-time hardening to ${target}")

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${target} PRIVATE
            -fstack-protector-strong
            -fstack-clash-protection

            -fPIC

            -D_FORTIFY_SOURCE=2

            $<$<CXX_COMPILER_ID:Clang>:-fsanitize=cfi>
            $<$<CXX_COMPILER_ID:Clang>:-fvisibility=hidden>

            -Wl,-z,noexecstack

            $<$<CONFIG:Release>:-s>
        )

        target_link_options(${target} PRIVATE
            -Wl,-z,relro,-z,now

            -Wl,-z,noexecstack

            -Wl,-z,now
        )
    endif()

    if(MSVC)
        target_compile_options(${target} PRIVATE
            /GS

            /sdl

            /guard:cf

            /Qspectre
        )

        target_link_options(${target} PRIVATE
            /DYNAMICBASE

            /NXCOMPAT

            /guard:cf

            $<$<EQUAL:${CMAKE_SIZEOF_VOID_P},8>:/HIGHENTROPYVA>
        )
    endif()
endfunction()

function(apply_llvm_obfuscation target level)
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        message(WARNING "[Protection] LLVM obfuscation requires Clang compiler")
        return()
    endif()

    message(STATUS "[Protection] Applying LLVM obfuscation (level: ${level}) to ${target}")

    set(OBFUSCATION_FLAGS "")

    if(level STREQUAL "minimal")
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub
            -mllvm -bcf_prob=30
        )
    elseif(level STREQUAL "standard")
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub
            -mllvm -bcf
            -mllvm -bcf_prob=50
            -mllvm -fla
            -mllvm -split
            -mllvm -split_num=3
        )
    elseif(level STREQUAL "maximum")
        list(APPEND OBFUSCATION_FLAGS
            -mllvm -sub
            -mllvm -sub_loop=3
            -mllvm -bcf
            -mllvm -bcf_prob=80
            -mllvm -bcf_loop=3
            -mllvm -fla
            -mllvm -split
            -mllvm -split_num=5
            -mllvm -sobf
        )
    endif()

    target_compile_options(${target} PRIVATE ${OBFUSCATION_FLAGS})
endfunction()

function(enable_string_encryption target)
    message(STATUS "[Protection] Enabling string encryption for ${target}")

    target_compile_definitions(${target} PRIVATE
        ECLIPTIX_ENABLE_STRING_ENCRYPTION=1
    )

    if(CMAKE_CXX_STANDARD GREATER_EQUAL 20)
        target_compile_definitions(${target} PRIVATE
            ECLIPTIX_USE_CONSTEXPR_ENCRYPTION=1
        )
    endif()
endfunction()

function(enable_anti_debug target)
    message(STATUS "[Protection] Enabling anti-debug for ${target}")

    target_compile_definitions(${target} PRIVATE
        ECLIPTIX_ENABLE_ANTI_DEBUG=1
        ECLIPTIX_ENABLE_ANTI_TAMPER=1
    )
endfunction()

function(apply_vmprotect target vmp_path level)
    if(NOT EXISTS "${vmp_path}")
        message(WARNING "[Protection] VMProtect not found at: ${vmp_path}")
        return()
    endif()

    message(STATUS "[Protection] Configuring VMProtect for ${target}")

    set(VMP_OPTIONS "")
    if(level STREQUAL "minimal")
        set(VMP_OPTIONS "--mutation-level=low --vm-code-level=low")
    elseif(level STREQUAL "standard")
        set(VMP_OPTIONS "--mutation-level=medium --vm-code-level=medium --anti-debug")
    elseif(level STREQUAL "maximum")
        set(VMP_OPTIONS "--mutation-level=ultra --vm-code-level=ultra --anti-debug --anti-vm --pack-resources")
    endif()

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

function(apply_themida target themida_path level)
    if(NOT EXISTS "${themida_path}")
        message(WARNING "[Protection] Themida not found at: ${themida_path}")
        return()
    endif()

    message(STATUS "[Protection] Configuring Themida for ${target}")

    set(THEMIDA_VM "FISH_WHITE")
    if(level STREQUAL "minimal")
        set(THEMIDA_VM "FISH_LITE")
    elseif(level STREQUAL "maximum")
        set(THEMIDA_VM "TIGER_BLACK")
    endif()

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

function(enable_code_protection target)
    if(NOT ENABLE_CODE_PROTECTION)
        message(STATUS "[Protection] Code protection disabled for ${target}")
        return()
    endif()

    message(STATUS "============================================")
    message(STATUS "[Protection] Configuring protection for: ${target}")
    message(STATUS "[Protection] Level: ${PROTECTION_LEVEL}")
    message(STATUS "============================================")

    apply_compile_hardening(${target})

    if(USE_LLVM_OBFUSCATOR AND CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        apply_llvm_obfuscation(${target} ${PROTECTION_LEVEL})
    endif()

    if(NOT PROTECTION_LEVEL STREQUAL "minimal")
        enable_string_encryption(${target})
    endif()

    if(PROTECTION_LEVEL STREQUAL "maximum")
        enable_anti_debug(${target})
    endif()

    if(VMPROTECT_PATH AND EXISTS "${VMPROTECT_PATH}")
        apply_vmprotect(${target} "${VMPROTECT_PATH}" ${PROTECTION_LEVEL})
    endif()

    if(WIN32 AND THEMIDA_PATH AND EXISTS "${THEMIDA_PATH}")
        apply_themida(${target} "${THEMIDA_PATH}" ${PROTECTION_LEVEL})
    endif()

    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
            add_custom_command(TARGET ${target} POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all "$<TARGET_FILE:${target}>" || true
                COMMENT "[Protection] Stripping symbols from ${target}"
            )
        endif()
    endif()
endfunction()

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
