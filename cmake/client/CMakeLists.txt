set(CLIENT_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/src/client/opaque_client.cpp
)

if(BUILD_DOTNET_INTEROP)
    list(APPEND CLIENT_SOURCES ${CMAKE_SOURCE_DIR}/src/interop/client_exports.cpp)
    add_library(opaque_client SHARED ${CLIENT_SOURCES})
    set_target_properties(opaque_client PROPERTIES
        OUTPUT_NAME "opaque_client"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
else()
    add_library(opaque_client_static STATIC ${CLIENT_SOURCES})
    set_target_properties(opaque_client_static PROPERTIES
        OUTPUT_NAME "opaque_client"
    )
    target_compile_definitions(opaque_client_static PRIVATE OPAQUE_STATIC_LIB)
    set(CLIENT_TARGET opaque_client_static)
endif()

if(TARGET opaque_client)
    set(CLIENT_TARGET opaque_client)
endif()

target_include_directories(${CLIENT_TARGET} PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(${CLIENT_TARGET}
    ${SODIUM_LIBRARIES}
)

target_link_directories(${CLIENT_TARGET} PRIVATE ${SODIUM_LIBRARY_DIRS})

if(NOT SODIUM_LIBRARIES)
    target_link_libraries(${CLIENT_TARGET} sodium)
endif()

target_compile_definitions(${CLIENT_TARGET} PRIVATE
    OPAQUE_CLIENT_BUILD
)

if(BUILD_DOTNET_INTEROP AND TARGET opaque_client)
    if(WIN32)
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".dll"
        )
    elseif(APPLE)
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".dylib"
        )
    else()
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".so"
        )
    endif()
endif()

install(TARGETS ${CLIENT_TARGET}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/opaque
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)