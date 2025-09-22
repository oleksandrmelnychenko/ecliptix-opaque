cmake_minimum_required(VERSION 3.20)

project(Catch2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(Catch2 INTERFACE)
add_library(Catch2::Catch2 ALIAS Catch2)

target_include_directories(Catch2 INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/single_include>
    $<INSTALL_INTERFACE:include>
)

add_library(Catch2WithMain catch2_main.cpp)
add_library(Catch2::Catch2WithMain ALIAS Catch2WithMain)

target_link_libraries(Catch2WithMain PUBLIC Catch2)

target_include_directories(Catch2WithMain PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/single_include>
    $<INSTALL_INTERFACE:include>
)