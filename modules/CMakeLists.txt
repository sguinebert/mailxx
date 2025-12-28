# CMakeLists.txt for mailxx C++20 modules
#
# This is EXPERIMENTAL and requires:
# - CMake 3.28+
# - A compiler with C++20 modules support (MSVC 2022, GCC 14+, Clang 16+)
# - Ninja generator recommended
#
# Usage:
#   cmake -G Ninja -B build -Dmailxx_BUILD_MODULES=ON
#   cmake --build build

cmake_minimum_required(VERSION 3.28)

# Check if modules are enabled
if(NOT mailxx_BUILD_MODULES)
    return()
endif()

message(STATUS "Building mailxx C++20 modules (EXPERIMENTAL)")

# Module source files
set(mailxx_MODULE_SOURCES
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.codec.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.net.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.mime.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.smtp.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.pop3.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.imap.cppm
    ${CMAKE_CURRENT_SOURCE_DIR}/mailxx.cppm
)

# Create module library
add_library(mailxx_modules)

target_sources(mailxx_modules
    PUBLIC
        FILE_SET CXX_MODULES FILES
            ${mailxx_MODULE_SOURCES}
)

target_compile_features(mailxx_modules PUBLIC cxx_std_20)

target_include_directories(mailxx_modules
    PUBLIC
        ${CMAKE_SOURCE_DIR}/include
        ${Boost_INCLUDE_DIRS}
)

target_link_libraries(mailxx_modules
    PUBLIC
        ${Boost_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        Threads::Threads
)

# Alias for consistent naming
add_library(mailxx::modules ALIAS mailxx_modules)
