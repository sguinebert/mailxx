cmake_minimum_required (VERSION 3.28)

project(mailxx VERSION 1.0.0)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT DEFINED LIB_SUFFIX)
  set(LIB_SUFFIX "" CACHE STRING "Suffix for installed library path. Ex. 64 for lib64")
endif(NOT DEFINED LIB_SUFFIX)

# Set bindir, if not use -DBIN_INSTALL_DIR
if(NOT BIN_INSTALL_DIR)
  if(CMAKE_INSTALL_BINDIR)
    set(BIN_INSTALL_DIR ${CMAKE_INSTALL_BINDIR})
  else(CMAKE_INSTALL_BINDIR)
    set(BIN_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/bin")
  endif(CMAKE_INSTALL_BINDIR)
endif(NOT BIN_INSTALL_DIR)

# Set libdir, if not use -DLIB_INSTALL_DIR
if(NOT LIB_INSTALL_DIR)
  if(CMAKE_INSTALL_LIBDIR)
    set(LIB_INSTALL_DIR ${CMAKE_INSTALL_LIBDIR})
  else(CMAKE_INSTALL_LIBDIR)
    set(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib${LIB_SUFFIX}")
  endif(CMAKE_INSTALL_LIBDIR)
endif(NOT LIB_INSTALL_DIR)

# Set includedir, if not use -DINCLUDE_INSTALL_DIR
if(NOT INCLUDE_INSTALL_DIR)
  if(CMAKE_INSTALL_INCLUDEDIR)
    set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_INCLUDEDIR})
  else(CMAKE_INSTALL_INCLUDEDIR)
    set(INCLUDE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/include")
  endif(CMAKE_INSTALL_INCLUDEDIR)
endif(NOT INCLUDE_INSTALL_DIR)

# Set sharedir, if not use -DSHARE_INSTALL_DIR
if(NOT SHARE_INSTALL_DIR)
  if(CMAKE_INSTALL_DATADIR)
    set(SHARE_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}")
  else(CMAKE_INSTALL_DATADIR)
    set(SHARE_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/share")
  endif(CMAKE_INSTALL_DATADIR)
endif(NOT SHARE_INSTALL_DIR)

# options for mailxx to control how the project is built.
option(mailxx_BUILD_DOCUMENTATION "Turn on to build doxygen based documentation." ON)
option(mailxx_BUILD_EXAMPLES "Turn on to build examples." ON)
option(mailxx_BUILD_TESTS "Turn on to build the tests." ON)
option(mailxx_DYN_LINK_TESTS "Turn on to dynamically link the tests." OFF)
option(mailxx_BUILD_MODULES "Turn on to build C++20 modules (EXPERIMENTAL, requires CMake 3.28+)." OFF)

option(BUILD_SHARED_LIBS "Turn on to build mailxx as a shared library. When off mailxx is build as a static library." ON)

# add a dependent option to build latex documentation or not.
include(CMakeDependentOption)
cmake_dependent_option(mailxx_BUILD_LATEX_DOCUMENTATION "Build latex docs" ON "mailxx_BUILD_DOCUMENTATION" ON)

if(WIN32)
    set(Boost_USE_STATIC_LIBS ON)
endif(WIN32)

find_package(Boost REQUIRED COMPONENTS regex)
find_package(OpenSSL)
set(CMAKE_THREAD_PREFER_PTHREAD)
# "Use of both the imported target as well as this switch is highly recommended for new code."
set(THREADS_PREFER_PTHREAD_FLAG)
find_package(Threads)

set(project_sources
    ${PROJECT_SOURCE_DIR}/src/message.cpp
    ${PROJECT_SOURCE_DIR}/src/mime.cpp
)

set(project_headers
    ${PROJECT_SOURCE_DIR}/include/mailxx/export.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/mailxx.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/imap.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/import.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/message.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/pop3.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/smtp.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/detail/append.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/detail/async_mutex.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/detail/ascii.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/base64.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/binary.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/bit7.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/bit8.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/codec.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/percent.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/q_codec.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/codec/quoted_printable.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/mime/mailboxes.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/mime/message.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/mime/mime.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/net/dialog.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/net/upgradable_stream.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/imap/client.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/imap/error.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/imap/types.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/pop3/client.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/pop3/error.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/pop3/types.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/smtp/client.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/smtp/error.hpp
    ${PROJECT_SOURCE_DIR}/include/mailxx/smtp/types.hpp
)

# handle documentation
if(${mailxx_BUILD_DOCUMENTATION})
    find_package(Doxygen COMPONENTS doxygen OPTIONAL_COMPONENTS dot)
    if(DOXYGEN_FOUND)
        set(DOXYGEN_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/docs/mailxx)
        set(DOXYGEN_GENERATE_LATEX ${mailxx_BUILD_LATEX_DOCUMENTATION})
        set(DOXYGEN_OUTPUT_PATH ${DOCOUTDIR})

        doxygen_add_docs(docs ${PROJECT_SOURCE_DIR}/include ALL WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
    else(DOXYGEN_FOUND)
        message(STATUS "doxygen was not found, documentation will not be built")
    endif(DOXYGEN_FOUND)
endif(${mailxx_BUILD_DOCUMENTATION})

add_library(${PROJECT_NAME} ${project_sources} ${project_headers})
add_library(${PROJECT_NAME}::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

# pkg-config support
set(prefix "${CMAKE_INSTALL_PREFIX}")
set(exec_prefix "\${prefix}" )

if(IS_ABSOLUTE "${LIB_INSTALL_DIR}")
  set(libdir "${LIB_INSTALL_DIR}")
else(IS_ABSOLUTE "${LIB_INSTALL_DIR}")
  set(libdir "\${exec_prefix}/${LIB_INSTALL_DIR}")
endif(IS_ABSOLUTE "${LIB_INSTALL_DIR}")

if(IS_ABSOLUTE "${INCLUDE_INSTALL_DIR}")
  set(includedir "${INCLUDE_INSTALL_DIR}/${PROJECT_NAME}")
else(IS_ABSOLUTE "${INCLUDE_INSTALL_DIR}")
  set(includedir "\${prefix}/${INCLUDE_INSTALL_DIR}/${PROJECT_NAME}")
endif(IS_ABSOLUTE "${INCLUDE_INSTALL_DIR}")

configure_file(mailxx.pc.in ${CMAKE_BINARY_DIR}/mailxx.pc IMMEDIATE @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/mailxx.pc DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)

configure_file(${PROJECT_SOURCE_DIR}/include/version.hpp.in version.hpp)
install(FILES ${CMAKE_BINARY_DIR}/version.hpp DESTINATION ${INCLUDE_INSTALL_DIR}/${PROJECT_NAME})

# generate the export header for exporting symbols
# this is needed to generate a shared library.
include(GenerateExportHeader)
generate_export_header(${PROJECT_NAME} EXPORT_FILE_NAME export.hpp)
target_include_directories(${PROJECT_NAME}
    PUBLIC
        "$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include;${CMAKE_CURRENT_BINARY_DIR}>"
        "$<INSTALL_INTERFACE:include>"
)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/export.hpp DESTINATION "${INCLUDE_INSTALL_DIR}/${PROJECT_NAME}")

if(Boost_FOUND)
    target_include_directories(${PROJECT_NAME} PUBLIC ${Boost_INCLUDE_DIRS})
    target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES})
endif()

if(OPENSSL_FOUND)
    target_include_directories(${PROJECT_NAME} PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
endif()

if(MINGW)
    target_link_libraries(${PROJECT_NAME} -lws2_32 )
endif(MINGW)

if (MSVC)
    target_compile_options(${PROJECT_NAME} PRIVATE /W2 /WX)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(DIRECTORY include/mailxx DESTINATION ${INCLUDE_INSTALL_DIR})

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

# Target
install(TARGETS ${PROJECT_NAME}
    EXPORT ${PROJECT_NAME}-export
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

export(
    EXPORT ${PROJECT_NAME}-export
    NAMESPACE ${PROJECT_NAME}::
    FILE ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-targets.cmake
)

install(EXPORT ${PROJECT_NAME}-export
    NAMESPACE ${PROJECT_NAME}::
    FILE ${PROJECT_NAME}-targets.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/
)

# Config and version
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/${PROJECT_NAME}-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}/
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
)

# optionally build examples
if(${mailxx_BUILD_EXAMPLES})
    add_subdirectory(examples)
    file(GLOB PNGS "${PROJECT_SOURCE_DIR}/examples/*.png")
    install(FILES ${PNGS} DESTINATION "${SHARE_INSTALL_DIR}/${PROJECT_NAME}/examples/")
endif(${mailxx_BUILD_EXAMPLES})

if(${mailxx_BUILD_TESTS})
    enable_testing()
    add_subdirectory(test)
    file(GLOB PNGS "${PROJECT_SOURCE_DIR}/test/aleph0.png")
    install(FILES ${PNGS} DESTINATION "${SHARE_INSTALL_DIR}/${PROJECT_NAME}/test/")
    file(GLOB TXTS "${PROJECT_SOURCE_DIR}/test/cv.txt")
    install(FILES ${TXTS} DESTINATION "${SHARE_INSTALL_DIR}/${PROJECT_NAME}/test/")
endif(${mailxx_BUILD_TESTS})

# optionally build C++20 modules (EXPERIMENTAL)
if(${mailxx_BUILD_MODULES})
    if(CMAKE_VERSION VERSION_LESS "3.28")
        message(WARNING "C++20 modules require CMake 3.28+. Skipping modules build.")
    else()
        add_subdirectory(modules)
    endif()
endif(${mailxx_BUILD_MODULES})
