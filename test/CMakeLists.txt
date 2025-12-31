find_package(Boost REQUIRED COMPONENTS unit_test_framework)

function(add_mailxx_tests SOURCE_FILE)
    get_filename_component(file_name ${SOURCE_FILE} NAME_WE)
    add_executable(${file_name} ${SOURCE_FILE})
    add_test(NAME ${file_name} COMMAND ${file_name})
    include("CTest")
    set_tests_properties(${file_name} PROPERTIES WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}/test")
    if(${mailxx_DYN_LINK_TESTS})
        add_definitions(-DBOOST_TEST_DYN_LINK)
    endif()
    target_link_directories(${file_name} PUBLIC ${Boost_LIBRARY_DIRS})
    target_link_libraries(${file_name} PUBLIC ${Boost_LIBRARIES} mailxx ${CMAKE_THREAD_LIBS_INIT})
    install(TARGETS ${file_name} DESTINATION "${SHARE_INSTALL_DIR}/${PROJECT_NAME}/test")

    # MinGW COFF string table can overflow with heavy coroutine symbols in Debug.
    if (MINGW AND file_name MATCHES "test_(imap_append_streaming|smtp_streaming)")
        target_compile_options(${file_name} PRIVATE -g0)
    endif()
endfunction(add_mailxx_tests)

file(GLOB test_files ${CMAKE_CURRENT_SOURCE_DIR}/test*.cpp)
if (MINGW)
    # MinGW COFF string table overflows on heavy coroutine tests.
    list(FILTER test_files EXCLUDE REGEX "test_(imap_append_streaming|smtp_streaming)\\.cpp$")
endif()
foreach(file_name ${test_files})
    add_mailxx_tests(${file_name})
endforeach(file_name ${test_files})
