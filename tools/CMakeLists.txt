if(mailxx_BUILD_REALWORLD_CLI)
    include(FetchContent)

    find_package(CLI11 CONFIG QUIET)
    if(NOT CLI11_FOUND)
        FetchContent_Declare(
            CLI11
            GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
            GIT_TAG v2.6.2
        )
        FetchContent_MakeAvailable(CLI11)
    endif()

    add_executable(mailxx_realworld_cli mailxx_realworld_cli.cpp)
    target_link_libraries(mailxx_realworld_cli PRIVATE mailxx CLI11::CLI11)
    target_compile_definitions(mailxx_realworld_cli PRIVATE MAILXX_REPO_ROOT="${PROJECT_SOURCE_DIR}")

    install(TARGETS mailxx_realworld_cli DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

if(mailxx_BUILD_LAB_RECIPES)
    add_executable(lab_postfix_frozen lab_postfix_frozen.cpp)
    target_link_libraries(lab_postfix_frozen PRIVATE mailxx)

    add_executable(lab_dovecot_peek lab_dovecot_peek.cpp)
    target_link_libraries(lab_dovecot_peek PRIVATE mailxx)

    add_executable(lab_wsl_proof lab_wsl_proof.cpp)
    target_link_libraries(lab_wsl_proof PRIVATE mailxx)
    if(WIN32)
        target_link_libraries(lab_wsl_proof PRIVATE ws2_32 mswsock)
    endif()
endif()
