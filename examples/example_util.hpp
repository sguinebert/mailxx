#pragma once

#include <iostream>
#include <mailxx/detail/result.hpp>

inline void print_error(const mailxx::error_info& err)
{
    std::cout << "Error: " << mailxx::to_string(err.code) << " - " << err.message << "\n";
    std::cout << "Detail: " << err.detail << "\n";
    std::cout << "Sys: " << err.sys.message() << "\n";
    std::cout << "Where: " << err.where.file_name() << ":" << err.where.line()
              << " " << err.where.function_name() << "\n";
}
