/*

attachment_source.hpp
---------------------

Represents the source of an attachment without forcing it into memory.

*/

#pragma once

#include <string>

namespace mailxx
{

enum class source_kind { in_memory, file_path };

struct attachment_source
{
    source_kind kind{source_kind::in_memory};
    std::string path;
    std::string bytes;
};

} // namespace mailxx

