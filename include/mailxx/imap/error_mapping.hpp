/*

error_mapping.hpp
-----------------

Centralized mapping between IMAP responses and mailxx::errc.

*/

#pragma once

#include <cstddef>
#include <string_view>

#include <mailxx/detail/result.hpp>

namespace mailxx::imap
{

enum class error_kind
{
    tagged_no,
    tagged_bad,
    continuation_expected,
    parse
};

[[nodiscard]] constexpr errc map_imap_error(error_kind kind) noexcept
{
    switch (kind)
    {
        case error_kind::tagged_no: return errc::imap_tagged_no;
        case error_kind::tagged_bad: return errc::imap_tagged_bad;
        case error_kind::continuation_expected: return errc::imap_continuation_expected;
        case error_kind::parse: return errc::imap_parse_error;
    }
    return errc::imap_parse_error;
}

[[nodiscard]] inline detail::error_detail make_imap_detail(
    std::string_view tag,
    std::string_view command,
    std::string_view tagged_line,
    std::size_t untagged_count,
    std::size_t literals_count)
{
    detail::error_detail detail;
    detail.add("proto", "imap");
    detail.add("tag", tag);
    detail.add("command", command);
    detail.add("tagged.line", tagged_line);
    detail.add("untagged.count", untagged_count);
    detail.add("literals.count", literals_count);
    return detail;
}

} // namespace mailxx::imap
