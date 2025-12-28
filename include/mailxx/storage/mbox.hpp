/*

mbox.hpp
--------

Minimal mbox reader/writer without external dependencies.

*/

#pragma once

#include <optional>
#include <ostream>
#include <istream>
#include <string>
#include <string_view>

namespace mailxx::storage
{

struct from_line_metadata
{
    std::string sender;
    std::string date; // Already formatted date portion of the "From " line
};

class mbox_reader
{
public:
    explicit mbox_reader(std::istream& in) : in_(&in) {}

    std::optional<std::string> next()
    {
        if (!in_ || !*in_)
            return std::nullopt;

        std::string message;
        bool started = false;

        auto is_from_separator = [](std::string_view line) {
            return line.rfind("From ", 0) == 0;
        };

        auto consume_line = [this](std::string& line) -> bool {
            if (!std::getline(*in_, line))
                return false;
            if (!line.empty() && line.back() == '\r')
                line.pop_back();
            return true;
        };

        // If we already peeked a separator, skip it and start collecting.
        if (lookahead_from_separator_)
        {
            started = true;
            lookahead_from_separator_ = false;
        }

        std::string line;
        while (true)
        {
            if (!consume_line(line))
            {
                if (started)
                    return message;
                return std::nullopt;
            }

            if (!started)
            {
                if (is_from_separator(line))
                {
                    started = true;
                    continue; // Separator consumed, start collecting
                }
                continue; // Skip until first separator
            }

            if (is_from_separator(line))
            {
                // Boundary for next message.
                lookahead_from_separator_ = true;
                return message;
            }

            if (line.rfind(">From ", 0) == 0)
                line.erase(0, 1);
            message += line;
            message.push_back('\n');
        }
    }

private:
    std::istream* in_{nullptr};
    bool lookahead_from_separator_{false};
};

class mbox_writer
{
public:
    explicit mbox_writer(std::ostream& out) : out_(&out) {}

    void append_message(std::string_view rfc822, const from_line_metadata& meta)
    {
        if (!out_)
            return;
        (*out_) << "From " << meta.sender << " " << meta.date << "\n";

        auto flush_line = [this](std::string_view line) {
            if (line.rfind("From ", 0) == 0)
                (*out_) << '>';
            (*out_) << line << "\n";
        };

        std::size_t start = 0;
        while (start <= rfc822.size())
        {
            auto pos = rfc822.find('\n', start);
            if (pos == std::string_view::npos)
            {
                std::string_view line = rfc822.substr(start);
                if (line.size() && line.back() == '\r')
                    line.remove_suffix(1);
                flush_line(line);
                break;
            }
            std::string_view line = rfc822.substr(start, pos - start);
            if (!line.empty() && line.back() == '\r')
                line.remove_suffix(1);
            flush_line(line);
            start = pos + 1;
        }
    }

private:
    std::ostream* out_{nullptr};
};

} // namespace mailxx::storage
