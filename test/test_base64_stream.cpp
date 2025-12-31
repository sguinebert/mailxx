/*

test_base64_stream.cpp
----------------------

Validate streaming Base64 encoding matches existing encoder output and wrapping.

*/

#define BOOST_TEST_MODULE base64_stream_test

#include <boost/test/unit_test.hpp>
#include <mailxx/codec/base64.hpp>
#include <mailxx/codec/base64_stream.hpp>
#include <mailxx/detail/output_sink.hpp>
#include <vector>
#include <string>
#include <algorithm>
#include <string_view>

using namespace mailxx;

namespace
{
std::string join_lines(const std::vector<std::string>& lines, std::string_view eol)
{
    if (lines.empty())
        return {};
    std::size_t total = 0;
    for (const auto& line : lines)
        total += line.size();
    total += eol.size() * (lines.size() - 1);
    std::string out;
    out.reserve(total);
    for (std::size_t i = 0; i < lines.size(); ++i)
    {
        if (i != 0)
            out.append(eol);
        out.append(lines[i]);
    }
    return out;
}

std::string encode_streaming(std::string_view input, std::size_t line_policy = 76)
{
    base64_stream_encoder enc(line_policy);
    std::string out;
    detail::string_sink sink(out);

    const auto* data = reinterpret_cast<const std::byte*>(input.data());
    const std::size_t size = input.size();

    // Chunk the input to ensure incremental paths are covered
    std::vector<std::size_t> chunks{5, 7, 13, 29};
    std::size_t offset = 0;
    for (std::size_t chunk : chunks)
    {
        if (offset >= size)
            break;
        const std::size_t len = std::min(chunk, size - offset);
        enc.update(std::span<const std::byte>(data + offset, len), sink);
        offset += len;
    }
    if (offset < size)
        enc.update(std::span<const std::byte>(data + offset, size - offset), sink);

    enc.finalize(sink);
    return out;
}
} // namespace

BOOST_AUTO_TEST_CASE(stream_matches_classic_encoder)
{
    const std::string input = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";

    base64 codec(76, 76);
    auto expected_res = codec.encode(input);
    BOOST_REQUIRE(!expected_res.empty());
    const std::string expected = join_lines(expected_res, codec::END_OF_LINE);
    const std::string streamed = encode_streaming(input, 76);

    BOOST_TEST(streamed == expected);
}

BOOST_AUTO_TEST_CASE(stream_handles_short_inputs)
{
    const std::string input = "pad";
    base64 codec(76, 76);
    auto expected_res = codec.encode(input);
    BOOST_REQUIRE(!expected_res.empty());
    const std::string expected = join_lines(expected_res, codec::END_OF_LINE);
    const std::string streamed = encode_streaming(input, 76);
    BOOST_TEST(streamed == expected);
}
