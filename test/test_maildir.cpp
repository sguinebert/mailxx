/*

test_maildir.cpp
----------------

Validates basic Maildir operations: add, list, move, read.

*/

#define BOOST_TEST_MODULE maildir_test

#include <string>
#include <filesystem>
#include <chrono>
#include <boost/test/unit_test.hpp>
#include <mailxx/storage/maildir.hpp>

using mailxx::storage::maildir;

static std::filesystem::path make_temp_dir()
{
    auto base = std::filesystem::temp_directory_path() / "mailxx_maildir_test";
    std::filesystem::create_directories(base);
    auto dir = base / std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
    std::filesystem::create_directories(dir);
    return dir;
}

BOOST_AUTO_TEST_CASE(maildir_basic_flow)
{
    auto tmp = make_temp_dir();
    maildir md(tmp);

    const std::string payload = "From: a@example.com\r\n\r\nHello\r\n";
    auto e_new = md.add_message(payload);
    auto new_list = md.list_new();
    BOOST_CHECK_EQUAL(new_list.size(), 1u);

    auto e_cur = md.move_to_cur(e_new, "RS");
    auto cur_list = md.list_cur();
    BOOST_CHECK_EQUAL(cur_list.size(), 1u);
    BOOST_CHECK_EQUAL(cur_list.front().flags, "RS");

    auto read_back = md.read_message(cur_list.front());
    BOOST_CHECK_EQUAL(read_back, payload);

    // update flags
    auto e_cur2 = md.set_flags(cur_list.front(), "FT");
    auto cur_list2 = md.list_cur();
    BOOST_CHECK_EQUAL(cur_list2.size(), 1u);
    BOOST_CHECK_EQUAL(cur_list2.front().flags, "FT");

    std::filesystem::remove_all(tmp);
}
