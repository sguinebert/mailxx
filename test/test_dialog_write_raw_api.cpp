#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <mailxx/net/dialog.hpp>
#include <mailxx/net/upgradable_stream.hpp>

#define BOOST_TEST_MODULE test_dialog_write_raw_api
#include <boost/test/included/unit_test.hpp>

namespace
{

using dialog_t = mailxx::net::dialog<mailxx::net::upgradable_stream>;

template<typename Dialog>
concept can_write_raw_move_string = requires(Dialog& dlg, std::string& payload)
{
    dlg.write_raw(std::move(payload), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_lvalue_string = requires(Dialog& dlg, std::string& payload)
{
    dlg.write_raw(payload, mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_move_vector = requires(Dialog& dlg, std::vector<char>& payload)
{
    dlg.write_raw(std::move(payload), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_view_lvalue = requires(Dialog& dlg, std::string_view& view)
{
    dlg.write_raw_view(view, mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_view_temporary = requires(Dialog& dlg)
{
    dlg.write_raw_view(std::string_view("temp"), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_buffer_move_owner = requires(Dialog& dlg, std::span<const char>& view, std::shared_ptr<std::string>& owner)
{
    dlg.write_raw_buffer(view, std::move(owner), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_raw_buffer_lvalue_owner = requires(Dialog& dlg, std::span<const char>& view, std::shared_ptr<std::string>& owner)
{
    dlg.write_raw_buffer(view, owner, mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_move_string = requires(Dialog& dlg, std::string& line)
{
    dlg.write_line(std::move(line), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_lvalue_string = requires(Dialog& dlg, std::string& line)
{
    dlg.write_line(line, mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_view_lvalue = requires(Dialog& dlg, std::string_view& view)
{
    dlg.write_line_view(view, mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_view_temporary = requires(Dialog& dlg)
{
    dlg.write_line_view(std::string_view("temp\r\n"), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_view_literal = requires(Dialog& dlg)
{
    dlg.write_line_view("NOOP", mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_buffer_move_owner = requires(Dialog& dlg, std::string_view& view, std::shared_ptr<std::string>& owner)
{
    dlg.write_line_buffer(view, std::move(owner), mailxx::asio::use_future);
};

template<typename Dialog>
concept can_write_line_buffer_lvalue_owner = requires(Dialog& dlg, std::string_view& view, std::shared_ptr<std::string>& owner)
{
    dlg.write_line_buffer(view, owner, mailxx::asio::use_future);
};

static_assert(can_write_raw_move_string<dialog_t>);
static_assert(!can_write_raw_lvalue_string<dialog_t>);
static_assert(can_write_raw_move_vector<dialog_t>);
static_assert(can_write_raw_view_lvalue<dialog_t>);
static_assert(!can_write_raw_view_temporary<dialog_t>);
static_assert(can_write_raw_buffer_move_owner<dialog_t>);
static_assert(!can_write_raw_buffer_lvalue_owner<dialog_t>);
static_assert(!can_write_line_move_string<dialog_t>);
static_assert(!can_write_line_lvalue_string<dialog_t>);
static_assert(can_write_line_view_lvalue<dialog_t>);
static_assert(can_write_line_view_literal<dialog_t>);
static_assert(!can_write_line_view_temporary<dialog_t>);
static_assert(can_write_line_buffer_move_owner<dialog_t>);
static_assert(!can_write_line_buffer_lvalue_owner<dialog_t>);

} // namespace

BOOST_AUTO_TEST_CASE(dialog_write_raw_api_contract_compiles)
{
    BOOST_TEST(true);
}
