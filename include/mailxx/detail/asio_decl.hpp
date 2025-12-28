/*

asio_decl.hpp
-------------

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

Centralized Boost.Asio / standalone Asio declarations for mailxx.
This header simplifies async notation throughout the library.

*/

#pragma once

// Check for standalone Asio first
#if defined(MAILXX_USE_STANDALONE_ASIO)

#include <asio/version.hpp>
#if ASIO_VERSION < 121000 // Asio 1.21.0
#error "Asio version 1.21.0 or higher is required"
#endif

// Platform optimizations
#if defined(__linux__)
#define ASIO_HAS_IO_URING 1
#define ASIO_DISABLE_EPOLL 1
#endif

#include <asio.hpp>
#include <asio/ssl.hpp>

#if defined(ASIO_HAS_CO_AWAIT)
#include <asio/experimental/as_tuple.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>

namespace mailxx::asio
{
    // Core types
    using ::asio::awaitable;
    using ::asio::buffer;
    using ::asio::co_spawn;
    using ::asio::detached;
    using ::asio::use_awaitable;
    using ::asio::io_context;
    using ::asio::any_io_executor;
    using ::asio::steady_timer;
    using ::asio::streambuf;
    
    // IP networking
    namespace ip = ::asio::ip;
    using tcp = ::asio::ip::tcp;
    
    // Async operations
    using ::asio::async_write;
    using ::asio::async_read;
    using ::asio::async_read_until;
    using ::asio::async_compose;
    using ::asio::async_connect;
    using ::asio::dynamic_buffer;
    using ::asio::transfer_exactly;
    using ::asio::get_lowest_layer;
    
    namespace ssl = ::asio::ssl;
    namespace error = ::asio::error;
    
    using executor_t = ::asio::io_context::executor_type;
    
    /// Non-throwing awaitable for use with std::expected
    inline constexpr auto use_nothrow_awaitable = ::asio::experimental::as_tuple(::asio::use_awaitable);
    
    namespace operators = ::asio::experimental::awaitable_operators;
    
    using error_code = ::asio::error_code;
    using system_error = ::asio::system_error;
    
} // namespace mailxx::asio

#else
#error "mailxx requires coroutine support (C++20) and Asio 1.21+"
#endif

#else // Use Boost.Asio (default)

#include <boost/asio/version.hpp>
#if BOOST_ASIO_VERSION < 102100 // Boost.Asio 1.21.0
#error "Boost.Asio version 1.21.0 or higher is required (Boost 1.78+)"
#endif

// Platform optimizations
#if defined(__linux__)
#define BOOST_ASIO_HAS_IO_URING 1
#define BOOST_ASIO_DISABLE_EPOLL 1
#endif

#include <boost/asio.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ssl.hpp>

#if defined(BOOST_ASIO_HAS_CO_AWAIT)
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/redirect_error.hpp>

namespace mailxx::asio
{
    // Core types
    using boost::asio::awaitable;
    using boost::asio::buffer;
    using boost::asio::co_spawn;
    using boost::asio::detached;
    using boost::asio::use_awaitable;
    using boost::asio::io_context;
    using boost::asio::any_io_executor;
    using boost::asio::steady_timer;
    using boost::asio::redirect_error;
    using boost::asio::streambuf;
    
    // IP networking
    namespace ip = boost::asio::ip;
    using tcp = boost::asio::ip::tcp;
    
    // Async operations
    using boost::asio::async_write;
    using boost::asio::async_read;
    using boost::asio::async_read_until;
    using boost::asio::async_compose;
    using boost::asio::async_connect;
    using boost::asio::dynamic_buffer;
    using boost::asio::transfer_exactly;
    using boost::asio::get_lowest_layer;
    
    namespace ssl = boost::asio::ssl;
    namespace error = boost::asio::error;
    
    using executor_t = boost::asio::io_context::executor_type;
    
    /// Non-throwing awaitable for use with std::expected
    inline constexpr auto use_nothrow_awaitable = boost::asio::as_tuple(boost::asio::use_awaitable);
    
    namespace operators = boost::asio::experimental::awaitable_operators;
    
    using error_code = boost::system::error_code;
    using system_error = boost::system::system_error;

} // namespace mailxx::asio

#else
#error "mailxx requires coroutine support (C++20) and Boost.Asio 1.21+ (Boost 1.78+)"
#endif

#endif // MAILXX_USE_STANDALONE_ASIO

// Common chrono literals
namespace mailxx
{
    using namespace std::literals::chrono_literals;
    using std::chrono::steady_clock;
}
