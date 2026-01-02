/*

mailxx.pool.cppm
----------------

C++20 module interface for mailxx connection pooling.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

module;

// Global module fragment - non-modular dependencies
#include <string>
#include <vector>
#include <list>
#include <deque>
#include <memory>
#include <optional>
#include <functional>
#include <atomic>
#include <mutex>
#include <variant>
#include <span>
#include <chrono>
#include <tuple>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

export module mailxx.pool;

// Import dependencies
export import mailxx.smtp;

// Export pool headers
export {
    #include <mailxx/pool/pool_config.hpp>
    #include <mailxx/pool/connection_pool.hpp>
    #include <mailxx/pool/smtp_pool.hpp>
}
