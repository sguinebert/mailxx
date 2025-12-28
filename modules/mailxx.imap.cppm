/*

mailxx.imap.cppm
----------------

C++20 module interface for mailxx IMAP client.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

module;

// Global module fragment - non-modular dependencies
#include <string>
#include <vector>
#include <list>
#include <map>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <tuple>
#include <variant>
#include <optional>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

export module mailxx.imap;

// Import dependencies
export import mailxx.net;
export import mailxx.mime;

// Export IMAP headers
export {
    #include <mailxx/imap/types.hpp>
    #include <mailxx/imap/error.hpp>
    #include <mailxx/imap/client.hpp>
}
