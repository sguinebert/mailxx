/*

mailxx.smtp.cppm
----------------

C++20 module interface for mailxx SMTP client.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/

module;

// Global module fragment - non-modular dependencies
#include <string>
#include <vector>
#include <list>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/algorithm/string.hpp>

export module mailxx.smtp;

// Import dependencies
export import mailxx.net;
export import mailxx.mime;

// Export SMTP headers
export {
    #include <mailxx/smtp/types.hpp>
    #include <mailxx/smtp/client.hpp>
}
