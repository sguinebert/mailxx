/*

mailxx.pop3.cppm
----------------

C++20 module interface for mailxx POP3 client.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

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
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

export module mailxx.pop3;

// Import dependencies
export import mailxx.net;
export import mailxx.mime;

// Export POP3 headers
export {
    #include <mailxx/pop3/types.hpp>
    #include <mailxx/pop3/client.hpp>
}
