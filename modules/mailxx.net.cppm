/*

mailxx.net.cppm
---------------

C++20 module interface for mailxx networking components.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the MIT license, see the accompanying file LICENSE or
copy at https://opensource.org/licenses/MIT.

*/

module;

// Global module fragment - non-modular dependencies
#include <string>
#include <memory>
#include <stdexcept>
#include <chrono>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

export module mailxx.net;

// Export networking headers
export {
    #include <mailxx/net/upgradable_stream.hpp>
    #include <mailxx/net/dialog.hpp>
    #include <mailxx/net/tls_mode.hpp>
}
