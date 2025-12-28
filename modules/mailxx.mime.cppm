/*

mailxx.mime.cppm
----------------

C++20 module interface for mailxx MIME components.

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
#include <utility>
#include <tuple>
#include <optional>
#include <chrono>
#include <istream>
#include <boost/algorithm/string.hpp>
#include <boost/regex.hpp>

export module mailxx.mime;

// Import codec module dependency
export import mailxx.codec;

// Export MIME headers
export {
    #include <mailxx/mime/mailboxes.hpp>
    #include <mailxx/mime/mime.hpp>
    #include <mailxx/mime/message.hpp>
}
