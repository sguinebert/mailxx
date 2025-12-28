/*

mailxx.codec.cppm
-----------------

C++20 module interface for mailxx codec components.

Copyright (C) 2025, Sylvain Guinebert (github.com/sguinebert).

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/

module;

// Global module fragment - non-modular dependencies
#include <string>
#include <vector>
#include <stdexcept>
#include <tuple>
#include <algorithm>
#include <boost/algorithm/string.hpp>

export module mailxx.codec;

// Export all codec headers
export {
    #include <mailxx/codec/codec.hpp>
    #include <mailxx/codec/base64.hpp>
    #include <mailxx/codec/binary.hpp>
    #include <mailxx/codec/bit7.hpp>
    #include <mailxx/codec/bit8.hpp>
    #include <mailxx/codec/percent.hpp>
    #include <mailxx/codec/quoted_printable.hpp>
    #include <mailxx/codec/q_codec.hpp>
}
