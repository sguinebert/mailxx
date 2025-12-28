/*

config.hpp
----------

Global build configuration for mailxx.

Define MAILXX_NO_EXCEPTIONS to disable exception-based wrappers.

*/

#pragma once

#if defined(MAILXX_NO_EXCEPTIONS)
#define MAILXX_THROWING_ENABLED 0
#else
#define MAILXX_THROWING_ENABLED 1
#endif
