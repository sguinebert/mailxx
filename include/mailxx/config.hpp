/*

config.hpp
----------

Global build configuration for mailxx.

mailxx does not use exceptions; errors are returned via result<T>.
Define MAILXX_USE_STD_REGEX=1 to use std::regex instead of boost::regex (default: 0).

*/

#pragma once

// Symbol visibility (kept here to avoid a dedicated export.hpp).
#if defined(MAILXX_STATIC_DEFINE)
#  ifndef MAILXX_EXPORT
#    define MAILXX_EXPORT
#  endif
#  ifndef MAILXX_NO_EXPORT
#    define MAILXX_NO_EXPORT
#  endif
#else
#  ifndef MAILXX_EXPORT
#    if defined(_WIN32) || defined(__CYGWIN__)
#      ifdef MAILXX_EXPORTS
#        define MAILXX_EXPORT __declspec(dllexport)
#      else
#        define MAILXX_EXPORT __declspec(dllimport)
#      endif
#      define MAILXX_NO_EXPORT
#    else
#      if defined(__GNUC__) && __GNUC__ >= 4
#        define MAILXX_EXPORT __attribute__((visibility("default")))
#        define MAILXX_NO_EXPORT __attribute__((visibility("hidden")))
#      else
#        define MAILXX_EXPORT
#        define MAILXX_NO_EXPORT
#      endif
#    endif
#  endif
#endif

#ifndef MAILXX_USE_STD_REGEX
#define MAILXX_USE_STD_REGEX 0
#endif
