#pragma once

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
