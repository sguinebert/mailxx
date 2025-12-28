#pragma once

// Use only when the toolchain supports C++20 modules and the mailxx module interface is built.
#if defined(MAILXX_USE_MODULES)
import mailxx;
#else
#include <mailxx/mailxx.hpp>
#endif
