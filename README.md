# mailxx

![C++](https://img.shields.io/badge/C++-23-blue)
[![License](https://img.shields.io/badge/License-MIT-darkgreen)](LICENSE)
![FreeBSD](https://img.shields.io/badge/OS-FreeBSD-870000)
![Linux](https://img.shields.io/badge/OS-Linux-870000)
![Windows](https://img.shields.io/badge/OS-Windows-870000)
![macOS](https://img.shields.io/badge/OS-macOS-870000)

**mailxx** is a modern, header-only C++23 library for email protocols (SMTP, IMAP, POP3) with full async/await support using coroutines.

## ✨ Key Features

- **Header-only**: No compilation required, just include and use
- **Modern C++23**: Leverages coroutines and std::expected
- **Async/Await**: Native coroutine support with `co_await` for non-blocking I/O
- **Connection Pooling**: Built-in connection pool with automatic reconnection
- **Rate Limiting**: Token bucket algorithm for API rate limiting
- **Flexible Asio**: Works with both Boost.Asio and standalone Asio

## 📧 Protocol Support

| Protocol | Coverage | Key Features |
|----------|----------|--------------|
| **SMTP** | 100% | PIPELINING, SIZE, 8BITMIME, SMTPUTF8, DSN, AUTH (LOGIN, PLAIN, CRAM-MD5) |
| **IMAP** | 98% | IDLE, NAMESPACE, QUOTA, SORT/THREAD, SEARCH, Folder management |
| **POP3** | 95% | UIDL, TOP, STAT, LIST, Authentication |

## 🚀 Quick Start

### Installation

**Header-only** - Just copy the `include/mailxx` directory to your project, or:

```bash
# Clone the repository
git clone https://github.com/sguinebert/mailxx.git

# Or use CMake FetchContent
```

### Requirements

- C++23 compatible compiler (GCC 13+, Clang 16+, MSVC 2022+)
- Boost 1.81+ (Asio, Beast, SSL) or standalone Asio
- OpenSSL

### Send an Email

mailxx exposes a coroutine-only async API for performance and simplicity. A single code path means fewer executor edge
cases, no callback/future wrappers, and consistent error handling via `result<T>`.

If you need to drive it from callback-based code, you can bridge with `co_spawn` and invoke your handler when the
coroutine completes (example below). You can also pass any Asio completion token to
`co_spawn(io, task, token)`, and the raw handler receives `std::exception_ptr` for unhandled exceptions; mailxx uses
`result<T>`, so the pattern below keeps `error_info` at the boundary.

#### Coroutines (C++20/23)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::awaitable<void> send_email(mailxx::smtp::client& smtp)
{
    if (auto res = co_await smtp.connect("smtp.gmail.com", 587); !res) co_return;
    if (auto res = co_await smtp.read_greeting(); !res) co_return;
    if (auto res = co_await smtp.ehlo(); !res) co_return;

    mailxx::asio::ssl::context tls_ctx(mailxx::asio::ssl::context::tls_client);
    if (auto res = co_await smtp.start_tls(tls_ctx); !res) co_return;
    if (auto res = co_await smtp.ehlo(); !res) co_return;

    if (auto res = co_await smtp.authenticate("user@gmail.com", "app-password",
                                              mailxx::smtp::auth_method::login); !res) co_return;

    mailxx::message msg;
    msg.from({"Sender Name", "sender@gmail.com"});
    msg.add_recipient({"Recipient", "recipient@example.com"});
    msg.subject("Hello from mailxx!");
    msg.content("This is a test email sent with mailxx.");

    if (auto res = co_await smtp.send(msg); !res) co_return;
    if (auto res = co_await smtp.quit(); !res) co_return;
}

int main()
{
    mailxx::asio::io_context io;
    mailxx::smtp::client smtp(io);

    mailxx::asio::co_spawn(io, send_email(smtp), mailxx::asio::detached);
    io.run();
}
```

#### Bridge with co_spawn (callbacks or futures)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io);

auto on_done = [](const mailxx::error_info& err) {
    if (err.code != mailxx::errc::ok)
        std::cerr << "SMTP failed: " << err.message << "\n";
};

mailxx::asio::co_spawn(io,
    [&]() -> mailxx::asio::awaitable<void> {
        if (auto res = co_await smtp.connect("smtp.gmail.com", 587); !res) { on_done(res.error()); co_return; }
        if (auto res = co_await smtp.read_greeting(); !res) { on_done(res.error()); co_return; }
        if (auto res = co_await smtp.ehlo(); !res) { on_done(res.error()); co_return; }
        on_done({});
    },
    mailxx::asio::detached);

io.run();
```

To return a `std::future`, use `mailxx::asio::co_spawn(io, task, mailxx::asio::use_future)`.

### Receive Emails (IMAP)

#### Coroutines (C++20/23)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::awaitable<void> fetch_emails(mailxx::imap::client& imap)
{
    mailxx::asio::ssl::context tls_ctx(mailxx::asio::ssl::context::tls_client);
    if (auto res = co_await imap.connect("imap.gmail.com", 993, mailxx::net::tls_mode::implicit, &tls_ctx); !res)
        co_return;
    if (auto res = co_await imap.read_greeting(); !res) co_return;
    if (auto res = co_await imap.login("user@gmail.com", "app-password"); !res) co_return;

    if (auto sel = co_await imap.select("INBOX"); !sel) co_return;
    auto uids = co_await imap.uid_search("ALL");
    if (!uids || uids->empty()) co_return;

    auto msg = co_await imap.uid_fetch_rfc822(uids->front());
    if (msg)
        std::cout << "Subject: " << msg->subject() << "\n";

    (void)co_await imap.logout();
}
```

### IMAP IDLE (Push Notifications)

```cpp
auto idle_res = co_await imap.idle_start();
if (!idle_res)
    co_return;
auto idle = std::move(*idle_res);

auto line = co_await idle.idle_read();
if (line)
    std::cout << "Server update: " << *line << "\n";

(void)co_await idle.idle_stop();
```

### Connection Pooling

```cpp
#include <mailxx/pool/smtp_pool.hpp>

mailxx::pool::pool_config config{
    .min_connections = 2,
    .max_connections = 10,
    .connection_timeout = std::chrono::seconds(30),
    .idle_timeout = std::chrono::minutes(5)
};

mailxx::pool::smtp_pool pool(io.get_executor(), config);
mailxx::asio::ssl::context tls_ctx(mailxx::asio::ssl::context::tls_client);
pool.configure("smtp.example.com", "587", tls_ctx,
               mailxx::pool::pool_credentials{"user", "pass"},
               mailxx::smtp::auth_method::login);

mailxx::message message;
// ... setup message ...

auto reply = co_await pool.send(message);
// Reply available in reply.status / reply.lines
```

### Rate Limiting

```cpp
#include <mailxx/pool/rate_limiter.hpp>

// 100 emails per hour
mailxx::pool::rate_limiter limiter(100, std::chrono::hours(1));

for (const auto& msg : messages) {
    co_await limiter.acquire();  // Wait if rate limit exceeded
    (void)co_await smtp.send(msg);
}

// Non-blocking check
if (limiter.try_acquire()) {
    (void)co_await smtp.send(msg);
} else {
    std::cout << "Rate limit exceeded, retry in "
              << limiter.time_until_available().count() << "ms\n";
}
```

### Delivery Status Notification (DSN)

```cpp
mailxx::smtp::dsn_options dsn{
    .notify = mailxx::smtp::dsn_notify::success | 
              mailxx::smtp::dsn_notify::failure,
    .ret = mailxx::smtp::dsn_ret::hdrs,
    .envid = "unique-envelope-id"
};

auto reply = co_await smtp.send(msg, dsn);
```

## Project Structure
```
mailxx/
├── include/mailxx/
│   ├── mailxx.hpp          # Main header (includes all)
│   ├── codec/              # Base64, Quoted-Printable, etc.
│   ├── mime/               # MIME message handling
│   ├── smtp/               # SMTP client
│   ├── imap/               # IMAP client  
│   ├── pop3/               # POP3 client
│   ├── pool/               # Connection pooling & rate limiting
│   ├── net/                # Network abstractions
│   └── detail/             # Internal implementation
├── examples/               # Usage examples
├── test/                   # Unit tests
└── modules/                # C++20 modules (experimental)
```

## 🔧 CMake Integration

```cmake
# Option 1: FetchContent
include(FetchContent)
FetchContent_Declare(
    mailxx
    GIT_REPOSITORY https://github.com/sguinebert/mailxx.git
    GIT_TAG main
)
FetchContent_MakeAvailable(mailxx)

target_link_libraries(your_target PRIVATE mailxx::mailxx)

# Option 2: find_package (after installation)
find_package(mailxx REQUIRED)
target_link_libraries(your_target PRIVATE mailxx::mailxx)
```

## 📦 C++20 Modules (Experimental)

mailxx provides experimental C++20 module support for faster compilation and better encapsulation:

```
modules/
├── mailxx.cppm          # Primary module interface
├── mailxx.codec.cppm    # Base64, Quoted-Printable, etc.
├── mailxx.mime.cppm     # MIME message handling
├── mailxx.smtp.cppm     # SMTP client
├── mailxx.imap.cppm     # IMAP client
├── mailxx.pop3.cppm     # POP3 client
└── mailxx.net.cppm      # Network abstractions
```

### Usage with Modules

```cpp
import mailxx;           // Import everything
// or selectively:
import mailxx.smtp;      // Only SMTP
import mailxx.mime;      // Only MIME

int main() {
    mailxx::smtp::client smtp(io);
    // ...
}
```

### CMake with Modules

```cmake
# Requires CMake 3.28+ and a compatible compiler
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_executable(my_app main.cpp)
target_sources(my_app
    PUBLIC FILE_SET CXX_MODULES FILES
        ${mailxx_SOURCE_DIR}/modules/mailxx.cppm
        ${mailxx_SOURCE_DIR}/modules/mailxx.smtp.cppm
        # ... other modules as needed
)
```

### Compiler Support

| Compiler | Module Support | Notes |
|----------|----------------|-------|
| **MSVC 2022** | ✅ Full | Best support currently |
| **GCC 14+** | ✅ Good | Requires `-fmodules-ts` |
| **Clang 17+** | ⚠️ Partial | Improving rapidly |

> **Note**: C++20 modules are still evolving. For production use, the traditional header-only approach is recommended until module tooling matures.

## 🔐 Security Notes

- **Never hardcode passwords** - Use environment variables or secure vaults
- **Use App Passwords** for Gmail/Outlook when 2FA is enabled
- **Prefer TLS/SSL** connections (port 465/993/995 or STARTTLS on 587/143/110)

## 📋 Supported RFCs

| RFC | Description |
|-----|-------------|
| [RFC 5321](https://tools.ietf.org/html/rfc5321) | SMTP Protocol |
| [RFC 5322](https://tools.ietf.org/html/rfc5322) | Internet Message Format |
| [RFC 3501](https://tools.ietf.org/html/rfc3501) | IMAP4rev1 |
| [RFC 1939](https://tools.ietf.org/html/rfc1939) | POP3 Protocol |
| [RFC 2045-2049](https://tools.ietf.org/html/rfc2045) | MIME |
| [RFC 2177](https://tools.ietf.org/html/rfc2177) | IMAP IDLE |
| [RFC 2087](https://tools.ietf.org/html/rfc2087) | IMAP QUOTA |
| [RFC 2342](https://tools.ietf.org/html/rfc2342) | IMAP NAMESPACE |
| [RFC 5256](https://tools.ietf.org/html/rfc5256) | IMAP SORT/THREAD |
| [RFC 2920](https://tools.ietf.org/html/rfc2920) | SMTP PIPELINING |
| [RFC 1870](https://tools.ietf.org/html/rfc1870) | SMTP SIZE |
| [RFC 6152](https://tools.ietf.org/html/rfc6152) | SMTP 8BITMIME |
| [RFC 6531](https://tools.ietf.org/html/rfc6531) | SMTP SMTPUTF8 |
| [RFC 3461](https://tools.ietf.org/html/rfc3461) | SMTP DSN |

## 📄 License

MIT License - Copyright (c) 2025 Sylvain Guinebert

## 🙏 Acknowledgments

This project was originally inspired by [mailio](https://github.com/karastojko/mailio) by Tomislav Karastojković. 
mailxx has since evolved into a completely redesigned modern C++23 library with async/coroutine support, 
header-only architecture, and extensive new features.

## 📬 Contact

- **Issues**: [GitHub Issues](https://github.com/sguinebert/mailxx/issues)
- **Author**: Sylvain Guinebert





