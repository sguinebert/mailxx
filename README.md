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
- **Modern C++23**: Leverages coroutines, concepts, ranges, and std::expected
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

mailxx supports multiple async patterns. Choose what fits your project:

#### 🔹 Coroutines (C++20/23)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::task<void> send_email() {
    mailxx::asio::io_context io;
    mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

    co_await smtp.async_connect();
    co_await smtp.async_starttls();
    co_await smtp.async_authenticate("user@gmail.com", "app-password", 
                                      mailxx::smtp::auth_method::login);

    mailxx::mime::message msg;
    msg.from({"Sender Name", "sender@gmail.com"});
    msg.add_recipient({"Recipient", "recipient@example.com"});
    msg.subject("Hello from mailxx!");
    msg.content("This is a test email sent with mailxx.");

    co_await smtp.async_send(msg);
    co_await smtp.async_quit();
}
```

#### 🔹 Callbacks (Traditional Async)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

smtp.async_connect([&](mailxx::error_code ec) {
    if (ec) { std::cerr << "Connect failed: " << ec.message() << "\n"; return; }
    
    smtp.async_starttls([&](mailxx::error_code ec) {
        if (ec) { std::cerr << "STARTTLS failed: " << ec.message() << "\n"; return; }
        
        smtp.async_authenticate("user@gmail.com", "app-password",
                                 mailxx::smtp::auth_method::login,
                                 [&](mailxx::error_code ec) {
            if (ec) { std::cerr << "Auth failed: " << ec.message() << "\n"; return; }
            
            mailxx::mime::message msg;
            msg.from({"Sender", "sender@gmail.com"});
            msg.add_recipient({"Recipient", "recipient@example.com"});
            msg.subject("Hello from mailxx!");
            msg.content("Callback style!");
            
            smtp.async_send(msg, [&](mailxx::error_code ec) {
                if (!ec) std::cout << "Email sent!\n";
                smtp.async_quit([](auto) {});
            });
        });
    });
});

io.run();
```

#### 🔹 Futures (std::future)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

// Use mailxx::use_future token
std::future<void> fut = smtp.async_connect(mailxx::use_future);

std::thread io_thread([&]() { io.run(); });

fut.get();  // Wait for connection

auto auth_fut = smtp.async_authenticate("user@gmail.com", "app-password",
                                         mailxx::smtp::auth_method::login,
                                         mailxx::use_future);
auth_fut.get();

mailxx::mime::message msg;
// ... setup message ...

smtp.async_send(msg, mailxx::use_future).get();
smtp.async_quit(mailxx::use_future).get();

io_thread.join();
```

#### 🔹 Synchronous (Blocking)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

// Simple blocking calls
smtp.connect();
smtp.starttls();
smtp.authenticate("user@gmail.com", "app-password", 
                   mailxx::smtp::auth_method::login);

mailxx::mime::message msg;
msg.from({"Sender Name", "sender@gmail.com"});
msg.add_recipient({"Recipient", "recipient@example.com"});
msg.subject("Hello from mailxx!");
msg.content("Synchronous style - simple and straightforward.");

smtp.send(msg);
smtp.quit();
```

### Receive Emails (IMAP)

#### Coroutines

```cpp
#include <mailxx/mailxx.hpp>

mailxx::task<void> fetch_emails() {
    mailxx::asio::io_context io;
    mailxx::imap::client imap(io, "imap.gmail.com", 993);

    co_await imap.async_connect_ssl();
    co_await imap.async_authenticate("user@gmail.com", "app-password",
                                      mailxx::imap::auth_method::login);

    co_await imap.async_select("INBOX");

    // Fetch message
    auto msg = co_await imap.async_fetch(1);
    std::cout << "Subject: " << msg.subject() << "\n";
    std::cout << "From: " << msg.from().name << "\n";

    co_await imap.async_logout();
}
```

#### Callbacks with Progress

```cpp
mailxx::imap::client imap(io, "imap.gmail.com", 993);

imap.async_connect_ssl([&](mailxx::error_code ec) {
    if (ec) return;
    
    imap.async_authenticate("user@gmail.com", "app-password",
                             mailxx::imap::auth_method::login,
                             [&](mailxx::error_code ec) {
        if (ec) return;
        
        imap.async_select("INBOX", [&](mailxx::error_code ec, 
                                        const mailxx::imap::mailbox_info& info) {
            std::cout << "Messages: " << info.exists << "\n";
            std::cout << "Unseen: " << info.unseen << "\n";
            
            // Fetch with progress callback
            mailxx::imap::fetch_options opts;
            opts.on_progress = [](size_t bytes, size_t total) {
                std::cout << "Progress: " << (bytes * 100 / total) << "%\n";
            };
            
            imap.async_fetch(1, opts, [&](mailxx::error_code ec, 
                                           mailxx::mime::message msg) {
                if (!ec) {
                    std::cout << "Subject: " << msg.subject() << "\n";
                }
            });
        });
    });
});
```

### IMAP IDLE (Push Notifications)

```cpp
// Coroutine style
auto result = co_await imap.async_idle(std::chrono::minutes(29));

if (result == mailxx::imap::idle_result::new_mail) {
    std::cout << "New message arrived!\n";
}

// Callback style with event handler
imap.async_idle(std::chrono::minutes(29), 
    [](mailxx::error_code ec, mailxx::imap::idle_result result) {
        if (result == mailxx::imap::idle_result::new_mail) {
            std::cout << "New message arrived!\n";
        }
    });
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

mailxx::pool::smtp_pool pool(io, "smtp.example.com", 587, config);

// Coroutine style
auto conn = co_await pool.async_acquire();
co_await conn->async_send(message);
// Connection automatically returned to pool

// Callback style
pool.async_acquire([&](mailxx::error_code ec, 
                        mailxx::pool::connection_handle conn) {
    if (ec) return;
    
    conn->async_send(message, [conn](mailxx::error_code ec) {
        // conn automatically returned when handle is destroyed
        if (!ec) std::cout << "Sent via pooled connection\n";
    });
});
```

### Rate Limiting

```cpp
#include <mailxx/pool/rate_limiter.hpp>

// 100 emails per hour
mailxx::pool::rate_limiter limiter(100, std::chrono::hours(1));

// Coroutine style
for (const auto& msg : messages) {
    co_await limiter.async_acquire();  // Wait if rate limit exceeded
    co_await smtp.async_send(msg);
}

// Callback style  
void send_next(size_t index) {
    if (index >= messages.size()) return;
    
    limiter.async_acquire([&, index](mailxx::error_code ec) {
        smtp.async_send(messages[index], [&, index](mailxx::error_code ec) {
            send_next(index + 1);  // Chain next send
        });
    });
}
send_next(0);

// Synchronous check (non-blocking)
if (limiter.try_acquire()) {
    smtp.send(msg);
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
    .return_type = mailxx::smtp::dsn_return::headers,
    .envid = "unique-envelope-id"
};

// Coroutine
co_await smtp.async_send(msg, dsn);

// Callback
smtp.async_send(msg, dsn, [](mailxx::error_code ec) {
    if (!ec) std::cout << "Sent with DSN request\n";
});

// Synchronous
smtp.send(msg, dsn);
```

## 🔄 Completion Token Patterns

mailxx follows the Asio completion token pattern, supporting:

| Pattern | Token | Use Case |
|---------|-------|----------|
| Callbacks | `[](error_code, result) {}` | Traditional async, fine-grained control |
| Coroutines | `mailxx::use_awaitable` | Modern C++20/23, clean sequential code |
| Futures | `mailxx::use_future` | Integration with std::future workflows |
| Deferred | `mailxx::deferred` | Lazy execution, composable operations |
| Synchronous | *(no token)* | Simple blocking calls |

```cpp
// All these are equivalent ways to connect:
smtp.connect();                                         // Sync
smtp.async_connect([](auto ec) { /* ... */ });         // Callback
co_await smtp.async_connect(mailxx::use_awaitable);    // Coroutine
smtp.async_connect(mailxx::use_future).get();          // Future
auto op = smtp.async_connect(mailxx::deferred);        // Deferred
std::move(op)(handler);                                // Execute later
```

## 📁 Project Structure

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
    mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);
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
