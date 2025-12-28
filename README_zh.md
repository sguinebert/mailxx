# mailxx

![C++](https://img.shields.io/badge/C++-23-blue)
[![License](https://img.shields.io/badge/License-MIT-darkgreen)](LICENSE)
![FreeBSD](https://img.shields.io/badge/OS-FreeBSD-870000)
![Linux](https://img.shields.io/badge/OS-Linux-870000)
![Windows](https://img.shields.io/badge/OS-Windows-870000)
![macOS](https://img.shields.io/badge/OS-macOS-870000)

**mailxx** 是一个现代化的、仅头文件的 C++23 库，用于电子邮件协议（SMTP、IMAP、POP3），完全支持使用协程的 async/await。

## ✨ 主要特性

- **仅头文件**：无需编译，直接包含使用
- **现代 C++23**：利用协程、概念、范围和 std::expected
- **异步/等待**：原生协程支持，使用 `co_await` 进行非阻塞 I/O
- **连接池**：内置连接池，支持自动重连
- **速率限制**：令牌桶算法用于 API 速率限制
- **灵活的 Asio**：同时支持 Boost.Asio 和独立 Asio

## 📧 协议支持

| 协议 | 覆盖率 | 主要特性 |
|------|--------|----------|
| **SMTP** | 100% | PIPELINING、SIZE、8BITMIME、SMTPUTF8、DSN、AUTH（LOGIN、PLAIN、CRAM-MD5） |
| **IMAP** | 98% | IDLE、NAMESPACE、QUOTA、SORT/THREAD、SEARCH、文件夹管理 |
| **POP3** | 95% | UIDL、TOP、STAT、LIST、身份验证 |

## 🚀 快速开始

### 安装

**仅头文件** - 只需将 `include/mailxx` 目录复制到您的项目中，或者：

```bash
# 克隆仓库
git clone https://github.com/sguinebert/mailxx.git

# 或使用 CMake FetchContent
```

### 依赖要求

- C++23 兼容编译器（GCC 13+、Clang 16+、MSVC 2022+）
- Boost 1.81+（Asio、Beast、SSL）或独立 Asio
- OpenSSL

### 发送邮件

mailxx 支持多种异步模式。选择适合您项目的方式：

#### 🔹 协程 (C++20/23)

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
    msg.from({"发送者姓名", "sender@gmail.com"});
    msg.add_recipient({"收件人", "recipient@example.com"});
    msg.subject("来自 mailxx 的问候！");
    msg.content("这是使用 mailxx 发送的测试邮件。");

    co_await smtp.async_send(msg);
    co_await smtp.async_quit();
}
```

#### 🔹 回调 (传统异步)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

smtp.async_connect([&](mailxx::error_code ec) {
    if (ec) { std::cerr << "连接失败: " << ec.message() << "\n"; return; }
    
    smtp.async_starttls([&](mailxx::error_code ec) {
        if (ec) { std::cerr << "STARTTLS 失败: " << ec.message() << "\n"; return; }
        
        smtp.async_authenticate("user@gmail.com", "app-password",
                                 mailxx::smtp::auth_method::login,
                                 [&](mailxx::error_code ec) {
            if (ec) { std::cerr << "认证失败: " << ec.message() << "\n"; return; }
            
            mailxx::mime::message msg;
            msg.from({"发送者", "sender@gmail.com"});
            msg.add_recipient({"收件人", "recipient@example.com"});
            msg.subject("来自 mailxx 的问候！");
            msg.content("回调风格！");
            
            smtp.async_send(msg, [&](mailxx::error_code ec) {
                if (!ec) std::cout << "邮件已发送！\n";
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

// 使用 mailxx::use_future 令牌
std::future<void> fut = smtp.async_connect(mailxx::use_future);

std::thread io_thread([&]() { io.run(); });

fut.get();  // 等待连接

auto auth_fut = smtp.async_authenticate("user@gmail.com", "app-password",
                                         mailxx::smtp::auth_method::login,
                                         mailxx::use_future);
auth_fut.get();

mailxx::mime::message msg;
// ... 设置消息 ...

smtp.async_send(msg, mailxx::use_future).get();
smtp.async_quit(mailxx::use_future).get();

io_thread.join();
```

#### 🔹 同步 (阻塞)

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::io_context io;
mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);

// 简单的阻塞调用
smtp.connect();
smtp.starttls();
smtp.authenticate("user@gmail.com", "app-password", 
                   mailxx::smtp::auth_method::login);

mailxx::mime::message msg;
msg.from({"发送者姓名", "sender@gmail.com"});
msg.add_recipient({"收件人", "recipient@example.com"});
msg.subject("来自 mailxx 的问候！");
msg.content("同步风格 - 简单直接。");

smtp.send(msg);
smtp.quit();
```

### 接收邮件（IMAP）

#### 协程

```cpp
#include <mailxx/mailxx.hpp>

mailxx::task<void> fetch_emails() {
    mailxx::asio::io_context io;
    mailxx::imap::client imap(io, "imap.gmail.com", 993);

    co_await imap.async_connect_ssl();
    co_await imap.async_authenticate("user@gmail.com", "app-password",
                                      mailxx::imap::auth_method::login);

    co_await imap.async_select("INBOX");

    // 获取邮件
    auto msg = co_await imap.async_fetch(1);
    std::cout << "主题: " << msg.subject() << "\n";
    std::cout << "发件人: " << msg.from().name << "\n";

    co_await imap.async_logout();
}
```

#### 带进度的回调

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
            std::cout << "邮件数: " << info.exists << "\n";
            std::cout << "未读: " << info.unseen << "\n";
            
            // 带进度回调的获取
            mailxx::imap::fetch_options opts;
            opts.on_progress = [](size_t bytes, size_t total) {
                std::cout << "进度: " << (bytes * 100 / total) << "%\n";
            };
            
            imap.async_fetch(1, opts, [&](mailxx::error_code ec, 
                                           mailxx::mime::message msg) {
                if (!ec) {
                    std::cout << "主题: " << msg.subject() << "\n";
                }
            });
        });
    });
});
```

### IMAP IDLE（推送通知）

```cpp
// 协程风格
auto result = co_await imap.async_idle(std::chrono::minutes(29));

if (result == mailxx::imap::idle_result::new_mail) {
    std::cout << "新邮件到达！\n";
}

// 带事件处理器的回调风格
imap.async_idle(std::chrono::minutes(29), 
    [](mailxx::error_code ec, mailxx::imap::idle_result result) {
        if (result == mailxx::imap::idle_result::new_mail) {
            std::cout << "新邮件到达！\n";
        }
    });
```

### 连接池

```cpp
#include <mailxx/pool/smtp_pool.hpp>

mailxx::pool::pool_config config{
    .min_connections = 2,
    .max_connections = 10,
    .connection_timeout = std::chrono::seconds(30),
    .idle_timeout = std::chrono::minutes(5)
};

mailxx::pool::smtp_pool pool(io, "smtp.example.com", 587, config);

// 协程风格
auto conn = co_await pool.async_acquire();
co_await conn->async_send(message);
// 连接自动返回池中

// 回调风格
pool.async_acquire([&](mailxx::error_code ec, 
                        mailxx::pool::connection_handle conn) {
    if (ec) return;
    
    conn->async_send(message, [conn](mailxx::error_code ec) {
        // 句柄销毁时连接自动返回
        if (!ec) std::cout << "通过池连接发送\n";
    });
});
```

### 速率限制

```cpp
#include <mailxx/pool/rate_limiter.hpp>

// 每小时 100 封邮件
mailxx::pool::rate_limiter limiter(100, std::chrono::hours(1));

// 协程风格
for (const auto& msg : messages) {
    co_await limiter.async_acquire();  // 超过限制时等待
    co_await smtp.async_send(msg);
}

// 回调风格
void send_next(size_t index) {
    if (index >= messages.size()) return;
    
    limiter.async_acquire([&, index](mailxx::error_code ec) {
        smtp.async_send(messages[index], [&, index](mailxx::error_code ec) {
            send_next(index + 1);  // 链接下一次发送
        });
    });
}
send_next(0);

// 同步检查（非阻塞）
if (limiter.try_acquire()) {
    smtp.send(msg);
} else {
    std::cout << "超过速率限制，" 
              << limiter.time_until_available().count() << "ms 后重试\n";
}
```

## 🔄 完成令牌模式

mailxx 遵循 Asio 完成令牌模式，支持：

| 模式 | 令牌 | 使用场景 |
|------|------|----------|
| 回调 | `[](error_code, result) {}` | 传统异步，细粒度控制 |
| 协程 | `mailxx::use_awaitable` | 现代 C++20/23，清晰的顺序代码 |
| Futures | `mailxx::use_future` | 与 std::future 工作流集成 |
| 延迟 | `mailxx::deferred` | 延迟执行，可组合操作 |
| 同步 | *(无令牌)* | 简单阻塞调用 |

```cpp
// 以下是等效的连接方式：
smtp.connect();                                         // 同步
smtp.async_connect([](auto ec) { /* ... */ });         // 回调
co_await smtp.async_connect(mailxx::use_awaitable);    // 协程
smtp.async_connect(mailxx::use_future).get();          // Future
auto op = smtp.async_connect(mailxx::deferred);        // 延迟
std::move(op)(handler);                                // 稍后执行
```

## 📁 项目结构

```
mailxx/
├── include/mailxx/
│   ├── mailxx.hpp          # 主头文件（包含所有）
│   ├── codec/              # Base64、Quoted-Printable 等
│   ├── mime/               # MIME 消息处理
│   ├── smtp/               # SMTP 客户端
│   ├── imap/               # IMAP 客户端  
│   ├── pop3/               # POP3 客户端
│   ├── pool/               # 连接池和速率限制
│   ├── net/                # 网络抽象
│   └── detail/             # 内部实现
├── examples/               # 使用示例
├── test/                   # 单元测试
└── modules/                # C++20 模块（实验性）
```

## 🔧 CMake 集成

```cmake
# 方式 1：FetchContent
include(FetchContent)
FetchContent_Declare(
    mailxx
    GIT_REPOSITORY https://github.com/sguinebert/mailxx.git
    GIT_TAG main
)
FetchContent_MakeAvailable(mailxx)

target_link_libraries(your_target PRIVATE mailxx::mailxx)

# 方式 2：find_package（安装后）
find_package(mailxx REQUIRED)
target_link_libraries(your_target PRIVATE mailxx::mailxx)
```

## 📦 C++20 模块（实验性）

mailxx 提供实验性的 C++20 模块支持，以获得更快的编译速度和更好的封装：

```
modules/
├── mailxx.cppm          # 主模块接口
├── mailxx.codec.cppm    # Base64、Quoted-Printable 等
├── mailxx.mime.cppm     # MIME 消息处理
├── mailxx.smtp.cppm     # SMTP 客户端
├── mailxx.imap.cppm     # IMAP 客户端
├── mailxx.pop3.cppm     # POP3 客户端
└── mailxx.net.cppm      # 网络抽象
```

### 模块使用方式

```cpp
import mailxx;           // 导入所有内容
// 或选择性导入：
import mailxx.smtp;      // 仅 SMTP
import mailxx.mime;      // 仅 MIME

int main() {
    mailxx::smtp::client smtp(io, "smtp.gmail.com", 587);
    // ...
}
```

### CMake 模块配置

```cmake
# 需要 CMake 3.28+ 和兼容的编译器
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_SCAN_FOR_MODULES ON)

add_executable(my_app main.cpp)
target_sources(my_app
    PUBLIC FILE_SET CXX_MODULES FILES
        ${mailxx_SOURCE_DIR}/modules/mailxx.cppm
        ${mailxx_SOURCE_DIR}/modules/mailxx.smtp.cppm
        # ... 根据需要添加其他模块
)
```

### 编译器支持

| 编译器 | 模块支持 | 备注 |
|--------|----------|------|
| **MSVC 2022** | ✅ 完整 | 目前支持最好 |
| **GCC 14+** | ✅ 良好 | 需要 `-fmodules-ts` |
| **Clang 17+** | ⚠️ 部分 | 正在快速改进 |

> **注意**：C++20 模块仍在发展中。对于生产环境，建议使用传统的仅头文件方式，直到模块工具链成熟。

## 🔐 安全说明

- **永远不要硬编码密码** - 使用环境变量或安全保险库
- 启用 2FA 时，为 Gmail/Outlook **使用应用密码**
- **优先使用 TLS/SSL** 连接（端口 465/993/995 或在 587/143/110 上使用 STARTTLS）

## 📋 支持的 RFC

| RFC | 描述 |
|-----|------|
| [RFC 5321](https://tools.ietf.org/html/rfc5321) | SMTP 协议 |
| [RFC 5322](https://tools.ietf.org/html/rfc5322) | 互联网消息格式 |
| [RFC 3501](https://tools.ietf.org/html/rfc3501) | IMAP4rev1 |
| [RFC 1939](https://tools.ietf.org/html/rfc1939) | POP3 协议 |
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

## 📄 许可证

MIT 许可证 - 版权所有 (c) 2025 Sylvain Guinebert

## 🙏 致谢

本项目最初受到 Tomislav Karastojković 的 [mailio](https://github.com/karastojko/mailio) 启发。
mailxx 已经发展成为一个完全重新设计的现代 C++23 库，支持 async/协程、仅头文件架构和大量新功能。

## 📬 联系方式

- **问题反馈**：[GitHub Issues](https://github.com/sguinebert/mailxx/issues)
- **作者**：Sylvain Guinebert
