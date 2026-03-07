# mailxx

![C++](https://img.shields.io/badge/C++-23-blue)
[![License](https://img.shields.io/badge/License-MIT-darkgreen)](LICENSE)
![FreeBSD](https://img.shields.io/badge/OS-FreeBSD-870000)
![Linux](https://img.shields.io/badge/OS-Linux-870000)
![Windows](https://img.shields.io/badge/OS-Windows-870000)
![macOS](https://img.shields.io/badge/OS-macOS-870000)

**mailxx** 是一个现代 C++23、仅头文件的邮件协议库，提供基于协程的 SMTP、IMAP、POP3 客户端。

## 主要特性

- 仅头文件，集成简单
- 基于 `std::expected` 的错误返回模型
- 原生协程 API，适合 Asio / Boost.Asio
- 支持 SMTP、IMAP、POP3
- 提供连接池与限流组件
- 自带基于 `CLI11` 的真实环境验证工具
- 底层网络写入 API 明确区分 borrowed view 与 owned buffer

## 协议状态

| 协议 | 当前状态 | 说明 |
|------|----------|------|
| SMTP | 已实测验证 | 25、587、STARTTLS、AUTH、PIPELINING、SMTPUTF8、DSN |
| IMAP | 已实测验证 | CAPABILITY、LOGIN/PLAIN、LIST、SELECT、SEARCH、FETCH、IDLE |
| POP3 | 已实测验证 | USER/PASS、PLAIN、LOGIN、APOP、UIDL、TOP、STAT、LIST |

## 依赖

- C++23 编译器
- Boost.Asio 或 standalone Asio
- OpenSSL

## 快速开始

### SMTP 发送

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::awaitable<void> send_email(mailxx::smtp::client& smtp)
{
    if (auto res = co_await smtp.connect("smtp.example.com", 587); !res) co_return;
    if (auto res = co_await smtp.read_greeting(); !res) co_return;
    if (auto res = co_await smtp.ehlo(); !res) co_return;

    mailxx::asio::ssl::context tls_ctx(mailxx::asio::ssl::context::tls_client);
    if (auto res = co_await smtp.start_tls(tls_ctx); !res) co_return;
    if (auto res = co_await smtp.ehlo(); !res) co_return;

    if (auto res = co_await smtp.authenticate("user@example.com", "secret",
                                              mailxx::smtp::auth_method::login); !res) co_return;

    mailxx::message msg;
    msg.from({"Sender", "sender@example.com"});
    msg.add_recipient({"Recipient", "recipient@example.com"});
    msg.subject("Hello from mailxx");
    msg.content("Test message");

    (void)co_await smtp.send(msg);
    (void)co_await smtp.quit();
}
```

### IMAP 接收

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::awaitable<void> fetch_one(mailxx::imap::client& imap)
{
    if (auto res = co_await imap.connect("imap.example.com", 143); !res) co_return;
    if (auto res = co_await imap.read_greeting(); !res) co_return;
    if (auto res = co_await imap.login("user@example.com", "secret"); !res) co_return;

    if (auto sel = co_await imap.select("INBOX"); !sel) co_return;
    if (auto uids = co_await imap.uid_search("ALL"); uids && !uids->empty())
    {
        auto msg = co_await imap.uid_fetch_rfc822(uids->front());
        if (msg)
            std::cout << msg->subject() << "\n";
    }

    (void)co_await imap.logout();
}
```

### POP3 接收

```cpp
#include <mailxx/mailxx.hpp>

mailxx::asio::awaitable<void> fetch_pop3(mailxx::pop3::client& pop3)
{
    if (auto res = co_await pop3.connect("pop.example.com", "110"); !res) co_return;
    if (auto res = co_await pop3.read_greeting(); !res) co_return;
    if (auto res = co_await pop3.login("user@example.com", "secret"); !res) co_return;

    auto stat = co_await pop3.statistics();
    if (stat)
        std::cout << "messages=" << stat->message_count << "\n";

    (void)co_await pop3.quit();
}
```

## CLI 真实环境验证

仓库包含一个 `CLI11` 命令行工具 `mailxx_realworld_cli`，用于真实服务器验证。

### 构建

```bash
cmake -S . -B build \
  -Dmailxx_BUILD_REALWORLD_CLI=ON \
  -Dmailxx_BUILD_TESTS=ON

cmake --build build --target mailxx_realworld_cli
```

### 示例

```bash
# SMTP 25
build/tools/mailxx_realworld_cli smtp \
  --host localhost --port 25 --tls-mode none \
  --from test.fse@caveo.fr --to test.fse@caveo.fr

# SMTP 587 + STARTTLS + AUTH
build/tools/mailxx_realworld_cli smtp \
  --host localhost --port 587 --tls-mode starttls --insecure \
  --username test.fse@caveo.fr --secret 'secret' --auth-method plain \
  --from test.fse@caveo.fr --to test.fse@caveo.fr

# IMAP
build/tools/mailxx_realworld_cli imap \
  --host localhost --port 143 --tls-mode none \
  --username test.fse@caveo.fr --secret 'secret' \
  --auth-method login --allow-cleartext-auth \
  --mailbox INBOX --search ALL

# POP3 / APOP
build/tools/mailxx_realworld_cli pop3 \
  --host localhost --port 110 --tls-mode none \
  --username test.fse@caveo.fr --secret 'secret' \
  --auth-method apop --message-no 1 --top-lines 20
```

## 底层 dialog API

`mailxx::net::dialog` 现在只保留显式所有权语义：

```cpp
co_await dlg.write_line_view_r("NOOP");

std::string_view view = payload;
co_await dlg.write_raw_view_r(view);

co_await dlg.write_raw_r(std::move(payload));
co_await dlg.write_raw_buffer_r(view, std::move(owner));
```

说明：

- `write_line_view*` 接收逻辑文本行，框架会在网络层附加 `CRLF`
- `write_line_buffer*` 适合 view 与 owner 分离的高级场景
- `write_raw*` 不再做隐式拷贝/隐式所有权判断

## 破坏性变更

以下旧 API 已移除：

- `mime::header_codec()`
- `mime::line_policy(encoder, decoder)`
- `codec::line_len_policy_t::VERYLARGE`
- `dialog::write_line(std::string&&)`

迁移建议：

- 使用 `string_t` 显式指定头字段编码
- 只使用 `line_policy(codec::line_len_policy_t)`
- 使用 `write_line_view*`、`write_line_buffer*`、`write_raw*`、`write_raw_view*`、`write_raw_buffer*`

## 严格模式

默认情况下，mailxx 更偏向真实世界兼容性而不是最严格拒绝。

如果需要严格 RFC 校验：

```cpp
mailxx::message msg;
msg.strict_mode(true);
msg.strict_codec_mode(true);
```

## 目录结构

```text
mailxx/
├── include/mailxx/        # 核心头文件
├── examples/              # 示例
├── test/                  # 单元测试
├── tools/                 # CLI11 真实环境验证工具
└── modules/               # C++20 modules（实验性）
```

## 支持的 RFC

- RFC 5321 / 5322
- RFC 3501
- RFC 1939
- RFC 2045-2049
- RFC 2177
- RFC 2087
- RFC 2342
- RFC 5256
- RFC 2920
- RFC 1870
- RFC 6152
- RFC 6531
- RFC 3461

## License

MIT
