#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <cstdint>
#include <functional>
#include <mailxx/detail/append.hpp>
#include <mailxx/detail/sanitize.hpp>
#include <mailxx/net/tls_options.hpp>

namespace mailxx
{
namespace smtp
{

struct reply
{
    int status = 0;
    std::vector<std::string> lines;

    [[nodiscard]] bool is_positive_completion() const noexcept { return status / 100 == 2; }
    [[nodiscard]] bool is_positive_intermediate() const noexcept { return status / 100 == 3; }
    [[nodiscard]] bool is_transient_negative() const noexcept { return status / 100 == 4; }
    [[nodiscard]] bool is_permanent_negative() const noexcept { return status / 100 == 5; }

    [[nodiscard]] std::string message() const
    {
        if (lines.empty())
            return std::string();

        std::string out = lines.front();
        for (std::size_t i = 1; i < lines.size(); ++i)
        {
            out += "\n";
            out += lines[i];
        }
        return out;
    }
};

struct capabilities
{
    std::map<std::string, std::vector<std::string>> entries;

    [[nodiscard]] bool empty() const noexcept { return entries.empty(); }

    [[nodiscard]] bool supports(std::string_view capability) const
    {
        const std::string key = normalize_key(capability);
        return entries.find(key) != entries.end();
    }

    [[nodiscard]] const std::vector<std::string>* parameters(std::string_view capability) const
    {
        const std::string key = normalize_key(capability);
        auto it = entries.find(key);
        return it == entries.end() ? nullptr : &it->second;
    }

private:
    [[nodiscard]] static std::string normalize_key(std::string_view key)
    {
        std::string out;
        out.reserve(key.size());
        for (char ch : key)
        {
            if (ch >= 'a' && ch <= 'z')
                out.push_back(static_cast<char>(ch - ('a' - 'A')));
            else
                out.push_back(ch);
        }
        return out;
    }
};

struct envelope
{
    std::string mail_from;
    std::vector<std::string> rcpt_to;
};

struct options
{
    std::string default_sni;
    bool auto_starttls = false;
    bool allow_cleartext_auth = false;
    bool require_tls_for_auth = true;
    mailxx::net::tls_options tls;
    mailxx::net::tls_mode default_tls_mode = mailxx::net::tls_mode::none;
    bool redact_secrets_in_trace = true;
    bool use_size_extension = true;
    bool use_smtputf8 = true;
    bool use_8bitmime = true;
};

// ==================== DSN Types (RFC 3461) ====================

/**
 * DSN (Delivery Status Notification) return type.
 * Specifies which part of the message to return in DSN reports.
 */
enum class dsn_ret
{
    none,      ///< Don't request specific return type
    full,      ///< Return full message in DSN (RET=FULL)
    hdrs       ///< Return only headers in DSN (RET=HDRS)
};

/**
 * DSN notification conditions.
 * Can be combined using bitwise OR.
 */
enum class dsn_notify : unsigned int
{
    none       = 0,       ///< Don't request DSN
    success    = 1 << 0,  ///< Notify on successful delivery
    failure    = 1 << 1,  ///< Notify on delivery failure
    delay      = 1 << 2,  ///< Notify if delivery is delayed
    never      = 1 << 3   ///< Never send DSN (overrides others)
};

/// Bitwise OR for dsn_notify
inline dsn_notify operator|(dsn_notify a, dsn_notify b) noexcept
{
    return static_cast<dsn_notify>(
        static_cast<unsigned int>(a) | static_cast<unsigned int>(b));
}

/// Bitwise AND for dsn_notify
inline dsn_notify operator&(dsn_notify a, dsn_notify b) noexcept
{
    return static_cast<dsn_notify>(
        static_cast<unsigned int>(a) & static_cast<unsigned int>(b));
}

/// Check if flag is set
inline bool has_flag(dsn_notify flags, dsn_notify flag) noexcept
{
    return (static_cast<unsigned int>(flags) & static_cast<unsigned int>(flag)) != 0;
}

/**
 * DSN options for a message.
 */
struct dsn_options
{
    dsn_ret ret = dsn_ret::none;           ///< What to return in DSN
    dsn_notify notify = dsn_notify::none;  ///< When to notify
    std::string envid;                     ///< Envelope ID for tracking
    std::string orcpt;                     ///< Original recipient (for forwarding)
    
    /// Check if DSN is requested
    [[nodiscard]] bool enabled() const noexcept
    {
        return ret != dsn_ret::none || notify != dsn_notify::none || !envid.empty();
    }
    
    /// Convert RET to SMTP parameter string
    [[nodiscard]] std::string ret_string() const
    {
        switch (ret)
        {
            case dsn_ret::full: return "FULL";
            case dsn_ret::hdrs: return "HDRS";
            default: return "";
        }
    }
    
    /// Convert NOTIFY to SMTP parameter string
    [[nodiscard]] std::string notify_string() const
    {
        if (has_flag(notify, dsn_notify::never))
            return "NEVER";
        
        std::string result;
        if (has_flag(notify, dsn_notify::success))
        {
            if (!result.empty()) result += ",";
            result += "SUCCESS";
        }
        if (has_flag(notify, dsn_notify::failure))
        {
            if (!result.empty()) result += ",";
            result += "FAILURE";
        }
        if (has_flag(notify, dsn_notify::delay))
        {
            if (!result.empty()) result += ",";
            result += "DELAY";
        }
        return result;
    }
    
    // Factory methods
    
    /// Request notification on failure only (most common)
    static dsn_options on_failure()
    {
        dsn_options opt;
        opt.notify = dsn_notify::failure;
        opt.ret = dsn_ret::hdrs;
        return opt;
    }
    
    /// Request notification on success and failure
    static dsn_options on_success_or_failure()
    {
        dsn_options opt;
        opt.notify = dsn_notify::success | dsn_notify::failure;
        opt.ret = dsn_ret::hdrs;
        return opt;
    }
    
    /// Request all notifications
    static dsn_options all()
    {
        dsn_options opt;
        opt.notify = dsn_notify::success | dsn_notify::failure | dsn_notify::delay;
        opt.ret = dsn_ret::full;
        return opt;
    }
    
    /// Explicitly disable DSN
    static dsn_options disabled()
    {
        dsn_options opt;
        opt.notify = dsn_notify::never;
        return opt;
    }
};

/**
 * Extended envelope with DSN support.
 */
struct envelope_dsn : envelope
{
    dsn_options dsn;  ///< DSN options for this envelope
    
    envelope_dsn() = default;
    
    envelope_dsn(const envelope& env, dsn_options dsn_opt = {})
        : envelope(env), dsn(std::move(dsn_opt))
    {
    }
};

// ==================== SMTP Extensions ====================

/**
 * SMTP BODY parameter for 8BITMIME (RFC 6152).
 * Specifies the encoding of the message body.
 */
enum class body_type
{
    auto_detect,   ///< Let client detect based on message content
    bit7,          ///< 7-bit ASCII only (default, always safe)
    bit8           ///< 8-bit content (requires 8BITMIME support)
};

/**
 * Extended envelope with SMTP extension support.
 * 
 * Supports:
 * - SIZE (RFC 1870): Declare message size before sending
 * - 8BITMIME (RFC 6152): 8-bit message transfer
 * - SMTPUTF8 (RFC 6531): Internationalized email addresses
 * - DSN (RFC 3461): Delivery status notifications
 */
struct envelope_ext : envelope
{
    // SIZE extension (RFC 1870)
    std::size_t size = 0;            ///< Message size in bytes (0 = auto-calculate)
    
    // 8BITMIME extension (RFC 6152)
    body_type body = body_type::auto_detect;  ///< Body encoding type
    
    // SMTPUTF8 extension (RFC 6531)
    bool smtputf8 = false;           ///< Enable UTF-8 in envelope (auto-detected if false)
    
    // DSN extension (RFC 3461)
    dsn_options dsn;                 ///< DSN options
    
    envelope_ext() = default;
    
    envelope_ext(const envelope& env)
        : envelope(env)
    {
    }
    
    /// Check if any extensions are in use
    [[nodiscard]] bool has_extensions() const noexcept
    {
        return size > 0 
            || body != body_type::auto_detect 
            || smtputf8 
            || dsn.enabled();
    }
};

/**
 * Server size limit information from SIZE extension.
 */
struct size_limit
{
    std::size_t max_size = 0;   ///< Maximum message size (0 = unlimited/unknown)
    
    [[nodiscard]] bool has_limit() const noexcept { return max_size > 0; }
    
    [[nodiscard]] bool exceeds(std::size_t msg_size) const noexcept
    {
        return has_limit() && msg_size > max_size;
    }
};

namespace detail
{
    struct mail_extension_flags
    {
        bool use_size = false;
        bool use_smtputf8 = false;
        bool use_8bitmime = false;
        bool supports_size = false;
        bool supports_smtputf8 = false;
        bool supports_8bitmime = false;
    };

    inline void append_mail_extensions(std::string& cmd, std::size_t msg_size, bool has_8bit, bool needs_utf8,
        const mail_extension_flags& flags)
    {
        if (flags.use_size && flags.supports_size)
        {
            mailxx::detail::append_sv(cmd, " SIZE=");
            mailxx::detail::append_uint(cmd, static_cast<std::uint64_t>(msg_size));
        }
        if (flags.use_smtputf8 && flags.supports_smtputf8 && needs_utf8)
            mailxx::detail::append_sv(cmd, " SMTPUTF8");
        if (flags.use_8bitmime && flags.supports_8bitmime && has_8bit)
            mailxx::detail::append_sv(cmd, " BODY=8BITMIME");
    }

    [[nodiscard]] inline std::string build_mail_from_command(std::string_view mail_from, std::size_t msg_size,
        bool has_8bit, bool needs_utf8, const mail_extension_flags& flags)
    {
        mailxx::detail::ensure_no_crlf_or_nul(mail_from, "mail_from");
        std::string cmd;
        mailxx::detail::append_sv(cmd, "MAIL FROM: ");
        mailxx::detail::append_angle_addr(cmd, mail_from);
        append_mail_extensions(cmd, msg_size, has_8bit, needs_utf8, flags);
        return cmd;
    }
} // namespace detail

enum class auth_method
{
    auto_detect,
    plain,
    login,
    xoauth2
};

// ==================== Progress Callback Types ====================

/**
 * Progress information for large message transfers.
 */
struct progress_info_t
{
    uint64_t bytes_transferred = 0;  ///< Bytes transferred so far
    uint64_t total_bytes = 0;        ///< Total bytes to transfer
    bool is_upload = true;           ///< Always true for SMTP (sending)
    
    /// Returns progress as a percentage (0-100), or -1 if total is unknown
    [[nodiscard]] double percent() const noexcept
    {
        return total_bytes > 0 ? (static_cast<double>(bytes_transferred) / total_bytes) * 100.0 : -1.0;
    }
    
    [[nodiscard]] bool is_complete() const noexcept
    {
        return total_bytes > 0 && bytes_transferred >= total_bytes;
    }
};

/// Progress callback signature
using progress_callback_t = std::function<void(const progress_info_t&)>;

} // namespace smtp
} // namespace mailxx
