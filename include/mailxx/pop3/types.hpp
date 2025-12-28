#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include <mailxx/net/dialog.hpp>
#include <mailxx/net/tls_options.hpp>

namespace mailxx::pop3
{

struct capabilities
{
    bool stls = false;
    bool uidl = false;
    bool top = false;
    std::vector<std::string> sasl_mechanisms;
    std::vector<std::string> raw_lines;
    
    [[nodiscard]] bool empty() const noexcept
    {
        return !stls && !uidl && !top && sasl_mechanisms.empty();
    }
    
    [[nodiscard]] bool supports_sasl(std::string_view mechanism) const noexcept
    {
        for (const auto& m : sasl_mechanisms)
            if (m == mechanism)
                return true;
        return false;
    }
};

struct mailbox_stat
{
    unsigned int messages_no = 0;
    unsigned long mailbox_size = 0;
};

using message_list = std::map<unsigned, unsigned long>;
using uidl_list = std::map<unsigned, std::string>;

struct options
{
    std::size_t max_line_length = mailxx::net::DEFAULT_MAX_LINE_LENGTH;
    std::optional<std::chrono::steady_clock::duration> timeout = std::nullopt;
    std::string default_sni;
    bool auto_starttls = false;
    bool allow_cleartext_auth = false;
    bool require_tls_for_auth = true;
    mailxx::net::tls_options tls;
    mailxx::net::tls_mode default_tls_mode = mailxx::net::tls_mode::none;
    bool redact_secrets_in_trace = true;
    bool store_credentials_for_reconnect = false;
};

// ==================== Progress Callback Types ====================

/**
 * Progress information for message downloads.
 */
struct progress_info_t
{
    uint64_t bytes_transferred = 0;  ///< Bytes downloaded so far
    uint64_t total_bytes = 0;        ///< Total bytes (from LIST, may be approximate)
    bool is_upload = false;          ///< Always false for POP3 (downloading)
    
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

} // namespace mailxx::pop3
