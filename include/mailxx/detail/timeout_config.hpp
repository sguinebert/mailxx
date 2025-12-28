/**
 * @file timeout_config.hpp
 * @brief Configurable per-operation timeouts for email protocols.
 * @author mailxx contributors
 * 
 * Granular timeout configuration for different phases of email operations.
 */

#ifndef MAILXX_DETAIL_TIMEOUT_CONFIG_HPP
#define MAILXX_DETAIL_TIMEOUT_CONFIG_HPP

#include <chrono>
#include <optional>

namespace mailxx {

using namespace std::chrono;

/**
 * Per-operation timeout configuration.
 * 
 * Allows fine-grained control over timeouts for different phases
 * of email protocol operations. If a specific timeout is not set,
 * the default_timeout is used.
 * 
 * Example:
 * @code
 * timeout_config timeouts;
 * timeouts.connect = seconds(10);
 * timeouts.greeting = seconds(30);
 * timeouts.auth = seconds(60);
 * timeouts.data_per_kb = milliseconds(100);  // Scale with message size
 * 
 * smtp_client client(executor, timeouts);
 * @endcode
 */
struct timeout_config
{
    /// Default timeout used when specific timeout is not set
    steady_clock::duration default_timeout{seconds(60)};
    
    /// TCP connection establishment timeout
    std::optional<steady_clock::duration> connect;
    
    /// Server greeting (banner) timeout
    std::optional<steady_clock::duration> greeting;
    
    /// EHLO/HELO command timeout
    std::optional<steady_clock::duration> ehlo;
    
    /// STARTTLS negotiation timeout
    std::optional<steady_clock::duration> starttls;
    
    /// Authentication timeout (may be longer for OAuth)
    std::optional<steady_clock::duration> auth;
    
    /// MAIL FROM command timeout
    std::optional<steady_clock::duration> mail_from;
    
    /// RCPT TO command timeout (per recipient)
    std::optional<steady_clock::duration> rcpt_to;
    
    /// DATA command timeout
    std::optional<steady_clock::duration> data_cmd;
    
    /// Base timeout for data transfer
    std::optional<steady_clock::duration> data_transfer;
    
    /// Additional timeout per KB of data (scales with message size)
    std::optional<steady_clock::duration> data_per_kb;
    
    /// QUIT command timeout
    std::optional<steady_clock::duration> quit;
    
    /// Generic command timeout
    std::optional<steady_clock::duration> command;
    
    /// Read operation timeout
    std::optional<steady_clock::duration> read;
    
    /// Write operation timeout  
    std::optional<steady_clock::duration> write;

    // ========== Getters with fallback to default ==========

    steady_clock::duration get_connect() const 
    { return connect.value_or(default_timeout); }
    
    steady_clock::duration get_greeting() const 
    { return greeting.value_or(default_timeout); }
    
    steady_clock::duration get_ehlo() const 
    { return ehlo.value_or(default_timeout); }
    
    steady_clock::duration get_starttls() const 
    { return starttls.value_or(default_timeout); }
    
    steady_clock::duration get_auth() const 
    { return auth.value_or(default_timeout); }
    
    steady_clock::duration get_mail_from() const 
    { return mail_from.value_or(command.value_or(default_timeout)); }
    
    steady_clock::duration get_rcpt_to() const 
    { return rcpt_to.value_or(command.value_or(default_timeout)); }
    
    steady_clock::duration get_data_cmd() const 
    { return data_cmd.value_or(command.value_or(default_timeout)); }
    
    steady_clock::duration get_data_transfer(size_t size_bytes = 0) const
    {
        auto base = data_transfer.value_or(default_timeout);
        if (data_per_kb && size_bytes > 0)
        {
            const size_t kb = (size_bytes + 1023) / 1024;
            base += *data_per_kb * kb;
        }
        return base;
    }
    
    steady_clock::duration get_quit() const 
    { return quit.value_or(seconds(10)); }  // QUIT usually fast
    
    steady_clock::duration get_command() const 
    { return command.value_or(default_timeout); }
    
    steady_clock::duration get_read() const 
    { return read.value_or(default_timeout); }
    
    steady_clock::duration get_write() const 
    { return write.value_or(default_timeout); }

    // ========== Factory methods ==========

    /**
     * Create default timeout configuration.
     * All operations use 60 second timeout.
     */
    static timeout_config defaults()
    {
        return {};
    }

    /**
     * Create configuration for fast/local servers.
     * Short timeouts suitable for local or well-connected servers.
     */
    static timeout_config fast()
    {
        timeout_config cfg;
        cfg.default_timeout = seconds(15);
        cfg.connect = seconds(5);
        cfg.greeting = seconds(10);
        cfg.auth = seconds(15);
        cfg.data_transfer = seconds(30);
        cfg.data_per_kb = milliseconds(10);
        cfg.quit = seconds(5);
        return cfg;
    }

    /**
     * Create configuration for slow/remote servers.
     * Longer timeouts for high-latency or overloaded servers.
     */
    static timeout_config slow()
    {
        timeout_config cfg;
        cfg.default_timeout = seconds(120);
        cfg.connect = seconds(30);
        cfg.greeting = seconds(60);
        cfg.auth = seconds(120);
        cfg.data_transfer = seconds(300);
        cfg.data_per_kb = milliseconds(200);
        cfg.quit = seconds(30);
        return cfg;
    }

    /**
     * Create configuration for large attachments.
     * Extended data transfer timeouts.
     */
    static timeout_config bulk_transfer()
    {
        timeout_config cfg;
        cfg.default_timeout = seconds(60);
        cfg.data_transfer = seconds(600);  // 10 minutes base
        cfg.data_per_kb = milliseconds(50);  // +50ms per KB
        return cfg;
    }

    /**
     * Create uniform configuration with single timeout for all operations.
     */
    static timeout_config uniform(steady_clock::duration timeout)
    {
        timeout_config cfg;
        cfg.default_timeout = timeout;
        return cfg;
    }
};

/**
 * IMAP-specific timeout extensions.
 */
struct imap_timeout_config : timeout_config
{
    /// SELECT/EXAMINE command timeout
    std::optional<steady_clock::duration> select;
    
    /// SEARCH command timeout
    std::optional<steady_clock::duration> search;
    
    /// FETCH command timeout (base)
    std::optional<steady_clock::duration> fetch;
    
    /// FETCH additional time per message
    std::optional<steady_clock::duration> fetch_per_msg;
    
    /// STORE command timeout
    std::optional<steady_clock::duration> store;
    
    /// COPY/MOVE command timeout
    std::optional<steady_clock::duration> copy;
    
    /// IDLE command maximum duration
    std::optional<steady_clock::duration> idle;

    steady_clock::duration get_select() const
    { return select.value_or(default_timeout); }
    
    steady_clock::duration get_search() const
    { return search.value_or(default_timeout); }
    
    steady_clock::duration get_fetch(size_t msg_count = 1) const
    {
        auto base = fetch.value_or(default_timeout);
        if (fetch_per_msg && msg_count > 1)
            base += *fetch_per_msg * (msg_count - 1);
        return base;
    }
    
    steady_clock::duration get_store() const
    { return store.value_or(default_timeout); }
    
    steady_clock::duration get_copy() const
    { return copy.value_or(default_timeout); }
    
    steady_clock::duration get_idle() const
    { return idle.value_or(minutes(29)); }  // RFC recommends < 30 min

    /**
     * Create IMAP defaults.
     */
    static imap_timeout_config defaults()
    {
        imap_timeout_config cfg;
        cfg.search = seconds(120);  // Searches can be slow
        cfg.fetch = seconds(60);
        cfg.fetch_per_msg = seconds(5);
        cfg.idle = minutes(25);
        return cfg;
    }
};

/**
 * POP3-specific timeout extensions.
 */
struct pop3_timeout_config : timeout_config
{
    /// STAT command timeout
    std::optional<steady_clock::duration> stat;
    
    /// LIST command timeout
    std::optional<steady_clock::duration> list;
    
    /// RETR command timeout (base)
    std::optional<steady_clock::duration> retr;
    
    /// RETR additional time per KB
    std::optional<steady_clock::duration> retr_per_kb;
    
    /// DELE command timeout
    std::optional<steady_clock::duration> dele;

    steady_clock::duration get_stat() const
    { return stat.value_or(default_timeout); }
    
    steady_clock::duration get_list() const
    { return list.value_or(default_timeout); }
    
    steady_clock::duration get_retr(size_t size_bytes = 0) const
    {
        auto base = retr.value_or(default_timeout);
        if (retr_per_kb && size_bytes > 0)
        {
            const size_t kb = (size_bytes + 1023) / 1024;
            base += *retr_per_kb * kb;
        }
        return base;
    }
    
    steady_clock::duration get_dele() const
    { return dele.value_or(default_timeout); }

    static pop3_timeout_config defaults()
    {
        pop3_timeout_config cfg;
        cfg.retr = seconds(120);
        cfg.retr_per_kb = milliseconds(50);
        return cfg;
    }
};

} // namespace mailxx

#endif // MAILXX_DETAIL_TIMEOUT_CONFIG_HPP
