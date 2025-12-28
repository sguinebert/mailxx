#pragma once

#include <variant>
#include <string>
#include <vector>
#include <utility>
#include <memory>
#include <mailxx/detail/asio_decl.hpp>
#if defined(__has_include)
#if __has_include(<asio/ssl/host_name_verification.hpp>)
#include <asio/ssl/host_name_verification.hpp>
#define MAILXX_HAS_SSL_HOST_NAME_VERIFICATION 1
#elif __has_include(<boost/asio/ssl/host_name_verification.hpp>)
#include <boost/asio/ssl/host_name_verification.hpp>
#define MAILXX_HAS_SSL_HOST_NAME_VERIFICATION 1
#endif
#elif defined(MAILXX_USE_STANDALONE_ASIO)
#include <asio/ssl/host_name_verification.hpp>
#define MAILXX_HAS_SSL_HOST_NAME_VERIFICATION 1
#else
#include <boost/asio/ssl/host_name_verification.hpp>
#define MAILXX_HAS_SSL_HOST_NAME_VERIFICATION 1
#endif
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <mailxx/net/tls_error.hpp>
#include <mailxx/net/tls_options.hpp>
#include <mailxx/net/tls_trust_store.hpp>

namespace mailxx
{
namespace net
{

// Import Asio types from centralized declarations
using namespace mailxx::asio;

/**
Stable stream type that can be upgraded to TLS without changing the type.
**/
class upgradable_stream
{
public:
    using ssl_stream = ssl::stream<tcp::socket>;
    using executor_type = any_io_executor;
    using lowest_layer_type = tcp::socket;

    explicit upgradable_stream(tcp::socket socket)
        : stream_(std::move(socket))
    {
    }

    explicit upgradable_stream(executor_type executor)
        : stream_(tcp::socket(executor))
    {
    }

    executor_type get_executor() const
    {
        return std::visit([](const auto& stream) -> executor_type
        {
            return stream.get_executor();
        }, stream_);
    }

    lowest_layer_type& lowest_layer()
    {
        return std::visit([](auto& stream) -> lowest_layer_type&
        {
            return stream.lowest_layer();
        }, stream_);
    }

    const lowest_layer_type& lowest_layer() const
    {
        return std::visit([](const auto& stream) -> const lowest_layer_type&
        {
            return stream.lowest_layer();
        }, stream_);
    }

    bool is_tls() const noexcept
    {
        return std::holds_alternative<ssl_stream>(stream_);
    }

    template<typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token)
    {
        return std::visit([&](auto& stream) -> decltype(auto)
        {
            return stream.async_read_some(buffers, std::forward<CompletionToken>(token));
        }, stream_);
    }

    template<typename ConstBufferSequence, typename CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token)
    {
        return std::visit([&](auto& stream) -> decltype(auto)
        {
            return stream.async_write_some(buffers, std::forward<CompletionToken>(token));
        }, stream_);
    }

    awaitable<void> start_tls(ssl::context& context, std::string sni)
    {
        co_return co_await start_tls(context, std::move(sni), tls_options{});
    }

    awaitable<void> start_tls(ssl::context& context, std::string sni, const tls_options& opt)
    {
        if (is_tls())
            co_return;

        configure_trust_store(context, opt);
        apply_tls_hardening(context, opt);

        auto socket = std::move(std::get<tcp::socket>(stream_));
        stream_.template emplace<ssl_stream>(std::move(socket), context);

        auto& tls_stream = std::get<ssl_stream>(stream_);
        if (!sni.empty())
        {
#if defined(SSL_CTRL_SET_TLSEXT_HOSTNAME)
            SSL_set_tlsext_host_name(tls_stream.native_handle(), sni.c_str());
#endif
        }

        if (opt.verify == verify_mode::peer)
            tls_stream.set_verify_mode(ssl::verify_peer);
        else
            tls_stream.set_verify_mode(ssl::verify_none);

        if (opt.verify == verify_mode::peer)
        {
            const bool needs_callback = opt.verify_host || opt.allow_self_signed || opt.allow_expired;
            if (needs_callback)
            {
                std::string hostname;
                if (opt.verify_host)
                {
                    hostname = sni;
                    if (hostname.empty())
                        throw tls_error("TLS hostname verification requires a host name.");
                }
#if defined(MAILXX_HAS_SSL_HOST_NAME_VERIFICATION)
                if (opt.verify_host)
                {
                    auto verifier = ssl::host_name_verification(hostname);
                    tls_stream.set_verify_callback([verifier,
                        allow_self_signed = opt.allow_self_signed,
                        allow_expired = opt.allow_expired](bool preverified, ssl::verify_context& ctx) mutable
                    {
                        if (!relax_verify(preverified, ctx, allow_self_signed, allow_expired))
                            return false;
                        return verifier(true, ctx);
                    });
                }
                else
                {
                    tls_stream.set_verify_callback(
                        [allow_self_signed = opt.allow_self_signed,
                         allow_expired = opt.allow_expired](bool preverified, ssl::verify_context& ctx)
                    {
                        return relax_verify(preverified, ctx, allow_self_signed, allow_expired);
                    });
                }
#else
                tls_stream.set_verify_callback([hostname,
                    verify_host = opt.verify_host,
                    allow_self_signed = opt.allow_self_signed,
                    allow_expired = opt.allow_expired](bool preverified, ssl::verify_context& ctx)
                {
                    if (!relax_verify(preverified, ctx, allow_self_signed, allow_expired))
                        return false;
                    if (!verify_host)
                        return true;
                    X509_STORE_CTX* store_ctx = ctx.native_handle();
                    if (store_ctx == nullptr)
                        return false;
                    if (X509_STORE_CTX_get_error_depth(store_ctx) != 0)
                        return true;
                    X509* cert = X509_STORE_CTX_get_current_cert(store_ctx);
                    if (cert == nullptr)
                        return false;
                    return X509_check_host(cert, hostname.c_str(), hostname.size(), 0, nullptr) == 1;
                });
#endif
            }
        }

        co_await tls_stream.async_handshake(ssl::stream_base::client, use_awaitable);
        enforce_pins(tls_stream, opt);
    }

private:
    static std::string openssl_error_message()
    {
        const unsigned long err = ERR_get_error();
        if (err == 0)
            return {};
        char buffer[256];
        ERR_error_string_n(err, buffer, sizeof(buffer));
        return std::string(buffer);
    }

    static void apply_tls_hardening(ssl::context& context, const tls_options& opt)
    {
        // Applies policy to the SSL_CTX; does not override existing min version.
        if (opt.min_tls_version.has_value())
        {
            const int current = SSL_CTX_get_min_proto_version(context.native_handle());
            if (current == 0)
            {
                if (SSL_CTX_set_min_proto_version(context.native_handle(),
                        opt.min_tls_version.value()) != 1)
                {
                    throw tls_error("TLS min version configuration failed.",
                        openssl_error_message());
                }
            }
        }

        if (!opt.cipher_list.empty())
        {
            if (SSL_CTX_set_cipher_list(context.native_handle(),
                    opt.cipher_list.c_str()) != 1)
            {
                throw tls_error("TLS cipher list configuration failed.",
                    openssl_error_message());
            }
        }
    }

    static bool relax_verify(bool preverified, ssl::verify_context& ctx,
        bool allow_self_signed, bool allow_expired) noexcept
    {
        if (preverified)
            return true;
        if (!allow_self_signed && !allow_expired)
            return false;

        X509_STORE_CTX* store_ctx = ctx.native_handle();
        if (store_ctx == nullptr)
            return false;

        const int err = X509_STORE_CTX_get_error(store_ctx);
        if (allow_self_signed)
        {
            if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN ||
                err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
            {
                return true;
            }
        }
        if (allow_expired)
        {
            if (err == X509_V_ERR_CERT_HAS_EXPIRED ||
                err == X509_V_ERR_CERT_NOT_YET_VALID)
            {
                return true;
            }
        }
        return false;
    }

    static bool valid_pin_length(std::size_t length) noexcept
    {
        constexpr std::size_t hex_len = SHA256_DIGEST_LENGTH * 2;
        constexpr std::size_t base64_len = 4 * ((SHA256_DIGEST_LENGTH + 2) / 3);
        return length == hex_len || length == base64_len;
    }

    static std::vector<std::string> normalize_pins(
        const std::vector<std::string>& pins, const char* label)
    {
        std::vector<std::string> out;
        out.reserve(pins.size());
        for (const auto& pin : pins)
        {
            std::string normalized = normalize_fingerprint(pin);
            if (normalized.empty())
                continue;
            if (!valid_pin_length(normalized.size()))
                throw tls_error(std::string("TLS pinning failure: invalid ") + label + " pin.");
            out.push_back(std::move(normalized));
        }
        return out;
    }

    static std::string digest_to_hex(const unsigned char* digest, std::size_t size)
    {
        static constexpr char hex[] = "0123456789abcdef";
        std::string out;
        out.reserve(size * 2);
        for (std::size_t i = 0; i < size; ++i)
        {
            const unsigned char byte = digest[i];
            out.push_back(hex[byte >> 4]);
            out.push_back(hex[byte & 0x0F]);
        }
        return out;
    }

    static std::string digest_to_base64(const unsigned char* digest, std::size_t size)
    {
        const std::size_t out_len = 4 * ((size + 2) / 3);
        std::string out(out_len, '\0');
        const int written = EVP_EncodeBlock(
            reinterpret_cast<unsigned char*>(&out[0]), digest, static_cast<int>(size));
        if (written <= 0)
            return {};
        out.resize(static_cast<std::size_t>(written));
        return out;
    }

    static bool sha256_fingerprints(const unsigned char* data, std::size_t size,
        std::string& hex, std::string& base64)
    {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        SHA256(data, size, digest);
        hex = digest_to_hex(digest, SHA256_DIGEST_LENGTH);
        base64 = digest_to_base64(digest, SHA256_DIGEST_LENGTH);
        return !hex.empty() && !base64.empty();
    }

    static bool sha256_cert(X509* cert, std::string& hex, std::string& base64)
    {
        const int len = i2d_X509(cert, nullptr);
        if (len <= 0)
            return false;
        std::vector<unsigned char> der(static_cast<std::size_t>(len));
        unsigned char* ptr = der.data();
        i2d_X509(cert, &ptr);
        return sha256_fingerprints(der.data(), der.size(), hex, base64);
    }

    static bool sha256_spki(X509* cert, std::string& hex, std::string& base64)
    {
        X509_PUBKEY* pubkey = X509_get_X509_PUBKEY(cert);
        if (pubkey == nullptr)
            return false;
        const int len = i2d_X509_PUBKEY(pubkey, nullptr);
        if (len <= 0)
            return false;
        std::vector<unsigned char> der(static_cast<std::size_t>(len));
        unsigned char* ptr = der.data();
        i2d_X509_PUBKEY(pubkey, &ptr);
        return sha256_fingerprints(der.data(), der.size(), hex, base64);
    }

    static bool match_pins(const std::vector<std::string>& pins,
        const std::string& hex, const std::string& base64) noexcept
    {
        bool matched = false;
        for (const auto& pin : pins)
        {
            matched |= constant_time_equals(pin, hex);
            matched |= constant_time_equals(pin, base64);
        }
        return matched;
    }

    static void enforce_pins(ssl_stream& tls_stream, const tls_options& opt)
    {
        const std::vector<std::string> cert_pins = normalize_pins(opt.pinned_cert_sha256, "cert");
        const std::vector<std::string> spki_pins = normalize_pins(opt.pinned_spki_sha256, "spki");
        if (cert_pins.empty() && spki_pins.empty())
            return;

        std::unique_ptr<X509, decltype(&X509_free)> cert(
            SSL_get_peer_certificate(tls_stream.native_handle()), X509_free);
        if (!cert)
            throw tls_error("TLS pinning failure: no peer certificate.");

        bool matched = false;
        if (!cert_pins.empty())
        {
            std::string cert_hex;
            std::string cert_base64;
            if (!sha256_cert(cert.get(), cert_hex, cert_base64))
                throw tls_error("TLS pinning failure: unable to hash certificate.");
            matched |= match_pins(cert_pins, cert_hex, cert_base64);
        }
        if (!spki_pins.empty())
        {
            std::string spki_hex;
            std::string spki_base64;
            if (!sha256_spki(cert.get(), spki_hex, spki_base64))
                throw tls_error("TLS pinning failure: unable to hash SPKI.");
            matched |= match_pins(spki_pins, spki_hex, spki_base64);
        }

        if (!matched)
            throw tls_error("TLS pinning failure: certificate mismatch.");
    }

    std::variant<tcp::socket, ssl_stream> stream_;
};

} // namespace net
} // namespace mailxx
