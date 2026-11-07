#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <variant>
#include <string>
#include <vector>
#include <utility>
#include <memory>
#include <type_traits>
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
#if defined(MAILXX_HAS_ZLIB)
#include <zlib.h>
#endif
#include <mailxx/detail/result.hpp>
#include <mailxx/net/tls_options.hpp>
#include <mailxx/net/tls_trust_store.hpp>

namespace mailxx
{
namespace net
{

// Import Asio types from centralized declarations
using mailxx::asio::any_io_executor;
using mailxx::asio::awaitable;
using mailxx::asio::tcp;
namespace ssl = mailxx::asio::ssl;

/**
Stable stream type that can be upgraded to TLS without changing the type.
**/
class upgradable_stream
{
public:
    using ssl_stream = ssl::stream<tcp::socket>;
    using executor_type = any_io_executor;
    using lowest_layer_type = std::remove_reference_t<decltype(std::declval<ssl_stream&>().lowest_layer())>;

    explicit upgradable_stream(tcp::socket socket)
        : stream_(std::move(socket))
    {
    }

    explicit upgradable_stream(executor_type executor)
        : stream_(tcp::socket(executor))
    {
    }

    executor_type get_executor()
    {
        return std::visit([](auto& stream) -> executor_type
        {
            return executor_type(stream.get_executor());
        }, stream_);
    }

    executor_type get_executor() const
    {
        return const_cast<upgradable_stream*>(this)->get_executor();
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

    [[nodiscard]] std::optional<std::array<std::uint8_t, 32>> peer_certificate_sha256() const
    {
        if (!peer_cert_sha256_ready_)
            return std::nullopt;
        return peer_cert_sha256_;
    }

    bool enable_deflate(std::size_t ceiling)
    {
#if defined(MAILXX_HAS_ZLIB)
        if (deflate_on_)
            return true;
        auto* raw_inflate = new z_stream();
        if (inflateInit(raw_inflate) != Z_OK)
        {
            delete raw_inflate;
            return false;
        }
        auto inflate_stream = std::unique_ptr<z_stream, inflate_delete>(raw_inflate);
        auto* raw_deflate = new z_stream();
        if (deflateInit(raw_deflate, Z_DEFAULT_COMPRESSION) != Z_OK)
        {
            delete raw_deflate;
            return false;
        }
        auto deflate_stream = std::unique_ptr<z_stream, deflate_delete>(raw_deflate);
        inflate_ = std::move(inflate_stream);
        deflate_ = std::move(deflate_stream);
        deflate_ceiling_ = ceiling == 0 ? 1 : ceiling;
        compressed_chunk_.assign(4096, 0);
        inflated_pending_.clear();
        compressed_out_.clear();
        deflate_on_ = true;
        return true;
#else
        (void)ceiling;
        return false;
#endif
    }

    template<typename MutableBufferSequence, typename CompletionToken>
    auto async_read_some(const MutableBufferSequence& buffers, CompletionToken&& token)
    {
        return mailxx::asio::async_compose<CompletionToken, void(mailxx::asio::error_code, std::size_t)>(
            [this, buffers, started = false](auto& self, mailxx::asio::error_code ec = {}, std::size_t n = 0) mutable
            {
#if defined(MAILXX_HAS_ZLIB)
                if (deflate_on_)
                {
                    auto copy_pending = [&]() -> bool
                    {
                        if (inflated_pending_.empty())
                            return false;
                        const std::size_t copied = mailxx::asio::buffer_copy(
                            buffers, mailxx::asio::buffer(inflated_pending_.data(), inflated_pending_.size()));
                        inflated_pending_.erase(0, copied);
                        self.complete({}, copied);
                        return true;
                    };
                    if (!started)
                    {
                        started = true;
                        if (copy_pending())
                            return;
                    }
                    else
                    {
                        if (ec)
                        {
                            self.complete(ec, 0);
                            return;
                        }
                        if (n == 0)
                        {
                            if (!copy_pending())
                                self.complete(mailxx::asio::error::eof, 0);
                            return;
                        }
                        const auto inflate_ec = inflate_chunk(compressed_chunk_.data(), n);
                        if (inflate_ec)
                        {
                            mailxx::asio::error_code ignore;
                            lowest_layer().close(ignore);
                            self.complete(inflate_ec, 0);
                            return;
                        }
                        if (copy_pending())
                            return;
                    }
                    const auto compressed = mailxx::asio::buffer(compressed_chunk_);
                    if (auto* plain = std::get_if<tcp::socket>(&stream_))
                        plain->async_read_some(compressed, std::move(self));
                    else
                        std::get<ssl_stream>(stream_).async_read_some(compressed, std::move(self));
                    return;
                }
#endif
                if (!started)
                {
                    started = true;
                    if (auto* plain = std::get_if<tcp::socket>(&stream_))
                        plain->async_read_some(buffers, std::move(self));
                    else
                        std::get<ssl_stream>(stream_).async_read_some(buffers, std::move(self));
                    return;
                }
                self.complete(ec, n);
            },
            token, lowest_layer());
    }

    template<typename ConstBufferSequence, typename CompletionToken>
    auto async_write_some(const ConstBufferSequence& buffers, CompletionToken&& token)
    {
        return mailxx::asio::async_compose<CompletionToken, void(mailxx::asio::error_code, std::size_t)>(
            [this, buffers, started = false](auto& self, mailxx::asio::error_code ec = {}, std::size_t n = 0) mutable
            {
#if defined(MAILXX_HAS_ZLIB)
                if (deflate_on_)
                {
                    if (!started)
                    {
                        started = true;
                        const std::size_t plain_size = mailxx::asio::buffer_size(buffers);
                        if (plain_size == 0)
                        {
                            self.complete({}, 0);
                            return;
                        }
                        std::string plain(plain_size, '\0');
                        mailxx::asio::buffer_copy(mailxx::asio::buffer(plain), buffers);
                        deflate_plain_count_ = plain_size;
                        const auto deflate_ec = deflate_plain(plain.data(), plain.size());
                        if (deflate_ec)
                        {
                            self.complete(deflate_ec, 0);
                            return;
                        }
                        compressed_out_off_ = 0;
                        if (compressed_out_.empty())
                        {
                            self.complete({}, deflate_plain_count_);
                            return;
                        }
                    }
                    else
                    {
                        if (ec)
                        {
                            self.complete(ec, 0);
                            return;
                        }
                        compressed_out_off_ += n;
                        if (compressed_out_off_ >= compressed_out_.size())
                        {
                            self.complete({}, deflate_plain_count_);
                            return;
                        }
                    }
                    const auto remaining = mailxx::asio::buffer(
                        compressed_out_.data() + compressed_out_off_,
                        compressed_out_.size() - compressed_out_off_);
                    if (auto* plain = std::get_if<tcp::socket>(&stream_))
                        plain->async_write_some(remaining, std::move(self));
                    else
                        std::get<ssl_stream>(stream_).async_write_some(remaining, std::move(self));
                    return;
                }
#endif
                if (!started)
                {
                    started = true;
                    if (auto* plain = std::get_if<tcp::socket>(&stream_))
                        plain->async_write_some(buffers, std::move(self));
                    else
                        std::get<ssl_stream>(stream_).async_write_some(buffers, std::move(self));
                    return;
                }
                self.complete(ec, n);
            },
            token, lowest_layer());
    }

    awaitable<mailxx::result<void>> start_tls(ssl::context& context, std::string sni)
    {
        co_return co_await start_tls(context, std::move(sni), tls_options{});
    }

    awaitable<mailxx::result<void>> start_tls(ssl::context& context, std::string sni, const tls_options& opt)
    {
        if (is_tls())
            co_return mailxx::ok();

        peer_cert_sha256_ready_ = false;

        auto trust_res = configure_trust_store(context, opt);
        if (!trust_res)
            co_return mailxx::fail<void>(std::move(trust_res).error());
        auto harden_res = apply_tls_hardening(context, opt);
        if (!harden_res)
            co_return mailxx::fail<void>(std::move(harden_res).error());

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
                        co_return mailxx::fail<void>(errc::tls_verify_failed,
                            "TLS hostname verification requires a host name.");
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

        auto [ec] = co_await tls_stream.async_handshake(ssl::stream_base::client, use_nothrow_awaitable);
        if (ec)
        {
            co_return mailxx::fail<void>(errc::tls_handshake_failed,
                "TLS handshake failed.", ec.message(), ec);
        }

        auto pin_res = remember_peer_certificate(tls_stream, opt);
        if (!pin_res)
            co_return mailxx::fail<void>(std::move(pin_res).error());
        co_return mailxx::ok();
    }

private:
#if defined(MAILXX_HAS_ZLIB)
    struct inflate_delete
    {
        void operator()(z_stream* stream) const
        {
            if (stream != nullptr)
            {
                inflateEnd(stream);
                delete stream;
            }
        }
    };

    struct deflate_delete
    {
        void operator()(z_stream* stream) const
        {
            if (stream != nullptr)
            {
                deflateEnd(stream);
                delete stream;
            }
        }
    };

    mailxx::asio::error_code inflate_chunk(const unsigned char* data, std::size_t size)
    {
        if (inflate_ == nullptr || size == 0)
            return {};
        unsigned char out[2048];
        inflate_->next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data));
        inflate_->avail_in = static_cast<uInt>(size);
        while (inflate_->avail_in > 0)
        {
            inflate_->next_out = out;
            inflate_->avail_out = sizeof out;
            const int rc = inflate(inflate_.get(), Z_NO_FLUSH);
            const std::size_t produced = sizeof out - inflate_->avail_out;
            if (inflated_pending_.size() + produced > deflate_ceiling_)
                return mailxx::asio::error::message_size;
            inflated_pending_.append(reinterpret_cast<const char*>(out), produced);
            if (rc == Z_STREAM_END)
                break;
            if (rc == Z_BUF_ERROR && produced == 0)
                break;
            if (rc != Z_OK && rc != Z_BUF_ERROR)
                return mailxx::asio::error::invalid_argument;
        }
        while (true)
        {
            inflate_->next_out = out;
            inflate_->avail_out = sizeof out;
            const int rc = inflate(inflate_.get(), Z_SYNC_FLUSH);
            const std::size_t produced = sizeof out - inflate_->avail_out;
            if (produced == 0)
                break;
            if (inflated_pending_.size() + produced > deflate_ceiling_)
                return mailxx::asio::error::message_size;
            inflated_pending_.append(reinterpret_cast<const char*>(out), produced);
            if (rc == Z_STREAM_END)
                break;
            if (rc != Z_OK && rc != Z_BUF_ERROR)
                return mailxx::asio::error::invalid_argument;
        }
        return {};
    }

    mailxx::asio::error_code deflate_plain(const char* data, std::size_t size)
    {
        compressed_out_.clear();
        if (deflate_ == nullptr)
            return mailxx::asio::error::invalid_argument;
        unsigned char out[2048];
        std::size_t offset = 0;
        while (offset < size)
        {
            const std::size_t step = std::min<std::size_t>(size - offset, 16384);
            deflate_->next_in = const_cast<Bytef*>(reinterpret_cast<const Bytef*>(data + offset));
            deflate_->avail_in = static_cast<uInt>(step);
            const bool last = offset + step == size;
            const int flush = last ? Z_SYNC_FLUSH : Z_NO_FLUSH;
            offset += step;
            while (true)
            {
                deflate_->next_out = out;
                deflate_->avail_out = sizeof out;
                const int rc = deflate(deflate_.get(), flush);
                const std::size_t produced = sizeof out - deflate_->avail_out;
                compressed_out_.append(reinterpret_cast<const char*>(out), produced);
                if (rc != Z_OK && rc != Z_BUF_ERROR)
                    return mailxx::asio::error::invalid_argument;
                if (deflate_->avail_out == 0)
                    continue;
                if (deflate_->avail_in == 0)
                    break;
            }
        }
        return {};
    }
#endif
    static std::string openssl_error_message()
    {
        const unsigned long err = ERR_get_error();
        if (err == 0)
            return {};
        char buffer[256];
        ERR_error_string_n(err, buffer, sizeof(buffer));
        return std::string(buffer);
    }

    static result<void> apply_tls_hardening(ssl::context& context, const tls_options& opt)
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
                    return fail<void>(errc::tls_handshake_failed,
                        "TLS min version configuration failed.", openssl_error_message());
                }
            }
        }

        if (!opt.cipher_list.empty())
        {
            if (SSL_CTX_set_cipher_list(context.native_handle(),
                    opt.cipher_list.c_str()) != 1)
            {
                return fail<void>(errc::tls_handshake_failed,
                    "TLS cipher list configuration failed.", openssl_error_message());
            }
        }
        return ok();
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

    static result<std::vector<std::string>> normalize_pins(
        const std::vector<std::string>& pins, const char* label)
    {
        std::vector<std::string> out;
        out.reserve(pins.size());
        for (const auto& pin : pins)
        {
            std::string normalized = mailxx::net::normalize_fingerprint(pin);
            if (normalized.empty())
                continue;
            if (!valid_pin_length(normalized.size()))
                return fail<std::vector<std::string>>(errc::tls_pinning_failed,
                    std::string("TLS pinning failure: invalid ") + label + " pin.");
            out.push_back(std::move(normalized));
        }
        return ok(std::move(out));
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
            matched |= mailxx::net::constant_time_equals(pin, hex);
            matched |= mailxx::net::constant_time_equals(pin, base64);
        }
        return matched;
    }

    static bool sha256_cert_digest(X509* cert, unsigned char* digest)
    {
        const int len = i2d_X509(cert, nullptr);
        if (len <= 0)
            return false;
        std::vector<unsigned char> der(static_cast<std::size_t>(len));
        unsigned char* ptr = der.data();
        if (i2d_X509(cert, &ptr) != len)
            return false;
        return SHA256(der.data(), der.size(), digest) != nullptr;
    }

    result<void> remember_peer_certificate(ssl_stream& tls_stream, const tls_options& opt)
    {
        peer_cert_sha256_ready_ = false;
        auto cert_pins_res = normalize_pins(opt.pinned_cert_sha256, "cert");
        if (!cert_pins_res)
            return fail<void>(std::move(cert_pins_res).error());
        auto spki_pins_res = normalize_pins(opt.pinned_spki_sha256, "spki");
        if (!spki_pins_res)
            return fail<void>(std::move(spki_pins_res).error());
        const std::vector<std::string> cert_pins = std::move(*cert_pins_res);
        const std::vector<std::string> spki_pins = std::move(*spki_pins_res);

        std::unique_ptr<X509, decltype(&X509_free)> cert(
            SSL_get_peer_certificate(tls_stream.native_handle()), X509_free);
        if (!cert)
        {
            if (cert_pins.empty() && spki_pins.empty())
                return ok();
            return fail<void>(errc::tls_pinning_failed, "TLS pinning failure: no peer certificate.");
        }

        unsigned char digest[SHA256_DIGEST_LENGTH];
        if (!sha256_cert_digest(cert.get(), digest))
            return fail<void>(errc::tls_handshake_failed, "TLS peer certificate hash failed.");
        std::copy(digest, digest + SHA256_DIGEST_LENGTH, peer_cert_sha256_.begin());
        peer_cert_sha256_ready_ = true;

        if (cert_pins.empty() && spki_pins.empty())
            return ok();

        bool matched = false;
        if (!cert_pins.empty())
        {
            const std::string cert_hex = digest_to_hex(digest, SHA256_DIGEST_LENGTH);
            const std::string cert_base64 = digest_to_base64(digest, SHA256_DIGEST_LENGTH);
            matched |= match_pins(cert_pins, cert_hex, cert_base64);
        }
        if (!spki_pins.empty())
        {
            std::string spki_hex;
            std::string spki_base64;
            if (!sha256_spki(cert.get(), spki_hex, spki_base64))
                return fail<void>(errc::tls_pinning_failed, "TLS pinning failure: unable to hash SPKI.");
            matched |= match_pins(spki_pins, spki_hex, spki_base64);
        }

        if (!matched)
            return fail<void>(errc::tls_pinning_failed, "TLS pinning failure: certificate mismatch.");
        return ok();
    }

    std::variant<tcp::socket, ssl_stream> stream_;
    std::array<std::uint8_t, 32> peer_cert_sha256_{};
    bool peer_cert_sha256_ready_{false};
#if defined(MAILXX_HAS_ZLIB)
    std::unique_ptr<z_stream, inflate_delete> inflate_;
    std::unique_ptr<z_stream, deflate_delete> deflate_;
    std::string inflated_pending_;
    std::string compressed_out_;
    std::vector<unsigned char> compressed_chunk_;
    std::size_t compressed_out_off_ = 0;
    std::size_t deflate_plain_count_ = 0;
    std::size_t deflate_ceiling_ = 0;
    bool deflate_on_ = false;
#endif
};

} // namespace net
} // namespace mailxx
