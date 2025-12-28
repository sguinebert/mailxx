/*

Copyright (C) 2025, Sylvain Guinebert.

Distributed under the FreeBSD license, see the accompanying file LICENSE or
copy at http://www.freebsd.org/copyright/freebsd-license.html.

*/


#pragma once

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable:4251)
#endif

#include <string>
#include <string_view>
#include <array>
#include <charconv>
#include <system_error>
#include <vector>
#include <list>
#include <utility>
#include <stdexcept>
#include <memory>
#include <tuple>
#include <istream>
#include <chrono>
#include <ostream>
#include <sstream>
#include <algorithm>
#include <optional>
#include <format>
#include <cctype>


#include <mailxx/codec/q_codec.hpp>
#include <mailxx/mime/mime.hpp>
#include <mailxx/mime/mailboxes.hpp>
#include <mailxx/detail/ascii.hpp>
#include <mailxx/export.hpp>


namespace mailxx
{

/**
Options to customize the formatting of a message. Used by message::format().
**/
struct message_format_options_t
{
    /**
    Flag if the leading dot should be escaped.
    **/
    bool dot_escape = false;

    /**
    Flag whether bcc addresses should be added.
    **/
    bool add_bcc_header = false;
};


/**
Mail message and applied parsing/formatting algorithms.
**/
class MAILXX_EXPORT message : public mime
{
public:

    /**
    Character to separate mail addresses in a list.
    **/
    static const char ADDRESS_SEPARATOR = ',';

    /**
    Mail group name separator from the list of addresses.
    **/
    static const char MAILGROUP_NAME_SEPARATOR = ':';

    /**
    Separator of several mail groups.
    **/
    static const char MAILGROUP_SEPARATOR = ';';

    /**
    Calling parent destructor, initializing date and time to local time in utc time zone, other members set to default.
    **/
    message();

    /**
    Default copy constructor.
    **/
    message(const message&) = default;

    /**
    Default move constructor.

    @todo Default implementation is probably a bug, but not manifested yet.
    **/
    message(message&&) = default;

    /**
    Default destructor.
    **/
    ~message() = default;

    /**
    Default assignment operator.
    **/
    message& operator=(const message&) = default;

    /**
    Default move assignment operator.

    @todo Default implementation is probably a bug, but not manifested yet.
    **/
    message& operator=(message&&) = default;

    /**
    Formatting the message to a string.

    If a line contains leading dot, then it can be escaped as required by mail protocols.

    @param message_str Resulting message as string.
    @param opts        Options to customize formatting.
    @throw *           `format_header(format_options)`, `format_content(bool)`, `mime::format(string&, bool)`.
    **/
    void format(std::string& message_str, const message_format_options_t& opts = message_format_options_t{}) const;

    /**
    Overload of `format(string&, const message_format_options&)`.

    Because of the way the u8string is comverted to string, it's more expensive when used with C++20.
    **/
#if defined(__cpp_char8_t)
    void format(std::u8string& message_str,  const message_format_options_t& = message_format_options_t{}) const;
#endif

    /**
    Parsing a message from a string.

    Essentially, the method calls the same one from `mime` and checks for errors.

    @param message_str   String to parse.
    @param dot_escape    Flag if the leading dot should be escaped.
    @throw message_error No author address.
    @throw *             `mime::parse(const string&, bool)`.
    **/
    void parse(const std::string& message_str, bool dot_escape = false);

    /**
    Overload of `parse(const string&, bool)`.

    Because of the way the u8string is comverted to string, it's more expensive when used with C++20.
    **/
#if defined(__cpp_char8_t)
    void parse(const std::u8string& mime_string, bool dot_escape = false);
#endif

    /**
    Checking if the mail is empty.

    @return True if empty, false if not.
    **/
    bool empty() const;

    /**
    Setting the author to a given address.

    The given address is set as the only one, others are deleted.

    @param mail Mail address to set.
    **/
    void from(const mail_address& mail);

    /**
    Getting the author address.

    @return Author mail address.
    **/
    mailboxes from() const;

    /**
    Adding an addrress to the author field.

    @param mail Mail address to set.
    **/
    void add_from(const mail_address& mail);

    /**
    Formatting the author as string.

    @return  Author name and address as formatted string.
    @throw * `format_address(const string&, const string&)`.
    **/
    std::string from_to_string() const;

    /**
    Setting the sender to the given address.

    @param mail Mail address to set.
    **/
    void sender(const mail_address& mail);

    /**
    Getting the sender address.

    @return Sender mail address.
    **/
    mail_address sender() const;

    /**
    Formatting the sender as string.

    @return  Sender name and address as formatted string.
    @throw * `format_address(const string&, const string&)`.
    **/
    std::string sender_to_string() const;

    /**
    Setting the reply address.

    @param mail Reply mail address.
    **/
    void reply_address(const mail_address& mail);

    /**
    Getting the reply address.

    @return Reply mail address.
    **/
    mail_address reply_address() const;

    /**
    Formatting the reply name and address as string.

    @return  Reply name and address as string.
    @throw * `format_address(const string&, const string&)`.
    **/
    std::string reply_address_to_string() const;

    /**
    Adding a recipent name and address.

    @param mail Address to add.
    **/
    void add_recipient(const mail_address& mail);

    /**
    Adding a recipient group.

    @param group Group to add.
    **/
    void add_recipient(const mail_group& group);

    /**
    Getting the recipients.

    @return List of recipients.
    **/
    mailboxes recipients() const;

    /**
    Getting the recipients names and addresses as string.

    @return  Recipients names and addresses as string.
    @throw * `format_mailbox`.
    **/
    std::string recipients_to_string() const;

    /**
    Adding a CC recipent name and address.

    @param mail Mail address to set.
    **/
    void add_cc_recipient(const mail_address& mail);

    /**
    Adding a CC recipient group.

    @param group Group to add.
    **/
    void add_cc_recipient(const mail_group& group);

    /**
    Getting the CC recipients names and addresses.

    @return List of CC recipients.
    **/
    mailboxes cc_recipients() const;

    /**
    Getting the CC recipients names and addresses as string.

    @return  CC recipients names and addresses as string.
    @throw * `format_mailbox`.
    **/
    std::string cc_recipients_to_string() const;

    /**
    Adding a BCC recipent name and address.

    @param mail Mail address to set.
    **/
    void add_bcc_recipient(const mail_address& mail);

    /**
    Adding a BCC recipient group.

    @param group Group to add.
    **/
    void add_bcc_recipient(const mail_group& group);

    /**
    Getting the BCC recipients names and addresses.

    @return List of BCC recipients.
    **/
    mailboxes bcc_recipients() const;

    /**
    Getting the BCC recipients names and addresses as string.

    @return  BCC recipients names and addresses as string.
    @throw * `format_mailbox`.
    **/
    std::string bcc_recipients_to_string() const;

    /**
    Setting the disposition notification mail address.

    @param mail Mail address to set.
    **/
    void disposition_notification(const mail_address& mail);

    /**
    Getting the disposition notification mail address.

    @return Dispostion notification mail address.
    **/
    mail_address disposition_notification() const;

    /**
    Getting the disposition notification mail address as string.

    @return  Disposition notification mail address as string.
    @throw * `format_address(const string&, const string&)`.
    **/
    std::string disposition_notification_to_string() const;

    /**
    Setting the message ID.

    @param id            The message ID in the format `string1@string2`.
    @throw message_error Invalid message ID.
    **/
    void message_id(std::string id);

    /**
    Getting the message ID.

    @return Message ID.
    **/
    std::string message_id() const;

    /**
    Adding the in-reply-to ID.

    @param in-reply ID of the in-reply-to header.
    **/
    void add_in_reply_to(const std::string& in_reply);

    /**
    Getting the in-reply-to ID.

    @return List of in-reply-to IDs.
    **/
    std::vector<std::string> in_reply_to() const;

    /**
    Adding the reference ID to the list.

    @param reference_id Reference ID.
    **/
    void add_references(const std::string& reference_id);

    /**
    Getting the references list of IDs.

    @return List of references IDs.
    **/
    std::vector<std::string> references() const;

    /**
    Setting the subject.

    @param mail_subject Subject to set.
    @param sub_codec    Codec of the subject to use.
    */
    void subject(const std::string& mail_subject, codec::codec_t sub_codec = codec::codec_t::ASCII);

    /**
    Setting the raw subject.

    @param mail_subject Subject to set.
    */
    void subject_raw(const string_t& mail_subject);

#if defined(__cpp_char8_t)

    /**
    Setting the subject.

    @param mail_subject Subject to set.
    @param sub_codec    Codec of the subject to use.
    */
    void subject(const std::u8string& mail_subject, codec::codec_t sub_codec = codec::codec_t::ASCII);

    /**
    Setting the raw subject.

    @param mail_subject Subject to set.
    */
    void subject_raw(const u8string_t& mail_subject);
#endif

    /**
    Getting the subject.

    @return Subject value.
    **/
    std::string subject() const;

    /**
    Getting the raw subject.

    @return Subject value.
    **/
    string_t subject_raw() const;

    /**
    Getting the date, time and zone.

    @return Date, time and zone.
    **/
    std::chrono::zoned_time<std::chrono::seconds> date_time() const;

    /**
    Setting the date, time and zone.

    @param the_date_time Date, time and zone to set.
    **/
    void date_time(const std::chrono::zoned_time<std::chrono::seconds>& mail_dt);

    /**
    Attaching a list of streams.

    If the content is set, attaching a file moves the content to the first MIME part. Thus, the content and the attached files are MIME parts, as described in
    RFC 2046 section 5.1. The consequence is that the content remains empty afterwards.

    @param attachments Files to attach. Each tuple consists of a stream, attachment name and content type.
    @throw *           `mime::content_type(const content_type_t&)`, `mime::content_transfer_encoding(content_transfer_encoding_t)`,
                       `mime::content_disposition(content_disposition_t)`.
    **/
    void attach(const std::list<std::tuple<std::istream&, string_t, content_type_t>>& attachments);

    /**
    Getting the number of attachments.

    @return Number of attachments.
    **/
    std::size_t attachments_size() const;

    /**
    Getting the attachment at the given index.

    @param index         Index of the attachment.
    @param att_strm      Stream to write the attachment.
    @param att_name      Name of the attachment.
    @throw message_error Bad attachment index.
    @todo                The attachment name should be also `string_t`.
    **/
    void attachment(std::size_t index, std::ostream& att_strm, string_t& att_name) const;

    /**
    Adding another header.

    Adding a header defined by other methods leads to the undefined behaviour.

    @param name  Header name.
    @param value Header value.
    @todo        Disallowing standard headers defined elsewhere?
    **/
    void add_header(const std::string& name, const std::string& value);

    /**
    Removing another header.

    Removing a header defined by other methods leads to the undefined behaviour.

    @param name Header to remove.
    **/
    void remove_header(const std::string& name);

    /**
    Returning the other headers.

    @return Message headers.
    **/
    const headers_t& headers() const;

protected:

    /**
    Printable ASCII characters without the alphanumerics, double quote, comma, colon, semicolon, angle and square brackets and monkey.
    **/
    static const std::string ATEXT;

    /**
    Printable ASCII characters without the alphanumerics, brackets and backslash.
    **/
    static const std::string DTEXT;

    /**
    `From` header name.
    **/
    static const std::string FROM_HEADER;

    /**
    `Sender` header name.
    **/
    static const std::string SENDER_HEADER;

    /**
    `Reply-To` header name.
    **/
    static const std::string REPLY_TO_HEADER;

    /**
    `To` header name.
    **/
    static const std::string TO_HEADER;

    /**
    `Cc` header name.
    **/
    static const std::string CC_HEADER;

    /**
    `Bcc` header name.
    **/
    static const std::string BCC_HEADER;

    /**
    `Message-ID` header name.
    **/
    static const std::string MESSAGE_ID_HEADER;

    /**
    `In-Reply-To` header name.
    **/
    static const std::string IN_REPLY_TO_HEADER;

    /**
    `References` header name.
    **/
    static const std::string REFERENCES_HEADER;

    /**
    Subject header name.
    **/
    static const std::string SUBJECT_HEADER;

    /**
    Date header name.
    **/
    static const std::string DATE_HEADER;

    /**
    Disposition notification header name.
    **/
    static const std::string DISPOSITION_NOTIFICATION_HEADER;

    /**
    Mime version header name.
    **/
    static const std::string MIME_VERSION_HEADER;

    /**
    Formatting the header to a string.

    @return              Header as string.
    @throw message_error No boundary for multipart message.
    @throw message_error No author.
    @throw message_error No sender for multiple authors.
    @throw *             `mime::format_header()`.
    **/
    virtual std::string format_header(bool add_bcc_header) const;

    /**
    Parsing a header line for a specific header.

    @param header_line   Header line to be parsed.
    @throw message_error Line policy overflow in a header.
    @throw message_error Empty author header.
    @throw *             `mime::parse_header_line(const string&)`, `mime::parse_header_name_value(const string&, string&, string&)`,
                         `parse_address_list(const string&)`, `parse_subject(const string&)`, `parse_date(const string&)`.
    **/
    virtual void parse_header_line(const std::string& header_line);

    /**
    Formatting a list of addresses to string.

    Multiple addresses are put into separate lines.

    @param mailbox_list  Mailbox to format.
    @return              Mailbox as string.
    @throw message_error Formatting failure of address list, bad group name.
    @throw *             `format_address(const string&, const string&)`.
    **/
    std::string format_address_list(const mailboxes& mailbox_list, const std::string& header_name = "") const;

    /**
    Formatting a name and an address.

    If the name is in ASCII or the header codec set to UTF8, then it is written in raw format. Otherwise, the encoding is performed. The header folding is
    performed if necessary.

    @param name          Mail name.
    @param address       Mail address.
    @param header_name   Header name of the address header.
    @return              The mail name and address formatted.
    @throw message_error Formatting failure of name.
    @throw message_error Formatting failure of address.
    **/
    std::string format_address(const string_t& name, const std::string& address, const std::string& header_name) const;

    /**
    Formatting the subject which can be ASCII or UTF-8.

    @return Formatted subject.
    **/
    std::string format_subject() const;

    /**
    Formatting email date.

    @return Date for the email format.
    **/
    std::string format_date() const;

    /**
    Formatting email date header.

    @return Date header for the email format.
    **/
    std::string format_date_header() const;

    /**
    Parsing a string into vector of names and addresses.

    @param address_list  String to parse.
    @return              Vector of names and addresses.
    @throw message_error Parsing failure of address or group at.
    @throw message_error Parsing failure of group at.
    @throw message_error Parsing failure of name or address at.
    @throw message_error Parsing failure of address at.
    @throw message_error Parsing failure of name at.
    @throw message_error Parsing failure of comment at.
    **/
    mailboxes parse_address_list(const std::string& address_list);

    /**
    Parsing a string into date and time.

    @param date_str      Date string to parse.
    @return              Date and time translated to local time zone.
    @throw message_error Parsing failure of date.
    **/
    std::chrono::zoned_time<std::chrono::seconds> parse_date(const std::string& date_str) const;

    /**
    Splitting string with Q encoded fragments into separate strings.

    @param text  String with Q encoded fragments.
    @return      Q encoded fragments as separate strings.
    **/
    static std::vector<std::string> split_qc_string(const std::string& text);

    /**
    Parsing a subject which can be ASCII or UTF-8.

    The result is string either ASCII or UTF-8 encoded. If another encoding is used like ISO-8859-X, then the result is undefined.

    @param subject       Subject to parse.
    @return              Parsed subject and charset.
    @throw message_error Parsing failure of Q encoding.
    @throw *             `q_codec::decode(const string&)`.
    **/
    std::tuple<std::string, std::string, codec::codec_t>
    parse_subject(const std::string& subject);

    /**
    Parsing a name part of a mail ASCII or UTF-8 encoded.

    The result is string ASCII or UTF-8 encoded. If another encoding is used, then it should be decoded by the method caller.

    @param address_name  Name part of mail.
    @return              Parsed name part of the address.
    @throw message_error Inconsistent Q encodings.
    @todo                Not tested with charsets different than ASCII and UTF-8.
    @todo                Throwing errors when Q codec is invalid?
    **/
    string_t parse_address_name(const std::string& address_name);

    /**
    From name and address.
    **/
    mailboxes from_;

    /**
    Sender name and address.
    **/
    mail_address sender_;

    /**
    Reply address.
    **/
    mail_address reply_address_;

    /**
    List of recipients.
    **/
    mailboxes recipients_;

    /**
    List of CC recipients.
    **/
    mailboxes cc_recipients_;

    /**
    List of BCC recipients.
    **/
    mailboxes bcc_recipients_;

    /**
    Disposition notification address.
    **/
    mail_address disposition_notification_;

    /**
    Message ID.
    **/
    std::string message_id_;

    /**
    In reply to list of IDs.
    **/
    std::vector<std::string> in_reply_to_;

    /**
    References list of IDs.
    **/
    std::vector<std::string> references_;

    /**
    Message subject.
    **/
    string_t subject_;

    /**
    Message date and time with time zone.
    **/
    std::chrono::zoned_time<std::chrono::seconds> date_time_;

    /**
    Other headers not included into the known ones.
    **/
    headers_t headers_;
};

[[deprecated]]
typedef mime_error message_error;


// ------------------------------------------------------------
// Header-only implementation (C++23)
// ------------------------------------------------------------
inline const std::string message::ATEXT{"!#$%&'*+-./=?^_`{|}~"};
inline const std::string message::DTEXT{"!#$%&'*+-.@/=?^_`{|}~"}; // atext with monkey
inline const std::string message::FROM_HEADER{"From"};
inline const std::string message::SENDER_HEADER{"Sender"};
inline const std::string message::REPLY_TO_HEADER{"Reply-To"};
inline const std::string message::TO_HEADER{"To"};
inline const std::string message::CC_HEADER{"Cc"};
inline const std::string message::BCC_HEADER{"Bcc"};
inline const std::string message::MESSAGE_ID_HEADER{"Message-ID"};
inline const std::string message::IN_REPLY_TO_HEADER{"In-Reply-To"};
inline const std::string message::REFERENCES_HEADER{"References"};
inline const std::string message::SUBJECT_HEADER{"Subject"};
inline const std::string message::DATE_HEADER{"Date"};
inline const std::string message::DISPOSITION_NOTIFICATION_HEADER{"Disposition-Notification-To"};
inline const std::string message::MIME_VERSION_HEADER{"MIME-Version"};


inline message::message() : mime(), date_time_(std::chrono::current_zone(), 
    std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()))
{
}


void inline message::format(std::string& message_str, const message_format_options_t& opts) const
{
    message_str += format_header(opts.add_bcc_header);

    if (!parts_.empty())
    {
        if (!content_.empty())
        {
            mime content_part;
            content_part.content(content_);
            content_type_t ct(media_type_t::TEXT, "plain", content_type_.charset());
            content_part.content_type(ct);
            content_part.content_transfer_encoding(encoding_);
            content_part.line_policy(line_policy_);
            content_part.strict_mode(strict_mode_);
            content_part.strict_codec_mode(strict_codec_mode_);
            std::string cps;
            content_part.format(cps, opts.dot_escape);
            message_str += BOUNDARY_DELIMITER + content_type_.boundary() + codec::END_OF_LINE + cps + codec::END_OF_LINE;
        }

        // Recursively format mime parts.

        for (const auto& p: parts_)
        {
            std::string p_str;
            p.format(p_str, opts.dot_escape);
            message_str += BOUNDARY_DELIMITER + content_type_.boundary() + codec::END_OF_LINE + p_str + codec::END_OF_LINE;
        }
        message_str += BOUNDARY_DELIMITER + content_type_.boundary() + BOUNDARY_DELIMITER + codec::END_OF_LINE;
    }
    else
        message_str += format_content(opts.dot_escape);
}


#if defined(__cpp_char8_t)
void inline message::format(std::u8string& message_str, const message_format_options_t& opts) const
{
    // Convert existing buffer (if any) to std::string, append formatted message, then convert back.
    std::string tmp;
    tmp.reserve(message_str.size());
    for (char8_t c : message_str)
        tmp.push_back(static_cast<char>(c));

    format(tmp, opts);

    message_str.clear();
    message_str.reserve(tmp.size());
    for (unsigned char c : tmp)
        message_str.push_back(static_cast<char8_t>(c));
}
#endif



void inline message::parse(const std::string& message_str, bool dot_escape)
{
    mime::parse(message_str, dot_escape);

    if (from_.addresses.size() == 0)
        throw message_error("No author address.", "");

    // There is no check if there is a sender in case of multiple authors, not sure if that logic is needed.
}


#if defined(__cpp_char8_t)
void inline message::parse(const std::u8string& message_str, bool dot_escape)
{
    std::string tmp;
    tmp.reserve(message_str.size());
    for (char8_t c : message_str)
        tmp.push_back(static_cast<char>(c));

    parse(tmp, dot_escape);
}
#endif



bool inline message::empty() const
{
    return content_.empty();
}


void inline message::from(const mail_address& mail)
{
    from_.clear();
    from_.addresses.push_back(mail);
}


mailboxes inline message::from() const
{
    return from_;
}


void inline message::add_from(const mail_address& mail)
{
    from_.addresses.push_back(mail);
}


std::string inline message::from_to_string() const
{
    return format_address_list(from_, FROM_HEADER);
}


void inline message::sender(const mail_address& mail)
{
    sender_ = mail;
}


mail_address inline message::sender() const
{
    return sender_;
}


std::string inline message::sender_to_string() const
{
    return format_address(sender_.name, sender_.address, SENDER_HEADER + HEADER_SEPARATOR_STR);
}

void inline message::reply_address(const mail_address& mail)
{
    reply_address_ = mail;
}


mail_address inline message::reply_address() const
{
    return reply_address_;
}


std::string inline message::reply_address_to_string() const
{
    return format_address(reply_address_.name, reply_address_.address, REPLY_TO_HEADER + HEADER_SEPARATOR_STR);
}


void inline message::add_recipient(const mail_address& mail)
{
    recipients_.addresses.push_back(mail);
}


void inline message::add_recipient(const mail_group& group)
{
    recipients_.groups.push_back(group);
}


mailboxes inline message::recipients() const
{
    return recipients_;
}


std::string inline message::recipients_to_string() const
{
    return format_address_list(recipients_, TO_HEADER);
}


void inline message::add_cc_recipient(const mail_address& mail)
{
    cc_recipients_.addresses.push_back(mail);
}


void inline message::add_cc_recipient(const mail_group& group)
{
    cc_recipients_.groups.push_back(group);
}


mailboxes inline message::cc_recipients() const
{
    return cc_recipients_;
}


std::string inline message::cc_recipients_to_string() const
{
    return format_address_list(cc_recipients_, CC_HEADER);
}


void inline message::add_bcc_recipient(const mail_address& mail)
{
    bcc_recipients_.addresses.push_back(mail);
}


void inline message::add_bcc_recipient(const mail_group& group)
{
    bcc_recipients_.groups.push_back(group);
}


mailboxes inline message::bcc_recipients() const
{
    return bcc_recipients_;
}


std::string inline message::bcc_recipients_to_string() const
{
    return format_address_list(bcc_recipients_, BCC_HEADER);
}


void inline message::disposition_notification(const mail_address& address)
{
    disposition_notification_ = address;
}


mail_address inline message::disposition_notification() const
{
    return disposition_notification_;
}


std::string inline message::disposition_notification_to_string() const
{
    return format_address(disposition_notification_.name, disposition_notification_.address, DISPOSITION_NOTIFICATION_HEADER + HEADER_SEPARATOR_STR);
}


void inline message::message_id(std::string id)
{
    // Normalize: trim and optionally strip surrounding angle brackets.
    detail::trim_inplace(id);
    if (id.size() >= 2 && id.front() == '<' && id.back() == '>')
    {
        id.erase(id.begin());
        id.pop_back();
        detail::trim_inplace(id);
    }

    const bool ok = strict_mode_ ? detail::is_valid_message_id_strict(id) : detail::is_valid_message_id_relaxed(id);
    if (!ok)
        throw message_error("Invalid message ID.", "ID is `" + id + "`.");

    message_id_ = std::move(id);
}
std::string inline message::message_id() const
{
    return message_id_;
}


void inline message::add_in_reply_to(const std::string& in_reply)
{
    std::string id = in_reply;
    detail::trim_inplace(id);
    if (id.size() >= 2 && id.front() == '<' && id.back() == '>')
    {
        id.erase(id.begin());
        id.pop_back();
        detail::trim_inplace(id);
    }

    if (!detail::is_valid_message_id_strict(id))
        throw message_error("Invalid In Reply To ID.", "In reply to `" + id + "`.");

    in_reply_to_.push_back(std::move(id));
}
std::vector<std::string> inline message::in_reply_to() const
{
    return in_reply_to_;
}


void inline message::add_references(const std::string& reference_id)
{
    std::string id = reference_id;
    detail::trim_inplace(id);
    if (id.size() >= 2 && id.front() == '<' && id.back() == '>')
    {
        id.erase(id.begin());
        id.pop_back();
        detail::trim_inplace(id);
    }

    if (!detail::is_valid_message_id_strict(id))
        throw message_error("Invalid Reference ID.", "Reference ID is `" + id + "`.");

    references_.push_back(std::move(id));
}
std::vector<std::string> inline message::references() const
{
    return references_;
}


void inline message::subject(const std::string& mail_subject, codec::codec_t sub_codec)
{
    subject_.buffer = mail_subject;
    subject_.charset = codec::CHARSET_ASCII;
    if (codec::is_utf8_string(subject_.buffer))
        subject_.charset = codec::CHARSET_UTF8;
    subject_.codec_type = sub_codec;
}


void inline message::subject_raw(const string_t& mail_subject)
{
    subject_ = mail_subject;
}


#if defined(__cpp_char8_t)

void inline message::subject(const std::u8string& mail_subject, codec::codec_t sub_codec)
{
    subject_.buffer = std::string(reinterpret_cast<const char*>(mail_subject.c_str()));
    subject_.charset = codec::CHARSET_UTF8;
    subject_.codec_type = sub_codec;
}


void inline message::subject_raw(const u8string_t& mail_subject)
{
    subject_.buffer = std::string(reinterpret_cast<const char*>(mail_subject.buffer.c_str()));
    subject_.charset = mail_subject.charset;
    subject_.codec_type = mail_subject.codec_type;
}

#endif


std::string inline message::subject() const
{
    return subject_.buffer;
}

string_t inline message::subject_raw() const
{
    return subject_;
}


std::chrono::zoned_time<std::chrono::seconds> inline message::date_time() const
{
    return date_time_;
}


void inline message::date_time(const std::chrono::zoned_time<std::chrono::seconds>& mail_dt)
{
    date_time_ = mail_dt;
}


void inline message::attach(const std::list<std::tuple<std::istream&, string_t, content_type_t>>& attachments)
{
    std::string bound;
    if (content_type_.boundary().empty())
    {
        bound = content_type_.make_boundary();
        content_type_.boundary(bound);
    }
    else
        bound = content_type_.boundary();

    // the content goes to the first mime part, and then it's deleted
    if (!content_.empty())
    {
        if (content_type_.media_type() == media_type_t::NONE)
            content_type_ = content_type_t(media_type_t::TEXT, "plain");

        mime content_part;
        content_part.content(content_);
        auto part_ct = content_type_t(content_type_.media_type(), content_type_.media_subtype(), content_type_.charset());
        content_part.content_type(part_ct);
        content_part.content_transfer_encoding(encoding_);
        content_part.line_policy(line_policy_);
        content_part.strict_mode(strict_mode_);
        content_part.strict_codec_mode(strict_codec_mode_);
        parts_.push_back(content_part);
        content_.clear();
    }

    content_type_ = content_type_t(media_type_t::MULTIPART, "mixed");
    content_type_.boundary(bound);
    for (const auto& att : attachments)
    {
        std::stringstream ss;
        ss << std::get<0>(att).rdbuf();

        mime m;
        m.line_policy(line_policy_);
        m.content_type(content_type_t(std::get<2>(att)));
        // content type charset is not set, so it will be treated as us-ascii
        m.content_transfer_encoding(content_transfer_encoding_t::BASE_64);
        m.content_disposition(content_disposition_t::ATTACHMENT);
        m.name(std::get<1>(att));
        m.content(ss.str());
        parts_.push_back(m);
    }
}


std::size_t inline message::attachments_size() const
{
    return std::count_if(parts_.begin(), parts_.end(), [](const mime& part) {
        return part.content_disposition() == content_disposition_t::ATTACHMENT;
    });
}


void inline message::attachment(std::size_t index, std::ostream& att_strm, string_t& att_name) const
{
    if (index == 0)
        throw message_error("Bad attachment index.", "");

    std::size_t no = 0;
    for (const auto& part : parts_)
    {
        if (part.content_disposition() != content_disposition_t::ATTACHMENT)
            continue;

        if (++no == index)
        {
            const auto& content = part.content();
            att_strm.write(content.data(), static_cast<std::streamsize>(content.size()));
            att_name = part.name();
            return;
        }
    }

    throw message_error("Bad attachment index.",
        "Given index is " + std::to_string(index) + ", number of attachments is " + std::to_string(no) + ".");
}
void inline message::add_header(const std::string& name, const std::string& value)
{
    if (!detail::is_valid_header_name(name))
        throw message_error("Header name format error.", "Name is `" + name + "`.");
    if (!detail::is_valid_header_value(value))
        throw message_error("Header value Format error.", "Value is `" + value + "`.");
    headers_.insert(std::make_pair(name, value));
}


void inline message::remove_header(const std::string& name)
{
    headers_.erase(name);
}


const message::headers_t& inline message::headers() const
{
    return headers_;
}


std::string inline message::format_header(bool add_bcc_header) const
{
    if (!content_type_.boundary().empty() && content_type_.media_type() != media_type_t::MULTIPART)
        throw message_error("No boundary for multipart message.", "");

    if (from_.addresses.size() == 0)
        throw message_error("No author.", "");

    if (from_.addresses.size() > 1 && sender_.empty())
        throw message_error("No sender for multiple authors.", "");

    std::string header;
    std::for_each(headers_.begin(), headers_.end(),
        [&header, this](const auto& hdr)
        {
            std::string::size_type l1p = static_cast<std::string::size_type>(line_policy_) - hdr.first.length() - HEADER_SEPARATOR_STR.length();
            bit7 b7(l1p, static_cast<std::string::size_type>(line_policy_));
            std::vector<std::string> hdr_enc = b7.encode(hdr.second);
            header += hdr.first + HEADER_SEPARATOR_STR + hdr_enc.at(0) + codec::END_OF_LINE;
            header += fold_header_line(hdr_enc);
        }
    );

    header += FROM_HEADER + HEADER_SEPARATOR_STR + from_to_string() + codec::END_OF_LINE;
    header += sender_.address.empty() ? "" : SENDER_HEADER + HEADER_SEPARATOR_STR + sender_to_string() + codec::END_OF_LINE;
    header += reply_address_.name.buffer.empty() ? "" : REPLY_TO_HEADER + HEADER_SEPARATOR_STR + reply_address_to_string() + codec::END_OF_LINE;
    header += TO_HEADER + HEADER_SEPARATOR_STR + recipients_to_string() + codec::END_OF_LINE;
    header += cc_recipients_.empty() ? "" : CC_HEADER + HEADER_SEPARATOR_STR + cc_recipients_to_string() + codec::END_OF_LINE;
    if(add_bcc_header)
        header += bcc_recipients_.empty() ? "" : BCC_HEADER + HEADER_SEPARATOR_STR + bcc_recipients_to_string() + codec::END_OF_LINE;
    header += disposition_notification_.empty() ? "" : DISPOSITION_NOTIFICATION_HEADER + HEADER_SEPARATOR_STR +
        format_address(disposition_notification_.name, disposition_notification_.address, DISPOSITION_NOTIFICATION_HEADER + HEADER_SEPARATOR_STR) +
        codec::END_OF_LINE;

    header += message_id_.empty() ? "" : MESSAGE_ID_HEADER + HEADER_SEPARATOR_STR + format_many_ids(message_id_, MESSAGE_ID_HEADER);
    header += in_reply_to_.size() == 0 ? "" : IN_REPLY_TO_HEADER + HEADER_SEPARATOR_STR + format_many_ids(in_reply_to_, IN_REPLY_TO_HEADER);
    header += references_.empty() ? "" : REFERENCES_HEADER + HEADER_SEPARATOR_STR + format_many_ids(references_, REFERENCES_HEADER);

    header += format_date_header();

    if (!parts_.empty())
        header += MIME_VERSION_HEADER + HEADER_SEPARATOR_STR + version_ + codec::END_OF_LINE;
    header += mime::format_header();

    if (!subject_.buffer.empty())
        header += SUBJECT_HEADER + HEADER_SEPARATOR_STR + format_subject() + codec::END_OF_LINE;

    return header;
}
void inline message::parse_header_line(const std::string& header_line)
{
    std::string header_name, header_value;
    parse_header_name_value(header_line, header_name, header_value);

    if (detail::iequals_ascii(header_name, CONTENT_TYPE_HEADER))
    {
        media_type_t media_type;
        std::string media_subtype;
        attributes_t attributes;
        parse_content_type(header_value, media_type, media_subtype, attributes);
        merge_attributes(attributes);

        std::string media_subtype_lower = boost::to_lower_copy(media_subtype);
        content_type_ = content_type_t(media_type, media_subtype_lower, attributes);
        auto bound_it = attributes.find(content_type_t::ATTR_BOUNDARY);
        if (bound_it != attributes.end())
            content_type_.add_attribute(content_type_t::ATTR_BOUNDARY, bound_it->second.buffer);
        auto charset_it = attributes.find(content_type_t::ATTR_CHARSET);
        if (charset_it != attributes.end())
            content_type_ = content_type_t(media_type, media_subtype_lower, attributes, boost::to_lower_copy(charset_it->second.buffer));
        auto name_it = attributes.find(ATTRIBUTE_NAME);
        if (name_it != attributes.end() && name_.buffer.empty())
            name_ = name_it->second;
    }
    else if (detail::iequals_ascii(header_name, CONTENT_TRANSFER_ENCODING_HEADER))
    {
        attributes_t attributes;
        parse_content_transfer_encoding(header_value, encoding_, attributes);
    }
    else if (detail::iequals_ascii(header_name, CONTENT_DISPOSITION_HEADER))
    {
        attributes_t attributes;
        parse_content_disposition(header_value, disposition_, attributes);
        merge_attributes(attributes);

        auto filename_it = attributes.find(ATTRIBUTE_FILENAME);
        if (filename_it != attributes.end())
            name_ = filename_it->second;
    }
    else if (detail::iequals_ascii(header_name, CONTENT_ID_HEADER))
    {
        auto ids = parse_many_ids(header_value);
        if (!ids.empty())
            content_id_ = ids[0];
    }

    if (detail::iequals_ascii(header_name, FROM_HEADER))
    {
        from_ = parse_address_list(header_value);
        if (from_.addresses.empty())
            throw message_error("Empty author header.", "");
    }
    else if (detail::iequals_ascii(header_name, SENDER_HEADER))
    {
        if (header_value.empty() && !strict_mode_)
            sender_.clear();
        else
        {
            mailboxes mbx = parse_address_list(header_value);
            if (!mbx.addresses.empty())
                sender_ = mbx.addresses[0];
        }
    }
    else if (detail::iequals_ascii(header_name, REPLY_TO_HEADER))
    {
        mailboxes mbx = parse_address_list(header_value);
        if (!mbx.addresses.empty())
            reply_address_ = mbx.addresses[0];
    }
    else if (detail::iequals_ascii(header_name, TO_HEADER))
    {
        recipients_ = parse_address_list(header_value);
    }
    else if (detail::iequals_ascii(header_name, CC_HEADER))
    {
        cc_recipients_ = parse_address_list(header_value);
    }
    else if (detail::iequals_ascii(header_name, DISPOSITION_NOTIFICATION_HEADER))
    {
        mailboxes mbx = parse_address_list(header_value);
        if (!mbx.addresses.empty())
            disposition_notification_ = mbx.addresses[0];
    }
    else if (detail::iequals_ascii(header_name, MESSAGE_ID_HEADER))
    {
        if (header_value.empty() && !strict_mode_)
            message_id_.clear();
        else
        {
            auto ids = parse_many_ids(header_value);
            if (!ids.empty())
                message_id_ = ids[0];
        }
    }
    else if (detail::iequals_ascii(header_name, IN_REPLY_TO_HEADER))
        in_reply_to_ = parse_many_ids(header_value);
    else if (detail::iequals_ascii(header_name, REFERENCES_HEADER))
        references_ = parse_many_ids(header_value);
    else if (detail::iequals_ascii(header_name, SUBJECT_HEADER))
    {
        if (header_value.empty() && !strict_mode_)
            subject_ = string_t();
        else
            std::tie(subject_.buffer, subject_.charset, subject_.codec_type) = parse_subject(header_value);
    }
    else if (detail::iequals_ascii(header_name, DATE_HEADER))
    {
        if (header_value.empty() && !strict_mode_)
        {
            date_time_ = std::chrono::zoned_time<std::chrono::seconds>(std::chrono::current_zone(),
                std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
        }
        else
        {
            date_time_ = parse_date(detail::trim_copy(header_value));
        }
    }
    else if (detail::iequals_ascii(header_name, MIME_VERSION_HEADER))
    {
        if (header_value.empty() && !strict_mode_)
            version_ = "1.0";
        else
            version_ = detail::trim_copy(header_value);
    }
    else
    {
        if (!detail::iequals_ascii(header_name, CONTENT_TYPE_HEADER) && !detail::iequals_ascii(header_name, CONTENT_TRANSFER_ENCODING_HEADER) &&
            !detail::iequals_ascii(header_name, CONTENT_DISPOSITION_HEADER))
        {
            headers_.insert(std::make_pair(header_name, header_value));
        }
    }
}


std::string inline message::format_address_list(const mailboxes& mailbox_list, const std::string& header_name) const
{
    std::string mailbox_str;

    for (auto ma = mailbox_list.addresses.begin(); ma != mailbox_list.addresses.end(); ma++)
    {
        if (mailbox_list.addresses.size() > 1 && ma != mailbox_list.addresses.begin())
            mailbox_str += NEW_LINE_INDENT + format_address(ma->name, ma->address, header_name);
        else
            mailbox_str += format_address(ma->name, ma->address, header_name);

        if (ma != mailbox_list.addresses.end() - 1)
            mailbox_str += ADDRESS_SEPARATOR + codec::END_OF_LINE;
    }

    if (!mailbox_list.groups.empty() && !mailbox_list.addresses.empty())
        mailbox_str += ADDRESS_SEPARATOR + codec::END_OF_LINE + NEW_LINE_INDENT;

    for (auto mg = mailbox_list.groups.begin(); mg != mailbox_list.groups.end(); mg++)
    {
        if (!detail::is_group_name(mg->name))
            throw message_error("Address std::list format error.", "Invalid group name `" + mg->name + "`.");

        mailbox_str += mg->name + MAILGROUP_NAME_SEPARATOR + codec::SPACE_CHAR;
        for (auto ma = mg->members.begin(); ma != mg->members.end(); ma++)
        {
            if (mg->members.size() > 1 && ma != mg->members.begin())
                mailbox_str += NEW_LINE_INDENT + format_address(ma->name, ma->address, header_name);
            else
                mailbox_str += format_address(ma->name, ma->address, header_name);

            if (ma != mg->members.end() - 1)
                mailbox_str += ADDRESS_SEPARATOR + codec::END_OF_LINE;
        }
        mailbox_str += mg != mailbox_list.groups.end() - 1 ? std::string(1, MAILGROUP_SEPARATOR) + codec::END_OF_LINE + NEW_LINE_INDENT : std::string(1, MAILGROUP_SEPARATOR);
    }

    return mailbox_str;
}


std::string inline message::format_address(const string_t& name, const std::string& address, const std::string& header_name) const
{
    if (name.buffer.empty() && address.empty())
        return "";

    const std::string::size_type HEADER_LEN = header_name.length() + HEADER_SEPARATOR_STR.length();
    const std::string::size_type line_policy = static_cast<std::string::size_type>(line_policy_);

    std::vector<std::string> name_formatted;

    // The charset has precedence over the header codec. Only for the non-ascii characters, consider the header encoding.

    if (name.codec_type == codec::codec_t::ASCII)
    {
        // Check the name format.

        const bool has_only_tokens = std::all_of(name.buffer.begin(), name.buffer.end(),
            [](char c) noexcept { return detail::is_name_token_char(c); });

        if (has_only_tokens)
        {
            bit7 b7(line_policy - HEADER_LEN, line_policy);
            name_formatted = b7.encode(name.buffer);
        }
        else
        {
            const bool has_only_qtext = std::all_of(name.buffer.begin(), name.buffer.end(),
                [](char c) noexcept { return detail::is_qtext_char(c); });

            if (has_only_qtext)
            {
                bit7 b7(line_policy - HEADER_LEN + 2, line_policy);
                name_formatted = b7.encode(codec::QUOTE_CHAR + name.buffer + codec::QUOTE_CHAR);
            }
            else
            {
                throw message_error("Name format error.", "Invalid name is `" + name.buffer + "`.");
            }
        }
    }
    else if (name.codec_type == codec::codec_t::UTF8)
    {
        bit8 b8(line_policy - HEADER_LEN, line_policy);
        name_formatted = b8.encode(name.buffer);
    }
    else if (name.codec_type == codec::codec_t::BASE64 || name.codec_type == codec::codec_t::QUOTED_PRINTABLE)
    {
        q_codec qc(line_policy - HEADER_LEN, static_cast<std::string::size_type>(line_policy_));
        name_formatted = qc.encode(name.buffer, name.charset, name.codec_type);
    }
    else if (name.codec_type == codec::codec_t::PERCENT)
        throw message_error("Percent codec not allowed for the mail address.", "");

    // Check address format.

    std::string addr;
    if (!address.empty())
    {
        if (codec::is_utf8_string(address))
        {
            addr = ADDRESS_BEGIN_CHAR + address + ADDRESS_END_CHAR;
        }
        else
        {
            const bool has_only_dtext = std::all_of(address.begin(), address.end(),
                [](char c) noexcept { return detail::is_dtext_char(c); });

            if (has_only_dtext)
                addr = ADDRESS_BEGIN_CHAR + address + ADDRESS_END_CHAR;
            else
                throw message_error("Address format error.", "Invalid address is `" + address + "`.");
        }
    }

    std::string::size_type last_line_len = (name_formatted.empty() ? 0 : name_formatted.back().length());
    std::string name_addr;
    for (auto sit = name_formatted.begin(); sit != name_formatted.end(); sit++)
        name_addr += (sit == name_formatted.begin() ? "" : codec::SPACE_STR + codec::SPACE_STR) +
            *sit + (sit == name_formatted.end() - 1 ? "" : codec::END_OF_LINE);

    if (!addr.empty())
    {
        if (last_line_len + addr.length() < line_policy)
            name_addr += (name_formatted.empty() ? "" : codec::SPACE_STR) + addr;
        else
            name_addr += codec::END_OF_LINE + codec::SPACE_STR + codec::SPACE_STR + addr;
    }

    return name_addr;
}
std::string inline message::format_subject() const
{
    std::string subject;
    const std::string::size_type line1_policy = static_cast<std::string::size_type>(line_policy_) - SUBJECT_HEADER.length() - HEADER_SEPARATOR_STR.length();
    const std::string::size_type line_policy = static_cast<std::string::size_type>(line_policy_) - HEADER_SEPARATOR_STR.length();

    if (subject_.codec_type == codec::codec_t::ASCII)
    {
        bit7 b7(line1_policy, line_policy);
        std::vector<std::string> hdr = b7.encode(subject_.buffer);
        subject += hdr.at(0) + codec::END_OF_LINE;
        subject += fold_header_line(hdr);
    }
    else if (subject_.codec_type == codec::codec_t::UTF8)
    {
        bit8 b8(line1_policy, line_policy);
        std::vector<std::string> hdr = b8.encode(subject_.buffer);
        subject += hdr.at(0) + codec::END_OF_LINE;
        subject += fold_header_line(hdr);
    }
    else if (subject_.codec_type == codec::codec_t::QUOTED_PRINTABLE || subject_.codec_type == codec::codec_t::BASE64)
    {
        q_codec qc(line1_policy, line_policy);
        std::vector<std::string> hdr = qc.encode(subject_.buffer, subject_.charset, subject_.codec_type);
        subject += hdr.at(0) + codec::END_OF_LINE;
        subject += fold_header_line(hdr);
    }
    else if (subject_.codec_type == codec::codec_t::PERCENT)
    {
        throw message_error("Percent codec not allowed for the subject.", "");
    }

    return subject;
}


std::string inline message::format_date() const
{
    // RFC 5322 format: "Fri, 21 Nov 1997 09:55:06 -0600"
    auto local_time = date_time_.get_local_time();
    auto sys_time = date_time_.get_sys_time();
    auto info = date_time_.get_time_zone()->get_info(sys_time);
    auto offset = info.offset;
    
    // Calculate offset hours and minutes
    auto offset_hours = std::chrono::duration_cast<std::chrono::hours>(offset).count();
    auto offset_minutes = std::chrono::abs(std::chrono::duration_cast<std::chrono::minutes>(offset) % std::chrono::hours(1)).count();
    
    // Format the main date/time part
    std::string result = std::format("{:%a, %d %b %Y %H:%M:%S}", local_time);
    
    // Append timezone offset
    std::format_to(std::back_inserter(result), " {:+03d}{:02d}", static_cast<int>(offset_hours), static_cast<int>(offset_minutes));
    
    return result;
}

std::string inline message::format_date_header() const
{
    if (date_time_.is_not_a_date_time())
        return "";

    std::string header = DATE_HEADER + HEADER_SEPARATOR_STR;
    header += format_date();
    header += codec::END_OF_LINE;
    return header;
}


/*
See [rfc 5322, section 3.4, page 16-18].

Implementation goes by using state machine. Diagram is shown in graphviz dot language:
```
digraph address_list
{
    rankdir=LR;
    node [shape = box];
    begin -> begin [label = "space"];
    begin -> nameaddrgrp [label = "atext"];
    begin -> qnameaddrbeg [label = "quote"];
    begin -> addrbrbeg [label="left_bracket"];
    nameaddrgrp -> nameaddrgrp [label = "atext"];
    nameaddrgrp -> name [label = "space"];
    nameaddrgrp -> addr [label = "monkey"];
    nameaddrgrp -> groupbeg [label = "colon"];
    nameaddrgrp -> addrbrbeg [label = "left_bracket"];
    nameaddrgrp -> begin [label = "comma"];
    nameaddrgrp -> qnameaddrbeg [label = "quote" style="dashed"];
    name -> name [label = "atext, space"];
    name -> addrbrbeg [label = "left_bracket"];
    name -> qnameaddrbeg [label = "quote" style="dashed"];
    addr -> addr [label = "atext"];
    addr -> begin [label = "comma"];
    addr -> groupend [label = "semicolon"];
    addr -> addrbrbeg [label="monkey" style="dashed"]
    addr -> commbeg [label = "left_parenthesis"];
    addr -> end [label = "eol"];
    qnameaddrbeg -> qnameaddrbeg [label = "qtext"];
    qnameaddrbeg -> qnameaddrend [label = "quote"];
    qnameaddrend -> qnameaddrend [label = "space"];
    qnameaddrend -> addrbrbeg [label = "left_bracket"];
    addrbrbeg -> addrbrbeg [label = "dtext"];
    addrbrbeg -> addrbrend [label = "right_bracket"];
    addrbrend -> begin [label = "comma"];
    addrbrend -> addrbrend [label = "space"];
    addrbrend -> groupend [label = "semicolon"];
    addrbrend -> commbeg [label = "left_parenthesis"];
    addrbrend -> end [label = "eol"];
    groupbeg -> begin [label = "atext"];
    groupbeg -> groupend [label = "semicolon"];
    groupbeg -> addrbrbeg [label = "left_bracket"];
    groupend -> begin [label = "atext"];
    groupend -> commbeg [label = "left_parenthesis"];
    groupend -> end [label = "eol"];
    commbeg -> commbeg [label = "atext"];
    commbeg -> commend [label = "right_parenthesis"];
    commend -> commend [label = "space"];
    commend -> end [label = "eol"];
}
```
Meanings of the labels:
- nameaddrgrp: begin of a name or address or group without qoutes
- name: a name without address
- addr: an address only
- qnameaddrbeg: begin of a quoted name
- qnameaddrend: end of a quoted name
- addrbrbeg: begin of an address in angle brackets
- addrbrend: end of an address in angle brackets
- groupbeg: begin of a group
- groupend: end of a group
- commbeg: begin of a comment
- commend: end of a comment
*/
mailboxes inline message::parse_address_list(const std::string& address_list)
{
    enum class state_t {BEGIN, NAMEADDRGRP, QNAMEADDRBEG, ADDR, NAME, QNAMEADDREND, ADDRBRBEG, ADDRBREND, GROUPBEG, GROUPEND, COMMBEG, COMMEND, EOL};

    std::vector<mail_address> mail_list;
    std::vector<mail_group> mail_group_list;
    mail_address cur_address;
    mail_group cur_group;
    // temporary mail std::list containing recipients or group members
    std::vector<mail_address> mail_addrs;
    state_t state = state_t::BEGIN;
    // flag if monkey char is found in the address part
    bool monkey_found = false;
    // flag if mailing group is being parsed, used to determine if addresses are part of a group or not
    bool group_found = false;
    // std::string being parsed so far
    std::string token;
    // track whitespace inside address in strict mode
    bool addr_ws_seen = false;

    std::size_t char_pos = 0;
    for (auto ch = address_list.begin(); ch != address_list.end(); ch++, char_pos++)
    {
        switch (state)
        {
            case state_t::BEGIN:
            {
                if (std::isspace(static_cast<unsigned char>(*ch)))
                    ;
                else if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                {
                    token += *ch;
                    state = state_t::NAMEADDRGRP;
                }
                else if (*ch == codec::QUOTE_CHAR)
                    state = state_t::QNAMEADDRBEG;
                else if (*ch == ADDRESS_BEGIN_CHAR)
                    state = state_t::ADDRBRBEG;
                else
                    throw message_error("Address or group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "`, at position " +
                        std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::BEGIN)
                        ;
                    // one character only, so it's the name part of the address
                    else if (state == state_t::NAMEADDRGRP)
                    {
                        if (group_found)
                            throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "`, at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                        else
                        {
                            if (!token.empty())
                            {
                                cur_address.name = token;
                                detail::trim_inplace(cur_address.name.buffer);
                                mail_list.push_back(cur_address);
                            }
                        }
                    }
                    // `QNAMEADDRBEG` or `ADDRBRBEG`
                    else
                        throw message_error("Name or address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "`, at position " +
                            std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::NAMEADDRGRP:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                    token += *ch;
                else if (*ch == codec::MONKEY_CHAR)
                {
                    token += *ch;
                    state = state_t::ADDR;
                    monkey_found = true;
                    addr_ws_seen = false;
                }
                else if (*ch == codec::QUOTE_CHAR && !strict_mode_)
                    state = state_t::QNAMEADDRBEG;
                else if (std::isspace(static_cast<unsigned char>(*ch)))
                {
                    token += *ch;
                    state = state_t::NAME;
                }
                else if (*ch == ADDRESS_SEPARATOR)
                {
                    cur_address.name = token;
                    detail::trim_inplace(cur_address.name.buffer);
                    token.clear();
                    mail_addrs.push_back(cur_address);
                    cur_address.clear();
                    monkey_found = false;
                    state = state_t::BEGIN;
                }
                else if (*ch == MAILGROUP_NAME_SEPARATOR)
                {
                    if (group_found)
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");

                    // if group is reached, store already found addresses in the std::list
                    mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    mail_addrs.clear();
                    cur_group.name = token;
                    token.clear();
                    group_found = true;
                    state = state_t::GROUPBEG;
                }
                else if (*ch == ADDRESS_BEGIN_CHAR)
                {
                    cur_address.name = token;
                    detail::trim_inplace(cur_address.name.buffer);
                    cur_address.name = parse_address_name(cur_address.name.buffer);
                    token.clear();
                    state = state_t::ADDRBRBEG;
                }
                else
                    throw message_error("Address or group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                        std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::NAMEADDRGRP)
                    {
                        if (group_found)
                            throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                        if (!token.empty())
                        {
                            cur_address.name = token;
                            mail_addrs.push_back(cur_address);
                            mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                        }
                    }
                    else if (state == state_t::ADDR)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");
                    else if (state == state_t::NAME)
                        throw message_error("Name parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                    else if (state == state_t::BEGIN)
                    {
                        if (group_found)
                            throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                        mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    }
                    else if (state == state_t::GROUPBEG)
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::NAME:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || std::isspace(static_cast<unsigned char>(*ch)) || codec::is_8bit_char(*ch))
                    token += *ch;
                else if (*ch == codec::QUOTE_CHAR && !strict_mode_)
                    state = state_t::QNAMEADDRBEG;
                else if (*ch == ADDRESS_BEGIN_CHAR)
                {
                    cur_address.name = token;
                    detail::trim_inplace(cur_address.name.buffer);
                    cur_address.name = parse_address_name(cur_address.name.buffer);
                    token.clear();
                    state = state_t::ADDRBRBEG;
                }
                else
                    throw message_error("Name parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                        ".\nAddress std::list is `" + address_list + "`.");

                // not allowed to end address std::list in this state
                if (ch == address_list.end() - 1)
                    throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                        ".\nAddress std::list is `" + address_list + "`.");

                break;
            }

            case state_t::ADDR:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                {
                    if (strict_mode_ && addr_ws_seen)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                    token += *ch;
                }
                else if (*ch == codec::MONKEY_CHAR)
                {
                    if (strict_mode_ && addr_ws_seen)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                    token += *ch;
                    monkey_found = true;
                }
                else if (*ch == ADDRESS_BEGIN_CHAR && !strict_mode_)
                {
                    cur_address.name = token;
                    detail::trim_inplace(cur_address.name.buffer);
                    token.clear();
                    state = state_t::ADDRBRBEG;
                }
                else if (std::isspace(static_cast<unsigned char>(*ch)))
                {
                    if (strict_mode_)
                        addr_ws_seen = true;
                }
                else if (*ch == ADDRESS_SEPARATOR)
                {
                    cur_address.address = token;
                    token.clear();
                    mail_addrs.push_back(cur_address);
                    cur_address.clear();
                    if (!monkey_found)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");
                    monkey_found = false;
                    state = state_t::BEGIN;
                }
                else if (*ch == MAILGROUP_SEPARATOR)
                {
                    if (group_found)
                    {
                        cur_address.address = token;
                        token.clear();
                        mail_addrs.push_back(cur_address);
                        cur_address.clear();
                        cur_group.add(mail_addrs);
                        mail_addrs.clear();
                        mail_group_list.push_back(cur_group);
                        cur_group.clear();
                        group_found = false;
                        state = state_t::GROUPEND;
                    }
                    else
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");
                }
                else if (*ch == codec::LEFT_PARENTHESIS_CHAR)
                {
                    if (group_found)
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                    else
                    {
                        cur_address.address = token;
                        token.clear();
                        mail_addrs.push_back(cur_address);
                        cur_address.clear();
                        if (!monkey_found)
                            throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                        mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    }
                    state = state_t::COMMBEG;
                }
                else
                    throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                        ".\nAddress std::list is `" + address_list + "`.");

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::ADDR)
                    {
                        if (group_found)
                            throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                        if (!monkey_found)
                            throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                        if (!token.empty())
                        {
                            cur_address.address = token;
                            mail_addrs.push_back(cur_address);
                            mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                        }
                    }
                    else if (state == state_t::BEGIN)
                    {
                        if (group_found)
                            throw message_error("Address or group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                        mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    }
                    else if (state == state_t::GROUPEND)
                        ;
                    else if (state == state_t::COMMBEG)
                        throw message_error("Comment parsing failure.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                            std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::QNAMEADDRBEG:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || std::isspace(static_cast<unsigned char>(*ch)) || QTEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                    token += *ch;
                // backslash is invisible, see [rfc 5322, section 3.2.4]
                else if (*ch == codec::BACKSLASH_CHAR)
                    ;
                else if (*ch == codec::QUOTE_CHAR)
                {
                    cur_address.name = token;
                    cur_address.name = parse_address_name(cur_address.name.buffer);
                    token.clear();
                    state = state_t::QNAMEADDREND;
                }
                else
                    throw message_error("Name or address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                        std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                // not allowed to end address std::list in this state in the strict mode
                if (ch == address_list.end() - 1)
                {
                    if (strict_mode_)
                        throw message_error("Name or address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                            std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");
                    else
                        mail_list.push_back(cur_address);
                }

                break;
            }

            case state_t::QNAMEADDREND:
            {
               if (std::isspace(static_cast<unsigned char>(*ch)))
                   ;
               else if (*ch == ADDRESS_BEGIN_CHAR)
                   state = state_t::ADDRBRBEG;
               else
                   throw message_error("Name or address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                       std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

               // not allowed to end address std::list in this state
               if (ch == address_list.end() - 1)
                   throw message_error("Name or address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                       std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

               break;
            }

            case state_t::ADDRBRBEG:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                    token += *ch;
                else if (*ch == codec::MONKEY_CHAR)
                {
                    token += *ch;
                    monkey_found = true;
                }
                else if (*ch == ADDRESS_END_CHAR)
                {
                    cur_address.address = token;
                    token.clear();
                    mail_addrs.push_back(cur_address);
                    cur_address.clear();
                    if (!monkey_found)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                            + ".\nAddress std::list is `" + address_list + "`.");
                    monkey_found = false;
                    state = state_t::ADDRBREND;
                }
                else
                    throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");

                // not allowed to end address std::list in this state
                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::ADDRBRBEG)
                        throw message_error("Address parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                            + ".\nAddress std::list is `" + address_list + "`.");
                    else if (state == state_t::ADDRBREND)
                    {
                        if (group_found)
                        {
                            cur_group.add(mail_addrs);
                            mail_group_list.push_back(cur_group);
                        }
                        else
                            mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    }

                }

                break;
            }

            case state_t::ADDRBREND:
            {
                if (std::isspace(static_cast<unsigned char>(*ch)))
                    ;
                else if (*ch == ADDRESS_SEPARATOR)
                    state = state_t::BEGIN;
                else if (*ch == MAILGROUP_SEPARATOR)
                {
                    if (group_found)
                    {
                        cur_group.add(mail_addrs);
                        mail_addrs.clear();
                        group_found = false;
                        mail_group_list.push_back(cur_group);
                        cur_group.clear();
                        group_found = false;
                        state = state_t::GROUPEND;
                    }
                    else
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                            + ".\nAddress std::list is `" + address_list + "`.");
                }
                else if (*ch == codec::LEFT_PARENTHESIS_CHAR)
                {
                    if (group_found)
                        throw message_error("Comment parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                            + ".\nAddress std::list is `" + address_list + "`.");
                    else
                        mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    state = state_t::COMMBEG;
                }

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::ADDRBREND || state == state_t::BEGIN)
                    {
                        if (group_found)
                            throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " +
                                std::to_string(char_pos) + ".\nAddress std::list is `" + address_list + "`.");

                        mail_list.insert(mail_list.end(), mail_addrs.begin(), mail_addrs.end());
                    }
                    else if (state == state_t::COMMBEG)
                        throw message_error("Comment parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                            + ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::GROUPBEG:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                {
                    token += *ch;
                    state = state_t::BEGIN;
                }
                else if (std::isspace(static_cast<unsigned char>(*ch)))
                    ;
                else if (*ch == ADDRESS_BEGIN_CHAR)
                {
                    state = state_t::ADDRBRBEG;
                }
                else if (*ch == MAILGROUP_SEPARATOR)
                {
                    cur_group.add(mail_addrs);
                    mail_addrs.clear();
                    mail_group_list.push_back(cur_group);
                    cur_group.clear();
                    group_found = false;
                    state = state_t::GROUPEND;
                }

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::BEGIN || state == state_t::ADDRBRBEG)
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::GROUPEND:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || codec::is_8bit_char(*ch))
                {
                    token += *ch;
                    state = state_t::BEGIN;
                }
                else if (*ch == codec::LEFT_PARENTHESIS_CHAR)
                {
                    state = state_t::COMMBEG;
                }
                else if (std::isspace(static_cast<unsigned char>(*ch)))
                {
                    ;
                }

                if (ch == address_list.end() - 1)
                {
                    if (state == state_t::BEGIN || state == state_t::COMMBEG)
                        throw message_error("Group parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos) +
                            ".\nAddress std::list is `" + address_list + "`.");
                }

                break;
            }

            case state_t::COMMBEG:
            {
                if (std::isalpha(static_cast<unsigned char>(*ch)) || std::isdigit(static_cast<unsigned char>(*ch)) || ATEXT.find(*ch) != std::string::npos || std::isspace(static_cast<unsigned char>(*ch)))
                    ;
                else if (*ch == codec::RIGHT_PARENTHESIS_CHAR)
                    state = state_t::COMMEND;
                else
                    throw message_error("Comment parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");
                break;
            }

            case state_t::COMMEND:
            {
                if (std::isspace(static_cast<unsigned char>(*ch)))
                    ;
                else
                    throw message_error("Comment parsing error.", "Syntax error at character `" + std::string(1, *ch) + "` at position " + std::to_string(char_pos)
                        + ".\nAddress std::list is `" + address_list + "`.");
                break;
            }

            case state_t::EOL:
            {
                throw message_error("Address parsing error.", "Unexpected end-of-line state at position " + std::to_string(char_pos)
                    + ".\nAddress std::list is `" + address_list + "`.");
            }
        }
    }

    return mailboxes(mail_list, mail_group_list);
}


/*
See [rfc 5322, section 3.3, page 14-16].
*/
std::chrono::zoned_time<std::chrono::seconds> inline message::parse_date(const std::string& date_str) const
{
    try
    {
        // RFC 5322 examples:
        //  - "Fri, 21 Nov 1997 09:55:06 -0600"
        //  - "Thu, 17 Jul 2014 10:31:49 +0200 (CET)"
        std::string_view sv = detail::trim_view(date_str);

        // Optional day-of-week: 3 letters, optional WSP, then comma.
        if (sv.size() >= 4 && detail::is_ascii_alpha(sv[0]) && detail::is_ascii_alpha(sv[1]) && detail::is_ascii_alpha(sv[2]))
        {
            std::size_t i = 3;
            while (i < sv.size() && (sv[i] == ' ' || sv[i] == '\t'))
                ++i;
            if (i < sv.size() && sv[i] == ',')
            {
                sv.remove_prefix(i + 1);
                sv = detail::trim_view(sv);
            }
        }

        auto parse_int = [](std::string_view& in, int min_digits, int max_digits, int& out) -> bool
        {
            in = detail::trim_view(in);
            if (in.empty())
                return false;

            int value = 0;
            std::size_t digits = 0;
            const char* begin = in.data();
            const char* end = in.data() + in.size();

            // Parse up to max_digits digits.
            const char* p = begin;
            while (p < end && digits < static_cast<std::size_t>(max_digits) && detail::is_ascii_digit(*p))
            {
                ++p;
                ++digits;
            }
            if (digits < static_cast<std::size_t>(min_digits))
                return false;

            auto res = std::from_chars(begin, p, value);
            if (res.ec != std::errc{})
                return false;

            out = value;
            in.remove_prefix(static_cast<std::size_t>(p - begin));
            return true;
        };

        auto consume_char = [](std::string_view& in, char expected) -> bool
        {
            if (!in.empty() && in.front() == expected)
            {
                in.remove_prefix(1);
                return true;
            }
            return false;
        };

        // day
        int day = 0;
        if (!parse_int(sv, 1, 2, day))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        // month (3 letters)
        sv = detail::trim_view(sv);
        if (sv.size() < 3 || !detail::is_ascii_alpha(sv[0]) || !detail::is_ascii_alpha(sv[1]) || !detail::is_ascii_alpha(sv[2]))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        const std::string_view mon_str = sv.substr(0, 3);
        sv.remove_prefix(3);

        auto month_from_abbrev = [](std::string_view mon) -> unsigned
        {
            // Case-insensitive 3-letter month abbreviations.
            struct entry { std::string_view k; unsigned v; };
            constexpr std::array<entry, 12> months = {{
                {"Jan", 1}, {"Feb", 2}, {"Mar", 3}, {"Apr", 4}, {"May", 5}, {"Jun", 6},
                {"Jul", 7}, {"Aug", 8}, {"Sep", 9}, {"Oct",10}, {"Nov",11}, {"Dec",12}
            }};

            char m0 = detail::ascii_tolower(mon.size() > 0 ? mon[0] : '\0');
            char m1 = detail::ascii_tolower(mon.size() > 1 ? mon[1] : '\0');
            char m2 = detail::ascii_tolower(mon.size() > 2 ? mon[2] : '\0');

            for (const auto& e : months)
            {
                if (detail::ascii_tolower(e.k[0]) == m0 && detail::ascii_tolower(e.k[1]) == m1 && detail::ascii_tolower(e.k[2]) == m2)
                    return e.v;
            }
            return 0;
        };

        const unsigned month = month_from_abbrev(mon_str);
        if (month == 0)
            throw message_error("Invalid month in date.", "Month is `" + std::string(mon_str) + "`.");

        // year
        int year = 0;
        if (!parse_int(sv, 4, 4, year))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        // time hh:mm:ss
        int hour = 0, minute = 0, second = 0;
        if (!parse_int(sv, 2, 2, hour) || !consume_char(sv, ':') || !parse_int(sv, 2, 2, minute) || !consume_char(sv, ':') || !parse_int(sv, 2, 2, second))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        // timezone +HHMM / -HHMM
        sv = detail::trim_view(sv);
        if (sv.empty() || (sv.front() != '+' && sv.front() != '-'))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};
        const char tz_sign_char = sv.front();
        sv.remove_prefix(1);

        int tz_h = 0, tz_m = 0;
        if (!parse_int(sv, 2, 2, tz_h) || !parse_int(sv, 2, 2, tz_m))
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        const int tz_sign = (tz_sign_char == '+') ? 1 : -1;

        // Validate date/time
        std::chrono::year_month_day ymd{std::chrono::year{year}, std::chrono::month{month}, std::chrono::day{static_cast<unsigned>(day)}};
        if (!ymd.ok())
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60)
            return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), std::chrono::sys_seconds{}};

        auto local_tp = std::chrono::local_days{ymd} + std::chrono::hours{hour} + std::chrono::minutes{minute} + std::chrono::seconds{second};

        const auto offset = std::chrono::hours{tz_sign * tz_h} + std::chrono::minutes{tz_sign * tz_m};

        // RFC 5322: local_time = utc + offset  =>  utc = local_time - offset
        auto sys_tp = std::chrono::sys_time<std::chrono::seconds>{local_tp.time_since_epoch() - offset};

        return std::chrono::zoned_time<std::chrono::seconds>{std::chrono::current_zone(), sys_tp};
    }
    catch (const message_error&)
    {
        throw;
    }
    catch (...)
    {
        throw message_error("Date parsing error.", "Date is `" + date_str + "`.");
    }
}


std::tuple<std::string, std::string, codec::codec_t>
inline message::parse_subject(const std::string& subject)
{
    if (codec::is_utf8_string(subject))
        return std::make_tuple(subject, codec::CHARSET_UTF8, codec::codec_t::ASCII);
    else
    {
        q_codec qc(static_cast<std::string::size_type>(line_policy_), static_cast<std::string::size_type>(line_policy_));
        auto subject_dec = qc.check_decode(subject);
        return std::make_tuple(std::get<0>(subject_dec), std::get<1>(subject_dec), std::get<2>(subject_dec));
    }
}


string_t inline message::parse_address_name(const std::string& address_name)
{
    q_codec qc(static_cast<std::string::size_type>(line_policy_), static_cast<std::string::size_type>(line_policy_));
    const std::string::size_type Q_CODEC_SEPARATORS_NO = 4;
    std::string::size_type addr_len = address_name.size();
    bool is_q_encoded = address_name.size() >= Q_CODEC_SEPARATORS_NO && address_name.at(0) == codec::EQUAL_CHAR &&
        address_name.at(1) == codec::QUESTION_MARK_CHAR && address_name.at(addr_len - 1) == codec::EQUAL_CHAR &&
        address_name.at(addr_len - 2) == codec::QUESTION_MARK_CHAR;

    bool starts_with_q_encoded_prefix = address_name.size() >= 2 && address_name.at(0) == codec::EQUAL_CHAR &&
        address_name.at(1) == codec::QUESTION_MARK_CHAR;
    bool ends_with_q_encoded_suffix = address_name.size() >= 2 && address_name.at(addr_len - 1) == codec::EQUAL_CHAR &&
        address_name.at(addr_len - 2) == codec::QUESTION_MARK_CHAR;
    if (starts_with_q_encoded_prefix && !ends_with_q_encoded_suffix)
    {
        if (codec::is_utf8_string(address_name))
            return string_t(address_name, codec::CHARSET_UTF8);
        else
            return string_t(address_name, codec::CHARSET_ASCII);
    }

    if (is_q_encoded)
    {
        auto parts = split_qc_string(address_name);
        std::string parts_str, charset;
        std::optional<codec::codec_t> buf_codec = std::nullopt;
        for (const auto& p : parts)
        {
            std::string::size_type p_len = p.length();
            auto an = qc.decode(p.substr(0, p_len - 2));
            parts_str += std::get<0>(an);
            if (charset.empty())
                charset = std::get<1>(an);
            if (charset != std::get<1>(an))
                throw message_error("Inconsistent Q encodings.", "Charset `" + charset + "` vs charset `" + std::get<1>(an) + "`.");
            if (!buf_codec)
                buf_codec = std::get<2>(an);
        }
        if (!buf_codec)
            buf_codec = codec::codec_t::ASCII;
        return string_t(parts_str, charset, buf_codec.value());
    }

    if (codec::is_utf8_string(address_name))
        return string_t(address_name, codec::CHARSET_UTF8);
    else
        return string_t(address_name, codec::CHARSET_ASCII);
}


std::vector<std::string> inline message::split_qc_string(const std::string& text)
{
    const std::string Q_ENCODING_BEGIN = "?=";
    const std::string Q_ENCODING_END = "=?";
    std::vector<std::string> parts;
    std::string::size_type begin_pos = text.find(Q_ENCODING_END);
    while (begin_pos != std::string::npos)
    {
        std::string::size_type charset_pos = text.find(codec::QUESTION_MARK_CHAR, begin_pos + 1);
        std::string::size_type method_pos = text.find(codec::QUESTION_MARK_CHAR, charset_pos + 1);
        std::string::size_type content_begin = text.find(codec::QUESTION_MARK_CHAR, method_pos + 1);
        std::string::size_type content_end = text.find(Q_ENCODING_BEGIN, content_begin + 1);
        parts.push_back(text.substr(begin_pos, content_end + 2 - begin_pos));
        begin_pos = text.find(Q_ENCODING_END, content_end + 2);
    }
    return parts;
}


} // namespace mailxx


#ifdef _MSC_VER
#pragma warning(pop)
#endif

