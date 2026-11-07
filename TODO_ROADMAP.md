# TODO Roadmap

This document groups the current `TODO` / `FIXME` markers found in `include/` and `test/` into implementation work items.

The `Files to touch` column lists the most likely entry points, not necessarily an exhaustive patch set.

## Legend

- Priority
  - `P0`: bug already visible in tests or formatting output
  - `P1`: correctness or RFC compliance gap
  - `P2`: maintainability or API cleanup
  - `P3`: design exploration or larger refactor
- Effort
  - `S`: small change
  - `M`: medium-sized change
  - `L`: multi-file or behavior-changing refactor
- Risk
  - `Low`: local behavior, narrow blast radius
  - `Medium`: formatting/parsing changes with protocol impact
  - `High`: public API, data model, or wire-format behavior changes

## Status

Items 1 to 14 and 16 are done. The library stays header-only. A MIME body stays a `std::string`, which already carries a NUL. `send(const message&)`, `uid_fetch_rfc822`, and `dialog::read_line` stay as they are.

- Items 1 to 7: frozen formatting, stable parse, and the strict codec checks covered by `test_message`, `test_message_stable`, and `test_codec_headers`.
- Items 8, 9, 10, 12, 13, 14, and 16: RFC 2231 continuations, the real Q-codec budget, Q separated from quoted-printable, US-ASCII as the default charset, strict 7bit/8bit, and reserved headers.
- Item 11: `mime::parse(std::string_view)` walks the caller buffer. A line is copied only when it is kept. `format_content` reserves one string for quoted-printable, 7bit, 8bit, and binary. Q and percent still return one string per folded line, because a continuation is a separate header parameter. No translation unit was extracted. A clean compile of `test_message` takes about 14 seconds.
- Dialogue: `send_frozen` accepts DSN on `MAIL FROM` and `RCPT TO` only, and uses `BDAT` when `CHUNKING` was announced. One `UID FETCH` asks for flags and a bounded `BODY.PEEK`. `IDLE` events are `EXISTS`, `EXPUNGE`, and `FETCH`. `UID MOVE` is refused unless `MOVE` was announced.
- Extensions, each only after the matching capability: `ENABLE CONDSTORE`, `ENABLE QRESYNC` with one `HIGHESTMODSEQ` token, `COMPRESS DEFLATE` under the dialogue with the literal size as the decompressed ceiling, and `ENABLE UTF8=ACCEPT`. SMTP international addresses already use `SMTPUTF8` when that capability was announced.
- The local Postfix accepts frozen `BDAT` and DSN submissions and returns `2.0.0 Ok: N bytes queued as <id>`. The local Dovecot advertises `CONDSTORE`, `QRESYNC`, and `MOVE`: the proof enables the first two, reads flags with a bounded `BODY.PEEK`, sees `IDLE EXISTS`, and `UID MOVE`s the message. `COMPRESS=DEFLATE` and `UTF8=ACCEPT` are not announced, so those commands are not sent.

## Decisions

15. The body, the attachment filename, and the display name stay in the current types. A `std::string` already stores a NUL, and splitting storage would change every format and parse caller.

17. `mixed` stays a multipart subtype, not a top-level media type. `7bit` is a content-transfer-encoding; US-ASCII is a charset. `content_disposition_t` stays an enumeration, and filename parameters stay on the attribute map.

18. The codec base stays a holder for the line policy. `encode` and `decode` are not a virtual interface: Base64, quoted-printable, Q, percent, and binary do not share one return type, and a virtual call would not remove a copy.

## Work Items

| ID | Work item | Source TODOs | Proposed implementation | Priority | Effort | Risk | Files to touch |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Fix encoded `From` header folding | `test/test_message.cpp:1937` | Inspect the encoded-word folding path for sender display names and prevent emission of an empty trailing Base64 chunk on the last folded line. Once fixed, tighten the test so it checks the exact serialized header instead of only documenting the bug. | P0 | M | Medium | `include/mailxx/mime/message.hpp`<br>`include/mailxx/codec/q_codec.hpp`<br>`test/test_message.cpp` |
| 2 | Apply line policy to long `Message-ID` values | `test/test_message.cpp:2408` | Route `Message-ID` formatting through the same line-wrapping policy as other structured headers, then replace the temporary bug-oriented assertion with a policy-compliant expectation. | P0 | S | Low | `include/mailxx/mime/message.hpp`<br>`test/test_message.cpp` |
| 3 | Restore delimiter between encoded name and address | `test/test_message.cpp:2592` | Audit address formatting when the display name is RFC 2047-encoded and ensure the serializer always inserts the required separator before `<address>`, including on folded output. | P0 | M | Medium | `include/mailxx/mime/message.hpp`<br>`include/mailxx/codec/q_codec.hpp`<br>`test/test_message.cpp` |
| 4 | Fold `Content-Type` attributes according to policy | `test/test_message.cpp:2752` | Rework `Content-Type` serialization so attribute continuation and line splitting obey the configured line policy instead of overflowing or splitting at the wrong boundaries. Update the test to assert the final wrapped header form. | P0 | M | Medium | `include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`include/mailxx/mime/message.hpp`<br>`test/test_message.cpp` |
| 5 | Preserve attachment filename charset on parse | `test/test_message.cpp:4676`<br>`include/mailxx/mime/message.hpp:508` | Keep the attachment filename as `string_t` end-to-end so parsed charset/codec metadata is preserved, then expose that richer value through `attachment()` and tighten the UTF-8 attachment test. | P0 | M | Medium | `include/mailxx/mime/message.hpp`<br>`include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`test/test_message.cpp` |
| 6 | Stabilize relaxed empty-header parsing on MSVC | `test/test_message.cpp:5559` | Reproduce the MSVC-specific behavior around empty headers, identify whether the issue comes from view lifetime, copy elision, or parser state, then make the relaxed parser deterministic across compilers and remove the workaround note from the test. | P1 | M | Medium | `include/mailxx/mime/message.hpp`<br>`include/mailxx/mime/mime.hpp`<br>`test/test_message.cpp` |
| 7 | Verify Base64 and binary line-policy behavior | `include/mailxx/codec/base64.hpp:37`<br>`include/mailxx/codec/base64.hpp:38`<br>`include/mailxx/codec/base64.hpp:182`<br>`include/mailxx/codec/binary.hpp:75` | Decide whether a dedicated single-line Base64 helper is needed for SMTP paths, make the first-line policy behavior explicit, and add coverage for wrapped decode/encode cases in both Base64 and binary codecs. | P2 | M | Medium | `include/mailxx/codec/base64.hpp`<br>`include/mailxx/codec/binary.hpp`<br>`test/` |
| 8 | Implement RFC 2231 percent codec line policies | `include/mailxx/codec/percent.hpp:34`<br>`include/mailxx/codec/percent.hpp:69`<br>`include/mailxx/codec/percent.hpp:70`<br>`include/mailxx/codec/percent.hpp:114` | Finish line splitting for percent-encoded attributes, migrate `encode()` to take `string_t`, and keep encode/decode behavior aligned with MIME attribute continuation rules so long filenames and charsets serialize cleanly. | P1 | L | High | `include/mailxx/codec/percent.hpp`<br>`include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`test/test_message.cpp` |
| 9 | Make Q codec header-aware and remove magic constants | `include/mailxx/codec/q_codec.hpp:77`<br>`include/mailxx/codec/q_codec.hpp:78`<br>`include/mailxx/codec/q_codec.hpp:82`<br>`include/mailxx/codec/q_codec.hpp:105`<br>`include/mailxx/codec/q_codec.hpp:174` | Change the Q codec API to accept `string_t` and a caller-supplied header prefix length, replace inline constants with named constants, and return a richer decoded object so folding decisions are based on the actual header name length. | P1 | M | Medium | `include/mailxx/codec/q_codec.hpp`<br>`include/mailxx/mime/message.hpp`<br>`test/` |
| 10 | Separate generic quoted-printable from Q-encoding mode | `include/mailxx/codec/quoted_printable.hpp:32`<br>`include/mailxx/codec/quoted_printable.hpp:232` | Remove the Q-mode flag from the generic quoted-printable codec, factor the shared hex-escape helper into a reusable internal function, and move RFC 2047-specific behavior behind the Q codec layer instead of a mode switch. | P2 | M | Medium | `include/mailxx/codec/quoted_printable.hpp`<br>`include/mailxx/codec/q_codec.hpp`<br>`test/` |
| 11 | Switch MIME parsing hot paths to `std::string_view` | `include/mailxx/mime/mime.hpp:319` | Replace repeated `substr()`-based parsing with `std::string_view` slicing to reduce allocations and simplify parser state transitions, while preserving the current `result<T>` error flow. | P2 | M | Medium | `include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`test/test_message.cpp` |
| 12 | Define default charset behavior and harden address-name parsing | `include/mailxx/mime/mime.hpp:346`<br>`include/mailxx/mime/message.hpp:718`<br>`include/mailxx/mime/message.hpp:719` | Make the parser choose a documented default charset when one is absent, add tests beyond ASCII/UTF-8 for address names, and ensure invalid Q-encoded names always become parse errors instead of partially decoded values. | P1 | M | Medium | `include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/message.hpp`<br>`include/mailxx/codec/q_codec.hpp`<br>`test/test_message.cpp` |
| 13 | Tighten MIME attribute parsing and RFC 2231 continuations | `include/mailxx/mime/mime.hpp:897`<br>`include/mailxx/mime/mime.hpp:915`<br>`include/mailxx/mime/mime.hpp:925` | Relax attribute character validation to match the RFC where appropriate, validate continuation markers like `foo*0*`, `foo*1*`, and `foo*2`, and extract percent-decoding into a dedicated helper shared by attribute parsing. | P1 | M | Medium | `include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`include/mailxx/codec/percent.hpp`<br>`test/test_message.cpp` |
| 14 | Clarify `7bit` / `8bit` / `binary` encoding semantics | `include/mailxx/mime/mime_impl.hpp:653`<br>`include/mailxx/mime/mime_impl.hpp:665`<br>`include/mailxx/mime/mime_impl.hpp:680` | Encode and validate `7bit`, `8bit`, and `binary` content according to documented rules, reject illegal bytes in strict mode, preserve raw octets in binary mode, and make the binary path safe when content contains `\\0`. | P1 | L | High | `include/mailxx/mime/mime_impl.hpp`<br>`include/mailxx/codec/binary.hpp`<br>`include/mailxx/codec/base64.hpp`<br>`include/mailxx/codec/quoted_printable.hpp`<br>`test/test_message.cpp` |
| 15 | Separate text metadata from binary attachment payloads | `include/mailxx/mime/mime.hpp:984`<br>`include/mailxx/mime/mime.hpp:1014`<br>`include/mailxx/mime/message.hpp:508`<br>`include/mailxx/codec/codec.hpp:36` | Split `name_`, attachment filename, and raw body storage into types with clearer semantics, likely keeping display text as `string_t` and binary payloads as `std::vector<std::uint8_t>` or equivalent. Plan this as a staged refactor to avoid breaking format/parse logic in one pass. | P2 | L | High | `include/mailxx/mime/mime.hpp`<br>`include/mailxx/mime/message.hpp`<br>`include/mailxx/codec/codec.hpp`<br>`include/mailxx/mime/mime_impl.hpp`<br>`test/` |
| 16 | Block duplicate use of standard headers in `add_header()` | `include/mailxx/mime/message.hpp:519` | Introduce a reserved-header lookup for headers already managed by dedicated APIs (`From`, `To`, `Subject`, `Date`, and similar) and make `add_header()` return an explicit `result` error when callers try to override them through the generic path. | P1 | S | Low | `include/mailxx/mime/message.hpp`<br>`test/test_message.cpp` |
| 17 | Clarify MIME type and disposition modeling | `include/mailxx/mime/mime.hpp:101`<br>`include/mailxx/mime/mime.hpp:239`<br>`include/mailxx/mime/mime.hpp:246` | Resolve the model questions before changing code: `mixed` looks like a `multipart` subtype rather than a top-level media type, `7bit` vs ASCII needs explicit docs or naming, and `content_disposition_t` likely wants a richer struct if filename/params become first-class. | P3 | M | Medium | `include/mailxx/mime/mime.hpp`<br>`README.md`<br>`test/` |
| 18 | Decide whether codecs need a real abstract interface | `include/mailxx/codec/codec.hpp:35` | Revisit the codec base class only after the behavior-level TODOs are closed. Either formalize `encode()` / `decode()` as a real abstract interface with consistent return types, or document why the current ad-hoc API is intentional and leave the base class as a utility holder. | P3 | L | High | `include/mailxx/codec/codec.hpp`<br>`include/mailxx/codec/base64.hpp`<br>`include/mailxx/codec/quoted_printable.hpp`<br>`include/mailxx/codec/percent.hpp`<br>`include/mailxx/codec/binary.hpp` |

## Suggested Order

Items 1 to 14 and 16 are closed. Items 15, 17, and 18 are the decisions above: the types stay as they are.
