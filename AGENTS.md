# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

## What this is

`github.com/go-pkgz/email` is a single-package library wrapping the stdlib `net/smtp` to simplify sending
messages (alerts, notifications, password-reset mails). It has no runtime dependencies — only `testify` for
tests. Not designed for high-volume/low-latency bulk sending. Go 1.19.

## Commands

- Test: `go test -race ./...` — CI runs with `TZ=America/Chicago`; the Date header uses RFC1123Z with an
  injectable clock, so timezone can affect assertions. Match CI: `TZ=America/Chicago go test -race ./...`.
- Single test: `go test -run TestEmail_Send`
- Lint: `golangci-lint run` from repo root (config is golangci-lint **v2** format; CI pins v2.15.0)
- Regenerate mocks: `go generate ./...` (requires `moq`; do not hand-edit files under `mocks/`)

## Architecture

Three source files, one package:

- `email.go` — `Sender` type, `Send`, `SendContext`, `SendBatch`, and MIME message construction (`buildMessage`).
- `options.go` — functional options (`Option = func(*Sender)`), all applied in `NewSender`.
- `auth.go` — custom LOGIN SASL auth mechanism.

Key design points that span files:

- **Functional options.** `Sender` fields are unexported and set only through `Option` funcs in `options.go`,
  applied in `NewSender` after defaults. Add a new config knob = new `Option` func + field, plus its line in the
  README options list.

- **`SMTPClient` interface is the seam.** It's a consumer-side subset of `net/smtp.Client` (Mail/Auth/Rcpt/
  Data/Quit/Close). If the caller injects one via the `SMTP()` option it's used for one send and then closed,
  with `QUIT` or, when that wasn't reached or failed, with `Close`; otherwise each send builds a fresh `net/smtp` client via
  `em.client()`. This interface is what the moq mock implements, so most `Send` tests run without a real SMTP
  server; the ones exercising `em.client()` use a local listener (`startSMTPTestServer`).

- **`em.client()` handles the two transport modes:** plain (dial + optional STARTTLS, port 587), and implicit
  `TLS` (dial over TLS, port 465), where `STARTTLS` is ignored. `InsecureSkipVerify` feeds the `tls.Config`.

- **Context binding.** `SendContext` and `SendBatch` hand `ctx` to `em.client()`, which dials with it, sets the
  ctx deadline on the connection and starts a goroutine closing the connection as soon as `ctx` is done: net/smtp
  calls take no context, so closing the connection is the only way to interrupt them. The returned `stop` func
  releases that goroutine. A client injected with `SMTP()` owns its connection, so `ctx` can't interrupt a call on
  it; it is checked before the send starts and, in a batch, before each message. `Send` is `SendContext` with
  `context.Background()`.

- **`SendBatch` and its reset rule.** It authenticates once and runs one `transaction` per message over the same
  connection, then sends `QUIT`. A message rejected before any SMTP command (no recipients, an empty recipient,
  no sender, a message that can't be built) is a `messageError` and the batch goes on untouched. A message the server rejects (a
  `*textproto.Error`) is aborted with `RSET` through the unexported `resetter` interface (`Reset() error`, which
  `*smtp.Client` has) and the batch goes on; an injected client without it, a failed `RSET`, a broken connection
  or a done `ctx` stops the batch and fills the remaining entries. Failures after the session is set up come back
  as `*BatchError`, with one entry per message; its `Is`/`As` look into the entries, since Go 1.19's `errors.Is`/`errors.As` don't follow a
  multi-error `Unwrap`.

- **`buildMessage` is the intricate part.** It assembles headers manually, then bodies: `multipart/mixed` for
  attachments, `multipart/related` for inline images, quoted-printable for the text body. Inline images get an
  auto `Content-ID` of `<N.name>`, their position in `InlineImages` and the file name with everything outside
  `[A-Za-z0-9._-]` replaced by `_` (`contentID`). Attachment/inline type is sniffed from the first 512 bytes via
  `http.DetectContentType`, then the file is re-seeked to 0 and base64-encoded. Changes here are easy to break
  silently — the tests assert on the exact serialized message string.

- **LOGIN auth (`auth.go`) exists because stdlib has PLAIN and CRAM-MD5, not LOGIN.** Needed for Office 365 /
  Outlook.com. Enabled with the `LoginAuth()` option; it refuses to send credentials over an unencrypted,
  non-localhost connection. `Sender.auth()` picks PLAIN vs LOGIN and returns nil (no auth) when username/password
  are empty.

- **Envelope vs. headers.** `extractEmailAddress` (via `net/mail`) strips a display name so `MAIL FROM` /
  `RCPT TO` get a bare address, while the `From`/`To` *headers* keep the `"Name" <addr>` form, with the name
  RFC 2047 encoded by `formatAddress`, and `joinAddresses` joins the `To` addresses, trimmed, with ", ".
  `extractEmailAddress` and `formatAddress` fall back to the raw string if parsing fails.

- **`timeNow` field** is an injectable clock (`func() time.Time`, defaults to `time.Now`) so tests can pin the
  Date header deterministically — set `s.timeNow` directly in tests.

## Testing conventions

- Mocks are moq-generated into `mocks/` from `//go:generate` directives at the top of `email.go` for the
  `SMTPClient` and `Logger` interfaces and the unexported `resetter` interface (`mocks.ResetterMock`). Use the
  mock's `*Calls()` accessors to assert interactions.
- `testdata/` holds attachment fixtures (`1.txt`, `2.txt`, `image.jpg`, `nullfile` for the empty-file path).
- Coverage in CI strips `mocks`/`_mock.go` lines before submitting to coveralls.
