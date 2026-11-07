// Package email provides email sender
package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:generate moq -out mocks/smpt_client.go -pkg mocks -skip-ensure -fmt goimports . SMTPClient
//go:generate moq -out mocks/logger.go -pkg mocks -skip-ensure -fmt goimports . Logger

// Sender implements email sender
type Sender struct {
	smtpClient         SMTPClient
	logger             Logger
	host               string     // SMTP host
	heloHost           string     // SMTP HELO/EHLO host
	port               int        // SMTP port
	contentType        string     // content type, optional. Will trigger MIME and Content-Type headers
	tls                bool       // TLS auth
	starttls           bool       // startTLS
	insecureSkipVerify bool       // insecure Skip Verify
	smtpUserName       string     // username
	smtpPassword       string     // password
	authMethod         authMethod // auth method
	timeOut            time.Duration
	contentCharset     string
	timeNow            func() time.Time
}

// Params contains all user-defined parameters to send emails
type Params struct {
	From            string   // from email field
	To              []string // from email field
	Subject         string   // email subject
	UnsubscribeLink string   // POST, https://support.google.com/mail/answer/81126 -> "Use one-click unsubscribe"
	InReplyTo       string   // identifier for email group (category), used for email grouping
	Attachments     []string // attachments path
	InlineImages    []string // InlineImages images path
}

// Logger is used to log errors and debug messages
type Logger interface {
	Logf(format string, args ...any)
}

// SMTPClient interface defines subset of net/smtp used by email client
type SMTPClient interface {
	Mail(from string) error
	Auth(auth smtp.Auth) error
	Rcpt(to string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}

// SMTPResetter is implemented by SMTP clients able to abort a failed transaction with RSET, as smtp.Client does.
// SendBatch needs it to carry on with the next message after one fails, and stops at the first failure without it.
type SMTPResetter interface {
	Reset() error
}

// Message is a single email for SendBatch, with the same text and params Send takes
type Message struct {
	Text   string
	Params Params
}

// BatchError is returned by SendBatch when some of the messages were not sent.
// Errs has an entry for every message, in the order they were passed, nil for the sent ones.
type BatchError struct {
	Errs []error
}

// Error lists the failed messages by their index in the batch
func (e *BatchError) Error() string {
	var failed []string
	for i, err := range e.Errs {
		if err != nil {
			failed = append(failed, fmt.Sprintf("message %d: %v", i, err))
		}
	}
	return fmt.Sprintf("failed to send %d of %d messages: %s", len(failed), len(e.Errs), strings.Join(failed, "; "))
}

// Is reports whether the error of any failed message matches target, it makes errors.Is look into the batch.
// Is and As are used in place of a multi-error Unwrap, which errors.Is and errors.As don't follow before Go 1.20.
func (e *BatchError) Is(target error) bool {
	for _, err := range e.Errs {
		if err != nil && errors.Is(err, target) {
			return true
		}
	}
	return false
}

// As finds the first failed message error that matches target and sets target to it, for errors.As
func (e *BatchError) As(target any) bool {
	for _, err := range e.Errs {
		if err != nil && errors.As(err, target) {
			return true
		}
	}
	return false
}

// NewSender creates email client with prepared smtp
func NewSender(smtpHost string, options ...Option) *Sender {
	res := Sender{
		smtpClient:         nil,
		logger:             nopLogger{},
		host:               smtpHost,
		port:               25,
		contentType:        `text/plain`,
		tls:                false,
		insecureSkipVerify: false,
		smtpUserName:       "",
		smtpPassword:       "",
		authMethod:         authMethodPlain,
		contentCharset:     "UTF-8",
		timeOut:            time.Second * 30,
		timeNow:            time.Now,
	}
	for _, opt := range options {
		opt(&res)
	}

	res.logger.Logf("[INFO] new email sender created with host: %s:%d, helo: %q, tls: %v, insecureSkipVerify: %v, username: %q, timeout: %v, "+
		"content type: %q, charset: %q", smtpHost, res.port, res.effectiveHELOHost(),
		res.tls, res.insecureSkipVerify, res.smtpUserName, res.timeOut, res.contentType, res.contentCharset)
	return &res
}

// Send email with given text, with no cancellation and with TimeOut applied to the connection setup only.
// See SendContext for the details.
func (em *Sender) Send(text string, params Params) error {
	return em.SendContext(context.Background(), text, params)
}

// SendContext sends email with given text and terminates the whole SMTP transaction as soon as ctx is done,
// including the greeting, the authentication and the message body transfer.
// If SMTPClient set with the SMTP option it will be used, if not - new smtp.Client on each send.
// Note that a client set that way owns its connection, so such a transaction can't be terminated in the middle.
// Always closes client on completion or failure.
func (em *Sender) SendContext(ctx context.Context, text string, params Params) error {
	em.logger.Logf("[DEBUG] send %q to %v", text, params.To)

	client := em.smtpClient // set by the SMTP option, nil when SendContext makes its own client below

	var quit bool
	defer func() {
		if quit || client == nil { // quit set if Quit() call passed because it's closing connection as well.
			return
		}
		if e := client.Close(); e != nil {
			em.logger.Logf("[WARN] can't close smtp connection, %v", e)
		}
	}()

	if err := ctx.Err(); err != nil { // nothing started yet, a client set with the SMTP option is closed by the defer
		return err
	}

	if len(params.To) == 0 {
		return errors.New("no recipients")
	}

	// message is built before the connection is made, this way a bad message doesn't reach the server at all
	msg, err := em.buildMessage(text, params)
	if err != nil {
		return fmt.Errorf("can't make email message: %w", err)
	}

	if client == nil { // if client not set make new net/smtp
		c, stop, e := em.client(ctx)
		if e != nil {
			return fmt.Errorf("failed to make smtp client: %w", e)
		}
		defer stop() // runs before the deferred close above, releasing the ctx watcher first
		client = c
	}

	if err := em.authenticate(client); err != nil {
		return err
	}

	if err := em.transaction(client, msg, params); err != nil {
		return err
	}

	quit = em.quit(client)
	return nil
}

// SendBatch sends messages one after another over a single SMTP connection, authenticating once,
// and ends the session with QUIT after the last one. The connection and the context are the same as for SendContext:
// the whole batch is terminated as soon as ctx is done.
//
// A message the server rejects doesn't stop the batch when the client implements SMTPResetter, smtp.Client does;
// a broken connection, a client without RSET or a done ctx leave that message and the rest of the batch unsent.
// It returns nil when every message is sent and *BatchError, telling which ones were not, when any failed
// after the session was set up. Any other error means the session couldn't be set up and nothing was sent.
func (em *Sender) SendBatch(ctx context.Context, msgs []Message) error {
	em.logger.Logf("[DEBUG] send batch of %d messages", len(msgs))

	client := em.smtpClient // set by the SMTP option, nil when SendBatch makes its own client below

	var quit bool
	defer func() {
		if quit || client == nil {
			return
		}
		if e := client.Close(); e != nil {
			em.logger.Logf("[WARN] can't close smtp connection, %v", e)
		}
	}()

	if err := ctx.Err(); err != nil {
		return err
	}
	if len(msgs) == 0 {
		return nil
	}

	if client == nil {
		c, stop, err := em.client(ctx)
		if err != nil {
			return fmt.Errorf("failed to make smtp client: %w", err)
		}
		defer stop()
		client = c
	}

	if err := em.authenticate(client); err != nil {
		return err
	}

	errs := make([]error, len(msgs))
	failed := false
	for i, m := range msgs {
		if err := ctx.Err(); err != nil {
			fillUnsent(errs[i:], err)
			failed = true
			break
		}

		em.logger.Logf("[DEBUG] send batch message %d, %q to %v", i, m.Text, m.Params.To)
		err := em.sendMessage(client, m)
		if err == nil {
			continue
		}
		errs[i], failed = err, true

		var msgErr *messageError
		if errors.As(err, &msgErr) {
			continue // the message was rejected before any SMTP command, the session is untouched
		}
		if rerr := em.reset(client, err); rerr != nil {
			fillUnsent(errs[i+1:], fmt.Errorf("not sent, the session ended after message %d failed: %w", i, rerr))
			break
		}
	}

	quit = em.quit(client)
	if failed {
		return &BatchError{Errs: errs}
	}
	return nil
}

// messageError is a message rejected before it reached the server, recipients or content
type messageError struct{ err error }

func (e *messageError) Error() string { return e.err.Error() }
func (e *messageError) Unwrap() error { return e.err }

// sendMessage builds a batch message and sends it in its own transaction
func (em *Sender) sendMessage(client SMTPClient, m Message) error {
	if len(m.Params.To) == 0 {
		return &messageError{err: errors.New("no recipients")}
	}
	msg, err := em.buildMessage(m.Text, m.Params)
	if err != nil {
		return &messageError{err: fmt.Errorf("can't make email message: %w", err)}
	}
	return em.transaction(client, msg, m.Params)
}

// reset aborts the failed transaction so the next message can start a new one.
// It returns an error when the session can't go on: the connection broke, or the client has no RSET.
func (em *Sender) reset(client SMTPClient, failure error) error {
	var reply *textproto.Error
	if !errors.As(failure, &reply) { // no reply from the server, i.e. the connection broke mid-transaction
		return failure
	}
	r, ok := client.(SMTPResetter)
	if !ok {
		return errors.New("smtp client can't reset the transaction")
	}
	if err := r.Reset(); err != nil {
		return fmt.Errorf("failed to reset smtp transaction: %w", err)
	}
	return nil
}

func fillUnsent(errs []error, err error) {
	for i := range errs {
		errs[i] = err
	}
}

// authenticate logs in to the server, if credentials are set
func (em *Sender) authenticate(client SMTPClient) error {
	auth := em.auth()
	if auth == nil {
		return nil
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("failed to auth to smtp %s:%d, %w", em.host, em.port, err)
	}
	return nil
}

// transaction sends a single message, from MAIL to the end of DATA, on a ready session
func (em *Sender) transaction(client SMTPClient, msg *bytes.Buffer, params Params) error {
	if err := client.Mail(extractEmailAddress(params.From)); err != nil {
		return fmt.Errorf("bad from address %q: %w", params.From, err)
	}

	for _, rcpt := range params.To {
		if err := client.Rcpt(extractEmailAddress(rcpt)); err != nil {
			return fmt.Errorf("bad to address %q: %w", params.To, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("can't make email writer: %w", err)
	}

	if _, err = msg.WriteTo(writer); err != nil {
		return fmt.Errorf("failed to send email body to %q: %w", params.To, err)
	}
	// closing the writer reports the final response to the DATA command, i.e. the actual delivery result
	if err = writer.Close(); err != nil {
		return fmt.Errorf("failed to send email to %q: %w", params.To, err)
	}
	return nil
}

// quit ends the session, it reports whether QUIT passed, closing the connection as well
func (em *Sender) quit(client SMTPClient) bool {
	if err := client.Quit(); err != nil {
		em.logger.Logf("[WARN] failed to send quit command to %s:%d, %v", em.host, em.port, err)
		return false
	}
	return true
}

// extractEmailAddress extracts the email address from a string that may contain a display name.
// For example, it converts `"John Doe" <john@example.com>` to `john@example.com`.
// If parsing fails, it returns the original string unchanged.
func extractEmailAddress(from string) string {
	addr, err := mail.ParseAddress(strings.TrimSpace(from))
	if err != nil {
		return from
	}
	return addr.Address
}

func (em *Sender) String() string {
	return fmt.Sprintf("smtp://%s:%d, helo:%q, auth:%v, tls:%v, starttls:%v, insecureSkipVerify:%v, timeout:%v, content-type:%q, charset:%q",
		em.host, em.port, em.effectiveHELOHost(), em.smtpUserName != "", em.tls, em.starttls, em.insecureSkipVerify,
		em.timeOut, em.contentType, em.contentCharset)
}

func (em *Sender) effectiveHELOHost() string {
	if em.smtpClient != nil {
		return "client-managed"
	}
	if em.heloHost == "" {
		return "localhost"
	}
	return em.heloHost
}

// client makes smtp client with the connection bound to ctx: it is closed as soon as ctx is done,
// which is the only way to interrupt net/smtp calls as they take no context.
// Returned stop function releases that binding and has to be called when the client is not needed anymore.
func (em *Sender) client(ctx context.Context) (c *smtp.Client, stop func(), err error) {
	srvAddress := net.JoinHostPort(em.host, strconv.Itoa(em.port))
	// #nosec G402
	tlsConf := &tls.Config{
		InsecureSkipVerify: em.insecureSkipVerify, // #nosec G402
		ServerName:         em.host,
		MinVersion:         tls.VersionTLS12,
	}

	dialer := &net.Dialer{Timeout: em.timeOut}

	var conn net.Conn
	if em.tls {
		if conn, err = (&tls.Dialer{NetDialer: dialer, Config: tlsConf}).DialContext(ctx, "tcp", srvAddress); err != nil {
			return nil, nil, fmt.Errorf("failed to dial smtp tls to %s: %w", srvAddress, err)
		}
	} else {
		if conn, err = dialer.DialContext(ctx, "tcp", srvAddress); err != nil {
			return nil, nil, fmt.Errorf("timeout connecting to %s: %w", srvAddress, err)
		}
	}

	// closing the connection is the only way to interrupt net/smtp calls, as they take no context
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	var stopOnce sync.Once
	stop = func() { stopOnce.Do(func() { close(watchDone) }) }

	if deadline, ok := ctx.Deadline(); ok {
		if e := conn.SetDeadline(deadline); e != nil {
			em.logger.Logf("[WARN] can't set deadline on smtp connection to %s, %v", srvAddress, e)
		}
	}

	if c, err = smtp.NewClient(conn, em.host); err != nil {
		stop()
		_ = conn.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("failed to make smtp client for %s: %w", srvAddress, ctxErr)
		}
		if em.tls {
			return nil, nil, fmt.Errorf("failed to make smtp client for %s: %w", srvAddress, err)
		}
		return nil, nil, fmt.Errorf("failed to dial: %w", err)
	}

	if err = em.hello(c); err != nil {
		stop()
		_ = c.Close()
		return nil, nil, err
	}

	if !em.tls && em.starttls {
		if err = c.StartTLS(tlsConf); err != nil {
			stop()
			_ = c.Close()
			return nil, nil, fmt.Errorf("failed to start tls: %w", err)
		}
	}

	return c, stop, nil
}

func (em *Sender) hello(client *smtp.Client) error {
	if em.heloHost == "" {
		return nil
	}
	if err := client.Hello(em.heloHost); err != nil {
		return fmt.Errorf("failed to send SMTP greeting: %w", err)
	}
	return nil
}

// auth returns an smtp.Auth that implements SMTP authentication mechanism
// depends on Sender settings.
func (em *Sender) auth() smtp.Auth {
	if em.smtpUserName == "" || em.smtpPassword == "" {
		return nil // no auth
	}

	if em.authMethod == authMethodLogin {
		return newLoginAuth(em.smtpUserName, em.smtpPassword, em.host)
	}
	return smtp.PlainAuth("", em.smtpUserName, em.smtpPassword, em.host)
}

// validateHeaders rejects user-provided values which would break out of the header they are put into.
// CR and LF allow injecting arbitrary headers and message body, i.e. sending a different email than the caller intended.
func (params Params) validateHeaders() error {
	check := func(name, value string) error {
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("invalid %s header value %q: contains CR or LF", name, value)
		}
		return nil
	}

	for _, h := range [][2]string{
		{"From", params.From},
		{"Subject", params.Subject},
		{"List-Unsubscribe", params.UnsubscribeLink},
		{"In-reply-to", params.InReplyTo},
	} {
		if err := check(h[0], h[1]); err != nil {
			return err
		}
	}

	for _, to := range params.To {
		if err := check("To", to); err != nil {
			return err
		}
	}
	return nil
}

// buildMessage makes the complete message, headers and body, in a single buffer the caller sends as is
func (em *Sender) buildMessage(text string, params Params) (*bytes.Buffer, error) {
	if err := params.validateHeaders(); err != nil {
		return nil, err
	}

	buff := &bytes.Buffer{}
	addHeader := func(h, v string) {
		fmt.Fprintf(buff, "%s: %s\n", h, v)
	}

	// body writers are made upfront because the boundaries they pick are needed in the headers,
	// they write nothing until used, i.e. after all the headers are in the buffer
	qp := quotedprintable.NewWriter(buff)
	mpMixed := multipart.NewWriter(buff)
	boundaryMixed := mpMixed.Boundary()
	mpRelated := multipart.NewWriter(buff)
	boundaryRelated := mpRelated.Boundary()

	addHeader("From", params.From)
	addHeader("To", strings.Join(params.To, ","))
	addHeader("Subject", mime.BEncoding.Encode("utf-8", params.Subject))

	if params.UnsubscribeLink != "" {
		addHeader("List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
		addHeader("List-Unsubscribe", "<"+params.UnsubscribeLink+">")
	}

	if params.InReplyTo != "" {
		addHeader("In-reply-to", "<"+params.InReplyTo+">")
	}

	withAttachments := len(params.Attachments) > 0
	withInlineImg := len(params.InlineImages) > 0

	if em.contentType != "" || withAttachments || withInlineImg {
		addHeader("MIME-version", "1.0")
	}

	addHeader("Date", em.timeNow().Format(time.RFC1123Z))

	if withAttachments {
		addHeader("Content-Type", fmt.Sprintf("multipart/mixed; boundary=%q\r\n\r\n%s\r",
			boundaryMixed, "--"+boundaryMixed))
	}

	if withInlineImg {
		addHeader("Content-Type", fmt.Sprintf("multipart/related; boundary=%q\r\n\r\n%s\r",
			boundaryRelated, "--"+boundaryRelated))
	}

	if em.contentType != "" {
		addHeader("Content-Transfer-Encoding", "quoted-printable")
		addHeader("Content-Type", fmt.Sprintf("%s; charset=%q", em.contentType, em.contentCharset))
	}

	buff.WriteString("\n") // empty line between the headers and the body

	if err := em.writeBody(qp, text); err != nil {
		return nil, fmt.Errorf("failed to write body: %w", err)
	}

	if withInlineImg {
		buff.WriteString("\r\n\r\n")
		if err := em.writeFiles(mpRelated, params.InlineImages, "inline"); err != nil {
			return nil, fmt.Errorf("failed to write inline images: %w", err)
		}
	}

	if withAttachments {
		buff.WriteString("\r\n\r\n")
		if err := em.writeFiles(mpMixed, params.Attachments, "attachment"); err != nil {
			return nil, fmt.Errorf("failed to write attachments: %w", err)
		}
	}

	return buff, nil
}

func (em *Sender) writeBody(wc io.WriteCloser, text string) error {
	if _, err := wc.Write([]byte(text)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return nil
}

func (em *Sender) writeFiles(mp *multipart.Writer, files []string, disposition string) error {
	for _, attachment := range files {
		if err := em.writeFile(mp, attachment, disposition); err != nil {
			return err
		}
	}
	if err := mp.Close(); err != nil {
		return err
	}
	return nil
}

// writeFile adds a single file as a mime part, the file is closed on every return path
func (em *Sender) writeFile(mp *multipart.Writer, attachment, disposition string) (err error) {
	file, err := os.Open(filepath.Clean(attachment))
	if err != nil {
		return err
	}
	defer func() {
		if e := file.Close(); e != nil && err == nil {
			err = e
		}
	}()

	// we need first 512 bytes to detect file type, an empty file is fine and detected as plain text
	fTypeBuff := make([]byte, 512)
	n, err := file.Read(fTypeBuff)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("failed to read file type %q: %w", attachment, err)
	}
	fTypeBuff = fTypeBuff[:n] // file can be shorter than the buffer

	fName := filepath.Base(attachment)
	// CR and LF are legal in file names but would terminate the header the name goes into
	if strings.ContainsAny(fName, "\r\n") {
		return fmt.Errorf("invalid file name %q: contains CR or LF", attachment)
	}

	// the detected type is always parseable, it comes from a fixed set of sniffed types
	contentType, ctParams, _ := mime.ParseMediaType(http.DetectContentType(fTypeBuff))
	params := map[string]string{"name": fName}
	for k, v := range ctParams { // carries the charset of the text types over
		params[k] = v
	}

	// mime formatting quotes and encodes the file name, plain interpolation would let it break out of the header
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", mime.FormatMediaType(contentType, params))
	header.Set("Content-Transfer-Encoding", "base64")

	switch disposition {
	case "attachment", "inline":
		header.Set("Content-Disposition", mime.FormatMediaType(disposition, map[string]string{"filename": fName}))
	}
	if disposition == "inline" {
		header.Set("Content-ID", fmt.Sprintf("<%s>", fName))
	}

	writer, err := mp.CreatePart(header)
	if err != nil {
		return err
	}

	// set reader offset at the beginning of the file because we read first 512 bytes
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return err
	}

	encoder := base64.NewEncoder(base64.StdEncoding, &lineWrapper{w: writer, limit: base64LineLimit})
	if _, err = io.Copy(encoder, file); err != nil {
		return err
	}
	return encoder.Close()
}

// base64LineLimit is the maximum line length for base64 encoded mime parts, set by RFC 2045
const base64LineLimit = 76

// crlf is shared by the line wrapper to keep it from allocating a separator for every line
var crlf = []byte("\r\n")

// lineWrapper breaks the stream written to it into lines of limit characters, separated by CRLF.
// Base64 encoders produce a single unbroken line, which mime doesn't allow and strict relays reject.
type lineWrapper struct {
	w     io.Writer
	limit int
	n     int // characters already written to the current line
}

func (lw *lineWrapper) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if lw.n == lw.limit {
			if _, err := lw.w.Write(crlf); err != nil {
				return written, err
			}
			lw.n = 0
		}

		size := lw.limit - lw.n
		if size > len(p) {
			size = len(p)
		}
		n, err := lw.w.Write(p[:size])
		written += n
		lw.n += n
		if err != nil {
			return written, err
		}
		p = p[size:]
	}
	return written, nil
}

type nopLogger struct{}

func (nopLogger) Logf(_ string, _ ...any) {}
