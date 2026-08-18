// Package email provides email sender
package email

import (
	"bytes"
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
	Logf(format string, args ...interface{})
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

// Send email with given text
// If SMTPClient set with the SMTP option it will be used, if not - new smtp.Client on each send.
// Always closes client on completion or failure.
func (em *Sender) Send(text string, params Params) error {
	em.logger.Logf("[DEBUG] send %q to %v", text, params.To)

	if len(params.To) == 0 {
		return errors.New("no recipients")
	}

	// message is built before the connection is made, this way a bad message doesn't reach the server at all
	msg, err := em.buildMessage(text, params)
	if err != nil {
		return fmt.Errorf("can't make email message: %w", err)
	}

	client := em.smtpClient
	if client == nil { // if client not set make new net/smtp
		c, e := em.client()
		if e != nil {
			return fmt.Errorf("failed to make smtp client: %w", e)
		}
		client = c
	}

	var quit bool
	defer func() {
		if quit || client == nil { // quit set if Quit() call passed because it's closing connection as well.
			return
		}
		if e := client.Close(); e != nil {
			em.logger.Logf("[WARN] can't close smtp connection, %v", e)
		}
	}()

	if auth := em.auth(); auth != nil {
		if err = client.Auth(auth); err != nil {
			return fmt.Errorf("failed to auth to smtp %s:%d, %w", em.host, em.port, err)
		}
	}

	if err = client.Mail(extractEmailAddress(params.From)); err != nil {
		return fmt.Errorf("bad from address %q: %w", params.From, err)
	}

	for _, rcpt := range params.To {
		if err = client.Rcpt(extractEmailAddress(rcpt)); err != nil {
			return fmt.Errorf("bad to address %q: %w", params.To, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("can't make email writer: %w", err)
	}

	buf := bytes.NewBufferString(msg)
	if _, err = buf.WriteTo(writer); err != nil {
		return fmt.Errorf("failed to send email body to %q: %w", params.To, err)
	}
	// closing the writer reports the final response to the DATA command, i.e. the actual delivery result
	if err = writer.Close(); err != nil {
		return fmt.Errorf("failed to send email to %q: %w", params.To, err)
	}

	if err = client.Quit(); err != nil {
		em.logger.Logf("[WARN] failed to send quit command to %s:%d, %v", em.host, em.port, err)
	} else {
		quit = true
	}
	return nil
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

func (em *Sender) client() (c *smtp.Client, err error) {
	srvAddress := net.JoinHostPort(em.host, strconv.Itoa(em.port))
	// #nosec G402
	tlsConf := &tls.Config{
		InsecureSkipVerify: em.insecureSkipVerify, // #nosec G402
		ServerName:         em.host,
		MinVersion:         tls.VersionTLS12,
	}

	if em.tls {
		conn, e := tls.DialWithDialer(&net.Dialer{Timeout: em.timeOut}, "tcp", srvAddress, tlsConf)
		if e != nil {
			return nil, fmt.Errorf("failed to dial smtp tls to %s: %w", srvAddress, e)
		}
		if c, err = smtp.NewClient(conn, em.host); err != nil {
			return nil, fmt.Errorf("failed to make smtp client for %s: %w", srvAddress, err)
		}
		if err = em.hello(c); err != nil {
			_ = c.Close()
			return nil, err
		}
		return c, nil
	}

	conn, err := net.DialTimeout("tcp", srvAddress, em.timeOut)
	if err != nil {
		return nil, fmt.Errorf("timeout connecting to %s: %w", srvAddress, err)
	}

	c, err = smtp.NewClient(conn, em.host)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	if err = em.hello(c); err != nil {
		_ = c.Close()
		return nil, err
	}

	if em.starttls {
		if err = c.StartTLS(tlsConf); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("failed to start tls: %w", err)
		}
	}

	return c, nil
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

func (em *Sender) buildMessage(text string, params Params) (message string, err error) {
	if e := params.validateHeaders(); e != nil {
		return "", e
	}

	addHeader := func(msg, h, v string) string {
		msg += fmt.Sprintf("%s: %s\n", h, v)
		return msg
	}
	message = addHeader(message, "From", params.From)
	message = addHeader(message, "To", strings.Join(params.To, ","))
	message = addHeader(message, "Subject", mime.BEncoding.Encode("utf-8", params.Subject))

	if params.UnsubscribeLink != "" {
		message = addHeader(message, "List-Unsubscribe-Post", "List-Unsubscribe=One-Click")
		message = addHeader(message, "List-Unsubscribe", "<"+params.UnsubscribeLink+">")
	}

	if params.InReplyTo != "" {
		message = addHeader(message, "In-reply-to", "<"+params.InReplyTo+">")
	}

	withAttachments := len(params.Attachments) > 0
	withInlineImg := len(params.InlineImages) > 0

	if em.contentType != "" || withAttachments || withInlineImg {
		message = addHeader(message, "MIME-version", "1.0")
	}

	message = addHeader(message, "Date", em.timeNow().Format(time.RFC1123Z))

	buff := &bytes.Buffer{}
	qp := quotedprintable.NewWriter(buff)
	mpMixed := multipart.NewWriter(buff)
	boundaryMixed := mpMixed.Boundary()
	mpRelated := multipart.NewWriter(buff)
	boundaryRelated := mpRelated.Boundary()

	if withAttachments {
		message = addHeader(message, "Content-Type", fmt.Sprintf("multipart/mixed; boundary=%q\r\n\r\n%s\r",
			boundaryMixed, "--"+boundaryMixed))
	}

	if withInlineImg {
		message = addHeader(message, "Content-Type", fmt.Sprintf("multipart/related; boundary=%q\r\n\r\n%s\r",
			boundaryRelated, "--"+boundaryRelated))
	}

	if em.contentType != "" {
		message = addHeader(message, "Content-Transfer-Encoding", "quoted-printable")
		message = addHeader(message, "Content-Type", fmt.Sprintf("%s; charset=%q", em.contentType, em.contentCharset))

	}

	if err := em.writeBody(qp, text); err != nil {
		return "", fmt.Errorf("failed to write body: %w", err)
	}

	if withInlineImg {
		buff.WriteString("\r\n\r\n")
		if err := em.writeFiles(mpRelated, params.InlineImages, "inline"); err != nil {
			return "", fmt.Errorf("failed to write inline images: %w", err)
		}
	}

	if withAttachments {
		buff.WriteString("\r\n\r\n")
		if err := em.writeFiles(mpMixed, params.Attachments, "attachment"); err != nil {
			return "", fmt.Errorf("failed to write attachments: %w", err)
		}
	}

	m := buff.String()
	message += "\n" + m
	// returns base part of the file location
	return message, nil
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

	// we need first 512 bytes to detect file type
	fTypeBuff := make([]byte, 512)
	if _, err = file.Read(fTypeBuff); err != nil {
		return fmt.Errorf("failed to read file type %q: %w", attachment, err)
	}

	// remove null bytes in case file less than 512 bytes
	fTypeBuff = bytes.Trim(fTypeBuff, "\x00")
	fName := filepath.Base(attachment)
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", http.DetectContentType(fTypeBuff)+"; name=\""+fName+"\"")
	header.Set("Content-Transfer-Encoding", "base64")

	switch disposition {
	case "attachment":
		header.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fName))
	case "inline":
		header.Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", fName))
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

	encoder := base64.NewEncoder(base64.StdEncoding, writer)
	if _, err = io.Copy(encoder, file); err != nil {
		return err
	}
	return encoder.Close()
}

type nopLogger struct{}

func (nopLogger) Logf(_ string, _ ...interface{}) {}
