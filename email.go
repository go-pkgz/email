// Package notify provides email notifier
package notify

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"
)

//go:generate moq -out mocks/smpt_client.go -pkg mocks -skip-ensure -fmt goimports . SMTPClient
//go:generate moq -out mocks/logger.go -pkg mocks -skip-ensure -fmt goimports . Logger

// Sender implements email sender
type Sender struct {
	smtpClient   SMTPClient
	logger       Logger
	host         string // SMTP host
	port         int    // SMTP port
	contentType  string // Content type, optional. Will trigger MIME and Content-Type headers
	tls          bool   // TLS auth
	smtpUserName string // username
	smtpPassword string // password
	timeOut      time.Duration

	timeNow func() time.Time
}

// Params contains all user-defined parameters to send emails
type Params struct {
	From    string   // From email field
	To      []string // From email field
	Subject string   // Email subject
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
		smtpClient:   nil,
		logger:       nopLogger{},
		host:         smtpHost,
		port:         25,
		contentType:  `text/plain`,
		tls:          false,
		smtpUserName: "",
		smtpPassword: "",
		timeOut:      time.Second * 30,
		timeNow:      time.Now,
	}
	for _, opt := range options {
		opt(&res)
	}

	res.logger.Logf("[INFO] new email sender created with host: %s:%d, tls: %v, username: %q, timeout: %v",
		smtpHost, res.port, res.tls, res.smtpUserName, res.timeOut)
	return &res
}

// Send email with given text
// If SMTPClient defined in Email struct it will be used, if not - new smtp.Client on each send.
// Always closes client on completion or failure.
func (em *Sender) Send(text string, params Params) error {
	if len(params.To) == 0 {
		return nil
	}
	em.logger.Logf("[DEBUG] send %q to %v", text, params.To)
	client := em.smtpClient
	if client == nil { // if client not set make new net/smtp
		c, err := em.client()
		if err != nil {
			return fmt.Errorf("failed to make smtp client: %w", err)
		}
		client = c
	}

	var quit bool
	defer func() {
		if quit { // quit set if Quit() call passed because it's closing connection as well.
			return
		}
		if err := client.Close(); err != nil {
			em.logger.Logf("[WARN] can't close smtp connection, %v", err)
		}
	}()

	if em.smtpUserName != "" && em.smtpPassword != "" {
		auth := smtp.PlainAuth("", em.smtpUserName, em.smtpPassword, em.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("failed to auth to smtp %s:%d, %w", em.host, em.port, err)
		}
	}

	if err := client.Mail(params.From); err != nil {
		return fmt.Errorf("bad from address %q: %w", params.From, err)
	}

	for _, rcpt := range params.To {
		if err := client.Rcpt(rcpt); err != nil {
			return fmt.Errorf("bad to address %q: %w", params.To, err)
		}
	}

	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("can't make email writer: %w", err)
	}

	msg, err := em.buildMessage(text, params)
	if err != nil {
		return fmt.Errorf("can't make email message: %w", err)
	}
	buf := bytes.NewBufferString(msg)
	if _, err = buf.WriteTo(writer); err != nil {
		return fmt.Errorf("failed to send email body to %q: %w", params.To, err)
	}
	if err = writer.Close(); err != nil {
		em.logger.Logf("[WARN] can't close smtp body writer, %v", err)
	}

	if err = client.Quit(); err != nil {
		em.logger.Logf("[WARN] failed to send quit command to %s:%d, %v", em.host, em.port, err)
	} else {
		quit = true
	}
	return nil
}

func (em *Sender) client() (c *smtp.Client, err error) {
	srvAddress := fmt.Sprintf("%s:%d", em.host, em.port)
	if em.tls {
		tlsConf := &tls.Config{
			InsecureSkipVerify: false,
			ServerName:         em.host,
			MinVersion:         tls.VersionTLS12,
		}
		conn, e := tls.Dial("tcp", srvAddress, tlsConf)
		if e != nil {
			return nil, fmt.Errorf("failed to dial smtp tls to %s: %w", srvAddress, e)
		}
		if c, err = smtp.NewClient(conn, em.host); err != nil {
			return nil, fmt.Errorf("failed to make smtp client for %s: %w", srvAddress, err)
		}
		return c, nil
	}

	conn, err := net.DialTimeout("tcp", srvAddress, em.timeOut)
	if err != nil {
		return nil, fmt.Errorf("timeout connecting to %s: %w", srvAddress, err)
	}

	c, err = smtp.NewClient(conn, srvAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to dial: %w", err)
	}
	return c, nil
}

func (em *Sender) buildMessage(msg string, params Params) (message string, err error) {
	addHeader := func(msg, h, v string) string {
		msg += fmt.Sprintf("%s: %s\n", h, v)
		return msg
	}
	message = addHeader(message, "From", params.From)
	message = addHeader(message, "To", strings.Join(params.To, ","))
	message = addHeader(message, "Subject", params.Subject)
	message = addHeader(message, "Content-Transfer-Encoding", "quoted-printable")

	if em.contentType != "" {
		message = addHeader(message, "MIME-version", "1.0")
		message = addHeader(message, "Content-Type", em.contentType+`; charset="UTF-8"`)
	}
	message = addHeader(message, "Date", em.timeNow().Format(time.RFC1123Z))

	buff := &bytes.Buffer{}
	qp := quotedprintable.NewWriter(buff)
	if _, err := qp.Write([]byte(msg)); err != nil {
		return "", err
	}
	defer qp.Close()
	m := buff.String()
	message += "\n" + m
	return message, nil
}

type nopLogger struct{}

func (nopLogger) Logf(format string, args ...interface{}) {}