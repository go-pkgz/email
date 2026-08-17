package email

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/email/mocks"
)

func TestEmail_New(t *testing.T) {
	logBuff := bytes.NewBuffer(nil)
	logger := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		_, _ = fmt.Fprintf(logBuff, format, args...)
	}}

	s := NewSender("localhost", ContentType("text/html"), Port(123),
		TLS(true), STARTTLS(true), InsecureSkipVerify(true), Auth("user", "pass"), TimeOut(time.Second),
		Log(logger), Charset("blah"),
	)
	require.NotNil(t, s)
	assert.Equal(t, "[INFO] new email sender created with host: localhost:123, helo: \"localhost\", tls: true, insecureSkipVerify: true, username: \"user\", timeout: 1s, content type: \"text/html\", charset: \"blah\"",
		logBuff.String())

	assert.Equal(t, "localhost", s.host)
	assert.Equal(t, 123, s.port)
	assert.Equal(t, "user", s.smtpUserName)
	assert.Equal(t, "pass", s.smtpPassword)
	assert.Equal(t, authMethodPlain, s.authMethod)
	assert.Equal(t, time.Second, s.timeOut)
	assert.Equal(t, "text/html", s.contentType)
	assert.Equal(t, "blah", s.contentCharset)
	assert.Empty(t, s.heloHost)
	assert.True(t, s.tls)
	assert.True(t, s.starttls)
}

func TestEmail_NewHELOHost(t *testing.T) {
	tests := []struct {
		name          string
		options       []Option
		wantStored    string
		wantEffective string
	}{
		{name: "unset greets as localhost", wantEffective: "localhost"},
		{name: "explicit empty greets as localhost", options: []Option{HELOHost("")}, wantEffective: "localhost"},
		{name: "explicit hostname", options: []Option{HELOHost("client.example.net")}, wantStored: "client.example.net", wantEffective: "client.example.net"},
		{name: "explicit localhost", options: []Option{HELOHost("localhost")}, wantStored: "localhost", wantEffective: "localhost"},
		{name: "address literal", options: []Option{HELOHost("[192.0.2.10]")}, wantStored: "[192.0.2.10]", wantEffective: "[192.0.2.10]"},
		{name: "injected client owns greeting", options: []Option{SMTP(&mocks.SMTPClientMock{}), HELOHost("ignored.example.net")}, wantStored: "ignored.example.net", wantEffective: "client-managed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSender("localhost", tt.options...)
			assert.Equal(t, tt.wantStored, s.heloHost)
			assert.Equal(t, tt.wantEffective, s.effectiveHELOHost())
		})
	}
}

func TestEmail_ClientHELOHost(t *testing.T) {
	tests := []struct {
		name    string
		sender  func(host string, port int) *Sender
		wantCmd string
	}{
		{
			name: "explicit address literal",
			sender: func(host string, port int) *Sender {
				return NewSender(host, Port(port), HELOHost("[192.0.2.10]"))
			},
			wantCmd: "EHLO [192.0.2.10]",
		},
		{
			name: "explicit hostname",
			sender: func(host string, port int) *Sender {
				return NewSender(host, Port(port), HELOHost("client.example.net"))
			},
			wantCmd: "EHLO client.example.net",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
				if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
					return err
				}
				reader := bufio.NewReader(conn)
				cmd, err := readSMTPCommand(reader)
				if err != nil {
					return err
				}
				if cmd != tt.wantCmd {
					return fmt.Errorf("unexpected greeting %q, want %q", cmd, tt.wantCmd)
				}
				if writeErr := writeSMTPResponse(conn, "250 smtp.example.net"); writeErr != nil {
					return writeErr
				}
				return expectSMTPQuit(conn, reader)
			})

			client, err := tt.sender(host, port).client()
			require.NoError(t, err)
			require.NoError(t, client.Quit())
			waitSMTPTestServer(t, done)
		})
	}
}

// pins backward compatibility: a caller setting no HELOHost must greet exactly as before the option existed
func TestEmail_ClientWithoutHELOHostGreetsLocalhost(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO localhost" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "250 smtp.example.net"); writeErr != nil {
			return writeErr
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "MAIL FROM:<sender@example.com>" {
			return fmt.Errorf("unexpected mail command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "250 sender accepted"); err != nil {
			return err
		}
		return expectSMTPQuit(conn, reader)
	})

	client, err := NewSender(host, Port(port)).client()
	require.NoError(t, err)
	require.NoError(t, client.Mail("sender@example.com"))
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientHELOFallback(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected EHLO command %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "500 EHLO unavailable"); writeErr != nil {
			return writeErr
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "HELO client.example.net" {
			return fmt.Errorf("unexpected HELO command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(conn, reader)
	})

	sender := NewSender(host, Port(port), HELOHost("client.example.net"))
	client, err := sender.client()
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientHELOFailureClosesConnection(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		if _, err := readSMTPCommand(reader); err != nil {
			return err
		}
		if err := writeSMTPResponse(conn, "500 EHLO unavailable"); err != nil {
			return err
		}
		if _, err := readSMTPCommand(reader); err != nil {
			return err
		}
		if err := writeSMTPResponse(conn, "550 HELO rejected"); err != nil {
			return err
		}
		return expectSMTPConnectionClosed(conn, reader)
	})

	sender := NewSender(host, Port(port), HELOHost("client.example.net"))
	client, err := sender.client()
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send SMTP greeting")
	assert.Contains(t, err.Error(), "550")
	assert.Contains(t, err.Error(), "HELO rejected")
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientSTARTTLSFailureClosesConnection(t *testing.T) {
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if _, err = io.WriteString(conn, "250-smtp.example.net\r\n250 STARTTLS\r\n"); err != nil {
			return err
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "STARTTLS" {
			return fmt.Errorf("unexpected command %q", cmd)
		}
		if err := writeSMTPResponse(conn, "454 TLS unavailable"); err != nil {
			return err
		}
		return expectSMTPConnectionClosed(conn, reader)
	})

	sender := NewSender(host, Port(port), STARTTLS(true), HELOHost("client.example.net"))
	client, err := sender.client()
	if client != nil {
		_ = client.Close()
	}
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to start tls")
	assert.Contains(t, err.Error(), "454")
	assert.Contains(t, err.Error(), "TLS unavailable")
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientSTARTTLSReusesHELOHost(t *testing.T) {
	serverTLS := smtpTestTLSConfig(t)
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting before STARTTLS %q", cmd)
		}
		if _, err = io.WriteString(conn, "250-smtp.example.net\r\n250 STARTTLS\r\n"); err != nil {
			return err
		}
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "STARTTLS" {
			return fmt.Errorf("unexpected command %q", cmd)
		}
		if writeErr := writeSMTPResponse(conn, "220 ready for TLS"); writeErr != nil {
			return writeErr
		}

		tlsConn := tls.Server(conn, serverTLS)
		if handshakeErr := tlsConn.Handshake(); handshakeErr != nil {
			return handshakeErr
		}
		reader = bufio.NewReader(tlsConn)
		cmd, err = readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting after STARTTLS %q", cmd)
		}
		if err := writeSMTPResponse(tlsConn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(tlsConn, reader)
	})

	sender := NewSender(host, Port(port), STARTTLS(true), InsecureSkipVerify(true), HELOHost("client.example.net"))
	client, err := sender.client()
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_ClientTLSHELOHost(t *testing.T) {
	serverTLS := smtpTestTLSConfig(t)
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		tlsConn := tls.Server(conn, serverTLS)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		if err := writeSMTPResponse(tlsConn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(tlsConn)
		cmd, err := readSMTPCommand(reader)
		if err != nil {
			return err
		}
		if cmd != "EHLO client.example.net" {
			return fmt.Errorf("unexpected greeting %q", cmd)
		}
		if err := writeSMTPResponse(tlsConn, "250 smtp.example.net"); err != nil {
			return err
		}
		return expectSMTPQuit(tlsConn, reader)
	})

	sender := NewSender(host, Port(port), TLS(true), InsecureSkipVerify(true), HELOHost("client.example.net"))
	client, err := sender.client()
	require.NoError(t, err)
	require.NoError(t, client.Quit())
	waitSMTPTestServer(t, done)
}

func TestEmail_Send(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"), TimeOut(time.Second), HELOHost("ignored.example.net"))

	s.timeNow = func() time.Time { return time.Date(2022, time.February, 10, 23, 33, 58, 0, time.UTC) }

	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)

	expBody := "From: from@example.com\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0\nDate: Thu, 10 Feb 2022 23:33:58 +0000\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())

	require.Len(t, smtpClient.MailCalls(), 1)
	assert.Equal(t, "from@example.com", smtpClient.MailCalls()[0].From)

	require.Len(t, smtpClient.RcptCalls(), 1)
	assert.Equal(t, "to@example.com", smtpClient.RcptCalls()[0].To)

	assert.Len(t, smtpClient.AuthCalls(), 1)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.DataCalls(), 1)

	assert.Empty(t, smtpClient.CloseCalls(), "not called because quit is called")
}

func TestEmail_SendWithDisplayName(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"), TimeOut(time.Second))

	s.timeNow = func() time.Time { return time.Date(2022, time.February, 10, 23, 33, 58, 0, time.UTC) }

	err := s.Send("some text\n", Params{
		From:    `"John Doe" <john@example.com>`,
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)

	expBody := "From: \"John Doe\" <john@example.com>\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0\nDate: Thu, 10 Feb 2022 23:33:58 +0000\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())
	assert.Equal(t, "john@example.com", smtpClient.MailCalls()[0].From)
}

func TestEmail_LoginAuth(t *testing.T) {
	s := NewSender("localhost", Auth("user", "pass"), LoginAuth())
	auth := s.auth()
	proto, _, err := auth.Start(&smtp.ServerInfo{Name: "localhost"})

	require.NoError(t, err)
	assert.Equal(t, "LOGIN", proto)
}

func TestEmail_SendFailedAuth(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return errors.New("auth error") },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.EqualError(t, err, "failed to auth to smtp localhost:25, auth error")
	assert.Len(t, smtpClient.AuthCalls(), 1)
	assert.Empty(t, smtpClient.QuitCalls())
	assert.Len(t, smtpClient.CloseCalls(), 1, "called because quit is not called before")
}

func TestEmail_SendFailedQUIT(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.CloseCalls(), 1)
}

func TestEmail_SendFailedCLOSE(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return errors.New("close error") },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(_ string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Len(t, smtpClient.QuitCalls(), 1)
	assert.Len(t, smtpClient.CloseCalls(), 1)
}

func TestEmail_SendFailedRCPTO(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(_ string) error { return errors.New("RCPT error") },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.EqualError(t, err, "bad to address [\"to@example.com\"]: RCPT error")
	assert.Len(t, smtpClient.RcptCalls(), 1)
}

func TestEmail_SendFailedMakeClient(t *testing.T) {
	{
		s := NewSender("198.18.0.254", Port(12345), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err, "failed to make smtp client")
		assert.Contains(t, err.Error(), "i/o timeout")
	}

	{
		s := NewSender("198.18.0.254", Port(225), TLS(true), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err, "failed to make smtp client")
		assert.Contains(t, err.Error(), "i/o timeout")
	}
}

func TestEmail_SendFailed(t *testing.T) {

	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil), fail: true}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "failed to send email body to [\"to@example.com\"]: write error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return errors.New("mail error") },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "bad from address \"from@example.com\": mail error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, errors.New("data error") },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.EqualError(t, err, "can't make email writer: data error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(_ smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(_ string) error { return nil },
			DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
		}

		s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
		err := s.Send("some text\n", Params{
			From:    "from@example.com",
			To:      []string{},
			Subject: "subj",
		})
		require.EqualError(t, err, "no recipients")
	}
}

func TestEmail_buildMessage(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}
	e := NewSender("localhost", Log(l))
	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com", "to2@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com,to2@example.com\nSubject: subj\n", msg)
	assert.Contains(t, msg, "this is a test\r\n12345", msg)
	assert.Contains(t, msg, "Date: ", msg)
	assert.Contains(t, msg, "Content-Transfer-Encoding: quoted-printable", msg)

	tree := parseMIMETree(t, msg)
	assert.Equal(t, "text/plain", tree.mediaType)
	assert.Empty(t, tree.children)
}

func TestEmail_buildMessageWithMIME(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))

	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:            "from@example.com",
		To:              []string{"to@example.com"},
		Subject:         "non-ascii symbols: Привет",
		UnsubscribeLink: "https://example.com/unsubscribe",
		InReplyTo:       "uuid@example.com",
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "Content-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"", msg)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com\nSubject: =?utf-8?b?bm9uLWFzY2lpIHN5bWJvbHM6INCf0YDQuNCy0LXRgg==?=\nList-Unsubscribe-Post: List-Unsubscribe=One-Click\nList-Unsubscribe: <https://example.com/unsubscribe>\nIn-reply-to: <uuid@example.com>\nMIME-version: 1.0", msg)
	assert.Contains(t, msg, "\n\nthis is a test\r\n12345\r\n", msg)
	assert.Contains(t, msg, "Date: ", msg)
}

func TestEmail_buildMessageWithMIMEAndAttachments(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
	})
	require.NoError(t, err)
	tree := parseMIMETree(t, msg)
	require.Equal(t, "multipart/mixed", tree.mediaType)
	body, ok := tree.firstChild("text/html")
	require.True(t, ok, "html body part present under mixed")
	assert.Empty(t, body.disposition)
	assert.Len(t, tree.childrenByDisposition("attachment"), 3)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"1.txt\"", msg)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"2.txt\"", msg)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"image.jpg\"", msg)

	fData1, err := os.ReadFile("testdata/1.txt")
	require.NoError(t, err)
	fData2, err := os.ReadFile("testdata/2.txt")
	require.NoError(t, err)
	fData3, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)

	b1 := make([]byte, base64.StdEncoding.EncodedLen(len(fData1)))
	base64.StdEncoding.Encode(b1, fData1)
	b2 := make([]byte, base64.StdEncoding.EncodedLen(len(fData2)))
	base64.StdEncoding.Encode(b2, fData2)
	b3 := make([]byte, base64.StdEncoding.EncodedLen(len(fData3)))
	base64.StdEncoding.Encode(b3, fData3)
	assert.Contains(t, msg, string(b1), msg)
	assert.Contains(t, msg, string(b2), msg)
	assert.Contains(t, msg, string(b3), msg)
}

func TestEmail_buildMessageWithMIMEAndWrongAttachments(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/1.txt", "testdata/2.txt", "does/not/exist/1.txt"},
	})
	require.Error(t, err)
	require.Equal(t, "failed to write attachments: "+
		"open does/not/exist/1.txt: no such file or directory", err.Error())
	require.Empty(t, msg)

	msg, err = e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/nullfile"},
	})
	require.Error(t, err)
	require.Equal(t, "failed to write attachments: failed to read file type \"testdata/nullfile\": EOF",
		err.Error())
	require.Empty(t, msg)
}

func TestEmail_buildMessageWithMIMEAndInlineImages(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with inline images</div><div><img src=\"cid:image.jpg\"></div>\n", Params{
		From:         "from@example.com",
		To:           []string{"to@example.com"},
		Subject:      "test email with attachments",
		InlineImages: []string{"testdata/image.jpg"},
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "MIME-version: 1.0", msg)
	tree := parseMIMETree(t, msg)
	require.Equal(t, "multipart/related", tree.mediaType)
	body, ok := tree.firstChild("text/html")
	require.True(t, ok, "html body part present under related")
	assert.Empty(t, body.disposition)
	img, ok := tree.firstChild("image/jpeg")
	require.True(t, ok, "inline image part present under related")
	assert.Equal(t, "inline", img.disposition)
	assert.Equal(t, "<image.jpg>", img.contentID)
	assert.Contains(t, msg, "Content-Disposition: inline; filename=\"image.jpg\"", msg)
	assert.Contains(t, msg, "Content-Id: <image.jpg>", msg)
	assert.Contains(t, msg, "Content-Transfer-Encoding: base64", msg)
	fData, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)

	b := make([]byte, base64.StdEncoding.EncodedLen(len(fData)))
	base64.StdEncoding.Encode(b, fData)
	assert.Contains(t, msg, string(b), msg)
}

func TestEmail_buildMessageWithMIMEAndAttachmentsAndInlineImages(t *testing.T) {
	l := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		fmt.Printf(format, args...)
		fmt.Printf("\n")
	}}

	e := NewSender("localhost", ContentType("text/html"),
		Port(2525),
		Log(l))

	msg, err := e.buildMessage("<div>this is a test mail with inline images</div><div><img src=\"cid:image.jpg\"></div>\n", Params{
		From:         "from@example.com",
		To:           []string{"to@example.com"},
		Subject:      "test email with attachments",
		Attachments:  []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
		InlineImages: []string{"testdata/image.jpg"},
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "MIME-version: 1.0", msg)
	tree := parseMIMETree(t, msg)
	require.Equal(t, "multipart/mixed", tree.mediaType)
	related, ok := tree.firstChild("multipart/related")
	require.True(t, ok, "related subtree present under mixed")
	htmlBody, ok := related.firstChild("text/html")
	require.True(t, ok, "html body inside related")
	assert.Empty(t, htmlBody.disposition)
	img, ok := related.firstChild("image/jpeg")
	require.True(t, ok, "inline image inside related, not directly under mixed")
	assert.Equal(t, "inline", img.disposition)
	assert.Equal(t, "<image.jpg>", img.contentID)
	assert.Len(t, tree.childrenByDisposition("attachment"), 3)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"1.txt\"", msg)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"2.txt\"", msg)
	assert.Contains(t, msg, "Content-Disposition: attachment; filename=\"image.jpg\"", msg)
	assert.Contains(t, msg, "Content-Disposition: inline; filename=\"image.jpg\"", msg)
	assert.Contains(t, msg, "Content-Id: <image.jpg>", msg)
	assert.Contains(t, msg, "Content-Transfer-Encoding: base64", msg)

	fData1, err := os.ReadFile("testdata/1.txt")
	require.NoError(t, err)
	fData2, err := os.ReadFile("testdata/2.txt")
	require.NoError(t, err)
	fData3, err := os.ReadFile("testdata/image.jpg")
	require.NoError(t, err)

	b1 := make([]byte, base64.StdEncoding.EncodedLen(len(fData1)))
	base64.StdEncoding.Encode(b1, fData1)
	b2 := make([]byte, base64.StdEncoding.EncodedLen(len(fData2)))
	base64.StdEncoding.Encode(b2, fData2)
	b3 := make([]byte, base64.StdEncoding.EncodedLen(len(fData3)))
	base64.StdEncoding.Encode(b3, fData3)
	assert.Contains(t, msg, string(b1), msg)
	assert.Contains(t, msg, string(b2), msg)
	assert.Contains(t, msg, string(b3), msg)
}

func TestWriteAttachmentsFailed(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{fail: true}
	mp := multipart.NewWriter(wc)
	err := e.writeFiles(mp, []string{"testdata/1.txt"}, "attachment")
	require.Error(t, err)
}

func TestWriteBody(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{buff: &bytes.Buffer{}}
	err := e.writeBody(wc, "this is a test 12345")
	require.NoError(t, err)
	assert.Equal(t, "this is a test 12345", wc.buff.String())
}

func TestWriteBodyFail(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{fail: true}
	err := e.writeBody(wc, "this is a test 12345")
	require.Error(t, err)
}

func TestSender_String(t *testing.T) {
	e := NewSender("localhost", ContentType("text/html"), Port(2525), Auth("user", "pass"))
	assert.Equal(t, `smtp://localhost:2525, helo:"localhost", auth:true, tls:false, starttls:false, insecureSkipVerify:false, timeout:30s, content-type:"text/html", charset:"UTF-8"`,
		e.String())

	e = NewSender("localhost", ContentType("text/html"), Port(2525), TLS(true), STARTTLS(true), InsecureSkipVerify(true),
		TimeOut(10*time.Second), HELOHost("client.example.net"))
	assert.Equal(t, `smtp://localhost:2525, helo:"client.example.net", auth:false, tls:true, starttls:true, insecureSkipVerify:true, timeout:10s, content-type:"text/html", charset:"UTF-8"`,
		e.String())

	e = NewSender("localhost", SMTP(&mocks.SMTPClientMock{}))
	assert.Equal(t, `smtp://localhost:25, helo:"client-managed", auth:false, tls:false, starttls:false, insecureSkipVerify:false, timeout:30s, content-type:"text/plain", charset:"UTF-8"`, e.String())
}

// uncomment to debug with real smtp server
// func TestSendIntegration(t *testing.T) {
//	client := NewSender("localhost", ContentType("text/html"), Port(2525))
//	err := client.Send("<html><div>some content, foo bar</div>\n<div><img src=\"cid:image.jpg\"/>\n</div></html>",
//		Params{From: "me@example.com", To: []string{"to@example.com"}, Subject: "Hello world!",
//			Attachments: []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"},
//			InlineImages: []string{"testdata/image.jpg"},
//		})
//	require.NoError(t, err)
// }

type fakeWriterCloser struct {
	buff *bytes.Buffer
	fail bool
}

func (wc *fakeWriterCloser) Write(p []byte) (n int, err error) {
	if wc.fail {
		return 0, errors.New("write error")
	}
	return wc.buff.Write(p)
}

func (wc *fakeWriterCloser) Close() error {
	return nil
}

func startSMTPTestServer(t *testing.T, handler func(net.Conn) error) (host string, port int, done <-chan error) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	result := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		result <- handler(conn)
	}()

	address := listener.Addr().(*net.TCPAddr)
	return address.IP.String(), address.Port, result
}

func waitSMTPTestServer(t *testing.T, done <-chan error) {
	t.Helper()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for SMTP test server")
	}
}

func readSMTPCommand(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"), nil
}

func writeSMTPResponse(conn net.Conn, response string) error {
	_, err := io.WriteString(conn, response+"\r\n")
	return err
}

func expectSMTPQuit(conn net.Conn, reader *bufio.Reader) error {
	cmd, err := readSMTPCommand(reader)
	if err != nil {
		return err
	}
	if cmd != "QUIT" {
		return fmt.Errorf("unexpected command %q, want QUIT", cmd)
	}
	return writeSMTPResponse(conn, "221 bye")
}

func expectSMTPConnectionClosed(conn net.Conn, reader *bufio.Reader) error {
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	_, err := reader.ReadByte()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("SMTP connection remained open")
	}
	return fmt.Errorf("waiting for SMTP connection close: %w", err)
}

func smtpTestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "smtp.example.net"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)

	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: privateKey}},
		MinVersion:   tls.VersionTLS12,
	}
}

func TestExtractEmailAddress(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"bare email", "john@example.com", "john@example.com"},
		{"with display name quoted", `"John Doe" <john@example.com>`, "john@example.com"},
		{"with display name unquoted", "John Doe <john@example.com>", "john@example.com"},
		{"angle brackets only", "<john@example.com>", "john@example.com"},
		{"with leading whitespace", "  john@example.com", "john@example.com"},
		{"with trailing whitespace", "john@example.com  ", "john@example.com"},
		{"display name with whitespace", "  \"John Doe\" <john@example.com>  ", "john@example.com"},
		{"invalid email returns original", "not-an-email", "not-an-email"},
		{"empty string returns original", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractEmailAddress(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// mimeNode is a parsed MIME part, used to assert message structure in tests
type mimeNode struct {
	mediaType   string
	disposition string
	contentID   string
	children    []mimeNode
}

// firstChild returns the first direct child with the given media type
func (n mimeNode) firstChild(mediaType string) (mimeNode, bool) {
	for _, c := range n.children {
		if c.mediaType == mediaType {
			return c, true
		}
	}
	return mimeNode{}, false
}

// childrenByDisposition returns the direct children with the given content-disposition
func (n mimeNode) childrenByDisposition(disposition string) []mimeNode {
	res := make([]mimeNode, 0, len(n.children))
	for _, c := range n.children {
		if c.disposition == disposition {
			res = append(res, c)
		}
	}
	return res
}

// parseMIMETree parses a raw email message and returns its MIME part tree,
// failing the test if the message or any part is not well-formed
func parseMIMETree(t *testing.T, raw string) mimeNode {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	require.NoError(t, err)
	return readMIMENode(t, m.Header.Get("Content-Type"), "", "", m.Body)
}

func readMIMENode(t *testing.T, contentType, disposition, contentID string, body io.Reader) mimeNode {
	t.Helper()
	mediaType, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	node := mimeNode{mediaType: mediaType, disposition: disposition, contentID: contentID}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return node
	}
	mr := multipart.NewReader(body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		disp := ""
		if d := p.Header.Get("Content-Disposition"); d != "" {
			disp, _, _ = mime.ParseMediaType(d)
		}
		node.children = append(node.children, readMIMENode(t, p.Header.Get("Content-Type"), disp, p.Header.Get("Content-Id"), p))
	}
	return node
}
