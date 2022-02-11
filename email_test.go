package notify

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"testing"
	"time"

	"github.com/go-pkgz/email/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
}

func TestEmail_buildMessageWithMIME(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))

	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com\nSubject: subj\nContent-Transfer-Encoding: quoted-printable\nMIME-version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"", msg)
	assert.Contains(t, msg, "\n\nthis is a test\r\n12345", msg)
	assert.Contains(t, msg, "Date: ", msg)
}

func TestEmail_New(t *testing.T) {
	logBuff := bytes.NewBuffer(nil)
	logger := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		logBuff.WriteString(fmt.Sprintf(format, args...))
	}}

	s := NewSender("localhost", ContentType("text/html"), Port(123),
		TLS, Auth("user", "pass"), TimeOut(time.Second), Log(logger))
	require.NotNil(t, s)
	assert.Equal(t, "[INFO] new email sender created with host: localhost:123, tls: true, username: \"user\", timeout: 1s",
		logBuff.String())
}

func TestEmail_Send(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(s string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient),
		Auth("user", "pass"), TimeOut(time.Second))

	s.timeNow = func() time.Time { return time.Date(2022, time.February, 10, 23, 33, 58, 0, time.UTC) }

	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)

	expBody := "From: from@example.com\nTo: to@example.com\nSubject: subj\nContent-Transfer-Encoding: quoted-printable\nMIME-version: 1.0\nContent-Type: text/html; charset=\"UTF-8\"\nDate: Thu, 10 Feb 2022 23:33:58 +0000\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())

	require.Equal(t, 1, len(smtpClient.MailCalls()))
	assert.Equal(t, "from@example.com", smtpClient.MailCalls()[0].From)

	require.Equal(t, 1, len(smtpClient.RcptCalls()))
	assert.Equal(t, "to@example.com", smtpClient.RcptCalls()[0].To)

	assert.Equal(t, 1, len(smtpClient.AuthCalls()))
	assert.Equal(t, 1, len(smtpClient.QuitCalls()))
	assert.Equal(t, 1, len(smtpClient.DataCalls()))

	assert.Equal(t, 0, len(smtpClient.CloseCalls()))
}

func TestEmail_SendFailedAuth(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return errors.New("auth error") },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(s string) error { return nil },
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
}

func TestEmail_SendFailedMakeClient(t *testing.T) {
	{
		s := NewSender("127.0.0.2", Port(12345), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err, "failed to make smtp client")
		assert.Contains(t, err.Error(),
			"failed to make smtp client: timeout connecting to 127.0.0.2:12345:")
	}

	{
		s := NewSender("127.0.0.1", Port(225), TLS, TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err)
	}
}

func TestEmail_SendFailed(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil), fail: true}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(s string) error { return nil },
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
