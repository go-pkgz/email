package email

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/smtp"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/email/mocks"
)

func TestEmail_New(t *testing.T) {
	logBuff := bytes.NewBuffer(nil)
	logger := &mocks.LoggerMock{LogfFunc: func(format string, args ...interface{}) {
		logBuff.WriteString(fmt.Sprintf(format, args...))
	}}

	s := NewSender("localhost", ContentType("text/html"), Port(123),
		TLS(true), STARTTLS(true), Auth("user", "pass"), TimeOut(time.Second),
		Log(logger), Charset("blah"),
	)
	require.NotNil(t, s)
	assert.Equal(t, "[INFO] new email sender created with host: localhost:123, tls: true, username: \"user\", timeout: 1s, content type: \"text/html\", charset: \"blah\"",
		logBuff.String())

	assert.Equal(t, "localhost", s.host)
	assert.Equal(t, 123, s.port)
	assert.Equal(t, "user", s.smtpUserName)
	assert.Equal(t, "pass", s.smtpPassword)
	assert.Equal(t, time.Second, s.timeOut)
	assert.Equal(t, "text/html", s.contentType)
	assert.Equal(t, "blah", s.contentCharset)
	assert.Equal(t, true, s.tls)
	assert.True(t, s.starttls)
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

	expBody := "From: from@example.com\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0\nDate: Thu, 10 Feb 2022 23:33:58 +0000\nContent-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"\n\nsome text\r\n"
	assert.Equal(t, expBody, wc.buff.String())

	require.Equal(t, 1, len(smtpClient.MailCalls()))
	assert.Equal(t, "from@example.com", smtpClient.MailCalls()[0].From)

	require.Equal(t, 1, len(smtpClient.RcptCalls()))
	assert.Equal(t, "to@example.com", smtpClient.RcptCalls()[0].To)

	assert.Equal(t, 1, len(smtpClient.AuthCalls()))
	assert.Equal(t, 1, len(smtpClient.QuitCalls()))
	assert.Equal(t, 1, len(smtpClient.DataCalls()))

	assert.Equal(t, 0, len(smtpClient.CloseCalls()), "not called because quit is called")
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
	assert.Equal(t, 1, len(smtpClient.AuthCalls()))
	assert.Equal(t, 0, len(smtpClient.QuitCalls()))
	assert.Equal(t, 1, len(smtpClient.CloseCalls()), "called because quit is not called before")
}

func TestEmail_SendFailedQUIT(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(s string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, len(smtpClient.QuitCalls()))
	assert.Equal(t, 1, len(smtpClient.CloseCalls()))
}

func TestEmail_SendFailedCLOSE(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return nil },
		CloseFunc: func() error { return errors.New("close error") },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return errors.New("quit error") },
		RcptFunc:  func(s string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, len(smtpClient.QuitCalls()))
	assert.Equal(t, 1, len(smtpClient.CloseCalls()))
}

func TestEmail_SendFailedRCPTO(t *testing.T) {
	wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
	smtpClient := &mocks.SMTPClientMock{
		AuthFunc:  func(auth smtp.Auth) error { return nil },
		CloseFunc: func() error { return nil },
		MailFunc:  func(string) error { return nil },
		QuitFunc:  func() error { return nil },
		RcptFunc:  func(s string) error { return errors.New("RCPT error") },
		DataFunc:  func() (io.WriteCloser, error) { return wc, nil },
	}

	s := NewSender("localhost", ContentType("text/html"), SMTP(smtpClient))
	err := s.Send("some text\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.Error(t, err)
	assert.EqualError(t, err, "bad to address [\"to@example.com\"]: RCPT error")
	assert.Equal(t, 1, len(smtpClient.RcptCalls()))
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
		s := NewSender("127.0.0.1", Port(225), TLS(true), TimeOut(time.Millisecond*200))
		err := s.Send("some text", Params{
			From:    "from@example.com",
			To:      []string{"to@example.com"},
			Subject: "subj",
		})
		require.Error(t, err)
	}
}

func TestEmail_SendFailed(t *testing.T) {

	{
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
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(auth smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return errors.New("mail error") },
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
		require.EqualError(t, err, "bad from address \"from@example.com\": mail error")
	}
	{
		wc := &fakeWriterCloser{buff: bytes.NewBuffer(nil)}
		smtpClient := &mocks.SMTPClientMock{
			AuthFunc:  func(auth smtp.Auth) error { return nil },
			CloseFunc: func() error { return nil },
			MailFunc:  func(string) error { return nil },
			QuitFunc:  func() error { return nil },
			RcptFunc:  func(s string) error { return nil },
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
}

func TestEmail_buildMessageWithMIME(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))

	msg, err := e.buildMessage("this is a test\n12345\n", Params{
		From:    "from@example.com",
		To:      []string{"to@example.com"},
		Subject: "subj",
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "Content-Transfer-Encoding: quoted-printable\nContent-Type: text/html; charset=\"UTF-8\"", msg)
	assert.Contains(t, msg, "From: from@example.com\nTo: to@example.com\nSubject: subj\nMIME-version: 1.0", msg)
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
	assert.Contains(t, msg, "Content-Type", "multipart/mixed; boundary=", msg)
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
	require.Equal(t, "", msg)

	msg, err = e.buildMessage("<div>this is a test mail with attachments\\n12345</div>\\n", Params{
		From:        "from@example.com",
		To:          []string{"to@example.com"},
		Subject:     "test email with attachments",
		Attachments: []string{"testdata/nullfile"},
	})
	require.Error(t, err)
	require.Equal(t, "failed to write attachments: failed to read file type \"testdata/nullfile\": EOF",
		err.Error())
	require.Equal(t, "", msg)
}

func TestWriteAttachmentsFailed(t *testing.T) {

	e := NewSender("localhost", ContentType("text/html"))
	wc := &fakeWriterCloser{fail: true}
	mp := multipart.NewWriter(wc)
	err := e.writeAttachments(mp, []string{"testdata/1.txt"})
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

// uncomment to debug with real smtp server
// func TestSendIntegration(t *testing.T) {
//	client := NewSender("localhost", ContentType("text/html"), Port(2525))
//	err := client.Send("<html>some content, foo bar</html>",
//		Params{From: "me@example.com", To: []string{"to@example.com"}, Subject: "Hello world!",
//			Attachments: []string{"testdata/1.txt", "testdata/2.txt", "testdata/image.jpg"}})
//	require.NoError(t, err)
//}

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
