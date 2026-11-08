package email

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pkgz/email/mocks"
)

func TestEmail_SendBatch(t *testing.T) {
	var delivered []string
	var resets int
	host, port, done := startSMTPTestServer(t, func(conn net.Conn) error {
		if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
			return err
		}
		reader := bufio.NewReader(conn)
		inTransaction, rcpt := false, ""
		for {
			cmd, err := readSMTPCommand(reader)
			if err != nil {
				return err
			}
			response := "250 ok"
			switch {
			case strings.HasPrefix(cmd, "MAIL FROM:"):
				if inTransaction {
					response = "503 nested MAIL command"
					break
				}
				inTransaction = true
			case strings.HasPrefix(cmd, "RCPT TO:"):
				rcpt = strings.TrimSuffix(strings.TrimPrefix(cmd, "RCPT TO:<"), ">")
				if rcpt == "unknown@example.com" {
					response = "550 no such user"
				}
			case cmd == "RSET":
				inTransaction, rcpt = false, ""
				resets++
			case cmd == "DATA":
				if e := writeSMTPResponse(conn, "354 send the message"); e != nil {
					return e
				}
				for {
					line, e := readSMTPCommand(reader)
					if e != nil {
						return e
					}
					if line == "." {
						break
					}
				}
				delivered = append(delivered, rcpt)
				inTransaction, rcpt = false, ""
				response = "250 queued"
			case cmd == "QUIT":
				return writeSMTPResponse(conn, "221 bye")
			}
			if err := writeSMTPResponse(conn, response); err != nil {
				return err
			}
		}
	})

	sender := NewSender(host, Port(port), TimeOut(time.Second*3))
	err := sender.SendBatch(context.Background(), []Message{
		{Text: "first", Params: Params{From: "from@example.com", To: []string{"one@example.com"}, Subject: "subj"}},
		{Text: "second", Params: Params{From: "from@example.com", To: []string{"unknown@example.com"}, Subject: "subj"}},
		{Text: "third", Params: Params{From: "from@example.com", To: []string{"three@example.com"}, Subject: "subj"}},
	})
	waitSMTPTestServer(t, done)

	var batchErr *BatchError
	require.ErrorAs(t, err, &batchErr)
	require.Len(t, batchErr.Errs, 3)
	require.NoError(t, batchErr.Errs[0])
	require.Error(t, batchErr.Errs[1])
	var reply *textproto.Error
	require.ErrorAs(t, err, &reply, "errors.As looks into the batch")
	assert.Equal(t, 550, reply.Code)
	require.NoError(t, batchErr.Errs[2], "the rejected message is followed by RSET, and the next one goes through")
	assert.Equal(t, []string{"one@example.com", "three@example.com"}, delivered)
	assert.Equal(t, 1, resets)
	assert.True(t, strings.HasPrefix(err.Error(), `failed to send 1 of 3 messages: message 1: bad to address ["unknown@example.com"]: 550`), err.Error())
}

type resettableClient struct {
	*mocks.SMTPClientMock
	*mocks.ResetterMock
}

func newResettableClient(client *mocks.SMTPClientMock, resetErr error) *resettableClient {
	return &resettableClient{SMTPClientMock: client, ResetterMock: &mocks.ResetterMock{ResetFunc: func() error { return resetErr }}}
}

// passingDeadlineCtx has its deadline passed once passed is set, while Err is still nil
type passingDeadlineCtx struct {
	context.Context
	passed atomic.Bool
}

func (c *passingDeadlineCtx) Deadline() (time.Time, bool) {
	if c.passed.Load() {
		return time.Now().Add(-time.Second), true
	}
	return time.Now().Add(time.Hour), true
}

func newBatchClientMock() *mocks.SMTPClientMock {
	return &mocks.SMTPClientMock{
		AuthFunc:  func(_ smtp.Auth) error { return nil },
		MailFunc:  func(string) error { return nil },
		RcptFunc:  func(string) error { return nil },
		DataFunc:  func() (io.WriteCloser, error) { return &fakeWriterCloser{buff: &bytes.Buffer{}}, nil },
		QuitFunc:  func() error { return nil },
		CloseFunc: func() error { return nil },
	}
}

func TestEmail_SendBatchWithClient(t *testing.T) {
	msg := func(to ...string) Message {
		return Message{Text: "text", Params: Params{From: "from@example.com", To: to, Subject: "subj"}}
	}
	rejected := &textproto.Error{Code: 550, Msg: "no such user"}

	t.Run("all sent with one auth and one quit", func(t *testing.T) {
		client := newBatchClientMock()
		sender := NewSender("localhost", SMTP(client), Auth("user", "passwd"))
		require.NoError(t, sender.SendBatch(context.Background(), []Message{msg("a@example.com"), msg("b@example.com"), msg("c@example.com")}))
		assert.Len(t, client.AuthCalls(), 1)
		assert.Len(t, client.MailCalls(), 3)
		assert.Len(t, client.DataCalls(), 3)
		assert.Len(t, client.QuitCalls(), 1)
		assert.Empty(t, client.CloseCalls(), "quit closes the connection")
	})

	t.Run("bad message skipped before any smtp command", func(t *testing.T) {
		client := newBatchClientMock()
		sender := NewSender("localhost", SMTP(client))
		bad := msg("b@example.com")
		bad.Params.Attachments = []string{"testdata/no-such-file"}
		err := sender.SendBatch(context.Background(), []Message{msg("a@example.com"), msg(), bad, msg("c@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.NoError(t, batchErr.Errs[0])
		require.EqualError(t, batchErr.Errs[1], "no recipients")
		require.ErrorContains(t, batchErr.Errs[2], "can't make email message")
		require.NoError(t, batchErr.Errs[3])
		assert.Len(t, client.MailCalls(), 2, "bad messages never reach the server")
		assert.Len(t, client.QuitCalls(), 1)
	})

	t.Run("rejected message reset and the batch goes on", func(t *testing.T) {
		mock := newBatchClientMock()
		mock.RcptFunc = func(to string) error {
			if to == "unknown@example.com" {
				return rejected
			}
			return nil
		}
		client := newResettableClient(mock, nil)
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(context.Background(), []Message{msg("unknown@example.com"), msg("b@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		var reply *textproto.Error
		require.ErrorAs(t, batchErr.Errs[0], &reply)
		assert.Equal(t, 550, reply.Code)
		require.NoError(t, batchErr.Errs[1])
		assert.Len(t, client.ResetCalls(), 1)
		assert.Len(t, mock.DataCalls(), 1)
	})

	t.Run("rejected message without rset support stops the batch", func(t *testing.T) {
		client := newBatchClientMock()
		client.RcptFunc = func(to string) error {
			if to == "unknown@example.com" {
				return rejected
			}
			return nil
		}
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(context.Background(), []Message{msg("unknown@example.com"), msg("b@example.com"), msg("c@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.ErrorIs(t, batchErr.Errs[0], rejected)
		require.ErrorContains(t, batchErr.Errs[1], "the session ended after message 0 failed: smtp client can't reset the transaction")
		require.ErrorContains(t, batchErr.Errs[2], "the session ended after message 0 failed")
		assert.Len(t, client.MailCalls(), 1)
		assert.Len(t, client.QuitCalls(), 1)
	})

	t.Run("failed reset stops the batch", func(t *testing.T) {
		mock := newBatchClientMock()
		mock.RcptFunc = func(string) error { return rejected }
		client := newResettableClient(mock, errors.New("reset failed"))
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(context.Background(), []Message{msg("a@example.com"), msg("b@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.ErrorIs(t, batchErr.Errs[0], rejected)
		require.ErrorContains(t, batchErr.Errs[1], "failed to reset smtp transaction: reset failed")
		assert.Len(t, client.ResetCalls(), 1)
		assert.Len(t, mock.MailCalls(), 1)
	})

	t.Run("broken connection stops the batch without rset", func(t *testing.T) {
		mock := newBatchClientMock()
		mock.DataFunc = func() (io.WriteCloser, error) { return &fakeWriterCloser{buff: &bytes.Buffer{}, fail: true}, nil }
		client := newResettableClient(mock, nil)
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(context.Background(), []Message{msg("a@example.com"), msg("b@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.ErrorContains(t, batchErr.Errs[0], "failed to send email body")
		require.ErrorContains(t, batchErr.Errs[1], "the session ended after message 0 failed")
		require.ErrorContains(t, batchErr.Errs[1], "write error")
		assert.Empty(t, client.ResetCalls(), "no RSET into a connection stuck in DATA")
		assert.Len(t, mock.MailCalls(), 1)
	})

	t.Run("canceled in the middle", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		client := newBatchClientMock()
		client.QuitFunc = func() error { return nil }
		client.MailFunc = func(string) error { cancel(); return nil }
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(ctx, []Message{msg("a@example.com"), msg("b@example.com"), msg("c@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.NoError(t, batchErr.Errs[0], "the transaction in flight completes on an injected client")
		require.ErrorIs(t, batchErr.Errs[1], context.Canceled)
		require.ErrorIs(t, batchErr.Errs[2], context.Canceled)
		require.ErrorIs(t, err, context.Canceled, "errors.Is looks into the batch")
		assert.Len(t, client.MailCalls(), 1)
	})

	t.Run("rejected as ctx is done keeps the server reply", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		mock := newBatchClientMock()
		mock.RcptFunc = func(string) error { cancel(); return rejected }
		client := newResettableClient(mock, nil)
		sender := NewSender("localhost", SMTP(client))
		err := sender.SendBatch(ctx, []Message{msg("a@example.com"), msg("b@example.com")})

		var batchErr *BatchError
		require.ErrorAs(t, err, &batchErr)
		require.ErrorIs(t, batchErr.Errs[0], rejected)
		require.NotErrorIs(t, batchErr.Errs[0], context.Canceled)
		require.ErrorIs(t, batchErr.Errs[1], context.Canceled)
		assert.Empty(t, client.ResetCalls())
	})

	t.Run("ctx done during reset after a rejection", func(t *testing.T) {
		tbl := []struct {
			name   string
			ctx    func() (ctx context.Context, end func())
			ctxErr error
		}{
			{name: "canceled", ctx: func() (context.Context, func()) {
				ctx, cancel := context.WithCancel(context.Background())
				return ctx, cancel
			}, ctxErr: context.Canceled},
			{name: "deadline", ctx: func() (context.Context, func()) {
				ctx := &passingDeadlineCtx{Context: context.Background()}
				return ctx, func() { ctx.passed.Store(true) }
			}, ctxErr: context.DeadlineExceeded},
		}
		for _, tt := range tbl {
			t.Run(tt.name, func(t *testing.T) {
				ctx, end := tt.ctx()
				defer end()
				mock := newBatchClientMock()
				mock.RcptFunc = func(string) error { return rejected }
				client := newResettableClient(mock, nil)
				client.ResetFunc = func() error { end(); return errors.New("connection closed") }
				sender := NewSender("localhost", SMTP(client))
				err := sender.SendBatch(ctx, []Message{msg("a@example.com"), msg("b@example.com")})

				var batchErr *BatchError
				require.ErrorAs(t, err, &batchErr)
				require.ErrorIs(t, batchErr.Errs[0], rejected)
				require.NotErrorIs(t, batchErr.Errs[0], tt.ctxErr)
				require.ErrorIs(t, batchErr.Errs[1], tt.ctxErr)
				require.ErrorContains(t, batchErr.Errs[1], "connection closed")
				require.ErrorIs(t, err, tt.ctxErr)
				assert.Len(t, client.ResetCalls(), 1)
			})
		}
	})

	t.Run("session not set up, nothing sent", func(t *testing.T) {
		client := newBatchClientMock()
		client.AuthFunc = func(smtp.Auth) error { return errors.New("bad credentials") }
		sender := NewSender("localhost", SMTP(client), Auth("user", "passwd"))
		err := sender.SendBatch(context.Background(), []Message{msg("a@example.com")})

		require.ErrorContains(t, err, "failed to auth to smtp localhost:25, bad credentials")
		var batchErr *BatchError
		assert.NotErrorAs(t, err, &batchErr, "not a batch error, nothing was sent")
		assert.Empty(t, client.MailCalls())
		assert.Len(t, client.CloseCalls(), 1)
	})

	t.Run("canceled before the call", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		client := newBatchClientMock()
		sender := NewSender("localhost", SMTP(client))
		require.ErrorIs(t, sender.SendBatch(ctx, []Message{msg("a@example.com")}), context.Canceled)
		assert.Empty(t, client.MailCalls())
		assert.Len(t, client.CloseCalls(), 1)
	})

	t.Run("empty batch", func(t *testing.T) {
		client := newBatchClientMock()
		sender := NewSender("localhost", SMTP(client))
		require.NoError(t, sender.SendBatch(context.Background(), nil))
		assert.Empty(t, client.MailCalls())
	})
}

func TestEmail_SendBatchCanceledInFlight(t *testing.T) {
	stalledServer := func(t *testing.T) (host string, port int, done <-chan error, stalled <-chan struct{}) {
		stalledCh := make(chan struct{})
		host, port, done = startSMTPTestServer(t, func(conn net.Conn) error {
			if err := writeSMTPResponse(conn, "220 smtp.example.net ESMTP ready"); err != nil {
				return err
			}
			reader := bufio.NewReader(conn)
			for {
				cmd, err := readSMTPCommand(reader)
				if err != nil {
					return err
				}
				if cmd == "DATA" {
					if e := writeSMTPResponse(conn, "354 send the message"); e != nil {
						return e
					}
					for line := ""; line != "."; {
						if line, err = readSMTPCommand(reader); err != nil {
							return err
						}
					}
					close(stalledCh)
					_, err = io.Copy(io.Discard, conn) // the message is received and never answered
					return err
				}
				if err := writeSMTPResponse(conn, "250 ok"); err != nil {
					return err
				}
			}
		})
		return host, port, done, stalledCh
	}
	msgs := []Message{
		{Text: "first", Params: Params{From: "from@example.com", To: []string{"one@example.com"}, Subject: "subj"}},
		{Text: "second", Params: Params{From: "from@example.com", To: []string{"two@example.com"}, Subject: "subj"}},
	}

	tbl := []struct {
		name   string
		ctx    func(stalled <-chan struct{}) (context.Context, context.CancelFunc)
		ctxErr error
	}{
		{name: "canceled", ctxErr: context.Canceled, ctx: func(stalled <-chan struct{}) (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				<-stalled
				cancel()
			}()
			return ctx, cancel
		}},
		{name: "deadline", ctxErr: context.DeadlineExceeded, ctx: func(<-chan struct{}) (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Millisecond*200)
		}},
	}

	for _, tt := range tbl {
		t.Run(tt.name, func(t *testing.T) {
			host, port, done, stalled := stalledServer(t)
			ctx, cancel := tt.ctx(stalled)
			defer cancel()

			sender := NewSender(host, Port(port), TimeOut(time.Minute))
			st := time.Now()
			err := sender.SendBatch(ctx, msgs)
			assert.Less(t, time.Since(st), time.Second*3, "batch ended with the context")
			waitSMTPTestServer(t, done)

			require.ErrorIs(t, err, tt.ctxErr)
			var batchErr *BatchError
			require.ErrorAs(t, err, &batchErr)
			require.ErrorIs(t, batchErr.Errs[0], tt.ctxErr)
			require.ErrorContains(t, batchErr.Errs[0], "failed to send email")
			require.ErrorIs(t, batchErr.Errs[1], tt.ctxErr)
		})
	}
}

func TestEmail_SendBatchNoServer(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())

	sender := NewSender("127.0.0.1", Port(port), TimeOut(time.Second))
	err = sender.SendBatch(context.Background(), []Message{{Text: "text", Params: Params{From: "from@example.com", To: []string{"a@example.com"}}}})
	require.ErrorContains(t, err, "failed to make smtp client")
	var batchErr *BatchError
	assert.NotErrorAs(t, err, &batchErr, "not a batch error")
}

func TestBatchError(t *testing.T) {
	rejected := &textproto.Error{Code: 550, Msg: "no such user"}
	var err error = &BatchError{Errs: []error{nil, fmt.Errorf("bad to address: %w", rejected), context.Canceled}}

	assert.Equal(t, `failed to send 2 of 3 messages: message 1: bad to address: 550 no such user; message 2: context canceled`,
		strings.ReplaceAll(err.Error(), `"`, ""), "textproto quotes the message on newer Go versions")

	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, err, rejected)
	require.NotErrorIs(t, err, io.EOF)

	var reply *textproto.Error
	require.ErrorAs(t, err, &reply)
	assert.Equal(t, 550, reply.Code)
	var netErr *net.OpError
	require.NotErrorAs(t, err, &netErr)

	var batchErr *BatchError
	require.ErrorAs(t, fmt.Errorf("wrapped: %w", err), &batchErr)
	assert.Len(t, batchErr.Errs, 3)
}
