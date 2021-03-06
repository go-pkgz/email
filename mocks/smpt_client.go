// Code generated by moq; DO NOT EDIT.
// github.com/matryer/moq

package mocks

import (
	"io"
	"net/smtp"
	"sync"
)

// SMTPClientMock is a mock implementation of notify.SMTPClient.
//
// 	func TestSomethingThatUsesSMTPClient(t *testing.T) {
//
// 		// make and configure a mocked notify.SMTPClient
// 		mockedSMTPClient := &SMTPClientMock{
// 			AuthFunc: func(auth smtp.Auth) error {
// 				panic("mock out the Auth method")
// 			},
// 			CloseFunc: func() error {
// 				panic("mock out the Close method")
// 			},
// 			DataFunc: func() (io.WriteCloser, error) {
// 				panic("mock out the Data method")
// 			},
// 			MailFunc: func(from string) error {
// 				panic("mock out the Mail method")
// 			},
// 			QuitFunc: func() error {
// 				panic("mock out the Quit method")
// 			},
// 			RcptFunc: func(to string) error {
// 				panic("mock out the Rcpt method")
// 			},
// 		}
//
// 		// use mockedSMTPClient in code that requires notify.SMTPClient
// 		// and then make assertions.
//
// 	}
type SMTPClientMock struct {
	// AuthFunc mocks the Auth method.
	AuthFunc func(auth smtp.Auth) error

	// CloseFunc mocks the Close method.
	CloseFunc func() error

	// DataFunc mocks the Data method.
	DataFunc func() (io.WriteCloser, error)

	// MailFunc mocks the Mail method.
	MailFunc func(from string) error

	// QuitFunc mocks the Quit method.
	QuitFunc func() error

	// RcptFunc mocks the Rcpt method.
	RcptFunc func(to string) error

	// calls tracks calls to the methods.
	calls struct {
		// Auth holds details about calls to the Auth method.
		Auth []struct {
			// Auth is the auth argument value.
			Auth smtp.Auth
		}
		// Close holds details about calls to the Close method.
		Close []struct {
		}
		// Data holds details about calls to the Data method.
		Data []struct {
		}
		// Mail holds details about calls to the Mail method.
		Mail []struct {
			// From is the from argument value.
			From string
		}
		// Quit holds details about calls to the Quit method.
		Quit []struct {
		}
		// Rcpt holds details about calls to the Rcpt method.
		Rcpt []struct {
			// To is the to argument value.
			To string
		}
	}
	lockAuth  sync.RWMutex
	lockClose sync.RWMutex
	lockData  sync.RWMutex
	lockMail  sync.RWMutex
	lockQuit  sync.RWMutex
	lockRcpt  sync.RWMutex
}

// Auth calls AuthFunc.
func (mock *SMTPClientMock) Auth(auth smtp.Auth) error {
	if mock.AuthFunc == nil {
		panic("SMTPClientMock.AuthFunc: method is nil but SMTPClient.Auth was just called")
	}
	callInfo := struct {
		Auth smtp.Auth
	}{
		Auth: auth,
	}
	mock.lockAuth.Lock()
	mock.calls.Auth = append(mock.calls.Auth, callInfo)
	mock.lockAuth.Unlock()
	return mock.AuthFunc(auth)
}

// AuthCalls gets all the calls that were made to Auth.
// Check the length with:
//     len(mockedSMTPClient.AuthCalls())
func (mock *SMTPClientMock) AuthCalls() []struct {
	Auth smtp.Auth
} {
	var calls []struct {
		Auth smtp.Auth
	}
	mock.lockAuth.RLock()
	calls = mock.calls.Auth
	mock.lockAuth.RUnlock()
	return calls
}

// Close calls CloseFunc.
func (mock *SMTPClientMock) Close() error {
	if mock.CloseFunc == nil {
		panic("SMTPClientMock.CloseFunc: method is nil but SMTPClient.Close was just called")
	}
	callInfo := struct {
	}{}
	mock.lockClose.Lock()
	mock.calls.Close = append(mock.calls.Close, callInfo)
	mock.lockClose.Unlock()
	return mock.CloseFunc()
}

// CloseCalls gets all the calls that were made to Close.
// Check the length with:
//     len(mockedSMTPClient.CloseCalls())
func (mock *SMTPClientMock) CloseCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockClose.RLock()
	calls = mock.calls.Close
	mock.lockClose.RUnlock()
	return calls
}

// Data calls DataFunc.
func (mock *SMTPClientMock) Data() (io.WriteCloser, error) {
	if mock.DataFunc == nil {
		panic("SMTPClientMock.DataFunc: method is nil but SMTPClient.Data was just called")
	}
	callInfo := struct {
	}{}
	mock.lockData.Lock()
	mock.calls.Data = append(mock.calls.Data, callInfo)
	mock.lockData.Unlock()
	return mock.DataFunc()
}

// DataCalls gets all the calls that were made to Data.
// Check the length with:
//     len(mockedSMTPClient.DataCalls())
func (mock *SMTPClientMock) DataCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockData.RLock()
	calls = mock.calls.Data
	mock.lockData.RUnlock()
	return calls
}

// Mail calls MailFunc.
func (mock *SMTPClientMock) Mail(from string) error {
	if mock.MailFunc == nil {
		panic("SMTPClientMock.MailFunc: method is nil but SMTPClient.Mail was just called")
	}
	callInfo := struct {
		From string
	}{
		From: from,
	}
	mock.lockMail.Lock()
	mock.calls.Mail = append(mock.calls.Mail, callInfo)
	mock.lockMail.Unlock()
	return mock.MailFunc(from)
}

// MailCalls gets all the calls that were made to Mail.
// Check the length with:
//     len(mockedSMTPClient.MailCalls())
func (mock *SMTPClientMock) MailCalls() []struct {
	From string
} {
	var calls []struct {
		From string
	}
	mock.lockMail.RLock()
	calls = mock.calls.Mail
	mock.lockMail.RUnlock()
	return calls
}

// Quit calls QuitFunc.
func (mock *SMTPClientMock) Quit() error {
	if mock.QuitFunc == nil {
		panic("SMTPClientMock.QuitFunc: method is nil but SMTPClient.Quit was just called")
	}
	callInfo := struct {
	}{}
	mock.lockQuit.Lock()
	mock.calls.Quit = append(mock.calls.Quit, callInfo)
	mock.lockQuit.Unlock()
	return mock.QuitFunc()
}

// QuitCalls gets all the calls that were made to Quit.
// Check the length with:
//     len(mockedSMTPClient.QuitCalls())
func (mock *SMTPClientMock) QuitCalls() []struct {
} {
	var calls []struct {
	}
	mock.lockQuit.RLock()
	calls = mock.calls.Quit
	mock.lockQuit.RUnlock()
	return calls
}

// Rcpt calls RcptFunc.
func (mock *SMTPClientMock) Rcpt(to string) error {
	if mock.RcptFunc == nil {
		panic("SMTPClientMock.RcptFunc: method is nil but SMTPClient.Rcpt was just called")
	}
	callInfo := struct {
		To string
	}{
		To: to,
	}
	mock.lockRcpt.Lock()
	mock.calls.Rcpt = append(mock.calls.Rcpt, callInfo)
	mock.lockRcpt.Unlock()
	return mock.RcptFunc(to)
}

// RcptCalls gets all the calls that were made to Rcpt.
// Check the length with:
//     len(mockedSMTPClient.RcptCalls())
func (mock *SMTPClientMock) RcptCalls() []struct {
	To string
} {
	var calls []struct {
		To string
	}
	mock.lockRcpt.RLock()
	calls = mock.calls.Rcpt
	mock.lockRcpt.RUnlock()
	return calls
}
