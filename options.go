package notify

import "time"

// Option func type
type Option func(s *Sender)

// SMTP sets SMTP client
func SMTP(smtp SMTPClient) Option {
	return func(s *Sender) {
		s.smtpClient = smtp
	}
}

// Log sets the logger for the email package
func Log(l Logger) Option {
	return func(s *Sender) {
		s.logger = l
	}
}

// Port sets SMTP port
func Port(port int) Option {
	return func(s *Sender) {
		s.port = port
	}
}

// ContentType sets content type of the email
func ContentType(contentType string) Option {
	return func(s *Sender) {
		s.contentType = contentType
	}
}

// TLS enables TLS support
func TLS(s *Sender) {
	s.tls = true
}

// Auth sets smtp username and password
func Auth(smtpUserName, smtpPasswd string) Option {
	return func(s *Sender) {
		s.smtpUserName = smtpUserName
		s.smtpPassword = smtpPasswd
	}
}

// Password sets smtp password
func Password(smtpPasswd string) Option {
	return func(s *Sender) {
		s.smtpPassword = smtpPasswd
	}
}

// TimeOut sets smtp timeout
func TimeOut(timeOut time.Duration) Option {
	return func(s *Sender) {
		s.timeOut = timeOut
	}
}