# email sending library

The library is a wrapper around the stdlib `net/smtp` simplifying email sending. It supports authentication, SSL/TLS, 
user-specified SMTP servers, content-type, multiple receipts and more.
    
Example:

```go
client := email.NewSender("localhost", email.ContentType("text/html"), email.Auth("user", "pass"))
err := client.Send("<html>some content, foo bar</html>", 
	email.Params{From: "me@example.com", To: []string{"to@example.com"}, Subject: "Hello world!"})
```

## options

`NewSender` accepts a number of options to configure the client:

- `Port`: SMTP port (default: 25)
- `TLS`: Use TLS SMTP (default: false)
- `Auth(user, password)`: Username and password for SMTP authentication (default: empty, no authentication)
- `ContentType`: Content type for the email (default: "text/plain")
- `TimeOut`: Timeout for the SMTP connection (default: 30 seconds)
- `Log`: Logger to use (default: no logging)
- `SMTP`: Set custom smtp client (default: none)

_Options should be passed to `NewSender` after the mandatory first (host) parameter._

## sending email

To send email you need to create sender first and then use `Send` method. The method accepts two parameters:

- email content (string)
- parameters (`email.Params`)
    ```go
    type Params struct {
        From    string   // From email field
        To      []string // From email field
        Subject string   // Email subject
    }
    ```

## technical details

- Content-Transfer-Encoding set to `quoted-printable'
- Custom SMTP client (`smtp.Client` from stdlib) can be set with `SMTP` option. In this case it will be used instead of making a new smtp client internally.
- Logger can be set with `Log` option. It should implement `email.Logger` interface with a single `Logf(format string, args ...interface{})` method. By default, "no logging" internal logger is used. This interface is compatible with the `go-pkgz/lgr` logger.
- The library has no external dependencies, except for testing. It uses the stdlib `net/smtp` package.
- SSL/TLS supported with `TLS` option. Pls note: this is not the same as `STARTTLS` (not supported) which is usually on port 587 vs SSL/TLS on port 465.

## limitations

This library is not intended to be used for sending emails with attachments or sending a lot of massive emails with low latency. 
The intended use case is sending messages, like alerts, notification and so on. For example, sending alerts from a monitoring
system, or for authentication-related emails, i.e.  "password reset email", "verification email", etc.