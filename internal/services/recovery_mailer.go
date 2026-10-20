package services

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/mail"
	"strings"
	"time"

	gomail "github.com/wneessen/go-mail"
)

// PasswordRecoveryMailer delivers a password recovery message. It knows
// nothing about tokens, expiry or credentials; those belong to
// CentralPasswordRecoveryService.
type PasswordRecoveryMailer interface {
	SendPasswordReset(
		ctx context.Context,
		email string,
		resetURL string,
	) error
}

// SMTPConfig is the transport configuration for SMTPRecoveryMailer.
type SMTPConfig struct {
	Host      string
	Port      int
	Username  string
	Password  string
	FromName  string
	FromEmail string
}

// recoveryMessage is the rendered message handed to the transport.
type recoveryMessage struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// smtpSender abstracts the SMTP transport so delivery can be unit tested
// without a network.
type smtpSender func(ctx context.Context, cfg SMTPConfig, msg recoveryMessage) error

type SMTPRecoveryMailer struct {
	cfg  SMTPConfig
	send smtpSender
}

func NewSMTPRecoveryMailer(cfg SMTPConfig) (*SMTPRecoveryMailer, error) {
	cfg.Host = strings.TrimSpace(cfg.Host)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.FromName = strings.TrimSpace(cfg.FromName)
	cfg.FromEmail = strings.TrimSpace(cfg.FromEmail)

	// Error messages deliberately never include credential values.
	if cfg.Host == "" {
		return nil, errors.New("SMTP_HOST is required")
	}

	if cfg.Port <= 0 || cfg.Port > 65535 {
		return nil, errors.New("SMTP_PORT must be a valid port number")
	}

	if cfg.FromEmail == "" {
		return nil, errors.New("SMTP_FROM_EMAIL is required")
	}

	if _, err := mail.ParseAddress(cfg.FromEmail); err != nil {
		return nil, errors.New("SMTP_FROM_EMAIL is not a valid email address")
	}

	if (cfg.Username == "") != (cfg.Password == "") {
		return nil, errors.New(
			"SMTP_USERNAME and SMTP_PASSWORD must be set together",
		)
	}

	return &SMTPRecoveryMailer{
		cfg:  cfg,
		send: sendViaGoMail,
	}, nil
}

func buildRecoveryMessage(email, resetURL string) recoveryMessage {
	return recoveryMessage{
		To:      email,
		Subject: "Reset Password Akun Balai",
		Text: "Permintaan pengaturan password telah diterima.\n\n" +
			"Buka tautan berikut untuk membuat password baru:\n" +
			resetURL +
			"\n\nTautan ini hanya dapat digunakan satu kali dan akan kedaluwarsa.\n" +
			"Jika Anda tidak meminta ini, abaikan email ini.",
		HTML: "<p>Permintaan pengaturan password telah diterima.</p>" +
			"<p><a href=\"" + html.EscapeString(resetURL) +
			"\">Atur password baru</a></p>" +
			"<p>Tautan ini hanya dapat digunakan satu kali dan akan kedaluwarsa.</p>" +
			"<p>Jika Anda tidak meminta ini, abaikan email ini.</p>",
	}
}

// ErrRecoveryDeliveryUnavailable is returned by the unavailable mailer.
// It is an internal delivery error only; the public forgot-password
// response never reflects it.
var ErrRecoveryDeliveryUnavailable = errors.New(
	"password recovery email delivery unavailable",
)

// UnavailableRecoveryMailer is used when SMTP is missing or invalid. It
// lets the SSO process start and serve authentication normally; only
// recovery email delivery is degraded.
type UnavailableRecoveryMailer struct {
	reason string
}

func (m *UnavailableRecoveryMailer) SendPasswordReset(
	context.Context,
	string,
	string,
) error {
	return fmt.Errorf("%w: %s", ErrRecoveryDeliveryUnavailable, m.reason)
}

// NewRecoveryMailer never fails. It returns the SMTP mailer when the
// configuration is valid, otherwise an UnavailableRecoveryMailer plus the
// (secret-free) configuration problem so the caller can log a warning.
func NewRecoveryMailer(
	cfg SMTPConfig,
) (PasswordRecoveryMailer, error) {
	mailer, err := NewSMTPRecoveryMailer(cfg)
	if err != nil {
		return &UnavailableRecoveryMailer{
			reason: err.Error(),
		}, err
	}

	return mailer, nil
}

// smtpSendTimeout bounds one delivery attempt so an unreachable SMTP
// host cannot hold a forgot-password request open indefinitely.
const smtpSendTimeout = 15 * time.Second

func (m *SMTPRecoveryMailer) SendPasswordReset(
	ctx context.Context,
	email string,
	resetURL string,
) error {
	email = strings.TrimSpace(email)
	resetURL = strings.TrimSpace(resetURL)

	if email == "" || resetURL == "" {
		return errors.New(
			"recovery email and reset URL are required",
		)
	}

	ctx, cancel := context.WithTimeout(ctx, smtpSendTimeout)
	defer cancel()

	return m.send(
		ctx,
		m.cfg,
		buildRecoveryMessage(email, resetURL),
	)
}

func sendViaGoMail(
	ctx context.Context,
	cfg SMTPConfig,
	rm recoveryMessage,
) error {
	msg := gomail.NewMsg()

	if err := msg.FromFormat(cfg.FromName, cfg.FromEmail); err != nil {
		return fmt.Errorf("set from address: %w", err)
	}

	if err := msg.To(rm.To); err != nil {
		return fmt.Errorf("set recipient address: %w", err)
	}

	msg.Subject(rm.Subject)
	msg.SetBodyString(gomail.TypeTextPlain, rm.Text)
	msg.AddAlternativeString(gomail.TypeTextHTML, rm.HTML)

	options := []gomail.Option{
		gomail.WithPort(cfg.Port),
	}

	if cfg.Port == 465 {
		options = append(options, gomail.WithSSL())
	} else {
		options = append(
			options,
			gomail.WithTLSPolicy(gomail.TLSMandatory),
		)
	}

	if cfg.Username != "" {
		options = append(
			options,
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
			gomail.WithUsername(cfg.Username),
			gomail.WithPassword(cfg.Password),
		)
	}

	client, err := gomail.NewClient(cfg.Host, options...)
	if err != nil {
		return fmt.Errorf("create SMTP client: %w", err)
	}

	if err := client.DialAndSendWithContext(ctx, msg); err != nil {
		return fmt.Errorf(
			"send email via %s:%d: %w",
			cfg.Host,
			cfg.Port,
			err,
		)
	}

	return nil
}
