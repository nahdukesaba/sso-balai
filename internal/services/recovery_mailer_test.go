package services

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func validSMTPConfig() SMTPConfig {
	return SMTPConfig{
		Host:      "smtp.example.com",
		Port:      587,
		Username:  "mailer-user",
		Password:  "super-secret-password",
		FromName:  "SSO Balai",
		FromEmail: "no-reply@example.com",
	}
}

func TestSMTPRecoveryMailerConfigValidation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*SMTPConfig)
	}{
		{"missing host", func(c *SMTPConfig) { c.Host = "" }},
		{"bad port", func(c *SMTPConfig) { c.Port = 0 }},
		{"missing from", func(c *SMTPConfig) { c.FromEmail = "" }},
		{"invalid from", func(c *SMTPConfig) { c.FromEmail = "nope" }},
		{"username without password", func(c *SMTPConfig) { c.Password = "" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validSMTPConfig()
			test.mutate(&cfg)

			_, err := NewSMTPRecoveryMailer(cfg)
			if err == nil {
				t.Fatal("expected configuration error")
			}

			if strings.Contains(err.Error(), "super-secret-password") {
				t.Fatal("configuration error leaked a secret")
			}
		})
	}

	if _, err := NewSMTPRecoveryMailer(validSMTPConfig()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
}

func TestSMTPRecoveryMailerDeliversThroughSender(t *testing.T) {
	mailer, err := NewSMTPRecoveryMailer(validSMTPConfig())
	if err != nil {
		t.Fatal(err)
	}

	var got recoveryMessage

	mailer.send = func(
		_ context.Context,
		_ SMTPConfig,
		msg recoveryMessage,
	) error {
		got = msg
		return nil
	}

	url := "https://sso.example.com/reset-password?token=abc&x=1"

	if err := mailer.SendPasswordReset(
		context.Background(),
		" user@example.com ",
		url,
	); err != nil {
		t.Fatal(err)
	}

	if got.To != "user@example.com" {
		t.Fatalf("unexpected recipient %q", got.To)
	}

	if !strings.Contains(got.Text, url) {
		t.Fatal("plain text body must contain the reset URL")
	}

	if !strings.Contains(got.HTML, "token=abc&amp;x=1") {
		t.Fatal("HTML body must contain the escaped reset URL")
	}

	if err := mailer.SendPasswordReset(
		context.Background(),
		"",
		url,
	); err == nil {
		t.Fatal("empty recipient must fail")
	}
}

func TestNewRecoveryMailerDegradesWithoutSMTP(
	t *testing.T,
) {
	mailer, configErr := NewRecoveryMailer(
		SMTPConfig{},
	)

	if configErr == nil {
		t.Fatal(
			"missing SMTP configuration should produce a configuration warning",
		)
	}

	if mailer == nil {
		t.Fatal(
			"factory must still return an unavailable mailer",
		)
	}

	err := mailer.SendPasswordReset(
		context.Background(),
		"user@example.com",
		"https://sso.example.com/reset-password?token=test",
	)

	if !errors.Is(
		err,
		ErrRecoveryDeliveryUnavailable,
	) {
		t.Fatalf(
			"expected ErrRecoveryDeliveryUnavailable, got %v",
			err,
		)
	}
}
