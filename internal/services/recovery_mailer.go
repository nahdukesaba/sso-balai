package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type PasswordRecoveryMailer interface {
	SendPasswordReset(
		ctx context.Context,
		email string,
		resetURL string,
	) error
}

type ResendRecoveryMailer struct {
	apiKey     string
	fromEmail  string
	fromName   string
	httpClient *http.Client
}

func NewResendRecoveryMailer(
	apiKey string,
	fromEmail string,
	fromName string,
) (*ResendRecoveryMailer, error) {
	apiKey = strings.TrimSpace(apiKey)
	fromEmail = strings.TrimSpace(fromEmail)
	fromName = strings.TrimSpace(fromName)

	if apiKey == "" || fromEmail == "" {
		return nil, errors.New(
			"RESEND_API_KEY and RESEND_FROM_EMAIL are required",
		)
	}

	return &ResendRecoveryMailer{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		fromName:  fromName,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}, nil
}

func (m *ResendRecoveryMailer) SendPasswordReset(
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

	from := m.fromEmail

	if m.fromName != "" {
		from = fmt.Sprintf(
			"%s <%s>",
			m.fromName,
			m.fromEmail,
		)
	}

	payload := map[string]any{
		"from":    from,
		"to":      []string{email},
		"subject": "Reset Password SSO Balai",
		"text": "Permintaan reset password telah diterima.\n\n" +
			"Buka tautan berikut untuk membuat password baru:\n" +
			resetURL +
			"\n\nTautan ini hanya dapat digunakan satu kali dan akan kedaluwarsa.",
		"html": "<p>Permintaan reset password telah diterima.</p>" +
			"<p><a href=\"" + resetURL +
			"\">Reset password</a></p>" +
			"<p>Tautan ini hanya dapat digunakan satu kali dan akan kedaluwarsa.</p>",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf(
			"marshal recovery email: %w",
			err,
		)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://api.resend.com/emails",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf(
			"create recovery email request: %w",
			err,
		)
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+m.apiKey,
	)
	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf(
			"send recovery email: %w",
			err,
		)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 &&
		resp.StatusCode < 300 {

		return nil
	}

	responseBody, _ := io.ReadAll(
		io.LimitReader(resp.Body, 4096),
	)

	return fmt.Errorf(
		"recovery email transport returned %d: %s",
		resp.StatusCode,
		strings.TrimSpace(string(responseBody)),
	)
}
