package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrAuthRateLimited    = errors.New("too many authentication attempts")
	ErrAuthUnavailable    = errors.New("authentication service unavailable")
)

type SupabaseAuthService struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

type passwordLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type supabaseTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	RefreshToken string `json:"refresh_token"`

	User struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	} `json:"user"`
}

func NewSupabaseAuthService(
	baseURL string,
	apiKey string,
) (*SupabaseAuthService, error) {
	baseURL = strings.TrimSpace(baseURL)
	apiKey = strings.TrimSpace(apiKey)

	if baseURL == "" {
		return nil, errors.New("SUPABASE_URL is required")
	}

	if apiKey == "" {
		return nil, errors.New("SUPABASE_ANON_KEY is required")
	}

	return &SupabaseAuthService{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (s *SupabaseAuthService) SignInWithPassword(
	ctx context.Context,
	email string,
	password string,
) (*models.SupabaseSession, error) {
	email = strings.TrimSpace(email)

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	payload := passwordLoginRequest{
		Email:    email,
		Password: password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal login request: %w", err)
	}

	endpoint := s.baseURL + "/auth/v1/token?grant_type=password"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create authentication request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue decoding the session.

	case http.StatusBadRequest, http.StatusUnauthorized:
		return nil, ErrInvalidCredentials

	case http.StatusTooManyRequests:
		return nil, ErrAuthRateLimited

	default:
		return nil, fmt.Errorf(
			"%w: upstream returned status %d",
			ErrAuthUnavailable,
			resp.StatusCode,
		)
	}

	var tokenResponse supabaseTokenResponse

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return nil, fmt.Errorf("decode authentication response: %w", err)
	}

	if tokenResponse.AccessToken == "" || tokenResponse.User.ID == "" {
		return nil, ErrAuthUnavailable
	}

	return &models.SupabaseSession{
		AccessToken:  tokenResponse.AccessToken,
		TokenType:    tokenResponse.TokenType,
		ExpiresIn:    tokenResponse.ExpiresIn,
		ExpiresAt:    tokenResponse.ExpiresAt,
		RefreshToken: tokenResponse.RefreshToken,
		User: models.SupabaseAuthUser{
			ID:    tokenResponse.User.ID,
			Email: tokenResponse.User.Email,
		},
	}, nil
}
