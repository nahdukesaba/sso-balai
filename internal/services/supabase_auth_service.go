package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrInvalidToken       = errors.New("invalid access token")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrSamePassword       = errors.New("new password must be different from old password")
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

type refreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type passwordRecoveryRequest struct {
	Email string `json:"email"`
}

type updatePasswordRequest struct {
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

type supabaseUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
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

func (s *SupabaseAuthService) RequestPasswordRecovery(
	ctx context.Context,
	email string,
	redirectURL string,
) error {
	email = strings.TrimSpace(email)
	redirectURL = strings.TrimSpace(redirectURL)

	if email == "" {
		return ErrInvalidCredentials
	}

	if redirectURL == "" {
		return fmt.Errorf(
			"%w: password recovery redirect URL is not configured",
			ErrAuthUnavailable,
		)
	}

	payload := passwordRecoveryRequest{
		Email: email,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal password recovery request: %w", err)
	}

	query := url.Values{}
	query.Set("redirect_to", redirectURL)

	endpoint := s.baseURL + "/auth/v1/recover?" + query.Encode()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create password recovery request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.apiKey)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK,
		http.StatusNoContent:
		return nil

	case http.StatusTooManyRequests:
		return ErrAuthRateLimited

	default:
		return fmt.Errorf(
			"%w: recovery upstream returned status %d",
			ErrAuthUnavailable,
			resp.StatusCode,
		)
	}
}

func (s *SupabaseAuthService) RefreshSession(
	ctx context.Context,
	refreshToken string,
) (*models.SupabaseSession, error) {
	refreshToken = strings.TrimSpace(refreshToken)

	if refreshToken == "" {
		return nil, ErrInvalidToken
	}

	payload := refreshTokenRequest{
		RefreshToken: refreshToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal refresh request: %w", err)
	}

	endpoint := s.baseURL + "/auth/v1/token?grant_type=refresh_token"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create refresh request: %w", err)
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
		// Continue.

	case http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden:
		return nil, ErrInvalidToken

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
		return nil, fmt.Errorf("decode refresh response: %w", err)
	}

	if tokenResponse.AccessToken == "" ||
		tokenResponse.RefreshToken == "" ||
		tokenResponse.User.ID == "" {
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

func (s *SupabaseAuthService) SignOut(
	ctx context.Context,
	accessToken string,
) error {
	accessToken = strings.TrimSpace(accessToken)

	if accessToken == "" {
		return ErrInvalidToken
	}

	endpoint := s.baseURL + "/auth/v1/logout?scope=local"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		nil,
	)
	if err != nil {
		return fmt.Errorf("create logout request: %w", err)
	}

	req.Header.Set("apikey", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK,
		http.StatusNoContent:
		return nil

	case http.StatusUnauthorized,
		http.StatusForbidden:
		return ErrInvalidToken

	case http.StatusTooManyRequests:
		return ErrAuthRateLimited

	default:
		return fmt.Errorf(
			"%w: upstream returned status %d",
			ErrAuthUnavailable,
			resp.StatusCode,
		)
	}
}

func (s *SupabaseAuthService) UpdatePassword(
	ctx context.Context,
	accessToken string,
	password string,
) error {
	accessToken = strings.TrimSpace(accessToken)

	if accessToken == "" {
		return ErrInvalidToken
	}

	if password == "" {
		return ErrInvalidPassword
	}

	payload := updatePasswordRequest{
		Password: password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal password update request: %w", err)
	}

	endpoint := s.baseURL + "/auth/v1/user"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPut,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("create password update request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("apikey", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return nil

	case http.StatusBadRequest,
		http.StatusUnprocessableEntity:
		var upstreamError struct {
			ErrorCode string `json:"error_code"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&upstreamError); err == nil {
			if upstreamError.ErrorCode == "same_password" {
				return ErrSamePassword
			}
		}

		return ErrInvalidPassword

	case http.StatusUnauthorized,
		http.StatusForbidden:
		return ErrInvalidToken

	case http.StatusTooManyRequests:
		return ErrAuthRateLimited

	default:
		return fmt.Errorf(
			"%w: password update upstream returned status %d",
			ErrAuthUnavailable,
			resp.StatusCode,
		)
	}
}

func (s *SupabaseAuthService) VerifyAccessToken(
	ctx context.Context,
	accessToken string,
) (*models.SupabaseAuthUser, error) {
	accessToken = strings.TrimSpace(accessToken)

	if accessToken == "" {
		return nil, ErrInvalidToken
	}

	endpoint := s.baseURL + "/auth/v1/user"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create token verification request: %w", err)
	}

	req.Header.Set("apikey", s.apiKey)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAuthUnavailable, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// Continue.

	case http.StatusUnauthorized, http.StatusForbidden:
		return nil, ErrInvalidToken

	default:
		return nil, fmt.Errorf(
			"%w: upstream returned status %d",
			ErrAuthUnavailable,
			resp.StatusCode,
		)
	}

	var userResponse supabaseUserResponse

	if err := json.NewDecoder(resp.Body).Decode(&userResponse); err != nil {
		return nil, fmt.Errorf("decode verified user: %w", err)
	}

	if userResponse.ID == "" {
		return nil, ErrInvalidToken
	}

	return &models.SupabaseAuthUser{
		ID:    userResponse.ID,
		Email: userResponse.Email,
	}, nil
}
