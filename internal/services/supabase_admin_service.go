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
	ErrAdminKeyRequired = errors.New("Supabase admin key is required")
	ErrAdminUnavailable = errors.New("Supabase admin service unavailable")
)

type SupabaseAdminService struct {
	baseURL string
	apiKey  string
	client  *http.Client
}

type createAuthUserRequest struct {
	Email        string                 `json:"email"`
	Password     string                 `json:"password"`
	EmailConfirm bool                   `json:"email_confirm"`
	UserMetadata map[string]interface{} `json:"user_metadata,omitempty"`
}

type adminAuthUserResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type adminListUsersResponse struct {
	Users []adminAuthUserResponse `json:"users"`
}

func (s *SupabaseAdminService) FindUserByEmail(
	ctx context.Context,
	email string,
) (*models.SupabaseAuthUser, error) {
	email = strings.TrimSpace(email)

	if email == "" {
		return nil, errors.New("email is required")
	}

	endpoint := s.baseURL + "/auth/v1/admin/users?page=1&per_page=1000"

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("create admin list users request: %w", err)
	}

	s.setAdminHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdminUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK ||
		resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf(
			"%w: upstream returned status %d",
			ErrAdminUnavailable,
			resp.StatusCode,
		)
	}

	var result adminListUsersResponse

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode admin users response: %w", err)
	}

	for _, user := range result.Users {
		if strings.EqualFold(user.Email, email) {
			return &models.SupabaseAuthUser{
				ID:    user.ID,
				Email: user.Email,
			}, nil
		}
	}

	return nil, nil
}

func NewSupabaseAdminService(
	baseURL string,
	apiKey string,
) (*SupabaseAdminService, error) {
	baseURL = strings.TrimSpace(baseURL)
	apiKey = strings.TrimSpace(apiKey)

	if baseURL == "" {
		return nil, errors.New("SUPABASE_URL is required")
	}

	if apiKey == "" {
		return nil, ErrAdminKeyRequired
	}

	return &SupabaseAdminService{
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

func (s *SupabaseAdminService) CreateUser(
	ctx context.Context,
	email string,
	password string,
	fullName string,
) (*models.SupabaseAuthUser, error) {
	payload := createAuthUserRequest{
		Email:        strings.TrimSpace(email),
		Password:     password,
		EmailConfirm: true,
		UserMetadata: map[string]interface{}{
			"full_name": strings.TrimSpace(fullName),
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal admin create user request: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.baseURL+"/auth/v1/admin/users",
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("create admin user request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	s.setAdminHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdminUnavailable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK ||
		resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf(
			"%w: upstream returned status %d",
			ErrAdminUnavailable,
			resp.StatusCode,
		)
	}

	var authUser adminAuthUserResponse

	if err := json.NewDecoder(resp.Body).Decode(&authUser); err != nil {
		return nil, fmt.Errorf("decode created auth user: %w", err)
	}

	if authUser.ID == "" {
		return nil, ErrAdminUnavailable
	}

	return &models.SupabaseAuthUser{
		ID:    authUser.ID,
		Email: authUser.Email,
	}, nil
}

func (s *SupabaseAdminService) setAdminHeaders(req *http.Request) {
	req.Header.Set("apikey", s.apiKey)

	if !strings.HasPrefix(s.apiKey, "sb_secret_") {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}
}
