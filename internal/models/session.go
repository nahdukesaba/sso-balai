package models

import "time"

type AuthSession struct {
	ID               string     `json:"id"`
	AppUserID        string     `json:"appUserId"`
	ApplicationID    string     `json:"applicationId"`
	RefreshTokenHash string     `json:"-"`
	ExpiresAt        time.Time  `json:"expiresAt"`
	LastUsedAt       *time.Time `json:"lastUsedAt,omitempty"`
	RevokedAt        *time.Time `json:"revokedAt,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	UpdatedAt        time.Time  `json:"updatedAt"`
}

type AuthTokenSet struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
	TokenType    string `json:"tokenType"`
	ExpiresIn    int    `json:"expiresIn"`
	ExpiresAt    int64  `json:"expiresAt"`
	SessionID    string `json:"sessionId"`
}
