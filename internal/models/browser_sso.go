package models

import "time"

type BrowserSSOSession struct {
	ID         string
	TokenHash  []byte
	AuthUserID string
	AppUserID  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	RevokedAt  *time.Time
}

type BrowserSSOAuthorizationCode struct {
	CodeHash         []byte
	BrowserSessionID string
	ClientID         string
	AuthUserID       string
	AppUserID        string
	RedirectURI      string
	CodeChallenge    string
	Nonce            string
	Scope            string
	ExpiresAt        time.Time
	UsedAt           *time.Time
	CreatedAt        time.Time
}

type BrowserSSOAuthorizeRequest struct {
	ClientID            string `json:"clientId"`
	RedirectURI         string `json:"redirectUri"`
	ResponseType        string `json:"responseType"`
	State               string `json:"state"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	// Scope and Nonce are OpenID Connect parameters; legacy clients omit them.
	Scope string `json:"scope,omitempty"`
	Nonce string `json:"nonce,omitempty"`
}

type BrowserSSOAuthorizeResult struct {
	LoginRequired bool
	Code          string
	Status        string
	State         string
	RedirectURI   string
}
