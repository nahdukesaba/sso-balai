package services

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ErrInvalidAccessToken is returned for any userinfo token that is not a live
// Central access token (bad signature, wrong issuer, expired, revoked session).
var ErrInvalidAccessToken = errors.New("invalid OIDC access token")

const (
	oidcTokenTTL        = 15 * time.Minute
	oidcAccessTokenType = "at+jwt"
)

// OIDCProvider makes Central a standard OpenID Connect provider on top of the
// Browser SSO session and client registry, so apps can use any generic
// "OpenID Connect" library, the same way they would add "Login with Google".
type OIDCProvider struct {
	issuer  string
	key     *rsa.PrivateKey
	kid     string
	browser *BrowserSSOService
	now     func() time.Time
}

func NewOIDCProvider(issuer string, privateKeyPEM []byte, browser *BrowserSSOService) (*OIDCProvider, error) {
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if !validAbsoluteHTTPURL(issuer) {
		return nil, errors.New("OIDC issuer must be an absolute HTTP(S) URL")
	}
	if browser == nil {
		return nil, errors.New("OIDC requires browser SSO")
	}
	key, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("OIDC signing key must be RSA 2048 bits or larger")
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	thumbprint := sha256.Sum256(der)
	return &OIDCProvider{
		issuer:  issuer,
		key:     key,
		kid:     base64.RawURLEncoding.EncodeToString(thumbprint[:16]),
		browser: browser,
		now:     time.Now,
	}, nil
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("OIDC signing key must be a PEM-encoded RSA private key")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse OIDC signing key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("OIDC signing key must be an RSA private key")
	}
	return key, nil
}

func (p *OIDCProvider) Issuer() string { return p.issuer }

func (p *OIDCProvider) Discovery() map[string]any {
	return map[string]any{
		"issuer":                                p.issuer,
		"authorization_endpoint":                p.issuer + "/authorize",
		"token_endpoint":                        p.issuer + "/oauth/token",
		"userinfo_endpoint":                     p.issuer + "/oauth/userinfo",
		"jwks_uri":                              p.issuer + "/.well-known/jwks.json",
		"end_session_endpoint":                  p.issuer + "/logout",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
		"prompt_values_supported":               []string{"create"},
		"claims_supported": []string{
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "sid",
			"email", "email_verified", "name", "preferred_username", "app_role",
		},
	}
}

func (p *OIDCProvider) JWKS() map[string]any {
	public := p.key.PublicKey
	return map[string]any{"keys": []map[string]string{{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": p.kid,
		"n":   base64.RawURLEncoding.EncodeToString(public.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(public.E)).Bytes()),
	}}}
}

// OIDCTokenResponse is the token endpoint body (RFC 6749 section 5.1).
type OIDCTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
	Scope       string `json:"scope,omitempty"`
}

func (p *OIDCProvider) Token(
	ctx context.Context,
	code, clientID, clientSecret, redirectURI, codeVerifier string,
) (*OIDCTokenResponse, error) {
	grant, err := p.browser.RedeemOIDCCode(ctx, code, clientID, clientSecret, redirectURI, codeVerifier)
	if err != nil {
		return nil, err
	}
	now := p.now()
	expires := now.Add(oidcTokenTTL)
	accessToken, err := p.sign(jwt.MapClaims{
		"iss": p.issuer, "sub": grant.User.ID, "aud": grant.ClientID, "client_id": grant.ClientID,
		"iat": now.Unix(), "exp": expires.Unix(), "sid": grant.SessionID, "scope": grant.Scope,
	}, oidcAccessTokenType)
	if err != nil {
		return nil, err
	}
	response := &OIDCTokenResponse{
		AccessToken: accessToken, TokenType: "Bearer",
		ExpiresIn: int(oidcTokenTTL.Seconds()), Scope: grant.Scope,
	}
	if hasScope(grant.Scope, "openid") {
		claims := jwt.MapClaims{
			"iss": p.issuer, "sub": grant.User.ID, "aud": grant.ClientID,
			"iat": now.Unix(), "exp": expires.Unix(), "sid": grant.SessionID,
		}
		if !grant.AuthTime.IsZero() {
			claims["auth_time"] = grant.AuthTime.Unix()
		}
		if grant.Nonce != "" {
			claims["nonce"] = grant.Nonce
		}
		for name, value := range userClaims(grant) {
			claims[name] = value
		}
		if response.IDToken, err = p.sign(claims, "JWT"); err != nil {
			return nil, err
		}
	}
	return response, nil
}

// UserInfo validates a Central access token and re-checks the browser session
// and membership, so a Central logout or revoked access takes effect here.
func (p *OIDCProvider) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(accessToken, claims, p.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(p.issuer),
		jwt.WithExpirationRequired(), jwt.WithTimeFunc(p.now))
	if err != nil || token.Header["typ"] != oidcAccessTokenType {
		return nil, ErrInvalidAccessToken
	}
	clientID, _ := claims["client_id"].(string)
	sessionID, _ := claims["sid"].(string)
	subject, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	grant, err := p.browser.CurrentGrant(ctx, clientID, sessionID, subject)
	if errors.Is(err, ErrInvalidBrowserSession) || errors.Is(err, ErrAccountUnavailable) {
		return nil, ErrInvalidAccessToken
	}
	if err != nil {
		return nil, err
	}
	grant.Scope = scope
	info := map[string]any{"sub": grant.User.ID}
	for name, value := range userClaims(grant) {
		info[name] = value
	}
	return info, nil
}

// ClientIDFromIDTokenHint returns the audience of an id_token issued by this
// provider; expiry is ignored because RP-initiated logout often sends old tokens.
func (p *OIDCProvider) ClientIDFromIDTokenHint(idToken string) string {
	claims := jwt.MapClaims{}
	if _, err := jwt.ParseWithClaims(idToken, claims, p.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(p.issuer),
		jwt.WithoutClaimsValidation()); err != nil {
		return ""
	}
	audience, err := claims.GetAudience()
	if err != nil || len(audience) != 1 {
		return ""
	}
	return audience[0]
}

func userClaims(grant *CodeGrant) map[string]any {
	claims := map[string]any{"app_role": grant.Role}
	if hasScope(grant.Scope, "email") {
		claims["email"] = grant.User.Email
		// Accounts are invite-only and activated through the emailed link.
		claims["email_verified"] = true
	}
	if hasScope(grant.Scope, "profile") {
		claims["name"] = grant.User.FullName
		claims["preferred_username"] = grant.User.Email
	}
	return claims
}

func hasScope(scope, want string) bool {
	for _, value := range strings.Fields(scope) {
		if value == want {
			return true
		}
	}
	return false
}

func (p *OIDCProvider) sign(claims jwt.MapClaims, tokenType string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.kid
	token.Header["typ"] = tokenType
	return token.SignedString(p.key)
}

func (p *OIDCProvider) keyFunc(token *jwt.Token) (any, error) {
	if token.Header["kid"] != p.kid {
		return nil, errors.New("unknown OIDC signing key")
	}
	return &p.key.PublicKey, nil
}
