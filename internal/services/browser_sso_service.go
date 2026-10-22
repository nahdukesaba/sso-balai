package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrBrowserSSODisabled       = errors.New("browser SSO is not configured")
	ErrInvalidAuthorizeRequest  = errors.New("invalid browser SSO authorize request")
	ErrInvalidBrowserSession    = errors.New("invalid browser SSO session")
	ErrInvalidAuthorizationCode = errors.New("invalid browser SSO authorization code")
	ErrInvalidPKCEVerifier      = errors.New("invalid PKCE verifier")
)

const (
	browserSSOStatusPending = "pending"
	browserSSOStatusDenied  = "denied"
)

var pkceValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

type BrowserSSOStore interface {
	CreateSession(context.Context, *models.BrowserSSOSession) error
	GetActiveSessionByTokenHash(context.Context, []byte) (*models.BrowserSSOSession, error)
	GetActiveSessionByID(context.Context, string) (*models.BrowserSSOSession, error)
	RevokeSession(context.Context, []byte) error
	CreateAuthorizationCode(context.Context, *models.BrowserSSOAuthorizationCode) error
	ConsumeAuthorizationCode(context.Context, []byte, string, string, string) (*models.BrowserSSOAuthorizationCode, error)
}

type BrowserSSOAuth interface {
	SignInWithPassword(context.Context, string, string) (*models.SupabaseSession, error)
	SignOut(context.Context, string) error
}

type BrowserSSOSessionIssuer interface {
	IssueSession(context.Context, string) (*models.SupabaseSession, error)
}

type BrowserSSOUsers interface {
	GetByAuthUserID(context.Context, string) (*models.AppUser, error)
}

type BrowserSSOApplications interface {
	GetByAppUserID(context.Context, string, string) (*models.ApplicationContext, error)
}

type BrowserSSOEnrollments interface {
	Request(context.Context, string, string) (*models.ApplicationEnrollmentResult, error)
}

type BrowserSSOIdentities interface {
	GetByUserID(context.Context, string) (*models.Identity, error)
}

type BrowserSSOConfig struct {
	Clients       []BrowserSSOClient
	SessionTTL    time.Duration
	CodeTTL       time.Duration
	EncryptionKey string
}

type BrowserSSOClient struct {
	ClientID               string
	ApplicationCode        string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

type registeredBrowserSSOClient struct {
	applicationCode string
	redirectURIs    map[string]struct{}
	postLogoutURIs  map[string]struct{}
}

type BrowserSSOService struct {
	store         BrowserSSOStore
	auth          BrowserSSOAuth
	sessionIssuer BrowserSSOSessionIssuer
	users         BrowserSSOUsers
	applications  BrowserSSOApplications
	enrollments   BrowserSSOEnrollments
	identities    BrowserSSOIdentities
	clients       map[string]registeredBrowserSSOClient
	sessionTTL    time.Duration
	codeTTL       time.Duration
	aead          cipher.AEAD
	now           func() time.Time
}

func NewBrowserSSOService(
	store BrowserSSOStore,
	auth BrowserSSOAuth,
	sessionIssuer BrowserSSOSessionIssuer,
	users BrowserSSOUsers,
	applications BrowserSSOApplications,
	enrollments BrowserSSOEnrollments,
	identities BrowserSSOIdentities,
	config BrowserSSOConfig,
) (*BrowserSSOService, error) {
	key, err := decodeBrowserSSOKey(config.EncryptionKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("initialize browser SSO encryption: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize browser SSO encryption: %w", err)
	}

	clients, err := buildBrowserSSOClientRegistry(config.Clients)
	if err != nil {
		return nil, err
	}
	if store == nil || auth == nil || sessionIssuer == nil || users == nil || applications == nil ||
		enrollments == nil || identities == nil || len(clients) == 0 {
		return nil, ErrBrowserSSODisabled
	}

	return &BrowserSSOService{
		store:         store,
		auth:          auth,
		sessionIssuer: sessionIssuer,
		users:         users,
		applications:  applications,
		enrollments:   enrollments,
		identities:    identities,
		clients:       clients,
		sessionTTL:    config.SessionTTL,
		codeTTL:       config.CodeTTL,
		aead:          aead,
		now:           time.Now,
	}, nil
}

func (s *BrowserSSOService) ValidatePostLogoutRedirect(clientID, redirectURI string) error {
	if clientID == "" && redirectURI == "" {
		return nil
	}
	client, ok := s.clients[clientID]
	if !ok {
		return ErrInvalidAuthorizeRequest
	}
	if _, ok := client.postLogoutURIs[redirectURI]; !ok {
		return ErrInvalidAuthorizeRequest
	}
	return nil
}

func buildBrowserSSOClientRegistry(configs []BrowserSSOClient) (map[string]registeredBrowserSSOClient, error) {
	clients := make(map[string]registeredBrowserSSOClient, len(configs))
	for _, config := range configs {
		clientID := strings.TrimSpace(config.ClientID)
		applicationCode := strings.ToLower(strings.TrimSpace(config.ApplicationCode))
		if clientID == "" || applicationCode == "" {
			return nil, fmt.Errorf("%w: client ID and application code are required", ErrBrowserSSODisabled)
		}
		if _, exists := clients[clientID]; exists {
			return nil, fmt.Errorf("%w: duplicate client ID %q", ErrBrowserSSODisabled, clientID)
		}

		redirectURIs, err := buildBrowserSSOURIAllowlist(config.RedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("%w: client %q redirect URIs: %v", ErrBrowserSSODisabled, clientID, err)
		}
		postLogoutURIs, err := buildBrowserSSOURIAllowlist(config.PostLogoutRedirectURIs)
		if err != nil {
			return nil, fmt.Errorf("%w: client %q post-logout redirect URIs: %v", ErrBrowserSSODisabled, clientID, err)
		}
		clients[clientID] = registeredBrowserSSOClient{
			applicationCode: applicationCode,
			redirectURIs:    redirectURIs,
			postLogoutURIs:  postLogoutURIs,
		}
	}
	return clients, nil
}

func buildBrowserSSOURIAllowlist(values []string) (map[string]struct{}, error) {
	allowlist := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if !validAbsoluteHTTPURL(value) {
			return nil, fmt.Errorf("invalid absolute HTTP(S) URI %q", value)
		}
		allowlist[value] = struct{}{}
	}
	if len(allowlist) == 0 {
		return nil, errors.New("at least one URI is required")
	}
	return allowlist, nil
}

func validAbsoluteHTTPURL(value string) bool {
	if value == "" || strings.ContainsAny(value, "*#") {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	scheme := strings.ToLower(parsed.Scheme)
	return scheme == "http" || scheme == "https"
}

func decodeBrowserSSOKey(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(encoded)
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("SSO_BROWSER_SESSION_KEY must be a base64-encoded 32-byte key")
	}
	return key, nil
}

func (s *BrowserSSOService) ValidateAuthorizeRequest(
	request models.BrowserSSOAuthorizeRequest,
) error {
	client, ok := s.clients[request.ClientID]
	if !ok {
		return ErrInvalidAuthorizeRequest
	}
	if _, ok := client.redirectURIs[request.RedirectURI]; !ok {
		return ErrInvalidAuthorizeRequest
	}
	if request.ResponseType != "code" || request.State == "" || len(request.State) > 512 ||
		request.CodeChallengeMethod != "S256" || !pkceValuePattern.MatchString(request.CodeChallenge) {
		return ErrInvalidAuthorizeRequest
	}
	return nil
}

func (s *BrowserSSOService) SealAuthorizeRequest(
	request models.BrowserSSOAuthorizeRequest,
) (string, error) {
	if err := s.ValidateAuthorizeRequest(request); err != nil {
		return "", err
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	sealed, err := s.seal(payload, []byte("authorize-context"))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (s *BrowserSSOService) OpenAuthorizeRequest(value string) (models.BrowserSSOAuthorizeRequest, error) {
	var request models.BrowserSSOAuthorizeRequest
	sealed, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
	if err != nil {
		return request, ErrInvalidAuthorizeRequest
	}
	payload, err := s.open(sealed, []byte("authorize-context"))
	if err != nil || json.Unmarshal(payload, &request) != nil {
		return request, ErrInvalidAuthorizeRequest
	}
	if err := s.ValidateAuthorizeRequest(request); err != nil {
		return request, err
	}
	return request, nil
}

func (s *BrowserSSOService) Login(
	ctx context.Context,
	email string,
	password string,
) (string, time.Time, error) {
	session, err := s.auth.SignInWithPassword(ctx, strings.TrimSpace(email), password)
	if err != nil {
		return "", time.Time{}, err
	}
	if session == nil || session.AccessToken == "" || session.User.ID == "" {
		return "", time.Time{}, ErrAuthUnavailable
	}
	defer func() { _ = s.auth.SignOut(ctx, session.AccessToken) }()
	user, err := s.users.GetByAuthUserID(ctx, session.User.ID)
	if err != nil {
		return "", time.Time{}, err
	}
	if user == nil {
		return "", time.Time{}, ErrAccountUnavailable
	}
	rawToken, err := randomURLToken(32)
	if err != nil {
		return "", time.Time{}, err
	}
	expiresAt := s.now().Add(s.sessionTTL)
	if err := s.store.CreateSession(ctx, &models.BrowserSSOSession{
		TokenHash:  hashOpaqueToken(rawToken),
		AuthUserID: session.User.ID,
		AppUserID:  user.ID,
		ExpiresAt:  expiresAt,
	}); err != nil {
		return "", time.Time{}, err
	}
	return rawToken, expiresAt, nil
}

func (s *BrowserSSOService) Authorize(
	ctx context.Context,
	request models.BrowserSSOAuthorizeRequest,
	browserToken string,
) (*models.BrowserSSOAuthorizeResult, error) {
	if err := s.ValidateAuthorizeRequest(request); err != nil {
		return nil, err
	}
	client := s.clients[request.ClientID]
	result := &models.BrowserSSOAuthorizeResult{
		State: request.State, RedirectURI: request.RedirectURI,
	}
	browserSession, err := s.store.GetActiveSessionByTokenHash(ctx, hashOpaqueToken(browserToken))
	if err != nil {
		return nil, err
	}
	if browserSession == nil {
		result.LoginRequired = true
		return result, nil
	}

	application, err := s.applications.GetByAppUserID(ctx, browserSession.AppUserID, client.applicationCode)
	if errors.Is(err, ErrApplicationMembershipUnavailable) {
		enrollment, enrollmentErr := s.enrollments.Request(ctx, browserSession.AppUserID, client.applicationCode)
		if enrollmentErr != nil {
			if errors.Is(enrollmentErr, ErrApplicationEnrollmentBlocked) {
				result.Status = browserSSOStatusDenied
				return result, nil
			}
			return nil, enrollmentErr
		}
		if enrollment == nil || enrollment.Status == models.MembershipStatusPending {
			result.Status = browserSSOStatusPending
			return result, nil
		}
		application, err = s.applications.GetByAppUserID(ctx, browserSession.AppUserID, client.applicationCode)
	}
	if err != nil {
		return nil, err
	}
	if application == nil {
		return nil, ErrAccountUnavailable
	}
	switch application.Status {
	case models.MembershipStatusPending:
		result.Status = browserSSOStatusPending
		return result, nil
	case models.MembershipStatusRejected, models.MembershipStatusDisabled:
		result.Status = browserSSOStatusDenied
		return result, nil
	case models.MembershipStatusApproved:
	default:
		return nil, ErrAccountUnavailable
	}

	rawCode, err := randomURLToken(32)
	if err != nil {
		return nil, err
	}
	if err := s.store.CreateAuthorizationCode(ctx, &models.BrowserSSOAuthorizationCode{
		CodeHash:         hashOpaqueToken(rawCode),
		BrowserSessionID: browserSession.ID,
		ClientID:         request.ClientID,
		AuthUserID:       browserSession.AuthUserID,
		AppUserID:        browserSession.AppUserID,
		RedirectURI:      request.RedirectURI,
		CodeChallenge:    request.CodeChallenge,
		ExpiresAt:        s.now().Add(s.codeTTL),
	}); err != nil {
		return nil, err
	}
	result.Code = rawCode
	return result, nil
}

func (s *BrowserSSOService) Exchange(
	ctx context.Context,
	code string,
	clientID string,
	redirectURI string,
	codeVerifier string,
) (*models.LoginResult, error) {
	client, ok := s.clients[clientID]
	if code == "" || !ok {
		return nil, ErrInvalidAuthorizationCode
	}
	if _, ok := client.redirectURIs[redirectURI]; !ok {
		return nil, ErrInvalidAuthorizationCode
	}
	if !pkceValuePattern.MatchString(codeVerifier) {
		return nil, ErrInvalidPKCEVerifier
	}
	expectedChallenge := pkceChallenge(codeVerifier)
	stored, err := s.store.ConsumeAuthorizationCode(
		ctx,
		hashOpaqueToken(code),
		clientID,
		redirectURI,
		expectedChallenge,
	)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrInvalidAuthorizationCode
	}
	browserSession, err := s.store.GetActiveSessionByID(ctx, stored.BrowserSessionID)
	if err != nil {
		return nil, err
	}
	if browserSession == nil || browserSession.AuthUserID != stored.AuthUserID ||
		browserSession.AppUserID != stored.AppUserID {
		return nil, ErrInvalidBrowserSession
	}
	user, err := s.users.GetByAuthUserID(ctx, stored.AuthUserID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.ID != stored.AppUserID || strings.TrimSpace(user.Email) == "" {
		return nil, ErrInvalidBrowserSession
	}
	supabaseSession, err := s.sessionIssuer.IssueSession(ctx, user.Email)
	if err != nil {
		return nil, err
	}
	if supabaseSession == nil || supabaseSession.User.ID != stored.AuthUserID ||
		supabaseSession.AccessToken == "" || supabaseSession.RefreshToken == "" {
		return nil, ErrInvalidBrowserSession
	}
	application, err := s.applications.GetByAppUserID(ctx, stored.AppUserID, client.applicationCode)
	if err != nil || application == nil || application.Status != models.MembershipStatusApproved {
		return nil, ErrAccountUnavailable
	}
	identity, err := s.identities.GetByUserID(ctx, stored.AppUserID)
	if err != nil {
		return nil, err
	}
	return &models.LoginResult{Session: supabaseSession, Identity: identity}, nil
}

func (s *BrowserSSOService) RevokeBrowserSession(ctx context.Context, rawToken string) error {
	if strings.TrimSpace(rawToken) == "" {
		return nil
	}
	return s.store.RevokeSession(ctx, hashOpaqueToken(rawToken))
}

// HasActiveBrowserSession checks the opaque browser cookie against the
// server-side store without mutating the session.
func (s *BrowserSSOService) HasActiveBrowserSession(ctx context.Context, rawToken string) (bool, error) {
	if strings.TrimSpace(rawToken) == "" {
		return false, nil
	}
	session, err := s.store.GetActiveSessionByTokenHash(ctx, hashOpaqueToken(rawToken))
	if err != nil {
		return false, err
	}
	return session != nil, nil
}

// ResolveBrowserIdentity validates the opaque browser session and returns the
// current internal identity. Missing, expired, revoked, or stale mappings are
// treated as logged out.
func (s *BrowserSSOService) ResolveBrowserIdentity(
	ctx context.Context,
	rawToken string,
) (*models.Identity, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, nil
	}
	session, err := s.store.GetActiveSessionByTokenHash(ctx, hashOpaqueToken(rawToken))
	if err != nil || session == nil {
		return nil, err
	}
	user, err := s.users.GetByAuthUserID(ctx, session.AuthUserID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.ID != session.AppUserID {
		return nil, nil
	}
	identity, err := s.identities.GetByUserID(ctx, session.AppUserID)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.User == nil || identity.User.ID != session.AppUserID {
		return nil, nil
	}
	return identity, nil
}

func (s *BrowserSSOService) seal(plaintext, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plaintext, additionalData), nil
}

func (s *BrowserSSOService) open(ciphertext, additionalData []byte) ([]byte, error) {
	if len(ciphertext) < s.aead.NonceSize() {
		return nil, errors.New("invalid encrypted browser SSO value")
	}
	nonce := ciphertext[:s.aead.NonceSize()]
	return s.aead.Open(nil, nonce, ciphertext[s.aead.NonceSize():], additionalData)
}

func randomURLToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func RandomBrowserSSOToken(size int) (string, error) {
	return randomURLToken(size)
}

func hashOpaqueToken(value string) []byte {
	hash := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hash[:]
}

func pkceChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
