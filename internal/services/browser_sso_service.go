package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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
	ErrInvalidClient            = errors.New("invalid browser SSO client credentials")
	ErrSignupNotAllowed         = errors.New("application does not accept self-service signup")
)

const (
	browserSSOStatusPending     = "pending"
	browserSSOStatusDenied      = "denied"
	ApplicationAccessAutoUser   = "AUTO_USER"
	ApplicationAccessRestricted = "RESTRICTED"
)

var pkceValuePattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
var browserSessionIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

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

// BrowserSSOClient is loaded from public.sso_clients at startup.
type BrowserSSOClient = models.SSOClient

type registeredBrowserSSOClient struct {
	applicationCode string
	applicationName string
	description     string
	launchURL       string
	accessPolicy    string
	secretHash      [32]byte
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
	clientByApp   map[string]string
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
	clientByApp := make(map[string]string, len(clients))
	for clientID, client := range clients {
		clientByApp[client.applicationCode] = clientID
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
		clientByApp:   clientByApp,
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

func (s *BrowserSSOService) ValidateCancelReturn(clientID, postLogoutRedirectURI, cancelReturn string) (string, error) {
	cancelReturn = strings.TrimSpace(cancelReturn)
	if cancelReturn == "" {
		return "", nil
	}
	if err := s.ValidatePostLogoutRedirect(clientID, postLogoutRedirectURI); err != nil {
		return "", err
	}
	parsedPostLogout, err := url.ParseRequestURI(postLogoutRedirectURI)
	if err != nil || parsedPostLogout.Host == "" {
		return "", ErrInvalidAuthorizeRequest
	}
	expectedOrigin := strings.ToLower(parsedPostLogout.Scheme + "://" + parsedPostLogout.Host)

	if strings.HasPrefix(cancelReturn, "http://") || strings.HasPrefix(cancelReturn, "https://") {
		parsedCancel, err := url.ParseRequestURI(cancelReturn)
		if err != nil || parsedCancel.Host == "" || parsedCancel.User != nil || parsedCancel.Fragment != "" {
			return "", ErrInvalidAuthorizeRequest
		}
		actualOrigin := strings.ToLower(parsedCancel.Scheme + "://" + parsedCancel.Host)
		if actualOrigin != expectedOrigin {
			return "", ErrInvalidAuthorizeRequest
		}
		return parsedCancel.String(), nil
	}

	if !strings.HasPrefix(cancelReturn, "/") || strings.HasPrefix(cancelReturn, "//") || strings.HasPrefix(cancelReturn, "/\\") || strings.Contains(cancelReturn, "\\") || strings.Contains(cancelReturn, "#") {
		return "", ErrInvalidAuthorizeRequest
	}
	for i := 0; i < len(cancelReturn); i++ {
		if cancelReturn[i] <= ' ' || cancelReturn[i] == 0x7f {
			return "", ErrInvalidAuthorizeRequest
		}
	}
	parsedRelative, err := url.Parse(cancelReturn)
	if err != nil || parsedRelative.Host != "" || !strings.HasPrefix(parsedRelative.Path, "/") {
		return "", ErrInvalidAuthorizeRequest
	}

	return expectedOrigin + cancelReturn, nil
}

func buildBrowserSSOClientRegistry(configs []BrowserSSOClient) (map[string]registeredBrowserSSOClient, error) {
	clients := make(map[string]registeredBrowserSSOClient, len(configs))
	applications := make(map[string]struct{}, len(configs))
	for _, config := range configs {
		clientID := strings.TrimSpace(config.ClientID)
		applicationCode := strings.ToLower(strings.TrimSpace(config.ApplicationCode))
		if clientID == "" || applicationCode == "" {
			return nil, fmt.Errorf("%w: client ID and application code are required", ErrBrowserSSODisabled)
		}
		if _, exists := clients[clientID]; exists {
			return nil, fmt.Errorf("%w: duplicate client ID %q", ErrBrowserSSODisabled, clientID)
		}
		if _, exists := applications[applicationCode]; exists {
			return nil, fmt.Errorf("%w: application %q has more than one client", ErrBrowserSSODisabled, applicationCode)
		}
		applications[applicationCode] = struct{}{}
		accessPolicy := normalizeApplicationAccessPolicy(config.AccessPolicy)
		var secretHash [32]byte
		if len(config.IntrospectionSecretHash) != len(secretHash) {
			return nil, fmt.Errorf("%w: client %q introspection secret hash must be 32 bytes", ErrBrowserSSODisabled, clientID)
		}
		copy(secretHash[:], config.IntrospectionSecretHash)
		launchURL := strings.TrimSpace(config.LaunchURL)
		if launchURL != "" && !validAbsoluteHTTPURL(launchURL) {
			return nil, fmt.Errorf("%w: client %q launch URL must be an absolute HTTP(S) URL", ErrBrowserSSODisabled, clientID)
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
			applicationName: strings.TrimSpace(config.ApplicationName),
			description:     strings.TrimSpace(config.Description),
			launchURL:       launchURL,
			accessPolicy:    accessPolicy,
			secretHash:      secretHash,
			redirectURIs:    redirectURIs,
			postLogoutURIs:  postLogoutURIs,
		}
	}
	return clients, nil
}

// ValidateBrowserSSOClient applies the startup registry checks to one client,
// so `cmd/sso-client` rejects a row the service would refuse to load.
func ValidateBrowserSSOClient(client BrowserSSOClient) error {
	_, err := buildBrowserSSOClientRegistry([]BrowserSSOClient{client})
	return err
}

// HashIntrospectionSecret returns the value stored in sso_clients.
func HashIntrospectionSecret(secret string) []byte {
	hash := sha256.Sum256([]byte(strings.TrimSpace(secret)))
	return hash[:]
}

func normalizeApplicationAccessPolicy(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case ApplicationAccessAutoUser:
		return ApplicationAccessAutoUser
	default:
		return ApplicationAccessRestricted
	}
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
		len(request.Scope) > 512 || len(request.Nonce) > 512 ||
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

func (s *BrowserSSOService) PendingAuthorization(value string) (string, error) {
	request, err := s.OpenAuthorizeRequest(value)
	if err != nil {
		return "", err
	}
	client, ok := s.clients[request.ClientID]
	if !ok {
		return "", ErrInvalidAuthorizeRequest
	}
	return client.applicationCode, nil
}

// SignupApplication returns the application of a pending authorization request
// when its client accepts self-service access requests (AUTO_USER). The new
// membership starts pending until an admin approves it.
func (s *BrowserSSOService) SignupApplication(sealed string) (string, error) {
	request, err := s.OpenAuthorizeRequest(sealed)
	if err != nil {
		return "", err
	}
	client := s.clients[request.ClientID]
	if client.accessPolicy != ApplicationAccessAutoUser {
		return "", ErrSignupNotAllowed
	}
	return client.applicationCode, nil
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
	if strings.TrimSpace(browserToken) == "" {
		result.LoginRequired = true
		return result, nil
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
		if client.accessPolicy != ApplicationAccessAutoUser {
			result.Status = browserSSOStatusPending
			return result, nil
		}
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
		Nonce:            request.Nonce,
		Scope:            request.Scope,
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
	grant, err := s.redeemCode(ctx, code, clientID, redirectURI, codeVerifier)
	if err != nil {
		return nil, err
	}
	supabaseSession, err := s.sessionIssuer.IssueSession(ctx, grant.User.Email)
	if err != nil {
		return nil, err
	}
	if supabaseSession == nil || supabaseSession.User.ID != grant.AuthUserID ||
		supabaseSession.AccessToken == "" || supabaseSession.RefreshToken == "" {
		return nil, ErrInvalidBrowserSession
	}
	identity, err := s.identities.GetByUserID(ctx, grant.User.ID)
	if err != nil {
		return nil, err
	}
	return &models.LoginResult{
		Session:      supabaseSession,
		Identity:     identity,
		SSOSessionID: grant.SessionID,
	}, nil
}

// CodeGrant is a redeemed authorization code whose browser session, user and
// approved application membership were all re-checked at redemption time.
type CodeGrant struct {
	ClientID   string
	SessionID  string
	AuthUserID string
	AuthTime   time.Time
	Nonce      string
	Scope      string
	User       *models.AppUser
	Role       string
}

// RedeemOIDCCode authenticates a confidential client with its secret (the
// same value it uses for introspection) and redeems an authorization code.
func (s *BrowserSSOService) RedeemOIDCCode(
	ctx context.Context,
	code, clientID, clientSecret, redirectURI, codeVerifier string,
) (*CodeGrant, error) {
	if !s.authenticateClient(clientID, clientSecret) {
		return nil, ErrInvalidClient
	}
	return s.redeemCode(ctx, code, clientID, redirectURI, codeVerifier)
}

func (s *BrowserSSOService) authenticateClient(clientID, secret string) bool {
	client, ok := s.clients[strings.TrimSpace(clientID)]
	return ok && strings.TrimSpace(secret) != "" &&
		subtle.ConstantTimeCompare(client.secretHash[:], HashIntrospectionSecret(secret)) == 1
}

// redeemCode consumes the code once and checks session, user and membership
// before any token is issued.
func (s *BrowserSSOService) redeemCode(
	ctx context.Context,
	code, clientID, redirectURI, codeVerifier string,
) (*CodeGrant, error) {
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
	stored, err := s.store.ConsumeAuthorizationCode(
		ctx, hashOpaqueToken(code), clientID, redirectURI, pkceChallenge(codeVerifier),
	)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, ErrInvalidAuthorizationCode
	}
	grant, err := s.currentGrant(ctx, clientID, stored.BrowserSessionID, stored.AppUserID)
	if err != nil {
		return nil, err
	}
	if grant.AuthUserID != stored.AuthUserID {
		return nil, ErrInvalidBrowserSession
	}
	grant.Nonce, grant.Scope = stored.Nonce, stored.Scope
	return grant, nil
}

// CurrentGrant re-checks that a session is active and still bound to the user,
// and that the user still has approved access to the client's application.
func (s *BrowserSSOService) CurrentGrant(ctx context.Context, clientID, sessionID, appUserID string) (*CodeGrant, error) {
	if _, ok := s.clients[clientID]; !ok || !browserSessionIDPattern.MatchString(sessionID) {
		return nil, ErrInvalidBrowserSession
	}
	return s.currentGrant(ctx, clientID, sessionID, appUserID)
}

func (s *BrowserSSOService) currentGrant(ctx context.Context, clientID, sessionID, appUserID string) (*CodeGrant, error) {
	browserSession, err := s.store.GetActiveSessionByID(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if browserSession == nil || browserSession.AppUserID != appUserID {
		return nil, ErrInvalidBrowserSession
	}
	user, err := s.users.GetByAuthUserID(ctx, browserSession.AuthUserID)
	if err != nil {
		return nil, err
	}
	if user == nil || user.ID != appUserID || strings.TrimSpace(user.Email) == "" {
		return nil, ErrInvalidBrowserSession
	}
	application, err := s.applications.GetByAppUserID(ctx, appUserID, s.clients[clientID].applicationCode)
	if err != nil || application == nil || application.Status != models.MembershipStatusApproved {
		return nil, ErrAccountUnavailable
	}
	return &CodeGrant{
		ClientID:   clientID,
		SessionID:  browserSession.ID,
		AuthUserID: browserSession.AuthUserID,
		AuthTime:   browserSession.CreatedAt,
		User:       user,
		Role:       application.Role,
	}, nil
}

func (s *BrowserSSOService) Introspect(
	ctx context.Context,
	clientID string,
	secret string,
	sessionID string,
	appUserID string,
) (bool, error) {
	client, ok := s.clients[strings.TrimSpace(clientID)]
	if !ok || subtle.ConstantTimeCompare(client.secretHash[:], HashIntrospectionSecret(secret)) != 1 {
		return false, ErrInvalidBrowserSession
	}
	sessionID = strings.TrimSpace(sessionID)
	appUserID = strings.TrimSpace(appUserID)
	if !browserSessionIDPattern.MatchString(sessionID) || appUserID == "" {
		return false, nil
	}
	session, err := s.store.GetActiveSessionByID(ctx, sessionID)
	if err != nil {
		return false, err
	}
	return session != nil && session.AppUserID == appUserID, nil
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
