package services

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeRecoveryStore struct {
	userID string
	email  string
	found  bool

	createdHash string
	consumedID  string
	consumeErr  error

	invalidatedUser bool
	invalidatedHash string
	restoredHash    string
}

func (f *fakeRecoveryStore) FindActiveUserByEmail(
	ctx context.Context,
	email string,
) (string, string, bool, error) {
	return f.userID, f.email, f.found, nil
}

func (f *fakeRecoveryStore) InvalidateUnusedByUser(
	ctx context.Context,
	appUserID string,
) error {
	f.invalidatedUser = true
	return nil
}

func (f *fakeRecoveryStore) Create(
	ctx context.Context,
	appUserID string,
	tokenHash string,
	expiresAt time.Time,
) error {
	f.createdHash = tokenHash
	return nil
}

func (f *fakeRecoveryStore) InvalidateHash(
	ctx context.Context,
	tokenHash string,
) error {
	f.invalidatedHash = tokenHash
	return nil
}

func (f *fakeRecoveryStore) ConsumeValidByHash(
	ctx context.Context,
	tokenHash string,
) (string, error) {
	if f.consumeErr != nil {
		return "", f.consumeErr
	}

	return f.consumedID, nil
}

func (f *fakeRecoveryStore) RestoreClaimedHash(
	ctx context.Context,
	tokenHash string,
) error {
	f.restoredHash = tokenHash
	return nil
}

type fakeRecoveryCredentials struct {
	replaceErr error
	created    bool
	replaced   bool
	password   string
}

func (f *fakeRecoveryCredentials) ReplacePassword(
	ctx context.Context,
	appUserID string,
	newPassword string,
) (*models.AuthCredential, error) {
	f.replaced = true
	f.password = newPassword

	if f.replaceErr != nil {
		return nil, f.replaceErr
	}

	return &models.AuthCredential{
		AppUserID: appUserID,
	}, nil
}

func (f *fakeRecoveryCredentials) CreateCredential(
	ctx context.Context,
	appUserID string,
	password string,
	mustChangePassword bool,
) (*models.AuthCredential, error) {
	f.created = true
	f.password = password

	return &models.AuthCredential{
		AppUserID: appUserID,
	}, nil
}

type fakeRecoverySessions struct {
	revokedUser string
}

func (f *fakeRecoverySessions) RevokeAllByAppUserID(
	ctx context.Context,
	appUserID string,
) error {
	f.revokedUser = appUserID
	return nil
}

type fakeRecoveryMailer struct {
	email    string
	resetURL string
}

func (f *fakeRecoveryMailer) SendPasswordReset(
	ctx context.Context,
	email string,
	resetURL string,
) error {
	f.email = email
	f.resetURL = resetURL
	return nil
}

func newTestRecoveryService(
	store CentralPasswordResetStore,
	creds CentralPasswordRecoveryCredentials,
	sessions CentralPasswordRecoverySessionRevoker,
	mailer PasswordRecoveryMailer,
) *CentralPasswordRecoveryService {
	service, err :=
		NewCentralPasswordRecoveryService(
			store,
			creds,
			sessions,
			mailer,
			"https://sso.example.com",
		)
	if err != nil {
		panic(err)
	}

	return service
}

func TestCentralPasswordRecoveryRequest(
	t *testing.T,
) {
	store := &fakeRecoveryStore{
		userID: "user-1",
		email:  "user@example.com",
		found:  true,
	}

	mailer := &fakeRecoveryMailer{}

	service := newTestRecoveryService(
		store,
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		mailer,
	)

	if err := service.Request(
		context.Background(),
		"user@example.com",
	); err != nil {
		t.Fatalf(
			"request recovery: %v",
			err,
		)
	}

	if store.createdHash == "" {
		t.Fatal(
			"reset token hash was not stored",
		)
	}

	parsed, err := url.Parse(
		mailer.resetURL,
	)
	if err != nil {
		t.Fatal(err)
	}

	rawToken := parsed.Query().Get(
		"token",
	)

	if rawToken == "" {
		t.Fatal(
			"raw recovery token missing from reset URL",
		)
	}

	if rawToken == store.createdHash {
		t.Fatal(
			"raw recovery token must never be stored",
		)
	}

	if hashPasswordRecoveryToken(
		rawToken,
	) != store.createdHash {
		t.Fatal(
			"stored recovery token hash does not match",
		)
	}
}

func TestCentralPasswordRecoveryDoesNotEnumerateUnknownEmail(
	t *testing.T,
) {
	store := &fakeRecoveryStore{
		found: false,
	}

	mailer := &fakeRecoveryMailer{}

	service := newTestRecoveryService(
		store,
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		mailer,
	)

	if err := service.Request(
		context.Background(),
		"unknown@example.com",
	); err != nil {
		t.Fatalf(
			"unknown recovery request must be generic: %v",
			err,
		)
	}

	if mailer.resetURL != "" ||
		store.createdHash != "" {

		t.Fatal(
			"unknown identity must not create or send a token",
		)
	}
}

func TestCentralPasswordRecoveryReset(
	t *testing.T,
) {
	store := &fakeRecoveryStore{
		consumedID: "user-1",
	}

	creds := &fakeRecoveryCredentials{}
	sessions := &fakeRecoverySessions{}

	service := newTestRecoveryService(
		store,
		creds,
		sessions,
		&fakeRecoveryMailer{},
	)

	if err := service.Reset(
		context.Background(),
		"raw-recovery-token",
		"new-password",
	); err != nil {
		t.Fatalf(
			"reset central password: %v",
			err,
		)
	}

	if !creds.replaced ||
		creds.password != "new-password" {

		t.Fatal(
			"central credential was not replaced",
		)
	}

	if sessions.revokedUser != "user-1" {
		t.Fatal(
			"existing central sessions were not revoked",
		)
	}
}

func TestCentralPasswordRecoveryCreatesMissingCredential(
	t *testing.T,
) {
	creds := &fakeRecoveryCredentials{
		replaceErr: ErrCredentialNotFound,
	}

	service := newTestRecoveryService(
		&fakeRecoveryStore{
			consumedID: "user-1",
		},
		creds,
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	if err := service.Reset(
		context.Background(),
		"raw-recovery-token",
		"new-password",
	); err != nil {
		t.Fatalf(
			"create credential during reset: %v",
			err,
		)
	}

	if !creds.created {
		t.Fatal(
			"missing central credential was not created",
		)
	}
}

func TestCentralPasswordRecoveryRejectsInvalidToken(
	t *testing.T,
) {
	service := newTestRecoveryService(
		&fakeRecoveryStore{
			consumeErr: repository.ErrPasswordResetTokenNotFound,
		},
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	err := service.Reset(
		context.Background(),
		"invalid-token",
		"new-password",
	)

	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf(
			"expected invalid token, got %v",
			err,
		)
	}
}

func TestCentralPasswordRecoveryTokenIsOpaque(
	t *testing.T,
) {
	raw, hash, err :=
		generatePasswordRecoveryToken()
	if err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(raw) == "" ||
		strings.TrimSpace(hash) == "" {

		t.Fatal(
			"generated recovery values must not be empty",
		)
	}

	if raw == hash {
		t.Fatal(
			"raw token and stored hash must differ",
		)
	}
}

func TestCentralPasswordRecoveryRestoresTokenOnPasswordFailure(
	t *testing.T,
) {
	store := &fakeRecoveryStore{
		consumedID: "user-1",
	}

	creds := &fakeRecoveryCredentials{
		replaceErr: errors.New(
			"database unavailable",
		),
	}

	service := newTestRecoveryService(
		store,
		creds,
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	err := service.Reset(
		context.Background(),
		"recoverable-token",
		"new-password",
	)

	if err == nil {
		t.Fatal(
			"expected password persistence failure",
		)
	}

	expectedHash :=
		hashPasswordRecoveryToken(
			"recoverable-token",
		)

	if store.restoredHash != expectedHash {
		t.Fatal(
			"claimed recovery token was not restored after failure",
		)
	}
}

func TestCentralPasswordRecoveryKeepsTokenConsumedOnSuccess(
	t *testing.T,
) {
	store := &fakeRecoveryStore{
		consumedID: "user-1",
	}

	service := newTestRecoveryService(
		store,
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	if err := service.Reset(
		context.Background(),
		"one-time-token",
		"new-password",
	); err != nil {
		t.Fatalf(
			"reset password: %v",
			err,
		)
	}

	if store.restoredHash != "" {
		t.Fatal(
			"successful reset must leave token consumed",
		)
	}
}

func TestCentralPasswordRecoveryRejectsExpiredToken(
	t *testing.T,
) {
	service := newTestRecoveryService(
		&fakeRecoveryStore{
			consumeErr: repository.ErrPasswordResetTokenExpired,
		},
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	err := service.Reset(
		context.Background(),
		"expired-token",
		"new-password",
	)

	if !errors.Is(err, ErrResetTokenExpired) {
		t.Fatalf("expected ErrResetTokenExpired, got %v", err)
	}
}

// onceStore models the one-time-use database behaviour: the first consume
// succeeds, any later consume of the same hash fails.
type onceStore struct {
	fakeRecoveryStore
	used map[string]bool
}

func (s *onceStore) ConsumeValidByHash(
	_ context.Context,
	tokenHash string,
) (string, error) {
	if s.used[tokenHash] {
		return "", repository.ErrPasswordResetTokenNotFound
	}

	s.used[tokenHash] = true

	return "user-1", nil
}

func TestCentralPasswordRecoveryTokenCannotBeReused(
	t *testing.T,
) {
	service := newTestRecoveryService(
		&onceStore{used: map[string]bool{}},
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	if err := service.Reset(
		context.Background(),
		"single-use-token",
		"new-password",
	); err != nil {
		t.Fatalf("first reset: %v", err)
	}

	err := service.Reset(
		context.Background(),
		"single-use-token",
		"another-password",
	)

	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("expected reuse rejection, got %v", err)
	}
}

func TestCentralPasswordRecoveryResetUpdatesExistingCredential(
	t *testing.T,
) {
	creds := &fakeRecoveryCredentials{}
	sessions := &fakeRecoverySessions{}

	service := newTestRecoveryService(
		&fakeRecoveryStore{consumedID: "user-1"},
		creds,
		sessions,
		&fakeRecoveryMailer{},
	)

	if err := service.Reset(
		context.Background(),
		"token",
		"new-password",
	); err != nil {
		t.Fatal(err)
	}

	if !creds.replaced || creds.created {
		t.Fatal("existing credential must be updated, not created")
	}

	if sessions.revokedUser != "user-1" {
		t.Fatal("sessions must be revoked on reset")
	}
}

type failingRecoveryMailer struct{}

func (failingRecoveryMailer) SendPasswordReset(
	context.Context,
	string,
	string,
) error {
	return errors.New("smtp unavailable")
}

func TestCentralPasswordRecoveryResponseDoesNotDiscloseExistence(
	t *testing.T,
) {
	// Known identity, delivery failure: same nil result as unknown email.
	known := newTestRecoveryService(
		&fakeRecoveryStore{
			userID: "user-1",
			email:  "user@example.com",
			found:  true,
		},
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		failingRecoveryMailer{},
	)

	unknown := newTestRecoveryService(
		&fakeRecoveryStore{},
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		&fakeRecoveryMailer{},
	)

	if err := known.Request(
		context.Background(),
		"user@example.com",
	); err != nil {
		t.Fatalf("known identity: %v", err)
	}

	if err := unknown.Request(
		context.Background(),
		"nobody@example.com",
	); err != nil {
		t.Fatalf("unknown identity: %v", err)
	}
}

func TestCentralPasswordRecoveryRequestWorksWithoutCredential(
	t *testing.T,
) {
	// The recovery store only looks at app_users, never auth_credentials,
	// so a legacy identity with no credential still receives a setup link.
	store := &fakeRecoveryStore{
		userID: "legacy-user",
		email:  "legacy@example.com",
		found:  true,
	}

	mailer := &fakeRecoveryMailer{}

	service := newTestRecoveryService(
		store,
		&fakeRecoveryCredentials{},
		&fakeRecoverySessions{},
		mailer,
	)

	if err := service.Request(
		context.Background(),
		"legacy@example.com",
	); err != nil {
		t.Fatal(err)
	}

	if mailer.email != "legacy@example.com" ||
		!strings.HasPrefix(
			mailer.resetURL,
			"https://sso.example.com/reset-password?token=",
		) {

		t.Fatalf("unexpected setup mail: %q", mailer.resetURL)
	}

	if !store.invalidatedUser {
		t.Fatal("previous tokens must be invalidated")
	}
}

func TestCentralPasswordRecoveryBurnsUndeliveredToken(
    t *testing.T,
) {
    store := &fakeRecoveryStore{
        userID: "user-1",
        email:  "user@example.com",
        found:  true,
    }

    service := newTestRecoveryService(
        store,
        &fakeRecoveryCredentials{},
        &fakeRecoverySessions{},
        failingRecoveryMailer{},
    )

    if err := service.Request(
        context.Background(),
        "user@example.com",
    ); err != nil {
        t.Fatalf(
            "request must remain enumeration-safe: %v",
            err,
        )
    }

    if store.createdHash == "" {
        t.Fatal(
            "expected reset token to be created before delivery",
        )
    }

    if store.invalidatedHash == "" {
        t.Fatal(
            "undelivered reset token must be invalidated",
        )
    }

    if store.invalidatedHash != store.createdHash {
        t.Fatalf(
            "invalidated token hash %q does not match created hash %q",
            store.invalidatedHash,
            store.createdHash,
        )
    }
}
