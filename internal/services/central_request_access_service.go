package services

import (
	"context"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var ErrApplicationAccessAlreadyGranted = errors.New(
	"application access already granted",
)

type RequestAccessAuthentication interface {
	SignInWithPassword(
		ctx context.Context,
		email string,
		password string,
	) (*models.SupabaseSession, error)
	SignOut(ctx context.Context, accessToken string) error
}

type RequestAccessUserStore interface {
	GetByEmailIncludingDeleted(
		ctx context.Context,
		email string,
	) (*models.AppUser, error)
}

type RequestAccessEnrollmentService interface {
	Request(
		ctx context.Context,
		appUserID string,
		applicationCode string,
	) (*models.ApplicationEnrollmentResult, error)
}

type CentralRequestAccessService struct {
	auth        RequestAccessAuthentication
	users       RequestAccessUserStore
	enrollments RequestAccessEnrollmentService
}

func NewCentralRequestAccessService(
	auth RequestAccessAuthentication,
	users RequestAccessUserStore,
	enrollments RequestAccessEnrollmentService,
) *CentralRequestAccessService {
	return &CentralRequestAccessService{
		auth:        auth,
		users:       users,
		enrollments: enrollments,
	}
}

// Request authenticates an existing mapped Central SSO identity without
// requiring membership in the requested application. The temporary Supabase
// session is always locally revoked and is never returned to the caller.
func (s *CentralRequestAccessService) Request(
	ctx context.Context,
	email string,
	password string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	applicationCode = strings.ToLower(strings.TrimSpace(applicationCode))

	if email == "" || password == "" {
		return nil, ErrInvalidCredentials
	}
	if applicationCode == "" {
		return nil, ErrInvalidApplicationEnrollment
	}
	if s.auth == nil || s.users == nil || s.enrollments == nil {
		return nil, ErrAuthUnavailable
	}

	user, err := s.users.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return nil, err
	}

	// Unknown, deleted, and unmapped legacy identities intentionally share a
	// generic credential error. Request-access does not perform lazy migration
	// and must not expose which email addresses exist.
	if user == nil || strings.TrimSpace(user.ID) == "" ||
		user.DeletedAt != nil || user.AuthUserID == nil ||
		strings.TrimSpace(*user.AuthUserID) == "" ||
		!strings.EqualFold(strings.TrimSpace(user.Email), email) {

		return nil, ErrInvalidCredentials
	}

	session, err := s.auth.SignInWithPassword(ctx, email, password)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrAuthUnavailable
	}

	accessToken := strings.TrimSpace(session.AccessToken)
	if accessToken != "" {
		defer s.cleanupTemporarySession(accessToken)
	}

	authUserID := strings.TrimSpace(session.User.ID)
	if accessToken == "" || authUserID == "" {
		return nil, ErrAuthUnavailable
	}
	if authUserID != strings.TrimSpace(*user.AuthUserID) {
		return nil, ErrInvalidCredentials
	}

	result, err := s.enrollments.Request(
		ctx,
		user.ID,
		applicationCode,
	)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrAuthUnavailable
	}

	if result.Outcome == models.ApplicationEnrollmentAlreadyApproved ||
		result.Status == models.MembershipStatusApproved {

		return nil, ErrApplicationAccessAlreadyGranted
	}

	if result.Status != models.MembershipStatusPending {
		return nil, ErrApplicationEnrollmentBlocked
	}

	return result, nil
}

func (s *CentralRequestAccessService) cleanupTemporarySession(
	accessToken string,
) {
	cleanupCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := s.auth.SignOut(cleanupCtx, accessToken); err != nil {
		// Membership state is not rolled back when local session cleanup fails.
		// Do not include the error because an upstream error could contain
		// sensitive request material.
		log.Print("request access: temporary session cleanup failed")
	}
}
