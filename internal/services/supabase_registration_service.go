package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type RegistrationService interface {
	Register(
		ctx context.Context,
		email string,
		password string,
		fullName string,
		phone string,
		applicationCode string,
	) (*models.Identity, error)
}

type SupabaseRegistrationUserStore interface {
	GetByEmailIncludingDeleted(
		ctx context.Context,
		email string,
	) (*models.AppUser, error)
}

type SupabaseRegistrationApplicationStore interface {
	GetByCode(
		ctx context.Context,
		code string,
	) (*models.Application, error)
}

type SupabaseRegistrationAdmin interface {
	FindUserByEmail(
		ctx context.Context,
		email string,
	) (*models.SupabaseAuthUser, error)

	CreateUser(
		ctx context.Context,
		email string,
		password string,
		fullName string,
	) (*models.SupabaseAuthUser, error)

	DeleteUser(
		ctx context.Context,
		userID string,
	) error
}

type SupabaseRegistrationWriter interface {
	CreateNewSupabaseIdentity(
		ctx context.Context,
		authUserID string,
		email string,
		fullName string,
		phone *string,
		userRole string,
		userStatus string,
		applicationID string,
		membershipRole string,
		membershipStatus string,
	) (*models.AppUser, error)
}

// SupabaseRegistrationService creates credentials only in Supabase Auth. The
// local transaction stores the internal profile, explicit auth_user_id
// mapping, and pending application membership.
type SupabaseRegistrationService struct {
	users        SupabaseRegistrationUserStore
	applications SupabaseRegistrationApplicationStore
	admin        SupabaseRegistrationAdmin
	writer       SupabaseRegistrationWriter
}

func NewSupabaseRegistrationService(
	users SupabaseRegistrationUserStore,
	applications SupabaseRegistrationApplicationStore,
	admin SupabaseRegistrationAdmin,
	writer SupabaseRegistrationWriter,
) *SupabaseRegistrationService {
	return &SupabaseRegistrationService{
		users:        users,
		applications: applications,
		admin:        admin,
		writer:       writer,
	}
}

func (s *SupabaseRegistrationService) Register(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	phone string,
	applicationCode string,
) (*models.Identity, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	fullName = strings.TrimSpace(fullName)
	phone = strings.TrimSpace(phone)
	applicationCode = strings.ToLower(strings.TrimSpace(applicationCode))

	if email == "" || password == "" || fullName == "" ||
		applicationCode == "" {

		return nil, ErrInvalidRegistrationRequest
	}

	if err := validateCentralPassword(password); err != nil {
		return nil, err
	}

	if s == nil || s.users == nil || s.applications == nil ||
		s.admin == nil || s.writer == nil {

		return nil, ErrAuthUnavailable
	}

	application, err := s.applications.GetByCode(ctx, applicationCode)
	if err != nil {
		return nil, fmt.Errorf(
			"resolve Supabase registration application: %w",
			err,
		)
	}

	if application == nil || !application.IsActive {
		return nil, ErrUnsupportedApplication
	}

	existingUser, err := s.users.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return nil, fmt.Errorf(
			"find Supabase registration profile: %w",
			err,
		)
	}

	if existingUser != nil {
		if existingUser.DeletedAt != nil {
			return nil, ErrRegistrationIdentityConflict
		}

		return nil, ErrAccountAlreadyExists
	}

	existingAuthUser, err := s.admin.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: find registration auth identity: %v",
			ErrAuthUnavailable,
			err,
		)
	}

	if existingAuthUser != nil {
		return nil, ErrRegistrationIdentityConflict
	}

	authUser, err := s.admin.CreateUser(
		ctx,
		email,
		password,
		fullName,
	)
	if err != nil {
		return nil, s.registrationCreateError(ctx, email, err)
	}

	if authUser == nil || strings.TrimSpace(authUser.ID) == "" {
		return nil, ErrAuthUnavailable
	}

	authUserID := strings.TrimSpace(authUser.ID)
	if strings.HasPrefix(phone, "0") {
		phone = "62" + phone[1:]
	}

	var phonePtr *string
	if phone != "" {
		phonePtr = &phone
	}

	user, createErr := s.writer.CreateNewSupabaseIdentity(
		ctx,
		authUserID,
		email,
		fullName,
		phonePtr,
		"user",
		models.UserStatusApproved,
		application.ID,
		"user",
		models.MembershipStatusPending,
	)
	if createErr != nil {
		if deleteErr := s.admin.DeleteUser(
			context.Background(),
			authUserID,
		); deleteErr != nil {

			return nil, fmt.Errorf(
				"%w: registration compensation failed: %v",
				ErrAuthUnavailable,
				deleteErr,
			)
		}

		switch {
		case errors.Is(createErr, repository.ErrCentralRegistrationConflict):
			return nil, ErrAccountAlreadyExists

		case errors.Is(
			createErr,
			repository.ErrCentralRegistrationApplicationUnavailable,
		):
			return nil, ErrUnsupportedApplication

		default:
			return nil, fmt.Errorf(
				"create Supabase registration profile: %w",
				createErr,
			)
		}
	}

	if user == nil {
		if deleteErr := s.admin.DeleteUser(
			context.Background(),
			authUserID,
		); deleteErr != nil {

			return nil, fmt.Errorf(
				"%w: registration compensation failed: %v",
				ErrAuthUnavailable,
				deleteErr,
			)
		}

		return nil, ErrAuthUnavailable
	}

	return &models.Identity{User: user}, nil
}

func (s *SupabaseRegistrationService) registrationCreateError(
	ctx context.Context,
	email string,
	createErr error,
) error {
	// A concurrent registration may have created the unique Supabase email
	// after the initial lookup. Never delete an identity this request did not
	// create, and resolve the latest local state for the safest public error.
	existingAuthUser, findErr := s.admin.FindUserByEmail(ctx, email)
	if findErr == nil && existingAuthUser != nil {
		existingUser, userErr := s.users.GetByEmailIncludingDeleted(ctx, email)
		if userErr == nil && existingUser != nil &&
			existingUser.DeletedAt == nil {

			return ErrAccountAlreadyExists
		}

		return ErrRegistrationIdentityConflict
	}

	return fmt.Errorf(
		"%w: create registration auth identity: %v",
		ErrAuthUnavailable,
		createErr,
	)
}
