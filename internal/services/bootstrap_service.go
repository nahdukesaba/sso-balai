package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrBootstrapConflict = errors.New("bootstrap user conflicts with existing data")
	ErrBootstrapInvalid  = errors.New("bootstrap configuration is invalid")
)

type BootstrapResult struct {
	Action string
}

type BootstrapService struct {
	adminService   *SupabaseAdminService
	userRepository *repository.UserRepository
}

func NewBootstrapService(
	adminService *SupabaseAdminService,
	userRepository *repository.UserRepository,
) *BootstrapService {
	return &BootstrapService{
		adminService:   adminService,
		userRepository: userRepository,
	}
}

func (s *BootstrapService) Bootstrap(
	ctx context.Context,
	email string,
	password string,
	fullName string,
	role string,
) (*BootstrapResult, error) {
	email = strings.TrimSpace(email)
	fullName = strings.TrimSpace(fullName)
	role = strings.TrimSpace(role)

	if email == "" ||
		password == "" ||
		fullName == "" ||
		role == "" {
		return nil, ErrBootstrapInvalid
	}

	authUser, err := s.adminService.FindUserByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("find auth user: %w", err)
	}

	appUserByEmail, err :=
		s.userRepository.GetByEmailIncludingDeleted(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("find app user by email: %w", err)
	}

	// Case 1:
	// Auth user already exists.
	if authUser != nil {
		return s.handleExistingAuthUser(
			ctx,
			authUser,
			appUserByEmail,
			email,
			fullName,
			role,
		)
	}

	// Case 2:
	// Auth user does not exist, but profile already exists.
	// Do not silently create or relink anything.
	if appUserByEmail != nil {
		return nil, fmt.Errorf(
			"%w: app_users record exists but auth user does not",
			ErrBootstrapConflict,
		)
	}

	// Case 3:
	// Neither exists. Create Supabase Auth user first.
	createdAuthUser, err := s.adminService.CreateUser(
		ctx,
		email,
		password,
		fullName,
	)
	if err != nil {
		return nil, fmt.Errorf("create bootstrap auth user: %w", err)
	}

	// Then create the matching app_users profile using the exact same UUID.
	_, err = s.userRepository.CreateBootstrapUser(
		ctx,
		createdAuthUser.ID,
		email,
		fullName,
		role,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"create bootstrap app user profile: %w",
			err,
		)
	}

	return &BootstrapResult{
		Action: "created",
	}, nil
}

func (s *BootstrapService) handleExistingAuthUser(
	ctx context.Context,
	authUser *models.SupabaseAuthUser,
	appUserByEmail *models.AppUser,
	email string,
	fullName string,
	role string,
) (*BootstrapResult, error) {
	appUserByID, err :=
		s.userRepository.GetByIDIncludingDeleted(
			ctx,
			authUser.ID,
		)
	if err != nil {
		return nil, fmt.Errorf(
			"find app user by auth user id: %w",
			err,
		)
	}

	// Auth exists but profile with the same UUID does not.
	if appUserByID == nil {
		// Another app_users row already owns the requested email.
		if appUserByEmail != nil {
			return nil, fmt.Errorf(
				"%w: email belongs to a different app_users record",
				ErrBootstrapConflict,
			)
		}

		_, err := s.userRepository.CreateBootstrapUser(
			ctx,
			authUser.ID,
			email,
			fullName,
			role,
		)
		if err != nil {
			return nil, fmt.Errorf(
				"repair bootstrap app user profile: %w",
				err,
			)
		}

		return &BootstrapResult{
			Action: "profile_repaired",
		}, nil
	}

	// Never silently revive a soft-deleted account.
	if appUserByID.DeletedAt != nil {
		return nil, fmt.Errorf(
			"%w: matching app_users record is soft deleted",
			ErrBootstrapConflict,
		)
	}

	// The Auth UUID and app_users email must describe the same identity.
	if !strings.EqualFold(appUserByID.Email, email) {
		return nil, fmt.Errorf(
			"%w: auth user and app_users email do not match",
			ErrBootstrapConflict,
		)
	}

	if appUserByEmail != nil &&
		appUserByEmail.ID != authUser.ID {
		return nil, fmt.Errorf(
			"%w: email belongs to another app_users id",
			ErrBootstrapConflict,
		)
	}

	// Do not silently elevate or reactivate an existing user.
	if appUserByID.Status != models.UserStatusApproved {
		return nil, fmt.Errorf(
			"%w: existing bootstrap account is not approved",
			ErrBootstrapConflict,
		)
	}

	if appUserByID.Role != role {
		return nil, fmt.Errorf(
			"%w: existing bootstrap account role differs",
			ErrBootstrapConflict,
		)
	}

	// Everything already exists in the expected state.
	return &BootstrapResult{
		Action: "already_exists",
	}, nil
}
