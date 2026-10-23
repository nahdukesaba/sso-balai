package services

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrKlinikAdminForbidden             = errors.New("Klinik admin access required")
	ErrInvalidKlinikProvisioningRequest = errors.New("invalid Klinik provisioning request")
)

type KlinikProvisioningAdmin interface {
	FindUserByEmail(context.Context, string) (*models.SupabaseAuthUser, error)
	InviteUser(context.Context, string, string) (*models.SupabaseAuthUser, error)
	DeleteUser(context.Context, string) error
}

type KlinikProvisioningWriter interface {
	Provision(context.Context, string, string, string, *string, *string, *string, *string, *string, *string, string, string) (*models.KlinikAdminUser, error)
}

type KlinikAdminAuthorizer interface {
	GetByAppUserID(context.Context, string, string) (*models.ApplicationContext, error)
}

type KlinikAdminProvisioningInput struct {
	Email         string
	FullName      string
	Phone         string
	NIP           string
	NIK           string
	Alamat        string
	GelarDepan    string
	GelarBelakang string
	Role          string
	Status        string
}

type KlinikAdminUserService struct {
	authorizer KlinikAdminAuthorizer
	admin      KlinikProvisioningAdmin
	writer     KlinikProvisioningWriter
}

func NewKlinikAdminUserService(authorizer KlinikAdminAuthorizer, admin KlinikProvisioningAdmin, writer KlinikProvisioningWriter) *KlinikAdminUserService {
	return &KlinikAdminUserService{authorizer: authorizer, admin: admin, writer: writer}
}

func (s *KlinikAdminUserService) Provision(ctx context.Context, actorAppUserID string, input KlinikAdminProvisioningInput) (*models.KlinikAdminUser, error) {
	if s == nil || s.authorizer == nil || s.admin == nil || s.writer == nil {
		return nil, ErrAuthUnavailable
	}
	authorization, err := s.authorizer.GetByAppUserID(ctx, actorAppUserID, models.ApplicationCodeKlinikPKP)
	if err != nil || authorization == nil || authorization.Role != "admin" || authorization.Status != models.MembershipStatusApproved {
		return nil, ErrKlinikAdminForbidden
	}

	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.FullName = strings.TrimSpace(input.FullName)
	input.Role = strings.ToLower(strings.TrimSpace(input.Role))
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	address, mailErr := mail.ParseAddress(input.Email)
	if mailErr != nil || address.Address != input.Email || input.FullName == "" || !validKlinikRole(input.Role) || !validMembershipStatus(input.Status) {
		return nil, ErrInvalidKlinikProvisioningRequest
	}

	authUser, err := s.admin.FindUserByEmail(ctx, input.Email)
	if err != nil {
		return nil, fmt.Errorf("%w: find Supabase identity: %v", ErrAuthUnavailable, err)
	}
	createdAuthUser := false
	if authUser == nil {
		authUser, err = s.admin.InviteUser(ctx, input.Email, input.FullName)
		if err != nil {
			// A concurrent request may have invited the same unique email after
			// our initial lookup. Re-read before reporting an upstream failure.
			authUser, _ = s.admin.FindUserByEmail(ctx, input.Email)
			if authUser == nil {
				return nil, fmt.Errorf("%w: invite Supabase identity: %v", ErrAuthUnavailable, err)
			}
		} else {
			createdAuthUser = true
		}
	}
	if authUser == nil || strings.TrimSpace(authUser.ID) == "" {
		return nil, ErrAuthUnavailable
	}

	result, err := s.writer.Provision(
		ctx, strings.TrimSpace(authUser.ID), input.Email, input.FullName,
		nullableString(input.Phone), nullableString(input.NIP), nullableString(input.NIK),
		nullableString(input.Alamat), nullableString(input.GelarDepan), nullableString(input.GelarBelakang),
		input.Role, input.Status,
	)
	if err != nil {
		if createdAuthUser {
			if deleteErr := s.admin.DeleteUser(context.Background(), authUser.ID); deleteErr != nil {
				return nil, fmt.Errorf("%w: provisioning compensation failed: %v", ErrAuthUnavailable, deleteErr)
			}
		}
		if errors.Is(err, repository.ErrKlinikProvisioningConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("provision canonical Klinik user: %w", err)
	}
	return result, nil
}

func nullableString(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}

func validKlinikRole(role string) bool { return role == "admin" || role == "user" }

func validMembershipStatus(status string) bool {
	switch status {
	case models.MembershipStatusPending, models.MembershipStatusApproved, models.MembershipStatusRejected, models.MembershipStatusDisabled:
		return true
	default:
		return false
	}
}
