package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrMembershipChangeInvalid   = errors.New("invalid membership change")
	ErrMembershipChangeForbidden = errors.New("membership change is not allowed")
)

type MembershipAdminStore interface {
	ListManaged(ctx context.Context, actorAppUserID string) ([]models.ManagedMembership, error)
	ManagesAnyApplication(ctx context.Context, actorAppUserID string) (bool, error)
	UpdateManaged(ctx context.Context, actorAppUserID, membershipID, role, status string) error
}

// MembershipAdminService lets Central admins (app_users.role = admin) manage
// every application and application admins manage only their own application.
// The store enforces scope and blocks changes to the actor's own membership.
type MembershipAdminService struct {
	store MembershipAdminStore
}

func NewMembershipAdminService(store MembershipAdminStore) *MembershipAdminService {
	return &MembershipAdminService{store: store}
}

func (s *MembershipAdminService) CanManage(ctx context.Context, actorAppUserID string) (bool, error) {
	return s.store.ManagesAnyApplication(ctx, actorAppUserID)
}

func (s *MembershipAdminService) List(ctx context.Context, actorAppUserID string) ([]models.ManagedMembership, error) {
	memberships, err := s.store.ListManaged(ctx, actorAppUserID)
	for i := range memberships {
		memberships[i].StatusLabel = portalStatusLabel(memberships[i].Status, true)
	}
	return memberships, err
}

func (s *MembershipAdminService) Update(ctx context.Context, actorAppUserID, membershipID, role, status string) error {
	membershipID = strings.TrimSpace(membershipID)
	if !browserSessionIDPattern.MatchString(membershipID) || (role != "admin" && role != "user") {
		return ErrMembershipChangeInvalid
	}
	switch status {
	case models.MembershipStatusApproved, models.MembershipStatusRejected, models.MembershipStatusDisabled:
	default:
		return ErrMembershipChangeInvalid
	}
	err := s.store.UpdateManaged(ctx, actorAppUserID, membershipID, role, status)
	if errors.Is(err, repository.ErrMembershipNotManaged) {
		return ErrMembershipChangeForbidden
	}
	return err
}
