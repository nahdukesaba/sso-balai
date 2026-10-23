package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var ErrKlinikAccountUnavailable = errors.New("Klinik account unavailable")

type KlinikIdentityStore interface {
	GetByAppUserID(
		context.Context,
		string,
	) (*models.KlinikIdentity, error)
}

type KlinikContextService struct {
	identities KlinikIdentityStore
}

func NewKlinikContextService(
	identities KlinikIdentityStore,
) *KlinikContextService {
	return &KlinikContextService{
		identities: identities,
	}
}

func (s *KlinikContextService) GetByAppUserID(
	ctx context.Context,
	appUserID string,
) (*models.KlinikIdentity, error) {
	appUserID = strings.TrimSpace(appUserID)

	if appUserID == "" || s == nil || s.identities == nil {
		return nil, ErrKlinikAccountUnavailable
	}

	identity, err := s.identities.GetByAppUserID(
		ctx,
		appUserID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get canonical Klinik context: %w",
			err,
		)
	}

	if identity == nil ||
		identity.AppUserID != appUserID ||
		strings.TrimSpace(identity.AuthUserID) == "" ||
		identity.ApplicationCode != models.ApplicationCodeKlinikPKP ||
		identity.Status != models.MembershipStatusApproved ||
		!isKlinikRole(identity.Role) {

		return nil, ErrKlinikAccountUnavailable
	}

	identity.Role = strings.ToLower(strings.TrimSpace(identity.Role))
	return identity, nil
}

func isKlinikRole(role string) bool {
	role = strings.ToLower(strings.TrimSpace(role))
	return role == "admin" || role == "user"
}
