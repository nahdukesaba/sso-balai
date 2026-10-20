package services

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

var (
	ErrApplicationUnavailable           = errors.New("application unavailable")
	ErrApplicationMembershipUnavailable = errors.New("application membership unavailable")
)

type ApplicationLookup interface {
	GetByCode(
		ctx context.Context,
		code string,
	) (*models.Application, error)
}

type MembershipLookup interface {
	GetByAppUserAndApplicationID(
		ctx context.Context,
		appUserID string,
		applicationID string,
	) (*models.AppMembership, error)
}

type ApplicationContextService struct {
	applicationRepository ApplicationLookup
	membershipRepository  MembershipLookup
}

func NewApplicationContextService(
	applicationRepository ApplicationLookup,
	membershipRepository MembershipLookup,
) *ApplicationContextService {
	return &ApplicationContextService{
		applicationRepository: applicationRepository,
		membershipRepository:  membershipRepository,
	}
}

func (s *ApplicationContextService) GetByAppUserID(
	ctx context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationContext, error) {
	appUserID = strings.TrimSpace(appUserID)
	applicationCode = strings.ToLower(strings.TrimSpace(applicationCode))

	if appUserID == "" || applicationCode == "" {
		return nil, ErrApplicationMembershipUnavailable
	}

	application, err := s.applicationRepository.GetByCode(
		ctx,
		applicationCode,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get application context application: %w",
			err,
		)
	}

	if application == nil || !application.IsActive {
		return nil, ErrApplicationUnavailable
	}

	membership, err := s.membershipRepository.GetByAppUserAndApplicationID(
		ctx,
		appUserID,
		application.ID,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"get application context membership: %w",
			err,
		)
	}

	if membership == nil {
		return nil, ErrApplicationMembershipUnavailable
	}

	return &models.ApplicationContext{
		UserID:          appUserID,
		ApplicationID:   application.ID,
		Application:     application.Code,
		ApplicationName: application.Name,
		Role:            membership.Role,
		Status:          membership.Status,
	}, nil
}
