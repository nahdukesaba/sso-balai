package services

import (
	"context"
	"errors"
	"strings"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

var (
	ErrInvalidApplicationEnrollment = errors.New(
		"invalid application enrollment request",
	)

	ErrApplicationEnrollmentUnavailable = errors.New(
		"application unavailable",
	)

	ErrApplicationEnrollmentBlocked = errors.New(
		"application enrollment blocked",
	)
)

type ApplicationEnrollmentStore interface {
	Request(
		ctx context.Context,
		appUserID string,
		applicationCode string,
	) (*models.ApplicationEnrollmentResult, error)
}

type ApplicationEnrollmentService struct {
	store ApplicationEnrollmentStore
}

func NewApplicationEnrollmentService(
	store ApplicationEnrollmentStore,
) *ApplicationEnrollmentService {
	return &ApplicationEnrollmentService{
		store: store,
	}
}

func (s *ApplicationEnrollmentService) Request(
	ctx context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	appUserID = strings.TrimSpace(
		appUserID,
	)

	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)

	if appUserID == "" ||
		applicationCode == "" {

		return nil, ErrInvalidApplicationEnrollment
	}

	if s.store == nil {
		return nil, ErrAuthUnavailable
	}

	result, err := s.store.Request(
		ctx,
		appUserID,
		applicationCode,
	)
	if err != nil {
		switch {
		case errors.Is(
			err,
			repository.ErrEnrollmentApplicationUnavailable,
		):
			return nil,
				ErrApplicationEnrollmentUnavailable

		case errors.Is(
			err,
			repository.ErrEnrollmentBlocked,
		):
			return nil,
				ErrApplicationEnrollmentBlocked

		default:
			return nil, err
		}
	}

	if result == nil || strings.TrimSpace(result.Status) == "" {
		return nil, ErrAuthUnavailable
	}

	return result, nil
}
