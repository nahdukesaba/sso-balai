package services

import (
	"context"
	"errors"
	"strings"

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
	) (string, error)
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
) (string, error) {
	appUserID = strings.TrimSpace(
		appUserID,
	)

	applicationCode = strings.ToLower(
		strings.TrimSpace(applicationCode),
	)

	if appUserID == "" ||
		applicationCode == "" {

		return "", ErrInvalidApplicationEnrollment
	}

	if s.store == nil {
		return "", ErrAuthUnavailable
	}

	status, err := s.store.Request(
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
			return "",
				ErrApplicationEnrollmentUnavailable

		case errors.Is(
			err,
			repository.ErrEnrollmentBlocked,
		):
			return "",
				ErrApplicationEnrollmentBlocked

		default:
			return "", err
		}
	}

	return status, nil
}
