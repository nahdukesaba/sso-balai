package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/models"
	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeApplicationEnrollmentStore struct {
	userID      string
	application string
	result      *models.ApplicationEnrollmentResult
	err         error
}

func (f *fakeApplicationEnrollmentStore) Request(
	ctx context.Context,
	appUserID string,
	applicationCode string,
) (*models.ApplicationEnrollmentResult, error) {
	f.userID = appUserID
	f.application = applicationCode

	return f.result, f.err
}

func TestApplicationEnrollmentCreatesPendingMembership(
	t *testing.T,
) {
	store := &fakeApplicationEnrollmentStore{
		result: &models.ApplicationEnrollmentResult{
			Application: "arsiparis",
			Status:      models.MembershipStatusPending,
			Outcome:     models.ApplicationEnrollmentCreated,
		},
	}

	service :=
		NewApplicationEnrollmentService(
			store,
		)

	result, err := service.Request(
		context.Background(),
		"user-1",
		" ARSIPARIS ",
	)
	if err != nil {
		t.Fatalf(
			"request enrollment: %v",
			err,
		)
	}

	if result.Status != models.MembershipStatusPending {
		t.Fatalf(
			"unexpected enrollment status %q",
			result.Status,
		)
	}

	if store.userID != "user-1" ||
		store.application != "arsiparis" {

		t.Fatal(
			"application enrollment input was not normalized",
		)
	}
}

func TestApplicationEnrollmentAllowsExistingApprovedMembership(
	t *testing.T,
) {
	service :=
		NewApplicationEnrollmentService(
			&fakeApplicationEnrollmentStore{
				result: &models.ApplicationEnrollmentResult{
					Application: "silapet",
					Status:      models.MembershipStatusApproved,
					Outcome:     models.ApplicationEnrollmentAlreadyApproved,
				},
			},
		)

	result, err := service.Request(
		context.Background(),
		"user-1",
		"silapet",
	)
	if err != nil {
		t.Fatalf(
			"existing approved enrollment: %v",
			err,
		)
	}

	if result.Status != models.MembershipStatusApproved {
		t.Fatalf(
			"unexpected status %q",
			result.Status,
		)
	}
}

func TestApplicationEnrollmentRejectsInactiveApplication(
	t *testing.T,
) {
	service :=
		NewApplicationEnrollmentService(
			&fakeApplicationEnrollmentStore{
				err: repository.
					ErrEnrollmentApplicationUnavailable,
			},
		)

	_, err := service.Request(
		context.Background(),
		"user-1",
		"unknown-app",
	)

	if !errors.Is(
		err,
		ErrApplicationEnrollmentUnavailable,
	) {
		t.Fatalf(
			"expected unavailable application, got %v",
			err,
		)
	}
}

func TestApplicationEnrollmentRejectsBlockedMembership(
	t *testing.T,
) {
	service :=
		NewApplicationEnrollmentService(
			&fakeApplicationEnrollmentStore{
				err: repository.
					ErrEnrollmentBlocked,
			},
		)

	_, err := service.Request(
		context.Background(),
		"user-1",
		"arsiparis",
	)

	if !errors.Is(
		err,
		ErrApplicationEnrollmentBlocked,
	) {
		t.Fatalf(
			"expected blocked enrollment, got %v",
			err,
		)
	}
}

func TestApplicationEnrollmentRejectsBlankApplication(
	t *testing.T,
) {
	service :=
		NewApplicationEnrollmentService(
			&fakeApplicationEnrollmentStore{},
		)

	_, err := service.Request(
		context.Background(),
		"user-1",
		" ",
	)

	if !errors.Is(
		err,
		ErrInvalidApplicationEnrollment,
	) {
		t.Fatalf(
			"expected invalid enrollment, got %v",
			err,
		)
	}
}
