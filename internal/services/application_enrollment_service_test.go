package services

import (
	"context"
	"errors"
	"testing"

	"github.com/nahdukesaba/sso-balai/internal/repository"
)

type fakeApplicationEnrollmentStore struct {
	userID      string
	application string
	status      string
	err         error
}

func (f *fakeApplicationEnrollmentStore) Request(
	ctx context.Context,
	appUserID string,
	applicationCode string,
) (string, error) {
	f.userID = appUserID
	f.application = applicationCode

	return f.status, f.err
}

func TestApplicationEnrollmentCreatesPendingMembership(
	t *testing.T,
) {
	store := &fakeApplicationEnrollmentStore{
		status: "pending",
	}

	service :=
		NewApplicationEnrollmentService(
			store,
		)

	status, err := service.Request(
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

	if status != "pending" {
		t.Fatalf(
			"unexpected enrollment status %q",
			status,
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
				status: "approved",
			},
		)

	status, err := service.Request(
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

	if status != "approved" {
		t.Fatalf(
			"unexpected status %q",
			status,
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
