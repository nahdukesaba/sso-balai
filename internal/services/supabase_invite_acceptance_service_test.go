package services

import (
	"context"
	"errors"
	"testing"
)

type fakeSupabaseInviteAcceptanceAuth struct {
	accessToken string
	password    string
	err         error
}

func (f *fakeSupabaseInviteAcceptanceAuth) UpdatePassword(
	_ context.Context,
	accessToken string,
	password string,
) error {
	f.accessToken = accessToken
	f.password = password
	return f.err
}

func TestSupabaseInviteAcceptanceSetsInitialPassword(t *testing.T) {
	auth := &fakeSupabaseInviteAcceptanceAuth{}
	service, err := NewSupabaseInviteAcceptanceService(auth)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Accept(
		context.Background(),
		" invite-access-token ",
		"valid-password",
	); err != nil {
		t.Fatalf("accept invite: %v", err)
	}
	if auth.accessToken != "invite-access-token" || auth.password != "valid-password" {
		t.Fatal("invite session was not delegated to Supabase password update")
	}
}

func TestSupabaseInviteAcceptanceRejectsInvalidInput(t *testing.T) {
	auth := &fakeSupabaseInviteAcceptanceAuth{}
	service, err := NewSupabaseInviteAcceptanceService(auth)
	if err != nil {
		t.Fatal(err)
	}

	if err := service.Accept(context.Background(), "", "valid-password"); !errors.Is(err, ErrInvalidToken) {

		t.Fatalf("expected invalid token, got %v", err)
	}
	if err := service.Accept(context.Background(), "invite-token", "short"); !errors.Is(err, ErrInvalidPassword) {

		t.Fatalf("expected invalid password, got %v", err)
	}
	if auth.accessToken != "" || auth.password != "" {
		t.Fatal("invalid invite input must not reach Supabase")
	}
}

func TestSupabaseInviteAcceptancePreservesSafeSupabaseErrors(t *testing.T) {
	for _, expected := range []error{
		ErrInvalidToken,
		ErrInvalidPassword,
		ErrAuthUnavailable,
	} {
		auth := &fakeSupabaseInviteAcceptanceAuth{err: expected}
		service, err := NewSupabaseInviteAcceptanceService(auth)
		if err != nil {
			t.Fatal(err)
		}

		err = service.Accept(
			context.Background(),
			"invite-token",
			"valid-password",
		)
		if !errors.Is(err, expected) {
			t.Fatalf("expected %v, got %v", expected, err)
		}
	}
}
