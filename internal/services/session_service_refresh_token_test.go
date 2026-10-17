package services

import "testing"

func TestCentralRefreshTokenCarriesApplication(
	t *testing.T,
) {
	token, err := generateRefreshToken(
		" SILAPET ",
	)
	if err != nil {
		t.Fatalf(
			"generate central refresh token: %v",
			err,
		)
	}

	application, ok :=
		centralRefreshTokenApplication(token)

	if !ok {
		t.Fatal(
			"central refresh token must be recognized",
		)
	}

	if application != "silapet" {
		t.Fatalf(
			"unexpected application %q",
			application,
		)
	}
}

func TestCentralRefreshTokenRejectsLegacyToken(
	t *testing.T,
) {
	application, ok :=
		centralRefreshTokenApplication(
			"legacy-refresh-token",
		)

	if ok {
		t.Fatalf(
			"legacy refresh token must not be classified as central: %q",
			application,
		)
	}
}
