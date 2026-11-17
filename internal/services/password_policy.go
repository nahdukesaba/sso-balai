package services

import "strings"

const (
	centralPasswordMinLength = 8
	centralPasswordMaxLength = 128
)

func validateCentralPassword(
	password string,
) error {
	if len(password) < centralPasswordMinLength ||
		len(password) > centralPasswordMaxLength ||
		strings.TrimSpace(password) == "" {
		return ErrInvalidPassword
	}

	return nil
}
