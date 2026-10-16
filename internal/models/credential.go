package models

import "time"

const (
	PasswordAlgorithmBcrypt = "bcrypt"
)

type AuthCredential struct {
	AppUserID          string     `json:"appUserId"`
	PasswordHash       string     `json:"-"`
	PasswordAlgorithm  string     `json:"passwordAlgorithm"`
	MustChangePassword bool       `json:"mustChangePassword"`
	FailedAttempts     int        `json:"failedAttempts"`
	LockedUntil        *time.Time `json:"lockedUntil,omitempty"`
	PasswordChangedAt  time.Time  `json:"passwordChangedAt"`
	CreatedAt          time.Time  `json:"createdAt"`
	UpdatedAt          time.Time  `json:"updatedAt"`
}
