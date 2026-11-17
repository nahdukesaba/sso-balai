package models

import "time"

// ManagedMembership is one application membership shown on the access admin page.
type ManagedMembership struct {
	ID              string
	ApplicationCode string
	ApplicationName string
	AppUserID       string
	FullName        string
	Email           string
	Role            string
	Status          string
	StatusLabel     string
	CreatedAt       time.Time
}
