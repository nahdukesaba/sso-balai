package models

import "time"

const (
	MembershipStatusPending  = "pending"
	MembershipStatusApproved = "approved"
	MembershipStatusRejected = "rejected"
	MembershipStatusDisabled = "disabled"
)

type AppMembership struct {
	ID            string     `json:"id"`
	AppUserID     string     `json:"appUserId"`
	ApplicationID string     `json:"applicationId"`
	Role          string     `json:"role"`
	Status        string     `json:"status"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	DeletedAt     *time.Time `json:"-"`
}

type ApplicationContext struct {
	UserID          string `json:"userId"`
	Application     string `json:"application"`
	ApplicationName string `json:"applicationName"`
	Role            string `json:"role"`
	Status          string `json:"status"`
}
