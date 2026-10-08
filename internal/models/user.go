package models

import "time"

type AppUser struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	FullName  string     `json:"fullName"`
	Role      string     `json:"role"`
	Status    string     `json:"status"`
	Phone     *string    `json:"phone,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	UpdatedAt time.Time  `json:"updatedAt"`
	DeletedAt *time.Time `json:"-"`
}

const (
	UserStatusPending  = "pending"
	UserStatusApproved = "approved"
	UserStatusRejected = "rejected"
)
