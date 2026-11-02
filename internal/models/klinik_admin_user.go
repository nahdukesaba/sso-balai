package models

// KlinikAdminUser is not a separate identity type or an admin-only account.
// The historical name refers to an operation initiated by a Klinik admin. The
// result stays minimal so provisioning does not become a second user-directory
// contract; the Klinik API reloads the full projection from canonical tables.
type KlinikAdminUser struct {
	AppUserID  string  `json:"appUserId"`
	AuthUserID *string `json:"authUserId,omitempty"`
	Email      string  `json:"email"`
	FullName   string  `json:"fullName"`
	Role       string  `json:"role"`
	Status     string  `json:"status"`
}
