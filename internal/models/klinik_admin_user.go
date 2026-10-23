package models

// KlinikAdminUser is the minimal result returned after Central SSO has
// provisioned an identity and its Klinik membership. The Klinik API loads the
// full directory projection from the canonical tables after this operation.
type KlinikAdminUser struct {
	AppUserID  string  `json:"appUserId"`
	AuthUserID *string `json:"authUserId,omitempty"`
	Email      string  `json:"email"`
	FullName   string  `json:"fullName"`
	Role       string  `json:"role"`
	Status     string  `json:"status"`
}
