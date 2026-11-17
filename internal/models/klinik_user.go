package models

// KlinikUser represents a legacy klinikpkp_user credential record retained for
// migration compatibility. It is not the canonical Klinik identity; new auth
// and authorization decisions must use app_users and app_memberships instead
// of Role or IsActive from this record.
type KlinikUser struct {
	ID       string
	Name     string
	Email    string
	Password string
	Phone    *string
	NIP      string
	Role     string
	IsActive bool
}
