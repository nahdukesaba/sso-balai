package models

// KlinikIdentity is the canonical Klinik PKP projection. Identity and profile
// fields come from app_users/app_pegawai, while role and status are scoped to
// the klinik_pkp application membership.
type KlinikIdentity struct {
	AppUserID       string
	AuthUserID      string
	Email           string
	FullName        string
	Phone           *string
	NIP             *string
	ApplicationCode string
	Role            string
	Status          string
}
