package models

// KlinikIdentity does not introduce a Klinik-owned identity. It is a read
// projection over the shared app_users identity, app_pegawai profile, and the
// klinik_pkp membership. Keeping role and status in this projection prevents
// callers from accidentally treating the global app_users fields as
// application authorization.
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
