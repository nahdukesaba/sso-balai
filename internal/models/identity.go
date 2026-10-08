package models

type Identity struct {
	User    *AppUser `json:"user"`
	Pegawai *Pegawai `json:"pegawai,omitempty"`
}
