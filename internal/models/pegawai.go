package models

import "time"

type Pegawai struct {
	ID            string     `json:"id"`
	AppUserID     string     `json:"appUserId"`
	NIP           *string    `json:"nip,omitempty"`
	NIK           *string    `json:"nik,omitempty"`
	Alamat        *string    `json:"alamat,omitempty"`
	GelarDepan    *string    `json:"gelarDepan,omitempty"`
	GelarBelakang *string    `json:"gelarBelakang,omitempty"`
	CreatedAt     time.Time  `json:"createdAt"`
	UpdatedAt     time.Time  `json:"updatedAt"`
	DeletedAt     *time.Time `json:"-"`
}
