package models

import "time"

const (
	ApplicationCodeSilapet   = "silapet"
	ApplicationCodeKlinikPKP = "klinik_pkp"
	ApplicationCodeArsiparis = "arsiparis"
)

type Application struct {
	ID        string    `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	IsActive  bool      `json:"isActive"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}
