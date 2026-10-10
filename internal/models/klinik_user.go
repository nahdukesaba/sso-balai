package models

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
