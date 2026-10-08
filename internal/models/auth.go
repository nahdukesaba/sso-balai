package models

type SupabaseAuthUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

type SupabaseSession struct {
	AccessToken  string           `json:"accessToken"`
	TokenType    string           `json:"tokenType"`
	ExpiresIn    int              `json:"expiresIn"`
	ExpiresAt    int64            `json:"expiresAt"`
	RefreshToken string           `json:"refreshToken"`
	User         SupabaseAuthUser `json:"user"`
}

type LoginResult struct {
	Session  *SupabaseSession
	Identity *Identity
}
