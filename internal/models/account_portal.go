package models

type PortalApplicationAccess struct {
	Code          string
	Name          string
	Role          string
	Status        string
	HasMembership bool
}

type PortalApplicationCard struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
	StatusLabel string `json:"statusLabel"`
	RoleLabel   string `json:"roleLabel"`
	LaunchURL   string `json:"launchUrl"`
	Launchable  bool   `json:"launchable"`
}

type AccountPortalView struct {
	Identity             *Identity
	IsSSOAdmin           bool
	Applications         []PortalApplicationCard
	PendingAuthorization *PortalPendingAuthorization
}

type PortalPendingAuthorization struct {
	ApplicationName string
	Request         string
	LoginURL        string
	ContinueURL     string
}
