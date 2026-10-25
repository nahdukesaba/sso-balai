package models

type PortalApplicationAccess struct {
	Code          string
	Name          string
	Role          string
	Status        string
	HasMembership bool
}

type PortalApplicationCard struct {
	Code        string
	Name        string
	Description string
	StatusLabel string
	RoleLabel   string
	LaunchURL   string
	Launchable  bool
}

type AccountPortalView struct {
	Identity             *Identity
	Applications         []PortalApplicationCard
	PendingAuthorization *PortalPendingAuthorization
}

type PortalPendingAuthorization struct {
	ApplicationName string
	Request         string
	LoginURL        string
	ContinueURL     string
}
