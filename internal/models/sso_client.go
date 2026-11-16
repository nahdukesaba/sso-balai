package models

// SSOClient is one registered Browser SSO application (public.sso_clients).
type SSOClient struct {
	ClientID                string
	ApplicationCode         string
	ApplicationName         string
	Description             string
	LaunchURL               string
	AccessPolicy            string
	IntrospectionSecretHash []byte
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
}
