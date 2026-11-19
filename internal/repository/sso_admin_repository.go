package repository

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

type SSOAdminApplication struct {
	ID                     string
	Code                   string
	Name                   string
	IsActive               bool
	ClientID               string
	AccessPolicy           string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
	LaunchURL              string
	Description            string
	Port                   *int
	BackendPort            *int
}

type SSOAdminUserMembership struct {
	ApplicationID   string
	ApplicationCode string
	ApplicationName string
	Role            string
	Status          string
}

type SSOAdminUser struct {
	ID          string
	Email       string
	FullName    string
	IsSSOAdmin  bool
	Memberships []SSOAdminUserMembership
}

type SSOAdminRepository struct {
	pool *pgxpool.Pool
}

func NewSSOAdminRepository(pool *pgxpool.Pool) *SSOAdminRepository {
	return &SSOAdminRepository{pool: pool}
}

func (r *SSOAdminRepository) IsSSOAdmin(ctx context.Context, appUserID string) (bool, error) {
	if r == nil || r.pool == nil || strings.TrimSpace(appUserID) == "" {
		return false, nil
	}
	var isAdmin bool
	err := r.pool.QueryRow(
		ctx,
		`SELECT COALESCE(is_sso_admin, false)
		 FROM public.app_users
		 WHERE id = $1 AND deleted_at IS NULL`,
		strings.TrimSpace(appUserID),
	).Scan(&isAdmin)
	if err != nil {
		return false, nil
	}
	return isAdmin, nil
}

func (r *SSOAdminRepository) ListApplications(ctx context.Context) ([]SSOAdminApplication, error) {
	rows, err := r.pool.Query(
		ctx,
		`SELECT
			id::text,
			code,
			name,
			is_active,
			COALESCE(client_id, ''),
			COALESCE(NULLIF(access_policy, ''), 'AUTO_USER'),
			COALESCE(redirect_uris, '{}'),
			COALESCE(post_logout_redirect_uris, '{}'),
			COALESCE(launch_url, ''),
			COALESCE(description, ''),
			port,
			backend_port
		 FROM public.applications
		 ORDER BY created_at ASC, name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []SSOAdminApplication
	for rows.Next() {
		var item SSOAdminApplication
		if err := rows.Scan(
			&item.ID,
			&item.Code,
			&item.Name,
			&item.IsActive,
			&item.ClientID,
			&item.AccessPolicy,
			&item.RedirectURIs,
			&item.PostLogoutRedirectURIs,
			&item.LaunchURL,
			&item.Description,
			&item.Port,
			&item.BackendPort,
		); err != nil {
			return nil, err
		}
		apps = append(apps, item)
	}
	return apps, rows.Err()
}

func (r *SSOAdminRepository) UpsertApplication(ctx context.Context, app SSOAdminApplication) error {
	code := strings.ToLower(strings.TrimSpace(app.Code))
	name := strings.TrimSpace(app.Name)
	clientID := strings.TrimSpace(app.ClientID)
	policy := strings.ToUpper(strings.TrimSpace(app.AccessPolicy))
	if policy != "RESTRICTED" {
		policy = "AUTO_USER"
	}

	var appID string
	err := r.pool.QueryRow(
		ctx,
		`INSERT INTO public.applications (
			code, name, is_active, client_id, access_policy,
			redirect_uris, post_logout_redirect_uris, launch_url, description, port, backend_port
		)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (code) DO UPDATE SET
			name = EXCLUDED.name,
			is_active = EXCLUDED.is_active,
			client_id = EXCLUDED.client_id,
			access_policy = EXCLUDED.access_policy,
			redirect_uris = EXCLUDED.redirect_uris,
			post_logout_redirect_uris = EXCLUDED.post_logout_redirect_uris,
			launch_url = EXCLUDED.launch_url,
			description = EXCLUDED.description,
			port = COALESCE(EXCLUDED.port, public.applications.port),
			backend_port = COALESCE(EXCLUDED.backend_port, public.applications.backend_port)
		RETURNING id::text`,
		code,
		name,
		app.IsActive,
		clientID,
		policy,
		app.RedirectURIs,
		app.PostLogoutRedirectURIs,
		strings.TrimSpace(app.LaunchURL),
		strings.TrimSpace(app.Description),
		app.Port,
		app.BackendPort,
	).Scan(&appID)
	if err != nil {
		return err
	}

	// Ensure all Central SSO Admins automatically get approved admin access to every app.
	_, err = r.pool.Exec(
		ctx,
		`INSERT INTO public.app_memberships (app_user_id, application_id, role, status)
		 SELECT id, $1::uuid, 'admin', 'approved'
		 FROM public.app_users
		 WHERE is_sso_admin = true AND deleted_at IS NULL
		 ON CONFLICT (app_user_id, application_id)
		 DO UPDATE SET role = 'admin', status = 'approved'`,
		appID,
	)
	return err
}

func (r *SSOAdminRepository) ListUsers(ctx context.Context, search string) ([]SSOAdminUser, error) {
	q := "%" + strings.ToLower(strings.TrimSpace(search)) + "%"
	rows, err := r.pool.Query(
		ctx,
		`SELECT id::text, email, full_name, COALESCE(is_sso_admin, false)
		 FROM public.app_users
		 WHERE deleted_at IS NULL
		   AND ($1 = '%%' OR lower(email) LIKE $1 OR lower(full_name) LIKE $1)
		 ORDER BY is_sso_admin DESC, full_name ASC, email ASC
		 LIMIT 100`,
		q,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []SSOAdminUser
	userIndex := make(map[string]int)
	for rows.Next() {
		var u SSOAdminUser
		if err := rows.Scan(&u.ID, &u.Email, &u.FullName, &u.IsSSOAdmin); err != nil {
			return nil, err
		}
		userIndex[u.ID] = len(users)
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return users, nil
	}

	mRows, err := r.pool.Query(
		ctx,
		`SELECT
			m.app_user_id::text,
			a.id::text,
			a.code,
			a.name,
			m.role,
			m.status
		 FROM public.app_memberships m
		 JOIN public.applications a ON a.id = m.application_id
		 ORDER BY a.name ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer mRows.Close()

	for mRows.Next() {
		var uid string
		var mem SSOAdminUserMembership
		if err := mRows.Scan(
			&uid,
			&mem.ApplicationID,
			&mem.ApplicationCode,
			&mem.ApplicationName,
			&mem.Role,
			&mem.Status,
		); err != nil {
			return nil, err
		}
		if idx, ok := userIndex[uid]; ok {
			users[idx].Memberships = append(users[idx].Memberships, mem)
		}
	}
	return users, mRows.Err()
}

func (r *SSOAdminRepository) UpsertMembership(
	ctx context.Context,
	appUserID string,
	applicationID string,
	role string,
	status string,
) error {
	cleanRole := strings.ToLower(strings.TrimSpace(role))
	if cleanRole != "admin" {
		cleanRole = "user"
	}
	cleanStatus := strings.ToLower(strings.TrimSpace(status))
	switch cleanStatus {
	case "approved", "pending", "rejected", "disabled":
	default:
		cleanStatus = "pending"
	}

	_, err := r.pool.Exec(
		ctx,
		`INSERT INTO public.app_memberships (app_user_id, application_id, role, status)
		 VALUES ($1::uuid, $2::uuid, $3, $4)
		 ON CONFLICT (app_user_id, application_id)
		 DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status`,
		strings.TrimSpace(appUserID),
		strings.TrimSpace(applicationID),
		cleanRole,
		cleanStatus,
	)
	return err
}

func (r *SSOAdminRepository) SetSSOAdmin(ctx context.Context, appUserID string, isAdmin bool) error {
	_, err := r.pool.Exec(
		ctx,
		`UPDATE public.app_users
		 SET is_sso_admin = $2
		 WHERE id = $1::uuid AND deleted_at IS NULL`,
		strings.TrimSpace(appUserID),
		isAdmin,
	)
	if err != nil {
		return err
	}
	if isAdmin {
		_, err = r.pool.Exec(
			ctx,
			`INSERT INTO public.app_memberships (app_user_id, application_id, role, status)
			 SELECT $1::uuid, id, 'admin', 'approved'
			 FROM public.applications
			 WHERE is_active = true
			 ON CONFLICT (app_user_id, application_id)
			 DO UPDATE SET role = 'admin', status = 'approved'`,
			strings.TrimSpace(appUserID),
		)
	}
	return err
}
