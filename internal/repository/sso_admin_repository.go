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
	Phone       string
	AuthUserID  string
	IsSSOAdmin  bool
	IsDeleted   bool
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

func (r *SSOAdminRepository) ListUsers(ctx context.Context, search string, filter string) ([]SSOAdminUser, error) {
	q := "%" + strings.ToLower(strings.TrimSpace(search)) + "%"
	whereDeleted := "deleted_at IS NULL"
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "deleted":
		whereDeleted = "deleted_at IS NOT NULL"
	case "all":
		whereDeleted = "true"
	}

	rows, err := r.pool.Query(
		ctx,
		`SELECT id::text, email, full_name, COALESCE(phone, ''), COALESCE(auth_user_id::text, ''), COALESCE(is_sso_admin, false), (deleted_at IS NOT NULL)
		 FROM public.app_users
		 WHERE `+whereDeleted+`
		   AND ($1 = '%%' OR lower(email) LIKE $1 OR lower(full_name) LIKE $1)
		 ORDER BY (deleted_at IS NOT NULL) ASC, is_sso_admin DESC, full_name ASC, email ASC
		 LIMIT 200`,
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
		if err := rows.Scan(&u.ID, &u.Email, &u.FullName, &u.Phone, &u.AuthUserID, &u.IsSSOAdmin, &u.IsDeleted); err != nil {
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

func (r *SSOAdminRepository) GetUserByID(ctx context.Context, appUserID string) (*SSOAdminUser, error) {
	var u SSOAdminUser
	err := r.pool.QueryRow(
		ctx,
		`SELECT id::text, email, full_name, COALESCE(phone, ''), COALESCE(auth_user_id::text, ''), COALESCE(is_sso_admin, false), (deleted_at IS NOT NULL)
		 FROM public.app_users
		 WHERE id = $1::uuid`,
		strings.TrimSpace(appUserID),
	).Scan(&u.ID, &u.Email, &u.FullName, &u.Phone, &u.AuthUserID, &u.IsSSOAdmin, &u.IsDeleted)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *SSOAdminRepository) UpsertUser(
	ctx context.Context,
	email string,
	fullName string,
	phone string,
	authUserID string,
	isSSOAdmin bool,
) (string, error) {
	cleanEmail := strings.ToLower(strings.TrimSpace(email))
	cleanName := strings.TrimSpace(fullName)
	cleanPhone := strings.TrimSpace(phone)
	cleanAuthID := strings.TrimSpace(authUserID)

	var appUserID string
	err := r.pool.QueryRow(
		ctx,
		`INSERT INTO public.app_users (id, email, full_name, phone, auth_user_id, is_sso_admin)
		 VALUES (gen_random_uuid(), $1, $2, NULLIF($3, ''), NULLIF($4, '')::uuid, $5)
		 ON CONFLICT (email) DO UPDATE SET
			full_name = CASE WHEN EXCLUDED.full_name <> '' THEN EXCLUDED.full_name ELSE public.app_users.full_name END,
			phone = COALESCE(EXCLUDED.phone, public.app_users.phone),
			auth_user_id = COALESCE(EXCLUDED.auth_user_id, public.app_users.auth_user_id),
			is_sso_admin = CASE WHEN EXCLUDED.is_sso_admin THEN true ELSE public.app_users.is_sso_admin END,
			deleted_at = NULL
		 RETURNING id::text`,
		cleanEmail,
		cleanName,
		cleanPhone,
		cleanAuthID,
		isSSOAdmin,
	).Scan(&appUserID)
	if err != nil {
		return "", err
	}
	if isSSOAdmin {
		if err := r.SetSSOAdmin(ctx, appUserID, true); err != nil {
			return appUserID, err
		}
	}
	return appUserID, nil
}

func (r *SSOAdminRepository) UpdateUserProfile(
	ctx context.Context,
	appUserID string,
	fullName string,
	phone string,
) error {
	_, err := r.pool.Exec(
		ctx,
		`UPDATE public.app_users
		 SET full_name = $2,
		     phone = NULLIF($3, '')
		 WHERE id = $1::uuid AND deleted_at IS NULL`,
		strings.TrimSpace(appUserID),
		strings.TrimSpace(fullName),
		strings.TrimSpace(phone),
	)
	return err
}

func (r *SSOAdminRepository) SoftDeleteUser(ctx context.Context, appUserID string) error {
	uid := strings.TrimSpace(appUserID)
	if _, err := r.pool.Exec(
		ctx,
		`UPDATE public.app_users
		 SET deleted_at = now(), is_sso_admin = false
		 WHERE id = $1::uuid AND deleted_at IS NULL`,
		uid,
	); err != nil {
		return err
	}
	_, err := r.pool.Exec(
		ctx,
		`UPDATE public.sso_browser_sessions
		 SET revoked_at = now()
		 WHERE app_user_id = $1::uuid AND revoked_at IS NULL`,
		uid,
	)
	return err
}

func (r *SSOAdminRepository) RestoreUser(ctx context.Context, appUserID string) error {
	_, err := r.pool.Exec(
		ctx,
		`UPDATE public.app_users
		 SET deleted_at = NULL
		 WHERE id = $1::uuid`,
		strings.TrimSpace(appUserID),
	)
	return err
}

func (r *SSOAdminRepository) BulkUpsertMemberships(
	ctx context.Context,
	appUserIDs []string,
	applicationID string,
	role string,
	status string,
) (int64, error) {
	if len(appUserIDs) == 0 {
		return 0, nil
	}
	cleanRole := strings.ToLower(strings.TrimSpace(role))
	if cleanRole != "admin" {
		cleanRole = "user"
	}
	cleanStatus := strings.ToLower(strings.TrimSpace(status))
	switch cleanStatus {
	case "approved", "pending", "rejected", "disabled":
	default:
		cleanStatus = "approved"
	}
	tag, err := r.pool.Exec(
		ctx,
		`INSERT INTO public.app_memberships (app_user_id, application_id, role, status)
		 SELECT u.id, $2::uuid, $3, $4
		 FROM public.app_users u
		 WHERE u.id = ANY($1::uuid[]) AND u.deleted_at IS NULL
		 ON CONFLICT (app_user_id, application_id)
		 DO UPDATE SET role = EXCLUDED.role, status = EXCLUDED.status`,
		appUserIDs,
		strings.TrimSpace(applicationID),
		cleanRole,
		cleanStatus,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (r *SSOAdminRepository) BulkSoftDeleteUsers(
	ctx context.Context,
	appUserIDs []string,
	excludeUserID string,
) (int64, error) {
	if len(appUserIDs) == 0 {
		return 0, nil
	}
	tag, err := r.pool.Exec(
		ctx,
		`UPDATE public.app_users
		 SET deleted_at = now(), is_sso_admin = false
		 WHERE id = ANY($1::uuid[])
		   AND id::text <> $2
		   AND deleted_at IS NULL`,
		appUserIDs,
		strings.TrimSpace(excludeUserID),
	)
	if err != nil {
		return 0, err
	}
	_, _ = r.pool.Exec(
		ctx,
		`UPDATE public.sso_browser_sessions
		 SET revoked_at = now()
		 WHERE app_user_id = ANY($1::uuid[])
		   AND app_user_id::text <> $2
		   AND revoked_at IS NULL`,
		appUserIDs,
		strings.TrimSpace(excludeUserID),
	)
	return tag.RowsAffected(), nil
}
