package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/nahdukesaba/sso-balai/internal/models"
)

// ErrMembershipNotManaged means the membership does not exist or the actor
// may not manage its application.
var ErrMembershipNotManaged = errors.New("membership is not managed by this actor")

// managedByActor is true when $1 is a Central admin or an approved admin of
// application a; every query re-checks it so permissions are never cached.
const managedByActor = `
a.is_active AND (
    EXISTS (
        SELECT 1 FROM public.app_users actor
        WHERE actor.id = $1 AND actor.role = 'admin'
          AND actor.status = 'approved' AND actor.deleted_at IS NULL
    )
    OR EXISTS (
        SELECT 1 FROM public.app_memberships own
        JOIN public.app_users actor ON actor.id = own.app_user_id
        WHERE own.app_user_id = $1 AND own.application_id = a.id
          AND own.role = 'admin' AND own.status = 'approved'
          AND own.deleted_at IS NULL AND actor.deleted_at IS NULL
    )
)`

type MembershipAdminRepository struct {
	pool *pgxpool.Pool
}

func NewMembershipAdminRepository(pool *pgxpool.Pool) *MembershipAdminRepository {
	return &MembershipAdminRepository{pool: pool}
}

// ListManaged returns every membership of the applications the actor manages,
// pending requests first.
func (r *MembershipAdminRepository) ListManaged(
	ctx context.Context,
	actorAppUserID string,
) ([]models.ManagedMembership, error) {
	rows, err := r.pool.Query(ctx, `
SELECT m.id, a.code, a.name, u.id, u.full_name, u.email, m.role, m.status, m.created_at
FROM public.app_memberships m
JOIN public.applications a ON a.id = m.application_id
JOIN public.app_users u ON u.id = m.app_user_id
WHERE m.deleted_at IS NULL AND u.deleted_at IS NULL AND `+managedByActor+`
ORDER BY (m.status = 'pending') DESC, a.name, u.full_name, u.email
`, actorAppUserID)
	if err != nil {
		return nil, fmt.Errorf("list managed memberships: %w", err)
	}
	memberships, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (models.ManagedMembership, error) {
		var m models.ManagedMembership
		err := row.Scan(&m.ID, &m.ApplicationCode, &m.ApplicationName, &m.AppUserID,
			&m.FullName, &m.Email, &m.Role, &m.Status, &m.CreatedAt)
		return m, err
	})
	if err != nil {
		return nil, fmt.Errorf("scan managed memberships: %w", err)
	}
	return memberships, nil
}

// ManagesAnyApplication reports whether the actor may open the admin page.
func (r *MembershipAdminRepository) ManagesAnyApplication(ctx context.Context, actorAppUserID string) (bool, error) {
	var manages bool
	err := r.pool.QueryRow(ctx, `
SELECT EXISTS (SELECT 1 FROM public.applications a WHERE `+managedByActor+`)
`, actorAppUserID).Scan(&manages)
	if err != nil {
		return false, fmt.Errorf("check managed applications: %w", err)
	}
	return manages, nil
}

// UpdateManaged changes role and status of a membership the actor manages and
// appends an audit event in the same transaction. The actor's own membership
// is never managed, so nobody can lock out or promote themselves.
func (r *MembershipAdminRepository) UpdateManaged(
	ctx context.Context,
	actorAppUserID, membershipID, role, status string,
) error {
	return pgx.BeginFunc(ctx, r.pool, func(tx pgx.Tx) error {
		var applicationCode, subjectID, oldRole, oldStatus string
		err := tx.QueryRow(ctx, `
SELECT a.code, m.app_user_id, m.role, m.status
FROM public.app_memberships m
JOIN public.applications a ON a.id = m.application_id
WHERE m.id = $2 AND m.deleted_at IS NULL AND m.app_user_id <> $1 AND `+managedByActor+`
FOR UPDATE OF m
`, actorAppUserID, membershipID).Scan(&applicationCode, &subjectID, &oldRole, &oldStatus)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrMembershipNotManaged
		}
		if err != nil {
			return fmt.Errorf("lock managed membership: %w", err)
		}

		changed := []string{}
		if oldRole != role {
			changed = append(changed, "role")
		}
		if oldStatus != status {
			changed = append(changed, "status")
		}
		if len(changed) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `
UPDATE public.app_memberships SET role = $2, status = $3, updated_at = now() WHERE id = $1
`, membershipID, role, status); err != nil {
			return fmt.Errorf("update managed membership: %w", err)
		}
		before, _ := json.Marshal(map[string]string{"role": oldRole, "status": oldStatus})
		after, _ := json.Marshal(map[string]string{"role": role, "status": status})
		if _, err := tx.Exec(ctx, `
INSERT INTO public.app_audit_events (
    actor_app_user_id, source_application, action, entity_kind, entity_id,
    subject_app_user_id, changed_fields, before_data, after_data
) VALUES ($1, $2, 'update', 'membership', $3, $4, $5, $6, $7)
`, actorAppUserID, applicationCode, membershipID, subjectID, changed, before, after); err != nil {
			return fmt.Errorf("audit managed membership: %w", err)
		}
		return nil
	})
}
