package services

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidAccessToken = errors.New(
		"invalid central access token",
	)

	ErrInvalidTokenConfiguration = errors.New(
		"invalid access token configuration",
	)
)

type AccessTokenClaims struct {
	SessionID string `json:"sid"`
	Role      string `json:"role"`

	jwt.RegisteredClaims
}

func (c *AccessTokenClaims) Application() string {
	if c == nil ||
		len(c.Audience) != 1 {
		return ""
	}

	return c.Audience[0]
}

type AccessTokenService struct {
	secret []byte
	issuer string
	ttl    time.Duration
}

func NewAccessTokenService(
	secret string,
	issuer string,
	ttl time.Duration,
) (*AccessTokenService, error) {
	secret = strings.TrimSpace(secret)
	issuer = strings.TrimSpace(issuer)

	if len(secret) < 32 {
		return nil, fmt.Errorf(
			"%w: signing secret must contain at least 32 characters",
			ErrInvalidTokenConfiguration,
		)
	}

	if issuer == "" {
		return nil, fmt.Errorf(
			"%w: issuer is required",
			ErrInvalidTokenConfiguration,
		)
	}

	if ttl <= 0 {
		return nil, fmt.Errorf(
			"%w: token ttl must be positive",
			ErrInvalidTokenConfiguration,
		)
	}

	return &AccessTokenService{
		secret: []byte(secret),
		issuer: issuer,
		ttl:    ttl,
	}, nil
}

func (s *AccessTokenService) Issue(
	userID string,
	sessionID string,
	application string,
	role string,
) (
	string,
	time.Time,
	error,
) {
	userID = strings.TrimSpace(userID)
	sessionID = strings.TrimSpace(sessionID)
	application = strings.ToLower(
		strings.TrimSpace(application),
	)
	role = strings.TrimSpace(role)

	if userID == "" ||
		sessionID == "" ||
		application == "" ||
		role == "" {
		return "", time.Time{}, ErrInvalidAccessToken
	}

	now := time.Now().UTC()
	expiresAt := now.Add(s.ttl)

	claims := AccessTokenClaims{
		SessionID: sessionID,
		Role:      role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{application},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		claims,
	)

	signedToken, err := token.SignedString(
		s.secret,
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf(
			"sign central access token: %w",
			err,
		)
	}

	return signedToken, expiresAt, nil
}

func (s *AccessTokenService) Parse(
	rawToken string,
) (*AccessTokenClaims, error) {
	rawToken = strings.TrimSpace(rawToken)

	if rawToken == "" {
		return nil, ErrInvalidAccessToken
	}

	claims := &AccessTokenClaims{}

	token, err := jwt.ParseWithClaims(
		rawToken,
		claims,
		func(token *jwt.Token) (any, error) {
			if token.Method.Alg() !=
				jwt.SigningMethodHS256.Alg() {

				return nil, ErrInvalidAccessToken
			}

			return s.secret, nil
		},
		jwt.WithValidMethods(
			[]string{
				jwt.SigningMethodHS256.Alg(),
			},
		),
		jwt.WithIssuer(s.issuer),
		jwt.WithExpirationRequired(),
	)
	if err != nil ||
		token == nil ||
		!token.Valid {
		return nil, ErrInvalidAccessToken
	}

	if strings.TrimSpace(claims.Subject) == "" ||
		strings.TrimSpace(claims.SessionID) == "" ||
		strings.TrimSpace(claims.Role) == "" ||
		claims.Application() == "" {

		return nil, ErrInvalidAccessToken
	}

	return claims, nil
}

func (s *AccessTokenService) TTL() time.Duration {
	return s.ttl
}
