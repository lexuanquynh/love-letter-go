package database

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
	"time"
)

// PostgresRepository has the implementation of the db methods.
type PostgresRepository struct {
	db     *sqlx.DB
	logger hclog.Logger
}

// NewPostgresRepository creates a new PostgresRepository.
func NewPostgresRepository(db *sqlx.DB, logger hclog.Logger) *PostgresRepository {
	return &PostgresRepository{
		db:     db,
		logger: logger,
	}
}

// CreateUser inserts the given user into the database.
func (repo *PostgresRepository) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.NewV4().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := repo.db.ExecContext(ctx, query, user.ID, user.Email, user.Username, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// StoreVerificationData adds a mail verification data to db
func (repo *PostgresRepository) StoreVerificationData(ctx context.Context, verificationData *VerificationData) error {
	query := "insert into verifications(email, code, expiresat, type, numofresets) values($1, $2, $3, $4, $5)"
	_, err := repo.db.ExecContext(ctx, query,
		verificationData.Email,
		verificationData.Code,
		verificationData.ExpiresAt,
		verificationData.Type,
		verificationData.Numofresets)
	return err
}

// GetUserByEmail returns the user with the given email.
func (repo *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := "select id, email, username, password, tokenhash, createdat, updatedat from users where email = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, email)
	return user, err
}
