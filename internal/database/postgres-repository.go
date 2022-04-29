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

// GetUserByID returns the user with the given id.
func (repo *PostgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := "select id, email, username, password, tokenhash, createdat, updatedat from users where id = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, id)
	return user, err
}

// UpdateUser updates the user with the given id.
func (repo *PostgresRepository) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	query := "update users set email = $1, username = $2, password = $3, tokenhash = $4, updatedat = $5 where id = $6"
	_, err := repo.db.ExecContext(ctx, query, user.Email, user.Username, user.Password, user.TokenHash, user.UpdatedAt, user.ID)
	return err
}

// StoreProfileData stores the profile data in the database
func (repo *PostgresRepository) StoreProfileData(ctx context.Context, profileData *ProfileData) error {
	profileData.ID = uuid.NewV4().String()
	profileData.CreatedAt = time.Now()
	profileData.UpdatedAt = time.Now()
	query := "insert into profiles(id, userid, email, createdat, updatedat) values($1, $2, $3, $4, $5)"
	_, err := repo.db.ExecContext(ctx, query,
		profileData.ID,
		profileData.UserID,
		profileData.Email,
		profileData.CreatedAt,
		profileData.UpdatedAt)
	return err
}

// UpdateProfileData updates the profile data in the database
func (repo *PostgresRepository) UpdateProfileData(ctx context.Context, profileData *ProfileData) error {
	profileData.UpdatedAt = time.Now()
	query := "update profiles set  firstname = $1, lastname = $2, avatar_url = $3, phone = $4, street = $5, city = $6, state = $7, zip_code = $8, country = $9, updatedat = $10 where id = $11"
	_, err := repo.db.ExecContext(ctx, query,
		profileData.FirstName,
		profileData.LastName,
		profileData.AvatarURL,
		profileData.Phone,
		profileData.Street,
		profileData.City,
		profileData.State,
		profileData.ZipCode,
		profileData.Country,
		profileData.UpdatedAt,
		profileData.ID)
	return err
}

// GetProfileByID returns the profile with the given user id.
func (repo *PostgresRepository) GetProfileByID(ctx context.Context, userId string) (*ProfileData, error) {
	query := "select id, userid, email, firstname, lastname, avatarurl, phone, street, city, state, zipcode, country, createdat, updatedat from profiles where userid = $1"
	profile := &ProfileData{}
	err := repo.db.GetContext(ctx, profile, query, userId)
	return profile, err
}

// UpdateProfile updates the profile data.
func (repo *PostgresRepository) UpdateProfile(ctx context.Context, profile *ProfileData) error {
	profile.UpdatedAt = time.Now()
	query := "update profiles set firstname = $1, lastname = $2, avatarurl = $3, phone = $4, street = $5, city = $6, state = $7, zipcode = $8, country = $9, updatedat = $10 where userid = $11"
	_, err := repo.db.ExecContext(ctx, query,
		profile.FirstName,
		profile.LastName,
		profile.AvatarURL,
		profile.Phone,
		profile.Street,
		profile.City,
		profile.State,
		profile.ZipCode,
		profile.Country,
		profile.UpdatedAt,
		profile.UserID)
	return err
}
