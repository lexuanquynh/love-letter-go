package database

import (
	"context"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
	"time"
)

// postgresRepository has the implementation of the db methods.
type postgresRepository struct {
	db     *sqlx.DB
	logger hclog.Logger
}

// NewPostgresRepository creates a new PostgresRepository.
func NewPostgresRepository(db *sqlx.DB, logger hclog.Logger) *postgresRepository {
	return &postgresRepository{
		db:     db,
		logger: logger,
	}
}

// CreateUser inserts the given user into the database.
func (repo *postgresRepository) CreateUser(ctx context.Context, user *User) error {
	user.ID = uuid.NewV4().String()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	query := "insert into users (id, email, username, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := repo.db.ExecContext(ctx, query, user.ID, user.Email, user.Username, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// StoreVerificationData adds a mail verification data to db
func (repo *postgresRepository) StoreVerificationData(ctx context.Context, verificationData *VerificationData, isInsert bool) error {
	if isInsert {
		query := "insert into verifications(email, code, expiresat, type) values($1, $2, $3, $4)"
		_, err := repo.db.ExecContext(ctx, query,
			verificationData.Email,
			verificationData.Code,
			verificationData.ExpiresAt,
			verificationData.Type)
		return err
	} else {
		query := "update verifications set code=$1, expiresat=$2, type=$3 where email=$4"
		_, err := repo.db.ExecContext(ctx, query,
			verificationData.Code,
			verificationData.ExpiresAt,
			verificationData.Type,
			verificationData.Email)
		return err
	}
}

// GetUserByEmail returns the user with the given email.
func (repo *postgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := "select id, email, username, password, tokenhash, createdat, updatedat from users where email = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, email)
	return user, err
}

// GetUserByID returns the user with the given id.
func (repo *postgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := "select id, email, username, password, tokenhash, createdat, updatedat from users where id = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, id)
	return user, err
}

// UpdateUser updates the user with the given id.
func (repo *postgresRepository) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	query := "update users set email = $1, username = $2, password = $3, tokenhash = $4, updatedat = $5 where id = $6"
	_, err := repo.db.ExecContext(ctx, query, user.Email, user.Username, user.Password, user.TokenHash, user.UpdatedAt, user.ID)
	return err
}

// StoreProfileData stores the profile data in the database
func (repo *postgresRepository) StoreProfileData(ctx context.Context, profileData *ProfileData) error {
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
func (repo *postgresRepository) UpdateProfileData(ctx context.Context, profileData *ProfileData) error {
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
func (repo *postgresRepository) GetProfileByID(ctx context.Context, userId string) (*ProfileData, error) {
	query := "select id, userid, email, firstname, lastname, avatarurl, phone, street, city, state, zipcode, country, createdat, updatedat from profiles where userid = $1"
	profile := &ProfileData{}
	err := repo.db.GetContext(ctx, profile, query, userId)
	return profile, err
}

// UpdateProfile updates the profile data.
func (repo *postgresRepository) UpdateProfile(ctx context.Context, profile *ProfileData) error {
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

// UpdatePassword updates the user password
func (repo *postgresRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {
	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}

// GetListOfPasswords returns the list of passwords
func (repo *postgresRepository) GetListOfPasswords(ctx context.Context, userID string) ([]string, error) {
	query := "select password from passworusers where userid = $1"
	rows, err := repo.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var passwords []string
	for rows.Next() {
		var password string
		err := rows.Scan(&password)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, password)
	}
	return passwords, nil
}

// InsertListOfPasswords updates the list of passwords
func (repo *postgresRepository) InsertListOfPasswords(ctx context.Context, passwordUsers *PassworUsers) error {
	passwordUsers.ID = uuid.NewV4().String()
	passwordUsers.CreatedAt = time.Now()
	passwordUsers.UpdatedAt = time.Now()

	query := "insert into passworusers(id, userid, password, createdat, updatedat) values($1, $2, $3, $4, $5)"
	_, err := repo.db.ExecContext(ctx, query,
		passwordUsers.ID,
		passwordUsers.UserID,
		passwordUsers.Password,
		passwordUsers.CreatedAt,
		passwordUsers.UpdatedAt)

	return err
}

// GetLimitData returns the limit data
func (repo *postgresRepository) GetLimitData(ctx context.Context, userID string) (*LimitData, error) {
	query := "select id, userid, numofsendmail, numofchangepassword, numoflogin, createdat, updatedat from limits where userid = $1"
	limitData := &LimitData{}
	err := repo.db.GetContext(ctx, limitData, query, userID)
	return limitData, err
}

// InsertOrUpdateLimitData updates the limit data
func (repo *postgresRepository) InsertOrUpdateLimitData(ctx context.Context, limitData *LimitData, isInsert bool) error {
	limitData.ID = uuid.NewV4().String()
	limitData.CreatedAt = time.Now()
	limitData.UpdatedAt = time.Now()
	// Insert or update
	if isInsert {
		// Insert the limit data
		query := "insert into limits(id, userid, numofsendmail, numofchangepassword, numoflogin, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7)"
		_, err := repo.db.ExecContext(ctx, query,
			limitData.ID,
			limitData.UserID,
			limitData.NumOfSendMail,
			limitData.NumOfChangePassword,
			limitData.NumOfLogin,
			limitData.CreatedAt,
			limitData.UpdatedAt)
		return err
	} else {
		// Update the limit data
		query := "update limits set numofsendmail = $1, numofchangepassword = $2, numoflogin = $3, updatedat = $4 where userid = $5"
		_, err := repo.db.ExecContext(ctx, query,
			limitData.NumOfSendMail,
			limitData.NumOfChangePassword,
			limitData.NumOfLogin,
			limitData.UpdatedAt,
			limitData.UserID)
		return err
	}
}

// ClearAllLimitData clears all limit data
func (repo *postgresRepository) ClearAllLimitData(ctx context.Context) error {
	query := "delete from limits"
	_, err := repo.db.ExecContext(ctx, query)
	return err
}
