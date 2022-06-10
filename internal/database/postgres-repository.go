package database

import (
	"context"
	"database/sql"
	"errors"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
	"log"
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

// UpdateUserVerificationStatus updates user verification status to true
func (repo *postgresRepository) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {
	query := "update users set verified = $1 where email = $2"
	if _, err := repo.db.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// CheckUsernameExists checks if the given username exists in the database.
func (repo *postgresRepository) CheckUsernameExists(ctx context.Context, username string) (bool, error) {
	query := "select count(*) from users where username = $1"
	var count int
	if err := repo.db.GetContext(ctx, &count, query, username); err != nil {
		return false, err
	}
	return count > 0, nil
}

// StoreVerificationData adds a mail verification data to db
func (repo *postgresRepository) StoreVerificationData(ctx context.Context, verificationData *VerificationData, isInsert bool) error {
	if isInsert {
		id := uuid.NewV4().String()
		query := "insert into verifications(id, email, code, expiresat, type) values($1, $2, $3, $4, $5)"
		_, err := repo.db.ExecContext(ctx, query,
			id,
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

// GetVerificationData retrieves the stored verification code.
func (repo *postgresRepository) GetVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) (*VerificationData, error) {
	query := "select * from verifications where email = $1 and type = $2"

	var verificationData VerificationData
	if err := repo.db.GetContext(ctx, &verificationData, query, email, verificationDataType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

// DeleteVerificationData deletes a used verification data
func (repo *postgresRepository) DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error {
	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.db.ExecContext(ctx, query, email, verificationDataType)
	return err
}

// GetUserByEmail returns the user with the given email.
func (repo *postgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := "select * from users where email = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, email)
	return user, err
}

// GetUserByID returns the user with the given id.
func (repo *postgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := "select  * from users where id = $1"
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

// GetProfileByID returns the profile with the given user id.
func (repo *postgresRepository) GetProfileByID(ctx context.Context, userId string) (*ProfileData, error) {
	query := "select * from profiles where userid = $1"
	profile := &ProfileData{}
	err := repo.db.GetContext(ctx, profile, query, userId)
	return profile, err
}

// InsertProfile insert profile data into db
func (repo *postgresRepository) InsertProfile(ctx context.Context, profile *ProfileData) error {
	profile.CreatedAt = time.Now()
	profile.UpdatedAt = time.Now()
	query := "insert into profiles (userid, email, gender, birthday, firstname, lastname, avatarurl, phone, street, city, state, zipcode, country, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)" +
		"on conflict (userid) do update set email = $2, gender = $3, birthday = $4, firstname = $5, lastname = $6, avatarurl = $7, phone = $8, street = $9, city = $10, state = $11, zipcode = $12, country = $13, updatedat = $15"
	_, err := repo.db.ExecContext(
		ctx,
		query,
		profile.UserID,
		profile.Email,
		profile.Gender,
		profile.Birthday,
		profile.FirstName,
		profile.LastName,
		profile.AvatarURL,
		profile.Phone,
		profile.Street,
		profile.City,
		profile.State,
		profile.ZipCode,
		profile.Country,
		profile.CreatedAt,
		profile.UpdatedAt)
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
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Println(err)
		}
	}(rows)
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
func (repo *postgresRepository) GetLimitData(ctx context.Context, userID string, limitType LimitType) (*LimitData, error) {
	query := "select * from limits where userid = $1"
	limitData := &LimitData{}
	err := repo.db.GetContext(ctx, limitData, query, userID)
	if err != nil {
		if limitType == LimitTypeLogin {
			limitData.NumOfLogin = 1
		} else if limitType == LimitTypeSendVerifyMail {
			limitData.NumOfSendMailVerify = 1
		} else if limitType == LimitTypeSendPassResetMail {
			limitData.NumOfSendResetPassword = 1
		} else if limitType == LimitTypeChangePassword {
			limitData.NumOfChangePassword = 1
		}
	} else {
		if limitType == LimitTypeLogin {
			limitData.NumOfLogin += 1
		} else if limitType == LimitTypeSendVerifyMail {
			limitData.NumOfSendMailVerify += 1
		} else if limitType == LimitTypeSendPassResetMail {
			limitData.NumOfSendResetPassword += 1
		} else if limitType == LimitTypeChangePassword {
			limitData.NumOfChangePassword += 1
		}
	}
	limitData.UserID = userID
	return limitData, err
}

// InsertOrUpdateLimitData updates the limit data
func (repo *postgresRepository) InsertOrUpdateLimitData(ctx context.Context, limitData *LimitData, limitType LimitType) error {
	// Check exist or not limit data
	_, err := repo.GetLimitData(ctx, limitData.UserID, limitType)
	isInsert := false
	if err != nil {
		isInsert = true
		limitData.ID = uuid.NewV4().String()
		limitData.CreatedAt = time.Now()
	}

	limitData.UpdatedAt = time.Now()
	// Insert or update
	if isInsert {
		// Insert the limit data
		query := "insert into limits(id, userid, numofsendmailverify, numofsendresetpassword, numofchangepassword, numoflogin, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7, $8)"
		_, err := repo.db.ExecContext(ctx, query,
			limitData.ID,
			limitData.UserID,
			limitData.NumOfSendMailVerify,
			limitData.NumOfSendResetPassword,
			limitData.NumOfChangePassword,
			limitData.NumOfLogin,
			limitData.CreatedAt,
			limitData.UpdatedAt)
		return err
	} else {
		// Update the limit data
		query := "update limits set numofsendmailverify = $1, numofsendresetpassword = $2, numofchangepassword = $3, numoflogin = $4, updatedat = $5 where userid = $6"
		_, err := repo.db.ExecContext(ctx, query,
			limitData.NumOfSendMailVerify,
			limitData.NumOfSendResetPassword,
			limitData.NumOfChangePassword,
			limitData.NumOfLogin,
			limitData.UpdatedAt,
			limitData.UserID)
		return err
	}
}

// ClearLimitData clears the limit data
func (repo *postgresRepository) ClearLimitData(ctx context.Context, limitType LimitType) error {
	var query string
	if limitType == LimitTypeLogin {
		// Clear all num of login limit
		query = "update limits set numoflogin = 0"
	} else if limitType == LimitTypeSendVerifyMail {
		// Clear all num of send mail limit
		query = "update limits set numofsendmailverify = 0"
	} else if limitType == LimitTypeSendPassResetMail {
		query = "update limits set numofsendresetpassword = 0"
	} else if limitType == LimitTypeChangePassword {
		// Clear all num of change password limit
		query = "update limits set numofchangepassword = 0"
	} else {
		return errors.New("limit type is not valid")
	}
	_, err := repo.db.ExecContext(ctx, query)
	return err
}

// InsertMatchVerifyData inserts the match data
func (repo *postgresRepository) InsertMatchVerifyData(ctx context.Context, matchData *MatchVerifyData) error {
	// Insert the match data
	matchData.CreatedAt = time.Now()
	matchData.UpdatedAt = time.Now()
	query := "insert into generatematchcodes(userid, email, code, expiresat, createdat, updatedat) values($1, $2, $3, $4, $5, $6)" +
		" on conflict (userid) do update set email = $2, code = $3, expiresat = $4, updatedat = $6"
	_, err := repo.db.ExecContext(ctx, query,
		matchData.UserID,
		matchData.Email,
		matchData.Code,
		matchData.ExpiresAt,
		matchData.CreatedAt,
		matchData.UpdatedAt)
	return err
}

// GetMatchVerifyDataByCode returns the match data
func (repo *postgresRepository) GetMatchVerifyDataByCode(ctx context.Context, code string) (*MatchVerifyData, error) {
	query := "select * from generatematchcodes where code = $1"
	matchData := &MatchVerifyData{}
	err := repo.db.GetContext(ctx, matchData, query, code)
	return matchData, err
}

// DeleteMatchVerifyDataByUserID deletes the match data
func (repo *postgresRepository) DeleteMatchVerifyDataByUserID(ctx context.Context, userID string) error {
	query := "delete from generatematchcodes where userid = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// GetMatchLoveDataByUserID returns the match love data
func (repo *postgresRepository) GetMatchLoveDataByUserID(ctx context.Context, userID string) (*MatchLoveData, error) {
	query := "select * from matchloves where userid1 = $1"
	matchData := &MatchLoveData{}
	err := repo.db.GetContext(ctx, matchData, query, userID)
	if err != nil {
		query = "select * from matchloves where userid2 = $1"
		err = repo.db.GetContext(ctx, matchData, query, userID)
	}
	return matchData, err
}

// InsertMatchLoveData inserts the match love data
func (repo *postgresRepository) InsertMatchLoveData(ctx context.Context, matchData *MatchLoveData) error {
	matchData.CreatedAt = time.Now()
	matchData.UpdatedAt = time.Now()
	query := "insert into matchloves(userid1, userid2, email1, email2, accept1, accept2, startdate, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7, $8, $9)" +
		" on conflict (userid1, userid2) do update set email1 = $3, email2 = $4, accept1 = $5, accept2 = $6, startdate = $7, updatedat = $9"
	_, err := repo.db.ExecContext(ctx, query,
		matchData.UserID1,
		matchData.UserID2,
		matchData.Email1,
		matchData.Email2,
		matchData.Accept1,
		matchData.Accept2,
		matchData.StartDate,
		matchData.CreatedAt,
		matchData.UpdatedAt)
	return err
}

// DeleteMatchLoveDataByUserID deletes the match love data
func (repo *postgresRepository) DeleteMatchLoveDataByUserID(ctx context.Context, userID string) error {
	query := "delete from matchloves where userid1 = $1 or userid2 = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// InsertPlayerData inserts player data
func (repo *postgresRepository) InsertPlayerData(ctx context.Context, playerData *PlayerData) error {
	playerData.CreatedAt = time.Now()
	playerData.UpdatedAt = time.Now()
	query := "insert into players(userid, uuid, playerid, devicename, deviceversion, devicemodel, deviceos, devicelocalize, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)" +
		" on conflict (userid) do update set uuid = $2, playerid = $3, devicename = $4, deviceversion = $5, devicemodel = $6, deviceos = $7, devicelocalize = $8, updatedat = $10"
	_, err := repo.db.ExecContext(ctx, query,
		playerData.UserID,
		playerData.UUID,
		playerData.PlayerId,
		playerData.DeviceName,
		playerData.DeviceVersion,
		playerData.DeviceModel,
		playerData.DeviceOS,
		playerData.DeviceLocalize,
		playerData.CreatedAt,
		playerData.UpdatedAt)
	return err
}

// GetPlayerData returns player data
func (repo *postgresRepository) GetPlayerData(ctx context.Context, userID string) (*PlayerData, error) {
	query := "select * from players where userid = $1"
	var playerData PlayerData
	err := repo.db.GetContext(ctx, &playerData, query, userID)
	return &playerData, err
}

// InsertUserStateData inserts user state data
func (repo *postgresRepository) InsertUserStateData(ctx context.Context, userStateData *UserStateData) error {
	userStateData.CreatedAt = time.Now()
	userStateData.UpdatedAt = time.Now()
	query := "insert into userstates(userid, keystring, stringvalue, intvalue, boolvalue, floatvalue, timevalue, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8, $9) " +
		"on conflict (userid, keystring) do update set stringvalue = $3, intvalue = $4, boolvalue = $5, floatvalue = $6, timevalue = $7, updatedat = $9"
	_, err := repo.db.ExecContext(ctx, query,
		userStateData.UserID,
		userStateData.KeyString,
		userStateData.StringValue,
		userStateData.IntValue,
		userStateData.BoolValue,
		userStateData.FloatValue,
		userStateData.TimeValue,
		userStateData.CreatedAt,
		userStateData.UpdatedAt)
	return err
}

// DeleteUserStateData deletes user state data
func (repo *postgresRepository) DeleteUserStateData(ctx context.Context, userID string, keyString string) error {
	query := "delete from userstates where userid = $1 and keystring = $2"
	_, err := repo.db.ExecContext(ctx, query, userID, keyString)
	return err
}

// GetUserStateData returns user state data
func (repo *postgresRepository) GetUserStateData(ctx context.Context, userID string, keyString string) (*UserStateData, error) {
	query := "select * from userstates where userid = $1 and keystring = $2"
	var userStateData UserStateData
	err := repo.db.GetContext(ctx, &userStateData, query, userID, keyString)
	return &userStateData, err
}
