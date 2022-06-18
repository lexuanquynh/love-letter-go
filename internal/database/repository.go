package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// UpdateUserVerificationStatus Update user verification status
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	// InsertVerificationData Save verification data into database
	InsertVerificationData(ctx context.Context, verificationData *VerificationData) error
	// GetVerificationData Get verification data from database
	GetVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) (*VerificationData, error)
	//DeleteVerificationData Delete verification data from database
	DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error
	// GetUserByEmail Get user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByID Get user by id
	GetUserByID(ctx context.Context, id string) (*User, error)
	// UpdateUser Update user
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	// CheckUsernameExists Check if username exists
	CheckUsernameExists(ctx context.Context, username string) (bool, error)
	// GetProfileByID Get profile by user id
	GetProfileByID(ctx context.Context, userId string) (*ProfileData, error)
	// InsertProfile Insert profile
	InsertProfile(ctx context.Context, profile *ProfileData) error
	// UpdatePassword Update password
	UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error
	// GetListOfPasswords Get list of passwords
	GetListOfPasswords(ctx context.Context, userID string) ([]string, error)
	// InsertListOfPasswords Update password into list of passwords
	InsertListOfPasswords(ctx context.Context, passwordUsers *PassworUsers) error
	// GetLimitData Get limit table data
	GetLimitData(ctx context.Context, userID string, limitType LimitType) (*LimitData, error)
	// InsertLimitData Insert or update limit data
	InsertLimitData(ctx context.Context, limitData *LimitData) error
	// ResetLimitData Clear limit data
	ResetLimitData(ctx context.Context, limitType LimitType) error
	// InsertMatchVerifyData Insert match verify data
	InsertMatchVerifyData(ctx context.Context, matchData *MatchVerifyData) error
	// GetMatchVerifyDataByCode Get match data
	GetMatchVerifyDataByCode(ctx context.Context, code string) (*MatchVerifyData, error)
	// DeleteMatchVerifyDataByUserID Delete match data
	DeleteMatchVerifyDataByUserID(ctx context.Context, userID string) error
	// GetMatchLoveDataByUserID Get match love data
	GetMatchLoveDataByUserID(ctx context.Context, userID string) (*MatchLoveData, error)
	// InsertMatchLoveData Insert match love data
	InsertMatchLoveData(ctx context.Context, matchData *MatchLoveData) error
	// DeleteMatchLoveDataByUserID Delete match love data
	DeleteMatchLoveDataByUserID(ctx context.Context, userID string) error
	// InsertPlayerData insert id for push notifications
	InsertPlayerData(ctx context.Context, playerData *PlayerData) error
	// GetPlayerData Get player data
	GetPlayerData(ctx context.Context, userID string) (*PlayerData, error)
	// InsertUserStateData Insert user state data
	InsertUserStateData(ctx context.Context, userStateData *UserStateData) error
	// DeleteUserStateData Delete user state data
	DeleteUserStateData(ctx context.Context, userID string, keyString string) error
	// GetUserStateData Get user state data
	GetUserStateData(ctx context.Context, userID string, keyString string) (*UserStateData, error)
	// RunSchedule Run schedule
	RunSchedule(ctx context.Context) error
	// InsertSchedule Set schedule
	InsertSchedule(ctx context.Context, schedule *Schedule) error
	// DeleteSchedule Delete schedule
	DeleteSchedule(ctx context.Context, userID string, name string) error
	// GetSchedule Get schedule
	GetSchedule(ctx context.Context, userID string, name string) (*Schedule, error)
	// CreateLetter Create letter
	CreateLetter(ctx context.Context, letter *Letter) error
	// DeleteLetter Delete letter
	DeleteLetter(ctx context.Context, userID string, letterID string) error
	// GetLetters Get letters by user id and page. maximum by pageSize letters, default is 10
	GetLetters(ctx context.Context, userID string, page int, maximum int) ([]Letter, error)
}
