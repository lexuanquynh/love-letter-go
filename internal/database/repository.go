package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// UpdateUserVerificationStatus Update user verification status
	UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error
	// StoreVerificationData Save verification data into database
	StoreVerificationData(ctx context.Context, verificationData *VerificationData, isInsert bool) error
	// StoreProfileData Save profile data into database
	StoreProfileData(ctx context.Context, profileData *ProfileData) error
	// GetVerificationData Get verification data from database
	GetVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) (*VerificationData, error)
	//DeleteVerificationData Delete verification data from database
	DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error
	// UpdateProfileData Update profile data into database
	UpdateProfileData(ctx context.Context, profileData *ProfileData) error
	// GetUserByEmail Get user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByID Get user by id
	GetUserByID(ctx context.Context, id string) (*User, error)
	// UpdateUser Update user
	UpdateUser(ctx context.Context, user *User) error
	// CheckUsernameExists Check if username exists
	CheckUsernameExists(ctx context.Context, username string) (bool, error)
	// GetProfileByID Get profile by user id
	GetProfileByID(ctx context.Context, userId string) (*ProfileData, error)
	// UpdateProfile Update profile
	UpdateProfile(ctx context.Context, profile *ProfileData) error
	// UpdatePassword Update password
	UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error
	// GetListOfPasswords Get list of passwords
	GetListOfPasswords(ctx context.Context, userID string) ([]string, error)
	// InsertListOfPasswords Update password into list of passwords
	InsertListOfPasswords(ctx context.Context, passwordUsers *PassworUsers) error
	// GetLimitData Get limit table data
	GetLimitData(ctx context.Context, userID string, limitType LimitType) (*LimitData, error)
	// InsertOrUpdateLimitData Insert or update limit data
	InsertOrUpdateLimitData(ctx context.Context, limitData *LimitData, limitType LimitType) error
	// ClearLimitData Clear limit data
	ClearLimitData(ctx context.Context, limitType LimitType) error
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
	// CreateLoveLetter Create love letter
	CreateLoveLetter(ctx context.Context, loveLetter *LoveLetter) error
	// UpdateLoveLetter Update love letter
	UpdateLoveLetter(ctx context.Context, loveLetter *LoveLetter) error
	// GetFeeds Get feeds
	GetFeeds(ctx context.Context) ([]*FeedsData, error)
	// InsertPlayerData Insert player data
	InsertPlayerData(ctx context.Context, playerData *PlayerData) error
	// GetPlayerData Get player data
	GetPlayerData(ctx context.Context, userID string) (*PlayerData, error)
	// InsertUserStateData Insert user state data
	InsertUserStateData(ctx context.Context, userStateData *UserStateData) error
	// DeleteUserStateData Delete user state data
	DeleteUserStateData(ctx context.Context, userID string, keyString string) error
	// GetUserStateData Get user state data
	GetUserStateData(ctx context.Context, userID string, keyString string) (*UserStateData, error)
}
