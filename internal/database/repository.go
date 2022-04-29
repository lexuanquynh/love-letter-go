package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// StoreVerificationData Save verification data into database
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) error
	// StoreProfileData Save profile data into database
	StoreProfileData(ctx context.Context, profileData *ProfileData) error
	// UpdateProfileData Update profile data into database
	UpdateProfileData(ctx context.Context, profileData *ProfileData) error
	// GetUserByEmail Get user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByID Get user by id
	GetUserByID(ctx context.Context, id string) (*User, error)
	// UpdateUser Update user
	UpdateUser(ctx context.Context, user *User) error
	// GetProfileByID Get profile by user id
	GetProfileByID(ctx context.Context, userId string) (*ProfileData, error)
}
