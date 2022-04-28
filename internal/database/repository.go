package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// StoreVerificationData Save verification data into database
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) error
	// GetUserByEmail Get user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
}
