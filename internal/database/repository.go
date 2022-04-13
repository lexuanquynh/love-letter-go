package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// StoreVerificationData Save verification data into database
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) error
}
