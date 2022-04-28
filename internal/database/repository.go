package database

import "context"

type UserRepository interface {
	// CreateUser Create  new user
	CreateUser(ctx context.Context, user *User) error
	// StoreVerificationData Save verification data into database
	StoreVerificationData(ctx context.Context, verificationData *VerificationData) error
	// GetUserByEmail Get user by email
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	// GetUserByID Get user by id
	GetUserByID(ctx context.Context, id string) (*User, error)
	// UpdateUser Update user
	UpdateUser(ctx context.Context, user *User) error
}
