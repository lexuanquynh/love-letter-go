package database

import (
	"golang.org/x/crypto/bcrypt"
	"time"
)

// User is the data type for user object
type User struct {
	ID        string    `json:"id" sql:"id"`
	Email     string    `json:"email" validate:"required,email" sql:"email"`
	Password  string    `json:"password" validate:"required" sql:"password"`
	PassCode  string    `json:"passcode" sql:"passcode"`
	Username  string    `json:"username" sql:"username"`
	TokenHash string    `json:"tokenhash" sql:"tokenhash"`
	Verified  bool      `json:"verified" sql:"verified"`
	Banned    bool      `json:"banned" sql:"banned"`
	Deleted   bool      `json:"deleted" sql:"deleted"`
	Role      string    `json:"role" sql:"role"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// HashPassword hashes the password
func (u User) HashPassword() (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hashedPass), nil
}
