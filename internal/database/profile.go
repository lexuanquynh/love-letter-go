package database

import "time"

// ProfileData represents a user profile
type ProfileData struct {
	ID        string    `json:"id" sql:"id"`
	UserID    string    `json:"user_id" sql:"userid"`
	Email     string    `json:"email" validate:"required,email" sql:"email"`
	FirstName string    `json:"firstname" sql:"firstname"`
	LastName  string    `json:"lastname" sql:"lastname"`
	AvatarURL string    `json:"avatar_url" sql:"avatarurl"`
	Phone     string    `json:"phone"sql:"phone"`
	Street    string    `json:"street" sql:"street"`
	City      string    `json:"city" sql:"city"`
	State     string    `json:"state" sql:"state"`
	ZipCode   string    `json:"zip_code" sql:"zipcode"`
	Country   string    `json:"country" sql:"country"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}
