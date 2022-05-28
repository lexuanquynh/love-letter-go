package authorization

import (
	"LoveLetterProject/internal/database"
	"time"
)

// RegisterRequest is used for registering a new account/user.
type RegisterRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	RePassword string `json:"re-password" validate:"required"`
}

// VerifyMailRequest is used for verifying a new account/user.
type VerifyMailRequest struct {
	Email string `json:"email" validate:"required,email"`
	Code  string `json:"code" validate:"required"`
}

// LoginRequest is the request for login
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

// LoginResponse is the response for login
type LoginResponse struct {
	Email        string `json:"email"`
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	Username     string `json:"username"`
	Verified     bool   `json:"verified"`
}

// LogoutRequest is the request for logout
type LogoutRequest struct {
	Email        string `json:"email" validate:"required,email"`
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// GetUserRequest is used to get user info
type GetUserRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// UpdateUserNameRequest is used to update user name
type UpdateUserNameRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Username    string `json:"username" validate:"required"`
}

// GetProfileRequest is used to get user profile
type GetProfileRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// UpdateProfileRequest is used to update user profile
type UpdateProfileRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	FirstName   string `json:"first_name"`
	LastName    string `json:"last_name"`
	AvatarURL   string `json:"avatar_url"`
	Phone       string `json:"phone"`
	Street      string `json:"street"`
	City        string `json:"city"`
	State       string `json:"state"`
	ZipCode     string `json:"zip_code"`
	Country     string `json:"country"`
}

// GetUserResponse is the response for get user info
type GetUserResponse struct {
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Verified bool   `json:"verified"`
}

// GetLoverResponse is the response for get lover info
type GetLoverResponse struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Accept   bool   `json:"accept"`
}

// GetProfileResponse is the response for get user profile
type GetProfileResponse struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
	AvatarURL string `json:"avatar_url,omitempty"`
	Phone     string `json:"phone,omitempty"`
	Street    string `json:"street,omitempty"`
	City      string `json:"city,omitempty"`
	State     string `json:"state,omitempty"`
	ZipCode   string `json:"zip_code,omitempty"`
	Country   string `json:"country,omitempty"`
}

// UpdatePasswordRequest is used to change password
type UpdatePasswordRequest struct {
	AccessToken     string `json:"access_token" validate:"required"`
	OldPassword     string `json:"old_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

// GenericResponse is the format of our response
type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type GenericErrorResponse struct {
	Status    bool   `json:"status"`
	ErrorCode int    `json:"error_code"`
	Message   string `json:"message"`
}

type AuthResponse struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	Username     string `json:"username,omitempty"`
}

type PasswordResetResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type GetForgetPasswordCodeRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type CreateNewPasswordWithCodeRequest struct {
	Code        string `json:"code" validate:"required"`
	Email       string `json:"email" validate:"required,email"`
	NewPassword string `json:"new_password" validate:"required"`
}

// GenerateAccessTokenRequest is used to generate access token
type GenerateAccessTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required"`
}

// GenerateAccessResponse is the response for generate access token
type GenerateAccessResponse struct {
	RefreshToken string `json:"refresh_token,omitempty"`
	AccessToken  string `json:"access_token,omitempty"`
	Username     string `json:"username,omitempty"`
}

// GetVerifyMailCodeRequest is used to get verify mail code
type GetVerifyMailCodeRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// GetMatchCodeRequest is used to get match code
type GetMatchCodeRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// GetMatchCodeResponse is the response for get match code
type GetMatchCodeResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// MatchLoverRequest is used to match love
type MatchLoverRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Code        string `json:"code" validate:"required"`
}

// UnMatchLoverRequest is used to unmatch love
type UnMatchLoverRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// GetMatchedLoverRequest is used to get match lover
type GetMatchedLoverRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// CreateLoveLetterRequest is used to create love letter
type CreateLoveLetterRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Title       string `json:"title" validate:"required"`
	Body        string `json:"body" validate:"required"`
}

// UpdateLoveLetterRequest is used to update love letter
type UpdateLoveLetterRequest struct {
	AccessToken string    `json:"access_token" validate:"required"`
	Title       string    `json:"title" validate:"required"`
	Body        string    `json:"body" validate:"required"`
	IsRead      bool      `json:"is_read"`
	IsDelete    bool      `json:"is_delete"`
	TimeOpen    time.Time `json:"time_open" sql:"timeopen"`
}

// GetFeedsResponse is the response for get feeds
type GetFeedsResponse struct {
	Feeds []*database.FeedsData `json:"feed_list"`
}
