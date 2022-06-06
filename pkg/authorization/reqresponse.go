package authorization

import (
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

// CommonAuthorizationRequest is used to get user info
type CommonAuthorizationRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// UpdateUserNameRequest is used to update user name
type UpdateUserNameRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Username    string `json:"username" validate:"required"`
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
	Accept1  int    `json:"accept1"`
	Accept2  int    `json:"accept2"`
}

// MatchLoverResponse is the response for match lover info
type MatchLoverResponse struct {
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Accept   int    `json:"accept"`
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

// GetMatchCodeResponse is the response for get match code
type GetMatchCodeResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Minutes int    `json:"minutes"`
}

// MatchLoverRequest is used to match love
type MatchLoverRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Code        string `json:"code" validate:"required"`
}

// AcceptMatchLoverRequest is used to accept match lover. accept: -1: not answer, 1: accept, 2: reject
type AcceptMatchLoverRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
	Accept      int    `json:"accept" validate:"required"`
}

// AcceptMatchLoverResponse is the response for accept match lover
type AcceptMatchLoverResponse struct {
	Accept  int    `json:"accept"`
	Message string `json:"message"`
}

// CreateLoveLetterRequest is used to create love letter
//type CreateLoveLetterRequest struct {
//	AccessToken string `json:"access_token" validate:"required"`
//	Title       string `json:"title" validate:"required"`
//	Body        string `json:"body" validate:"required"`
//}

// UpdateLoveLetterRequest is used to update love letter
type UpdateLoveLetterRequest struct {
	AccessToken string    `json:"access_token" validate:"required"`
	Title       string    `json:"title" validate:"required"`
	Body        string    `json:"body" validate:"required"`
	IsRead      bool      `json:"is_read"`
	IsDelete    bool      `json:"is_delete"`
	TimeOpen    time.Time `json:"time_open" sql:"timeopen"`
}

/*
	print(udid ?? "") // ABCDEF01-0123-ABCD-0123-ABCDEF012345
    print(name)       // Name's iPhone
    print(version)    // 14.5
    print(modelName)  // iPhone
    print(osName)     // iOS
    print(localized)  // iPhone
*/

// InsertPlayerDataRequest is used to save player id
type InsertPlayerDataRequest struct {
	AccessToken    string `json:"access_token" validate:"required"`
	PlayerID       string `json:"player_id" validate:"required"`
	DeviceName     string `json:"device_name"`
	DeviceVersion  string `json:"device_version"`
	DeviceModel    string `json:"device_model"`
	DeviceOS       string `json:"device_os"`
	DeviceLocalize string `json:"device_localize"`
}

// GetPlayerDataResponse is the response for get player data
type GetPlayerDataResponse struct {
	UserID         string `json:"user_id"`
	PlayerID       string `json:"player_id"`
	DeviceName     string `json:"device_name,omitempty"`
	DeviceVersion  string `json:"device_version,omitempty"`
	DeviceModel    string `json:"device_model,omitempty"`
	DeviceOS       string `json:"device_os,omitempty"`
	DeviceLocalize string `json:"device_localize,omitempty"`
}

// GetUserStateDataRequest is used to get user state data
type GetUserStateDataRequest struct {
	KeyString   string `json:"key" validate:"required"`
	AccessToken string `json:"access_token" validate:"required"`
}

// GetUserStateDataResponse is the response for get user state data
type GetUserStateDataResponse struct {
	UserID      string    `json:"user_id"`
	KeyString   string    `json:"key,omitempty"`
	StringValue string    `json:"string_value"`
	IntValue    int       `json:"int_value"`
	BoolValue   bool      `json:"bool_value"`
	FloatValue  float64   `json:"float_value"`
	TimeValue   time.Time `json:"time_value"`
}

// Feed is response for feeds API
type Feed struct {
	Type string      `json:"type"`
	Data interface{} `json:"data,omitempty"`
}
