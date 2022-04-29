package authorization

// RegisterRequest is used for registering a new account/user.
type RegisterRequest struct {
	Email      string `json:"email" validate:"required,email"`
	Password   string `json:"password" validate:"required"`
	RePassword string `json:"re-password" validate:"required"`
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

// GetProfileRequest is used to get user profile
type GetProfileRequest struct {
	AccessToken string `json:"access_token" validate:"required"`
}

// GetUserResponse is the response for get user info
type GetUserResponse struct {
	Email    string `json:"email"`
	Username string `json:"username,omitempty"`
	Verified bool   `json:"verified"`
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
