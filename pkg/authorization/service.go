package authorization

import "context"

// Service authentication service interface
type Service interface {
	HealthCheck(ctx context.Context) error
	SignUp(ctx context.Context, request *RegisterRequest) (string, error)
	Login(ctx context.Context, request *LoginRequest) (interface{}, error)
	Logout(ctx context.Context, request *LogoutRequest) error
	GetUser(ctx context.Context) (interface{}, error)
	GetProfile(ctx context.Context) (interface{}, error)
	UpdateProfile(ctx context.Context, request *UpdateProfileRequest) (interface{}, error)
	UpdatePassword(ctx context.Context, request *UpdatePasswordRequest) (string, error)
	GetForgetPasswordCode(ctx context.Context, email string) (string, error)
}
