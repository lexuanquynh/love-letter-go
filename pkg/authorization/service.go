package authorization

import "context"

// Service authentication service interface
type Service interface {
	SignUp(ctx context.Context, request *RegisterRequest) (string, error)
	Login(ctx context.Context, request *LoginRequest) (interface{}, error)
	Logout(ctx context.Context, request *LogoutRequest) error
	GetUser(ctx context.Context) (interface{}, error)
	GetProfile(ctx context.Context) (interface{}, error)
}
