package authorization

import "context"

// Service authentication service interface
type Service interface {
	SignUp(ctx context.Context, request *RegisterRequest) (string, error)
	Login(ctx context.Context, request *LoginRequest) (interface{}, error)
}
