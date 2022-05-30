package authorization

import "context"

// Service authentication service interface
type Service interface {
	HealthCheck(ctx context.Context) error
	SignUp(ctx context.Context, request *RegisterRequest) (string, error)
	VerifyMail(ctx context.Context, request *VerifyMailRequest) (string, error)
	Login(ctx context.Context, request *LoginRequest) (interface{}, error)
	Logout(ctx context.Context, request *LogoutRequest) error
	GetUser(ctx context.Context) (interface{}, error)
	UpdateUserName(ctx context.Context, request *UpdateUserNameRequest) (interface{}, error)
	GetProfile(ctx context.Context) (interface{}, error)
	UpdateProfile(ctx context.Context, request *UpdateProfileRequest) (interface{}, error)
	UpdatePassword(ctx context.Context, request *UpdatePasswordRequest) (string, error)
	GetForgetPasswordCode(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, request *CreateNewPasswordWithCodeRequest) error
	GenerateAccessToken(ctx context.Context) (interface{}, error)
	GetVerifyMailCode(ctx context.Context) error
	GetMatchCode(ctx context.Context) (interface{}, error)
	MatchLover(ctx context.Context, request *MatchLoverRequest) error
	ConfirmMatchLover(ctx context.Context, request *AcceptMatchLoverRequest) error
	UnMatchedLover(ctx context.Context) error
	GetMatchLover(ctx context.Context) (interface{}, error)
	CreateLoveLetter(ctx context.Context, request *CreateLoveLetterRequest) error
	UpdateLoveLetter(ctx context.Context, request *UpdateLoveLetterRequest) error
	GetFeeds(ctx context.Context) (interface{}, error)
	InsertPlayerData(ctx context.Context, request *InsertPlayerDataRequest) error
	GetPlayerData(ctx context.Context) (interface{}, error)
	GetUserStateData(ctx context.Context, request *GetUserStateDataRequest) (interface{}, error)
}
