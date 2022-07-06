package authorization

import "context"

// Service authentication service interface
type Service interface {
	HealthCheck(ctx context.Context) error
	SignUp(ctx context.Context, request *RegisterRequest) (string, error)
	VerifyMail(ctx context.Context, request *VerifyMailRequest) (string, error)
	Login(ctx context.Context, request *LoginRequest) (interface{}, error)
	Logout(ctx context.Context, request *LogoutRequest) error
	DeleteUser(ctx context.Context, request *DeleteUserRequest) error
	CancelDeleteUser(ctx context.Context, request *CancelDeleteUserRequest) error
	ConfirmCancelDeleteUser(ctx context.Context, request *ConfirmCancelDeleteUserRequest) error
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
	InsertPlayerData(ctx context.Context, request *InsertPlayerDataRequest) error
	GetPlayerData(ctx context.Context) (interface{}, error)
	GetUserStateData(ctx context.Context, request *GetUserStateDataRequest) (interface{}, error)
	SetUserStateData(ctx context.Context, request *SetUserStateDataRequest) (interface{}, error)
	GetFeeds(ctx context.Context) (interface{}, error)
	UpdateBeenLove(ctx context.Context, request *UpdateBeenLoveRequest) (interface{}, error)
	CheckPassCodeStatus(ctx context.Context) (interface{}, error)
	SetPassCode(ctx context.Context, request *SetPassCodeRequest) (interface{}, error)
	ComparePassCode(ctx context.Context, request *ComparePassCodeRequest) (interface{}, error)
	CreateLetter(ctx context.Context, request *CreateLetterRequest) (interface{}, error)
	DeleteLetter(ctx context.Context, request *DeleteLetterRequest) (interface{}, error)
	GetLetters(ctx context.Context, request *GetLettersRequest) (interface{}, error)
	GetLetter(ctx context.Context, request *GetLetterRequest) (interface{}, error)
	InsertPsychology(ctx context.Context, request *InsertPsychologyRequest) (interface{}, error)
	DeletePsychology(ctx context.Context, request *DeletePsychologyRequest) (interface{}, error)
	GetPsychologies(ctx context.Context, request *GetPsychologiesRequest) (interface{}, error)
	CreateHoliday(ctx context.Context, request *CreateHolidayRequest) (interface{}, error)
	DeleteHoliday(ctx context.Context, request *DeleteHolidayRequest) (interface{}, error)
	GetHolidays(ctx context.Context, request *GetHolidaysRequest) (interface{}, error)
	GetNotifications(ctx context.Context, request *GetNotificationsRequest) (interface{}, error)
	GetNotification(ctx context.Context, request *NotificationRequest) (interface{}, error)
	DeleteNotification(ctx context.Context, request *NotificationRequest) (interface{}, error)
	SendHolidayNotification(ctx context.Context, UserID string, holidayID string) error
	RunSchedule(ctx context.Context) error
}
