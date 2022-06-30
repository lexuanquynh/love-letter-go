package endpoints

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"github.com/go-kit/kit/endpoint"
	"github.com/hashicorp/go-hclog"
	"github.com/juju/ratelimit"
	"strings"
)

type Set struct {
	HealthCheckEndpoint             endpoint.Endpoint
	RegisterEndpoint                endpoint.Endpoint
	VerifyMailEndpoint              endpoint.Endpoint
	LoginEndpoint                   endpoint.Endpoint
	LogoutEndpoint                  endpoint.Endpoint
	DeleteUserEndpoint              endpoint.Endpoint
	CancelDeleteUserEndpoint        endpoint.Endpoint
	ConfirmCancelDeleteUserEndpoint endpoint.Endpoint
	GetUserEndpoint                 endpoint.Endpoint
	UpdateUserNameEndpoint          endpoint.Endpoint
	GetProfileEndpoint              endpoint.Endpoint
	UpdateProfileEndpoint           endpoint.Endpoint
	UpdatePasswordEndpoint          endpoint.Endpoint
	GetForgetPasswordCodeEndpoint   endpoint.Endpoint
	ResetPasswordEndpoint           endpoint.Endpoint
	GenerateAccessTokenEndpoint     endpoint.Endpoint
	GetVerifyMailCodeEndpoint       endpoint.Endpoint
	GetMatchCodeEndpoint            endpoint.Endpoint
	MatchLoverEndpoint              endpoint.Endpoint
	ConfirmMatchLoverEndpoint       endpoint.Endpoint
	UnMatchLoverEndpoint            endpoint.Endpoint
	GetMatchedLoverEndpoint         endpoint.Endpoint
	InsertPlayerDataEndpoint        endpoint.Endpoint
	GetPlayerDataEndpoint           endpoint.Endpoint
	GetUserStateDataEndpoint        endpoint.Endpoint
	SetUserStateDataEndpoint        endpoint.Endpoint
	GetFeedsEndpoint                endpoint.Endpoint
	UpdateBeenLoveEndpoint          endpoint.Endpoint
	CheckPassCodeStatusEndpoint     endpoint.Endpoint
	SetPassCodeEndpoint             endpoint.Endpoint
	ComparePassCodeEndpoint         endpoint.Endpoint
	CreateLetterEndpoint            endpoint.Endpoint
	DeleteLetterEndpoint            endpoint.Endpoint
	GetLettersEndpoint              endpoint.Endpoint
	GetLetterEndpoint               endpoint.Endpoint
	InsertPsychologyEndpoint        endpoint.Endpoint
	DeletePsychologyEndpoint        endpoint.Endpoint
	GetPsychologiesEndpoint         endpoint.Endpoint
	CreateHolidayEndpoint           endpoint.Endpoint
	DeleteHolidayEndpoint           endpoint.Endpoint
	GetHolidaysEndpoint             endpoint.Endpoint
}

func NewEndpointSet(svc authorization.Service,
	auth middleware.Authentication,
	r database.UserRepository,
	logger hclog.Logger,
	validator *database.Validation,
	tb *ratelimit.Bucket) Set {
	healthCheckEndpoint := MakeHealthCheckEndpoint(svc)
	healthCheckEndpoint = middleware.RateLimitRequest(tb, logger)(healthCheckEndpoint)

	registerEndpoint := MakeRegisterEndpoint(svc)
	registerEndpoint = middleware.ValidateParamRequest(validator, logger)(registerEndpoint)
	registerEndpoint = middleware.RateLimitRequest(tb, logger)(registerEndpoint)

	verifyMailEndpoint := MakeVerifyMailEndpoint(svc)
	verifyMailEndpoint = middleware.ValidateParamRequest(validator, logger)(verifyMailEndpoint)
	verifyMailEndpoint = middleware.RateLimitRequest(tb, logger)(verifyMailEndpoint)

	loginEndpoint := MakeLoginEndpoint(svc)
	loginEndpoint = middleware.RateLimitRequest(tb, logger)(loginEndpoint)
	loginEndpoint = middleware.ValidateParamRequest(validator, logger)(loginEndpoint)

	logoutEndpoint := MakeLogoutEndpoint(svc)
	logoutEndpoint = middleware.RateLimitRequest(tb, logger)(logoutEndpoint)
	logoutEndpoint = middleware.ValidateParamRequest(validator, logger)(logoutEndpoint)
	logoutEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(logoutEndpoint)

	deleteUserEndpoint := MakeDeleteUserEndpoint(svc)
	deleteUserEndpoint = middleware.RateLimitRequest(tb, logger)(deleteUserEndpoint)
	deleteUserEndpoint = middleware.ValidateParamRequest(validator, logger)(deleteUserEndpoint)
	deleteUserEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(deleteUserEndpoint)

	cancelDeleteUserEndpoint := MakeCancelDeleteUserEndpoint(svc)
	cancelDeleteUserEndpoint = middleware.RateLimitRequest(tb, logger)(cancelDeleteUserEndpoint)
	cancelDeleteUserEndpoint = middleware.ValidateParamRequest(validator, logger)(cancelDeleteUserEndpoint)

	confirmCancelDeleteUserEndpoint := MakeConfirmCancelDeleteUserEndpoint(svc)
	confirmCancelDeleteUserEndpoint = middleware.RateLimitRequest(tb, logger)(confirmCancelDeleteUserEndpoint)
	confirmCancelDeleteUserEndpoint = middleware.ValidateParamRequest(validator, logger)(confirmCancelDeleteUserEndpoint)

	getUserEndpoint := MakeGetUserEndpoint(svc)
	getUserEndpoint = middleware.RateLimitRequest(tb, logger)(getUserEndpoint)
	getUserEndpoint = middleware.ValidateParamRequest(validator, logger)(getUserEndpoint)
	getUserEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getUserEndpoint)

	updateUserNameEndpoint := MakeUpdateUserNameEndpoint(svc)
	updateUserNameEndpoint = middleware.RateLimitRequest(tb, logger)(updateUserNameEndpoint)
	updateUserNameEndpoint = middleware.ValidateParamRequest(validator, logger)(updateUserNameEndpoint)
	updateUserNameEndpoint = middleware.ValidateAccessToken(auth, r, logger)(updateUserNameEndpoint)

	getProfileEndpoint := MakeGetProfileEndpoint(svc)
	getProfileEndpoint = middleware.RateLimitRequest(tb, logger)(getProfileEndpoint)
	getProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(getProfileEndpoint)
	getProfileEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getProfileEndpoint)

	updateProfileEndpoint := MakeUpdateProfileEndpoint(svc)
	updateProfileEndpoint = middleware.RateLimitRequest(tb, logger)(updateProfileEndpoint)
	updateProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(updateProfileEndpoint)
	updateProfileEndpoint = middleware.ValidateAccessToken(auth, r, logger)(updateProfileEndpoint)

	updatePasswordEndpoint := MakeUpdatePasswordEndpoint(svc)
	updatePasswordEndpoint = middleware.RateLimitRequest(tb, logger)(updatePasswordEndpoint)
	updatePasswordEndpoint = middleware.ValidateParamRequest(validator, logger)(updatePasswordEndpoint)
	updatePasswordEndpoint = middleware.ValidateAccessToken(auth, r, logger)(updatePasswordEndpoint)

	getForgetPasswordCodeEndpoint := MakeGetForgetPasswordCodeEndpoint(svc)
	getForgetPasswordCodeEndpoint = middleware.RateLimitRequest(tb, logger)(getForgetPasswordCodeEndpoint)
	getForgetPasswordCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(getForgetPasswordCodeEndpoint)

	resetPasswordEndpoint := MakeCreateNewPasswordWithCodeEndpoint(svc)
	resetPasswordEndpoint = middleware.RateLimitRequest(tb, logger)(resetPasswordEndpoint)
	resetPasswordEndpoint = middleware.ValidateParamRequest(validator, logger)(resetPasswordEndpoint)

	generateAccessTokenEndpoint := MakeGenerateAccessTokenEndpoint(svc)
	generateAccessTokenEndpoint = middleware.RateLimitRequest(tb, logger)(generateAccessTokenEndpoint)
	generateAccessTokenEndpoint = middleware.ValidateParamRequest(validator, logger)(generateAccessTokenEndpoint)
	generateAccessTokenEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(generateAccessTokenEndpoint)

	getVerifyMailCodeEndpoint := MakeGetVerifyMailCodeEndpoint(svc)
	getVerifyMailCodeEndpoint = middleware.RateLimitRequest(tb, logger)(getVerifyMailCodeEndpoint)
	getVerifyMailCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(getVerifyMailCodeEndpoint)
	getVerifyMailCodeEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getVerifyMailCodeEndpoint)

	getMatchCodeEndpoint := MakeGetMatchCodeEndpoint(svc)
	getMatchCodeEndpoint = middleware.RateLimitRequest(tb, logger)(getMatchCodeEndpoint)
	getMatchCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(getMatchCodeEndpoint)
	getMatchCodeEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getMatchCodeEndpoint)

	matchLoverEndpoint := MakeMatchLoverEndpoint(svc)
	matchLoverEndpoint = middleware.RateLimitRequest(tb, logger)(matchLoverEndpoint)
	matchLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(matchLoverEndpoint)
	matchLoverEndpoint = middleware.ValidateAccessToken(auth, r, logger)(matchLoverEndpoint)

	confirmMatchLoverEndpoint := MakeConfirmMatchLoverEndpoint(svc)
	confirmMatchLoverEndpoint = middleware.RateLimitRequest(tb, logger)(confirmMatchLoverEndpoint)
	confirmMatchLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(confirmMatchLoverEndpoint)
	confirmMatchLoverEndpoint = middleware.ValidateAccessToken(auth, r, logger)(confirmMatchLoverEndpoint)

	unMatchLoverEndpoint := MakeUnMatchedLoverEndpoint(svc)
	unMatchLoverEndpoint = middleware.RateLimitRequest(tb, logger)(unMatchLoverEndpoint)
	unMatchLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(unMatchLoverEndpoint)
	unMatchLoverEndpoint = middleware.ValidateAccessToken(auth, r, logger)(unMatchLoverEndpoint)

	getMatchedLoverEndpoint := MakeGetMatchedLoverEndpoint(svc)
	getMatchedLoverEndpoint = middleware.RateLimitRequest(tb, logger)(getMatchedLoverEndpoint)
	getMatchedLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(getMatchedLoverEndpoint)
	getMatchedLoverEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getMatchedLoverEndpoint)

	insertPlayerDataEndpoint := InsertPlayerDataEndpoint(svc)
	insertPlayerDataEndpoint = middleware.RateLimitRequest(tb, logger)(insertPlayerDataEndpoint)
	insertPlayerDataEndpoint = middleware.ValidateParamRequest(validator, logger)(insertPlayerDataEndpoint)
	insertPlayerDataEndpoint = middleware.ValidateAccessToken(auth, r, logger)(insertPlayerDataEndpoint)

	getPlayerDataEndpoint := GetPlayerDataEndpoint(svc)
	getPlayerDataEndpoint = middleware.RateLimitRequest(tb, logger)(getPlayerDataEndpoint)
	getPlayerDataEndpoint = middleware.ValidateParamRequest(validator, logger)(getPlayerDataEndpoint)
	getPlayerDataEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getPlayerDataEndpoint)

	getUserStateDataEndpoint := GetUserStateDataEndpoint(svc)
	getUserStateDataEndpoint = middleware.RateLimitRequest(tb, logger)(getUserStateDataEndpoint)
	getUserStateDataEndpoint = middleware.ValidateParamRequest(validator, logger)(getUserStateDataEndpoint)
	getUserStateDataEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getUserStateDataEndpoint)

	setUserStateDataEndpoint := SetUserStateDataEndpoint(svc)
	setUserStateDataEndpoint = middleware.RateLimitRequest(tb, logger)(setUserStateDataEndpoint)
	setUserStateDataEndpoint = middleware.ValidateParamRequest(validator, logger)(setUserStateDataEndpoint)
	setUserStateDataEndpoint = middleware.ValidateAccessToken(auth, r, logger)(setUserStateDataEndpoint)

	getFeedsEndpoint := MakeGetFeedsEndpoint(svc)
	getFeedsEndpoint = middleware.RateLimitRequest(tb, logger)(getFeedsEndpoint)
	getFeedsEndpoint = middleware.ValidateParamRequest(validator, logger)(getFeedsEndpoint)
	getFeedsEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getFeedsEndpoint)

	updateBeenLoveEndpoint := MakeUpdateBeenLoveEndpoint(svc)
	updateBeenLoveEndpoint = middleware.RateLimitRequest(tb, logger)(updateBeenLoveEndpoint)
	updateBeenLoveEndpoint = middleware.ValidateParamRequest(validator, logger)(updateBeenLoveEndpoint)
	updateBeenLoveEndpoint = middleware.ValidateAccessToken(auth, r, logger)(updateBeenLoveEndpoint)

	checkPassCodeStatusEndpoint := MakeCheckPassCodeStatusEndpoint(svc)
	checkPassCodeStatusEndpoint = middleware.RateLimitRequest(tb, logger)(checkPassCodeStatusEndpoint)
	checkPassCodeStatusEndpoint = middleware.ValidateParamRequest(validator, logger)(checkPassCodeStatusEndpoint)
	checkPassCodeStatusEndpoint = middleware.ValidateAccessToken(auth, r, logger)(checkPassCodeStatusEndpoint)

	setPassCodeEndpoint := MakeSetPassCodeEndpoint(svc)
	setPassCodeEndpoint = middleware.RateLimitRequest(tb, logger)(setPassCodeEndpoint)
	setPassCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(setPassCodeEndpoint)
	setPassCodeEndpoint = middleware.ValidateAccessToken(auth, r, logger)(setPassCodeEndpoint)

	comparePassCodeEndpoint := MakeComparePassCodeEndpoint(svc)
	comparePassCodeEndpoint = middleware.RateLimitRequest(tb, logger)(comparePassCodeEndpoint)
	comparePassCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(comparePassCodeEndpoint)
	comparePassCodeEndpoint = middleware.ValidateAccessToken(auth, r, logger)(comparePassCodeEndpoint)

	createLetterEndpoint := MakeCreateLetterEndpoint(svc)
	createLetterEndpoint = middleware.RateLimitRequest(tb, logger)(createLetterEndpoint)
	createLetterEndpoint = middleware.ValidateParamRequest(validator, logger)(createLetterEndpoint)
	createLetterEndpoint = middleware.ValidateAccessToken(auth, r, logger)(createLetterEndpoint)

	deleteLetterEndpoint := MakeDeleteLetterEndpoint(svc)
	deleteLetterEndpoint = middleware.RateLimitRequest(tb, logger)(deleteLetterEndpoint)
	deleteLetterEndpoint = middleware.ValidateParamRequest(validator, logger)(deleteLetterEndpoint)
	deleteLetterEndpoint = middleware.ValidateAccessToken(auth, r, logger)(deleteLetterEndpoint)

	getLettersEndpoint := MakeGetLettersEndpoint(svc)
	getLettersEndpoint = middleware.RateLimitRequest(tb, logger)(getLettersEndpoint)
	getLettersEndpoint = middleware.ValidateParamRequest(validator, logger)(getLettersEndpoint)
	getLettersEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getLettersEndpoint)

	getLetterEndpoint := MakeGetLetterEndpoint(svc)
	getLetterEndpoint = middleware.RateLimitRequest(tb, logger)(getLetterEndpoint)
	getLetterEndpoint = middleware.ValidateParamRequest(validator, logger)(getLetterEndpoint)
	getLetterEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getLetterEndpoint)

	insertPsychologyEndpoint := MakeInsertPsychologyEndpoint(svc)
	insertPsychologyEndpoint = middleware.RateLimitRequest(tb, logger)(insertPsychologyEndpoint)
	insertPsychologyEndpoint = middleware.ValidateParamRequest(validator, logger)(insertPsychologyEndpoint)
	insertPsychologyEndpoint = middleware.ValidateAccessToken(auth, r, logger)(insertPsychologyEndpoint)

	deletePsychologyEndpoint := MakeDeletePsychologyEndpoint(svc)
	deletePsychologyEndpoint = middleware.RateLimitRequest(tb, logger)(deletePsychologyEndpoint)
	deletePsychologyEndpoint = middleware.ValidateParamRequest(validator, logger)(deletePsychologyEndpoint)
	deletePsychologyEndpoint = middleware.ValidateAccessToken(auth, r, logger)(deletePsychologyEndpoint)

	getPsychologiesEndpoint := MakeGetPsychologiesEndpoint(svc)
	getPsychologiesEndpoint = middleware.RateLimitRequest(tb, logger)(getPsychologiesEndpoint)
	getPsychologiesEndpoint = middleware.ValidateParamRequest(validator, logger)(getPsychologiesEndpoint)
	getPsychologiesEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getPsychologiesEndpoint)

	createHolidayEndpoint := MakeCreateHolidayEndpoint(svc)
	createHolidayEndpoint = middleware.RateLimitRequest(tb, logger)(createHolidayEndpoint)
	createHolidayEndpoint = middleware.ValidateParamRequest(validator, logger)(createHolidayEndpoint)
	createHolidayEndpoint = middleware.ValidateAccessToken(auth, r, logger)(createHolidayEndpoint)

	deleteHolidayEndpoint := MakeDeleteHolidayEndpoint(svc)
	deleteHolidayEndpoint = middleware.RateLimitRequest(tb, logger)(deleteHolidayEndpoint)
	deleteHolidayEndpoint = middleware.ValidateParamRequest(validator, logger)(deleteHolidayEndpoint)
	deleteHolidayEndpoint = middleware.ValidateAccessToken(auth, r, logger)(deleteHolidayEndpoint)

	getHolidaysEndpoint := MakeGetHolidaysEndpoint(svc)
	getHolidaysEndpoint = middleware.RateLimitRequest(tb, logger)(getHolidaysEndpoint)
	getHolidaysEndpoint = middleware.ValidateParamRequest(validator, logger)(getHolidaysEndpoint)
	getHolidaysEndpoint = middleware.ValidateAccessToken(auth, r, logger)(getHolidaysEndpoint)

	return Set{
		HealthCheckEndpoint:             healthCheckEndpoint,
		RegisterEndpoint:                registerEndpoint,
		VerifyMailEndpoint:              verifyMailEndpoint,
		LoginEndpoint:                   loginEndpoint,
		LogoutEndpoint:                  logoutEndpoint,
		DeleteUserEndpoint:              deleteUserEndpoint,
		CancelDeleteUserEndpoint:        cancelDeleteUserEndpoint,
		ConfirmCancelDeleteUserEndpoint: confirmCancelDeleteUserEndpoint,
		GetUserEndpoint:                 getUserEndpoint,
		GetProfileEndpoint:              getProfileEndpoint,
		UpdateProfileEndpoint:           updateProfileEndpoint,
		UpdateUserNameEndpoint:          updateUserNameEndpoint,
		UpdatePasswordEndpoint:          updatePasswordEndpoint,
		GetForgetPasswordCodeEndpoint:   getForgetPasswordCodeEndpoint,
		ResetPasswordEndpoint:           resetPasswordEndpoint,
		GenerateAccessTokenEndpoint:     generateAccessTokenEndpoint,
		GetVerifyMailCodeEndpoint:       getVerifyMailCodeEndpoint,
		GetMatchCodeEndpoint:            getMatchCodeEndpoint,
		MatchLoverEndpoint:              matchLoverEndpoint,
		ConfirmMatchLoverEndpoint:       confirmMatchLoverEndpoint,
		UnMatchLoverEndpoint:            unMatchLoverEndpoint,
		GetMatchedLoverEndpoint:         getMatchedLoverEndpoint,
		InsertPlayerDataEndpoint:        insertPlayerDataEndpoint,
		GetPlayerDataEndpoint:           getPlayerDataEndpoint,
		GetUserStateDataEndpoint:        getUserStateDataEndpoint,
		SetUserStateDataEndpoint:        setUserStateDataEndpoint,
		GetFeedsEndpoint:                getFeedsEndpoint,
		UpdateBeenLoveEndpoint:          updateBeenLoveEndpoint,
		CheckPassCodeStatusEndpoint:     checkPassCodeStatusEndpoint,
		SetPassCodeEndpoint:             setPassCodeEndpoint,
		ComparePassCodeEndpoint:         comparePassCodeEndpoint,
		CreateLetterEndpoint:            createLetterEndpoint,
		DeleteLetterEndpoint:            deleteLetterEndpoint,
		GetLettersEndpoint:              getLettersEndpoint,
		GetLetterEndpoint:               getLetterEndpoint,
		InsertPsychologyEndpoint:        insertPsychologyEndpoint,
		DeletePsychologyEndpoint:        deletePsychologyEndpoint,
		GetPsychologiesEndpoint:         getPsychologiesEndpoint,
		CreateHolidayEndpoint:           createHolidayEndpoint,
		DeleteHolidayEndpoint:           deleteHolidayEndpoint,
		GetHolidaysEndpoint:             getHolidaysEndpoint,
	}
}

// MakeRegisterEndpoint returns an endpoint that invokes Register on the service.
func MakeRegisterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.RegisterRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		message, err := svc.SignUp(ctx, &req)

		if err != nil {
			if strings.Contains(err.Error(), utils.PgDuplicateKeyMsg) {
				cusErr := utils.NewErrorResponse(utils.Conflict)
				return nil, cusErr
			}
			return nil, err
		}
		return message, err
	}
}

// MakeVerifyMailEndpoint returns an endpoint that invokes VerifyMail on the service.
func MakeVerifyMailEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.VerifyMailRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		message, err := svc.VerifyMail(ctx, &req)

		if err != nil {
			return nil, err
		}
		return message, err
	}
}

// MakeLoginEndpoint returns an endpoint that invokes Login on the service.
func MakeLoginEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.LoginRequest)
		if !ok {
			err := utils.NewErrorResponse(utils.BadRequest)
			return nil, err
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		user, err := svc.Login(ctx, &req)

		if err != nil {
			if strings.Contains(err.Error(), utils.PgDuplicateKeyMsg) {
				cusErr := utils.NewErrorResponse(utils.Conflict)
				return nil, cusErr
			}
			return nil, err
		}
		return user, err
	}
}

// MakeHealthCheckEndpoint returns an endpoint that invokes HealthCheck on the service.
func MakeHealthCheckEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		err := svc.HealthCheck(ctx)
		return nil, err
	}
}

// MakeLogoutEndpoint returns an endpoint that invokes Logout on the service.
func MakeLogoutEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.LogoutRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.Logout(ctx, &req)

		if err != nil {
			return nil, err
		}
		message := "Logout successfully"
		return message, nil
	}
}

// MakeDeleteUserEndpoint returns an endpoint that invokes DeleteUser on the service.
func MakeDeleteUserEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.DeleteUserRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.DeleteUser(ctx, &req)

		if err != nil {
			return nil, err
		}
		message := "Delete user successfully"
		return message, nil
	}
}

// MakeCancelDeleteUserEndpoint returns an endpoint that invokes CancelDeleteUser on the service.
func MakeCancelDeleteUserEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.CancelDeleteUserRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.CancelDeleteUser(ctx, &req)
		if err != nil {
			return nil, err
		}
		message := "Send code for cancel delete user successfully. Please check code in your email."
		return message, nil
	}
}

// MakeConfirmCancelDeleteUserEndpoint returns an endpoint that invokes ConfirmCancelDeleteUser on the service.
func MakeConfirmCancelDeleteUserEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.ConfirmCancelDeleteUserRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.ConfirmCancelDeleteUser(ctx, &req)
		if err != nil {
			return nil, err
		}
		message := "Cancel delete user successfully"
		return message, nil
	}
}

// MakeGetUserEndpoint returns an endpoint that invokes GetUser on the service.
func MakeGetUserEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		user, err := svc.GetUser(ctx)
		if err != nil {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}

		return user, err
	}
}

// MakeUpdateUserNameEndpoint returns an endpoint that invokes UpdateUserName on the service.
func MakeUpdateUserNameEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.UpdateUserNameRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		user, err := svc.UpdateUserName(ctx, &req)
		if err != nil {
			return nil, err
		}
		return user, nil
	}
}

// MakeGetProfileEndpoint returns an endpoint that invokes GetProfile on the service.
func MakeGetProfileEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		profile, err := svc.GetProfile(ctx)
		if err != nil {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}

		return profile, err
	}
}

// MakeUpdateProfileEndpoint returns an endpoint that invokes UpdateProfile on the service.
func MakeUpdateProfileEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.UpdateProfileRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		profile, err := svc.UpdateProfile(ctx, &req)
		if err != nil {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}
		return profile, nil
	}
}

// MakeUpdatePasswordEndpoint returns an endpoint that invokes UpdatePassword on the service.
func MakeUpdatePasswordEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.UpdatePasswordRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		message, err := svc.UpdatePassword(ctx, &req)
		return message, err
	}
}

// MakeGetForgetPasswordCodeEndpoint returns an endpoint that invokes GetForgetPasswordCode on the service.
func MakeGetForgetPasswordCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetForgetPasswordCodeRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.GetForgetPasswordCode(ctx, req.Email)
		if err != nil {
			if strings.Contains(err.Error(), "successfully mailed password reset code") {
				return "successfully mailed password reset code. Please check your email.", nil
			}
			return nil, err
		}
		return "successfully mailed password reset code. Please check your email.", nil
	}
}

// MakeCreateNewPasswordWithCodeEndpoint returns an endpoint that invokes ResetPassword on the service.
func MakeCreateNewPasswordWithCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.CreateNewPasswordWithCodeRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		// Change to lower case
		req.Email = strings.ToLower(req.Email)
		err := svc.ResetPassword(ctx, &req)
		if err != nil {
			return nil, err
		}
		return "successfully updated password.", nil
	}
}

// MakeGenerateAccessTokenEndpoint returns an endpoint that invokes GenerateAccessToken on the service.
func MakeGenerateAccessTokenEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.GenerateAccessTokenRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		token, err := svc.GenerateAccessToken(ctx)
		if err != nil {
			return nil, err
		}
		return token, nil
	}
}

// MakeGetVerifyMailCodeEndpoint returns an endpoint that invokes GetVerifyMailCode on the service.
func MakeGetVerifyMailCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.GetVerifyMailCode(ctx)
		if err != nil {
			return nil, err
		}
		return "Email has been successfully verified", nil
	}
}

// MakeGetMatchCodeEndpoint returns an endpoint that invokes GetMatchCode on the service.
func MakeGetMatchCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		matchCode, err := svc.GetMatchCode(ctx)
		if err != nil {
			return nil, err
		}
		return matchCode, nil
	}
}

// MakeMatchLoverEndpoint returns an endpoint that invokes MatchLover on the service.
func MakeMatchLoverEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.MatchLoverRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.MatchLover(ctx, &req)
		if err != nil {
			return nil, err
		}
		return "successfully matched lover", nil
	}
}

// MakeConfirmMatchLoverEndpoint returns an endpoint that invokes ConfirmMatchLover on the service.
func MakeConfirmMatchLoverEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.AcceptMatchLoverRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.ConfirmMatchLover(ctx, &req)
		if err != nil {
			return nil, err
		}
		response := authorization.AcceptMatchLoverResponse{
			Accept:  req.Accept,
			Message: "Finish response to match lover",
		}
		return response, nil
	}
}

// MakeUnMatchedLoverEndpoint returns an endpoint that invokes UnMatchedLover on the service.
func MakeUnMatchedLoverEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.UnMatchedLover(ctx)
		if err != nil {
			return nil, err
		}
		return "successfully unmatched lover", nil
	}
}

// MakeGetMatchedLoverEndpoint returns an endpoint that invokes GetMatchLover on the service.
func MakeGetMatchedLoverEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		matchLover, err := svc.GetMatchLover(ctx)
		if err != nil {
			return nil, err
		}
		return matchLover, nil
	}
}

// InsertPlayerDataEndpoint returns an endpoint that invokes SavePlayerId on the service.
func InsertPlayerDataEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.InsertPlayerDataRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.InsertPlayerData(ctx, &req)
		if err != nil {
			return nil, err
		}
		return "successfully saved player data", nil
	}
}

// GetPlayerDataEndpoint returns an endpoint that invokes GetPlayerData on the service.
func GetPlayerDataEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		playerData, err := svc.GetPlayerData(ctx)
		if err != nil {
			return nil, err
		}
		return playerData, nil
	}
}

// GetUserStateDataEndpoint returns an endpoint that invokes GetUserStateData on the service.
func GetUserStateDataEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetUserStateDataRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		userStateData, err := svc.GetUserStateData(ctx, &req)
		if err != nil {
			return nil, err
		}
		return userStateData, nil
	}
}

// SetUserStateDataEndpoint returns an endpoint that invokes SetUserStateData on the service.
func SetUserStateDataEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.SetUserStateDataRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		_, err := svc.SetUserStateData(ctx, &req)
		if err != nil {
			return nil, err
		}
		return "successfully set user state data", nil
	}
}

// MakeGetFeedsEndpoint returns an endpoint that invokes GetFeed on the service.
func MakeGetFeedsEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		feeds, err := svc.GetFeeds(ctx)
		if err != nil {
			return nil, err
		}
		return feeds, nil
	}
}

// MakeUpdateBeenLoveEndpoint returns an endpoint that invokes UpdateBeenLove on the service.
func MakeUpdateBeenLoveEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.UpdateBeenLoveRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.UpdateBeenLove(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeCheckPassCodeStatusEndpoint returns an endpoint that invokes CheckPassCodeStatus on the service.
func MakeCheckPassCodeStatusEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.CommonAuthorizationRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.CheckPassCodeStatus(ctx)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeSetPassCodeEndpoint returns an endpoint that invokes SetPassCode on the service.
func MakeSetPassCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.SetPassCodeRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.SetPassCode(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeComparePassCodeEndpoint returns an endpoint that invokes ComparePassCode on the service.
func MakeComparePassCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.ComparePassCodeRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.ComparePassCode(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeCreateLetterEndpoint returns an endpoint that invokes CreateLetter on the service.
func MakeCreateLetterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.CreateLetterRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.CreateLetter(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeDeleteLetterEndpoint returns an endpoint that invokes DeleteLetter on the service.
func MakeDeleteLetterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.DeleteLetterRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.DeleteLetter(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeGetLettersEndpoint returns an endpoint that invokes GetLetters on the service.
func MakeGetLettersEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetLettersRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.GetLetters(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeGetLetterEndpoint returns an endpoint that invokes GetLetter on the service.
func MakeGetLetterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetLetterRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.GetLetter(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeInsertPsychologyEndpoint returns an endpoint that invokes InsertPsychology on the service.
func MakeInsertPsychologyEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.InsertPsychologyRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.InsertPsychology(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeDeletePsychologyEndpoint returns an endpoint that invokes DeletePsychology on the service.
func MakeDeletePsychologyEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.DeletePsychologyRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.DeletePsychology(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeGetPsychologiesEndpoint returns an endpoint that invokes GetPsychologies on the service.
func MakeGetPsychologiesEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetPsychologiesRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.GetPsychologies(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeCreateHolidayEndpoint returns an endpoint that invokes CreateHoliday on the service.
func MakeCreateHolidayEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.CreateHolidayRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.CreateHoliday(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeDeleteHolidayEndpoint returns an endpoint that invokes DeleteHoliday on the service.
func MakeDeleteHolidayEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.DeleteHolidayRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.DeleteHoliday(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}

// MakeGetHolidaysEndpoint returns an endpoint that invokes GetHolidays on the service.
func MakeGetHolidaysEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetHolidaysRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		response, err := svc.GetHolidays(ctx, &req)
		if err != nil {
			return nil, err
		}
		return response, nil
	}
}
