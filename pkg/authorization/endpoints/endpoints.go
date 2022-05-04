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
	HealthCheckEndpoint           endpoint.Endpoint
	RegisterEndpoint              endpoint.Endpoint
	VerifyMailEndpoint            endpoint.Endpoint
	LoginEndpoint                 endpoint.Endpoint
	LogoutEndpoint                endpoint.Endpoint
	GetUserEndpoint               endpoint.Endpoint
	UpdateUserNameEndpoint        endpoint.Endpoint
	GetProfileEndpoint            endpoint.Endpoint
	UpdateProfileEndpoint         endpoint.Endpoint
	UpdatePasswordEndpoint        endpoint.Endpoint
	GetForgetPasswordCodeEndpoint endpoint.Endpoint
	ResetPasswordEndpoint         endpoint.Endpoint
	GenerateAccessTokenEndpoint   endpoint.Endpoint
	GetVerifyMailCodeEndpoint     endpoint.Endpoint
	GetMatchCodeEndpoint          endpoint.Endpoint
	MatchLoverEndpoint            endpoint.Endpoint
	UnMatchLoverEndpoint          endpoint.Endpoint
	GetMatchedLoverEndpoint       endpoint.Endpoint
	CreateLoveLetterEndpoint      endpoint.Endpoint
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

	getUserEndpoint := MakeGetUserEndpoint(svc)
	getUserEndpoint = middleware.RateLimitRequest(tb, logger)(getUserEndpoint)
	getUserEndpoint = middleware.ValidateParamRequest(validator, logger)(getUserEndpoint)
	getUserEndpoint = middleware.ValidateAccessToken(auth, logger)(getUserEndpoint)

	updateUserNameEndpoint := MakeUpdateUserNameEndpoint(svc)
	updateUserNameEndpoint = middleware.RateLimitRequest(tb, logger)(updateUserNameEndpoint)
	updateUserNameEndpoint = middleware.ValidateParamRequest(validator, logger)(updateUserNameEndpoint)
	updateUserNameEndpoint = middleware.ValidateAccessToken(auth, logger)(updateUserNameEndpoint)

	getProfileEndpoint := MakeGetProfileEndpoint(svc)
	getProfileEndpoint = middleware.RateLimitRequest(tb, logger)(getProfileEndpoint)
	getProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(getProfileEndpoint)
	getProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(getProfileEndpoint)

	updateProfileEndpoint := MakeUpdateProfileEndpoint(svc)
	updateProfileEndpoint = middleware.RateLimitRequest(tb, logger)(updateProfileEndpoint)
	updateProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(updateProfileEndpoint)
	updateProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(updateProfileEndpoint)

	updatePasswordEndpoint := MakeUpdatePasswordEndpoint(svc)
	updatePasswordEndpoint = middleware.RateLimitRequest(tb, logger)(updatePasswordEndpoint)
	updatePasswordEndpoint = middleware.ValidateParamRequest(validator, logger)(updatePasswordEndpoint)
	updatePasswordEndpoint = middleware.ValidateAccessToken(auth, logger)(updatePasswordEndpoint)

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
	getVerifyMailCodeEndpoint = middleware.ValidateAccessToken(auth, logger)(getVerifyMailCodeEndpoint)

	getMatchCodeEndpoint := MakeGetMatchCodeEndpoint(svc)
	getMatchCodeEndpoint = middleware.RateLimitRequest(tb, logger)(getMatchCodeEndpoint)
	getMatchCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(getMatchCodeEndpoint)
	getMatchCodeEndpoint = middleware.ValidateAccessToken(auth, logger)(getMatchCodeEndpoint)

	matchLoverEndpoint := MakeMatchLoverEndpoint(svc)
	matchLoverEndpoint = middleware.RateLimitRequest(tb, logger)(matchLoverEndpoint)
	matchLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(matchLoverEndpoint)
	matchLoverEndpoint = middleware.ValidateAccessToken(auth, logger)(matchLoverEndpoint)

	unMatchLoverEndpoint := MakeUnMatchedLoverEndpoint(svc)
	unMatchLoverEndpoint = middleware.RateLimitRequest(tb, logger)(unMatchLoverEndpoint)
	unMatchLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(unMatchLoverEndpoint)
	unMatchLoverEndpoint = middleware.ValidateAccessToken(auth, logger)(unMatchLoverEndpoint)

	getMatchedLoverEndpoint := MakeGetMatchedLoverEndpoint(svc)
	getMatchedLoverEndpoint = middleware.RateLimitRequest(tb, logger)(getMatchedLoverEndpoint)
	getMatchedLoverEndpoint = middleware.ValidateParamRequest(validator, logger)(getMatchedLoverEndpoint)
	getMatchedLoverEndpoint = middleware.ValidateAccessToken(auth, logger)(getMatchedLoverEndpoint)

	createLoveLetterEndpoint := MakeCreateLoveLetterEndpoint(svc)
	createLoveLetterEndpoint = middleware.RateLimitRequest(tb, logger)(createLoveLetterEndpoint)
	createLoveLetterEndpoint = middleware.ValidateParamRequest(validator, logger)(createLoveLetterEndpoint)
	createLoveLetterEndpoint = middleware.ValidateAccessToken(auth, logger)(createLoveLetterEndpoint)

	return Set{
		HealthCheckEndpoint:           healthCheckEndpoint,
		RegisterEndpoint:              registerEndpoint,
		VerifyMailEndpoint:            verifyMailEndpoint,
		LoginEndpoint:                 loginEndpoint,
		LogoutEndpoint:                logoutEndpoint,
		GetUserEndpoint:               getUserEndpoint,
		GetProfileEndpoint:            getProfileEndpoint,
		UpdateProfileEndpoint:         updateProfileEndpoint,
		UpdateUserNameEndpoint:        updateUserNameEndpoint,
		UpdatePasswordEndpoint:        updatePasswordEndpoint,
		GetForgetPasswordCodeEndpoint: getForgetPasswordCodeEndpoint,
		ResetPasswordEndpoint:         resetPasswordEndpoint,
		GenerateAccessTokenEndpoint:   generateAccessTokenEndpoint,
		GetVerifyMailCodeEndpoint:     getVerifyMailCodeEndpoint,
		GetMatchCodeEndpoint:          getMatchCodeEndpoint,
		MatchLoverEndpoint:            matchLoverEndpoint,
		UnMatchLoverEndpoint:          unMatchLoverEndpoint,
		GetMatchedLoverEndpoint:       getMatchedLoverEndpoint,
		CreateLoveLetterEndpoint:      createLoveLetterEndpoint,
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
		err := svc.Logout(ctx, &req)

		if err != nil {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		message := "Logout successfully"
		return message, nil
	}
}

// MakeGetUserEndpoint returns an endpoint that invokes GetUser on the service.
func MakeGetUserEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.GetUserRequest)
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
		_, ok := request.(authorization.GetProfileRequest)
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
		_, ok := request.(authorization.GetVerifyMailCodeRequest)
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
		_, ok := request.(authorization.GetMatchCodeRequest)
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

// MakeUnMatchedLoverEndpoint returns an endpoint that invokes UnMatchedLover on the service.
func MakeUnMatchedLoverEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.UnMatchLoverRequest)
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
		_, ok := request.(authorization.GetMatchedLoverRequest)
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

// MakeCreateLoveLetterEndpoint returns an endpoint that invokes CreateLoveLetter on the service.
func MakeCreateLoveLetterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.CreateLoveLetterRequest)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		err := svc.CreateLoveLetter(ctx, &req)
		if err != nil {
			return nil, err
		}
		return "successfully created love letter", nil
	}
}
