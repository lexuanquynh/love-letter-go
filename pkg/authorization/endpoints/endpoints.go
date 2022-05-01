package endpoints

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"errors"
	"github.com/go-kit/kit/endpoint"
	"github.com/hashicorp/go-hclog"
	"net/http"
	"strings"
)

type Set struct {
	HealthCheckEndpoint           endpoint.Endpoint
	RegisterEndpoint              endpoint.Endpoint
	LoginEndpoint                 endpoint.Endpoint
	LogoutEndpoint                endpoint.Endpoint
	GetUserEndpoint               endpoint.Endpoint
	GetProfileEndpoint            endpoint.Endpoint
	UpdateProfileEndpoint         endpoint.Endpoint
	UpdatePasswordEndpoint        endpoint.Endpoint
	GetForgetPasswordCodeEndpoint endpoint.Endpoint
}

func NewEndpointSet(svc authorization.Service, auth middleware.Authentication, r database.UserRepository, logger hclog.Logger, validator *database.Validation) Set {
	healthCheckEndpoint := MakeHealthCheckEndpoint(svc)

	registerEndpoint := MakeRegisterEndpoint(svc)
	registerEndpoint = middleware.ValidateParamRequest(validator, logger)(registerEndpoint)

	loginEndpoint := MakeLoginEndpoint(svc)
	loginEndpoint = middleware.ValidateParamRequest(validator, logger)(loginEndpoint)

	logoutEndpoint := MakeLogoutEndpoint(svc)
	logoutEndpoint = middleware.ValidateParamRequest(validator, logger)(logoutEndpoint)
	logoutEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(logoutEndpoint)

	getUserEndpoint := MakeGetUserEndpoint(svc)
	getUserEndpoint = middleware.ValidateParamRequest(validator, logger)(getUserEndpoint)
	getUserEndpoint = middleware.ValidateAccessToken(auth, logger)(getUserEndpoint)

	getProfileEndpoint := MakeGetProfileEndpoint(svc)
	getProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(getProfileEndpoint)
	getProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(getProfileEndpoint)

	updateProfileEndpoint := MakeUpdateProfileEndpoint(svc)
	updateProfileEndpoint = middleware.ValidateParamRequest(validator, logger)(updateProfileEndpoint)
	updateProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(updateProfileEndpoint)

	updatePasswordEndpoint := MakeUpdatePasswordEndpoint(svc)
	updatePasswordEndpoint = middleware.ValidateParamRequest(validator, logger)(updatePasswordEndpoint)
	updatePasswordEndpoint = middleware.ValidateAccessToken(auth, logger)(updatePasswordEndpoint)

	getForgetPasswordCodeEndpoint := MakeGetForgetPasswordCodeEndpoint(svc)
	getForgetPasswordCodeEndpoint = middleware.ValidateParamRequest(validator, logger)(getForgetPasswordCodeEndpoint)
	return Set{
		HealthCheckEndpoint:           healthCheckEndpoint,
		RegisterEndpoint:              registerEndpoint,
		LoginEndpoint:                 loginEndpoint,
		LogoutEndpoint:                logoutEndpoint,
		GetUserEndpoint:               getUserEndpoint,
		GetProfileEndpoint:            getProfileEndpoint,
		UpdateProfileEndpoint:         updateProfileEndpoint,
		UpdatePasswordEndpoint:        updatePasswordEndpoint,
		GetForgetPasswordCodeEndpoint: getForgetPasswordCodeEndpoint,
	}
}

// MakeRegisterEndpoint returns an endpoint that invokes Register on the service.
func MakeRegisterEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.RegisterRequest)
		if !ok {
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		message, err := svc.SignUp(ctx, &req)

		if err != nil {
			if strings.Contains(err.Error(), utils.PgDuplicateKeyMsg) {
				cusErr := utils.NewErrorWrapper(http.StatusConflict, err, "Tài khoản đã tồn tại. Vui lòng thử lại.")
				return nil, cusErr
			}
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "Không thể tạo tài khoản. Vui lòng thử lại.")
			return nil, cusErr
		}
		return message, err
	}
}

// MakeLoginEndpoint returns an endpoint that invokes Login on the service.
func MakeLoginEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.LoginRequest)
		if !ok {
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		user, err := svc.Login(ctx, &req)

		if err != nil {
			if strings.Contains(err.Error(), utils.PgDuplicateKeyMsg) {
				cusErr := utils.NewErrorWrapper(http.StatusConflict, err, "Account already exists. Please try again.")
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
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		err := svc.Logout(ctx, &req)

		if err != nil {
			cusErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, "Can't logout. Please try again later.")
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
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		user, err := svc.GetUser(ctx)
		if err != nil {
			cusErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, "Can't get user. Please try again later.")
			return nil, cusErr
		}

		return user, err
	}
}

// MakeGetProfileEndpoint returns an endpoint that invokes GetProfile on the service.
func MakeGetProfileEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		_, ok := request.(authorization.GetProfileRequest)
		if !ok {
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		profile, err := svc.GetProfile(ctx)
		if err != nil {
			cusErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, "Can't get profile. Please try again later.")
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
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		profile, err := svc.UpdateProfile(ctx, &req)
		if err != nil {
			cusErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, "Can't update profile. Please try again later.")
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
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		message, err := svc.UpdatePassword(ctx, &req)
		if err != nil {
			cusErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, message)
			return nil, cusErr
		}
		return message, nil
	}
}

// MakeGetForgetPasswordCodeEndpoint returns an endpoint that invokes GetForgetPasswordCode on the service.
func MakeGetForgetPasswordCodeEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.GetForgetPasswordCodeRequest)
		if !ok {
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		err := svc.GetForgetPasswordCode(ctx, req.Email)
		if err != nil {
			if strings.Contains(err.Error(), "successfully mailed password reset code") {
				return err.Error(), nil
			}
			return nil, err
		}
		return "successfully mailed password reset code. Please check your email.", nil
	}
}
