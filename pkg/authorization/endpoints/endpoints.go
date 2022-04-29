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
	RegisterEndpoint      endpoint.Endpoint
	LoginEndpoint         endpoint.Endpoint
	LogoutEndpoint        endpoint.Endpoint
	GetUserEndpoint       endpoint.Endpoint
	GetProfileEndpoint    endpoint.Endpoint
	UpdateProfileEndpoint endpoint.Endpoint
}

func NewEndpointSet(svc authorization.Service, auth middleware.Authentication, r database.UserRepository, logger hclog.Logger) Set {
	registerEndpoint := MakeRegisterEndpoint(svc)
	loginEndpoint := MakeLoginEndpoint(svc)

	logoutEndpoint := MakeLogoutEndpoint(svc)
	logoutEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(logoutEndpoint)

	getUserEndpoint := MakeGetUserEndpoint(svc)
	getUserEndpoint = middleware.ValidateAccessToken(auth, logger)(getUserEndpoint)

	getProfileEndpoint := MakeGetProfileEndpoint(svc)
	getProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(getProfileEndpoint)

	updateProfileEndpoint := MakeUpdateProfileEndpoint(svc)
	updateProfileEndpoint = middleware.ValidateAccessToken(auth, logger)(updateProfileEndpoint)

	return Set{
		RegisterEndpoint:      registerEndpoint,
		LoginEndpoint:         loginEndpoint,
		LogoutEndpoint:        logoutEndpoint,
		GetUserEndpoint:       getUserEndpoint,
		GetProfileEndpoint:    getProfileEndpoint,
		UpdateProfileEndpoint: updateProfileEndpoint,
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
				cusErr := utils.NewErrorWrapper(http.StatusConflict, err, "Tài khoản đã tồn tại. Vui lòng thử lại.")
				return nil, cusErr
			}
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "Không thể đăng nhập. Vui lòng thử lại.")
			return nil, cusErr
		}
		return user, err
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