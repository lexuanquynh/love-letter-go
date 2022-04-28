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
	RegisterEndpoint endpoint.Endpoint
	LoginEndpoint    endpoint.Endpoint
	LogoutEndpoint   endpoint.Endpoint
}

func NewEndpointSet(svc authorization.Service, auth middleware.Authentication, r database.UserRepository, logger hclog.Logger) Set {
	registerEndpoint := MakeRegisterEndpoint(svc)
	loginEndpoint := MakeLoginEndpoint(svc)

	logoutEndpoint := MakeLogoutEndpoint(svc)
	logoutEndpoint = middleware.ValidateRefreshToken(auth, r, logger)(logoutEndpoint)

	return Set{
		RegisterEndpoint: registerEndpoint,
		LoginEndpoint:    loginEndpoint,
		LogoutEndpoint:   logoutEndpoint,
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
// Primarily useful in a server.
func MakeLoginEndpoint(svc authorization.Service) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (interface{}, error) {
		req, ok := request.(authorization.LoginRequest)
		if !ok {
			err := errors.New("invalid request")
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "invalid request")
			return nil, cusErr
		}
		message, err := svc.Login(ctx, &req)

		if err != nil {
			if strings.Contains(err.Error(), utils.PgDuplicateKeyMsg) {
				cusErr := utils.NewErrorWrapper(http.StatusConflict, err, "Tài khoản đã tồn tại. Vui lòng thử lại.")
				return nil, cusErr
			}
			cusErr := utils.NewErrorWrapper(http.StatusBadRequest, err, "Không thể đăng nhập. Vui lòng thử lại.")
			return nil, cusErr
		}
		return message, err
	}
}

// MakeLogoutEndpoint returns an endpoint that invokes Logout on the service.
// Primarily useful in a server.
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
