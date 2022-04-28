package endpoints

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/pkg/authorization"
	"context"
	"errors"
	"github.com/go-kit/kit/endpoint"
	"net/http"
	"strings"
)

type Set struct {
	RegisterEndpoint endpoint.Endpoint
	LoginEndpoint    endpoint.Endpoint
}

func NewEndpointSet(svc authorization.Service) Set {
	return Set{
		RegisterEndpoint: MakeRegisterEndpoint(svc),
		LoginEndpoint:    MakeLoginEndpoint(svc),
	}
}

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
