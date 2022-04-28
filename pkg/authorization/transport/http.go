package transport

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/endpoints"
	"context"
	"encoding/json"
	"errors"
	httptransport "github.com/go-kit/kit/transport/http"
	"net/http"
)

func NewHTTPHandler(ep endpoints.Set) http.Handler {
	options := []httptransport.ServerOption{
		httptransport.ServerErrorEncoder(errEncoder),
	}

	m := http.NewServeMux()
	m.Handle("/signup", httptransport.NewServer(
		ep.RegisterEndpoint,
		decodeHTTPRegisterRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/login", httptransport.NewServer(
		ep.LoginEndpoint,
		decodeHTTPLoginRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/logout", httptransport.NewServer(
		ep.LogoutEndpoint,
		decodeHTTPLogoutRequest,
		encodeResponse,
		options...,
	))
	return m
}

func decodeHTTPRegisterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.RegisterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.Email == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("email is required"), "email is required")
		}
		if req.Password == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("password is required"), "password is required")
		}
		if req.Password != req.RePassword {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("passwords is not same"), "passwords is not same")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPLoginRequest
func decodeHTTPLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.Email == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("email is required"), "email is required")
		}
		if req.Password == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("password is required"), "password is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPLogoutRequest decode request
func decodeHTTPLogoutRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.LogoutRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.RefreshToken == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("refresh token is required"), "refresh token is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

func encodeResponse(ctx context.Context, w http.ResponseWriter, response interface{}) error {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	if resp, ok := response.(error); ok && resp != nil {
		w.WriteHeader(http.StatusBadRequest)
		return json.NewEncoder(w).Encode(map[string]string{"error": resp.Error()})
	}

	w.WriteHeader(http.StatusOK)
	res := authorization.GenericResponse{
		Status:  true,
		Message: "success",
		Data:    response,
	}
	return json.NewEncoder(w).Encode(res)
}

func errEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	cusErr, ok := err.(utils.CustomErrorWrapper)
	if !ok {
		catchErr := utils.NewErrorWrapper(http.StatusInternalServerError, err, err.Error())
		res := authorization.GenericErrorResponse{
			Status:    false,
			ErrorCode: catchErr.Code,
			Message:   catchErr.Error(),
		}
		json.NewEncoder(w).Encode(res)
		return
	}
	w.WriteHeader(cusErr.Code)
	res := authorization.GenericErrorResponse{
		Status:    false,
		ErrorCode: cusErr.Code,
		Message:   cusErr.Message,
	}
	json.NewEncoder(w).Encode(res)
}
