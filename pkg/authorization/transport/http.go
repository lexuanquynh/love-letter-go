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
	m.Handle("/health", httptransport.NewServer(
		ep.HealthCheckEndpoint,
		decodeHealthCheckRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/signup", httptransport.NewServer(
		ep.RegisterEndpoint,
		decodeHTTPRegisterRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/verify-mail", httptransport.NewServer(
		ep.VerifyMailEndpoint,
		decodeHTTPVerifyMailRequest,
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
	m.Handle("/get-user", httptransport.NewServer(
		ep.GetUserEndpoint,
		decodeHTTPGetUserRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/get-profile", httptransport.NewServer(
		ep.GetProfileEndpoint,
		decodeHTTPGetProfileRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/update-profile", httptransport.NewServer(
		ep.UpdateProfileEndpoint,
		decodeHTTPUpdateProfileRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/update-password", httptransport.NewServer(
		ep.UpdatePasswordEndpoint,
		decodeHTTPUpdatePasswordRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/get-forget-password-code", httptransport.NewServer(
		ep.GetForgetPasswordCodeEndpoint,
		decodeHTTPGetForgetPasswordCodeRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/reset-password", httptransport.NewServer(
		ep.ResetPasswordEndpoint,
		decodeHTTPResetPasswordRequest,
		encodeResponse,
		options...,
	))
	mux := http.NewServeMux()
	mux.Handle("/api/v1/", http.StripPrefix("/api/v1", m))
	return mux
}

// decodeHealthCheckRequest check server health
func decodeHealthCheckRequest(_ context.Context, r *http.Request) (interface{}, error) {
	return nil, nil
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

// decodeHTTPVerifyMailRequest decode verify mail request
func decodeHTTPVerifyMailRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.VerifyMailRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.Email == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("email is required"), "email is required")
		}
		if req.Code == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("code is required"), "code is required")
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

// decodeHTTPGetUserRequest decode request
func decodeHTTPGetUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetUserRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("access token is required"), "access token is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPGetProfileRequest decode request
func decodeHTTPGetProfileRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetProfileRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("access token is required"), "access token is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPUpdateProfileRequest decode request
func decodeHTTPUpdateProfileRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdateProfileRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("access token is required"), "access token is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPUpdatePasswordRequest decode request
func decodeHTTPUpdatePasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdatePasswordRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("access token is required"), "access token is required")
		}
		if req.OldPassword == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("old password is required"), "old password is required")
		}
		if req.NewPassword == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("new password is required"), "new password is required")
		}
		if req.ConfirmPassword == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("confirm password is required"), "confirm password is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPGetForgetPasswordCodeRequest decode request
func decodeHTTPGetForgetPasswordCodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetForgetPasswordCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.Email == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("email is required"), "email is required")
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorWrapper(http.StatusBadRequest, errors.New("bad Request"), "Bad Request")
		return nil, cusErr
	}
}

// decodeHTTPResetPasswordRequest decode request
func decodeHTTPResetPasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CreateNewPasswordWithCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("invalid request body"), "invalid request body")
		}
		if req.Email == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("email is required"), "email is required")
		}
		if req.Code == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("code is required"), "code is required")
		}
		if req.NewPassword == "" {
			return nil, utils.NewErrorWrapper(http.StatusBadRequest, errors.New("new password is required"), "new password is required")
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
		w.WriteHeader(catchErr.Code)
		err := json.NewEncoder(w).Encode(res)
		if err != nil {
			return
		}
		return
	}
	w.WriteHeader(cusErr.Code)
	res := authorization.GenericErrorResponse{
		Status:    false,
		ErrorCode: cusErr.Code,
		Message:   cusErr.Message,
	}
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		return
	}
}
