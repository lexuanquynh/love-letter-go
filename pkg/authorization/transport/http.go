package transport

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/endpoints"
	"context"
	"encoding/json"
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
	m.Handle("/update-username", httptransport.NewServer(
		ep.UpdateUserNameEndpoint,
		decodeHTTPUpdateUsernameRequest,
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
	m.Handle("/generate-access-token", httptransport.NewServer(
		ep.GenerateAccessTokenEndpoint,
		decodeHTTPGenerateAccessTokenRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/get-verify-mail-code", httptransport.NewServer(
		ep.GetVerifyMailCodeEndpoint,
		decodeHTTPGetVerifyMailCodeRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/get-match-code", httptransport.NewServer(
		ep.GetMatchCodeEndpoint,
		decodeHTTPGetMatchCodeRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/match-lover", httptransport.NewServer(
		ep.MatchLoverEndpoint,
		decodeHTTPMatchLoverRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/un-match-lover", httptransport.NewServer(
		ep.UnMatchLoverEndpoint,
		decodeHTTPUnMatchLoverRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/get-matched-lover", httptransport.NewServer(
		ep.GetMatchedLoverEndpoint,
		decodeHTTPGetMatchedLoverRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/create-love-letter", httptransport.NewServer(
		ep.CreateLoveLetterEndpoint,
		decodeHTTPCreateLoveLetterRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/get-feeds", httptransport.NewServer(
		ep.GetFeedsEndpoint,
		decodeHTTPGetFeedsRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/insert-player-data", httptransport.NewServer(
		ep.InsertPlayerDataEndpoint,
		decodeHTTPInsertPlayerDataRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/get-player-data", httptransport.NewServer(
		ep.GetPlayerDataEndpoint,
		decodeHTTPGetPlayerDataRequest,
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
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Email == "" {
			return nil, utils.NewErrorResponse(utils.MailRequired)
		}
		if req.Password == "" {
			return nil, utils.NewErrorResponse(utils.PasswordRequired)
		}
		if req.Password != req.RePassword {
			return nil, utils.NewErrorResponse(utils.PasswordNotMatch)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPVerifyMailRequest decode verify mail request
func decodeHTTPVerifyMailRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.VerifyMailRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Email == "" {
			return nil, utils.NewErrorResponse(utils.MailRequired)
		}
		if req.Code == "" {
			return nil, utils.NewErrorResponse(utils.CodeRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPLoginRequest
func decodeHTTPLoginRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.LoginRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Email == "" {
			return nil, utils.NewErrorResponse(utils.MailRequired)
		}
		if req.Password == "" {
			return nil, utils.NewErrorResponse(utils.PasswordRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPLogoutRequest decode request
func decodeHTTPLogoutRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.LogoutRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.RefreshToken == "" {
			return nil, utils.NewErrorResponse(utils.RefreshTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetUserRequest decode request
func decodeHTTPGetUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetProfileRequest decode request
func decodeHTTPGetProfileRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPUpdateProfileRequest decode request
func decodeHTTPUpdateProfileRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdateProfileRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPUpdateUsernameRequest decode request
func decodeHTTPUpdateUsernameRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdateUserNameRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Username == "" {
			return nil, utils.NewErrorResponse(utils.UsernameRequired)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPUpdatePasswordRequest decode request
func decodeHTTPUpdatePasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdatePasswordRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.OldPassword == "" {
			return nil, utils.NewErrorResponse(utils.OldPasswordRequired)
		}
		if req.NewPassword == "" {
			return nil, utils.NewErrorResponse(utils.NewPasswordRequired)
		}
		if req.ConfirmPassword == "" {
			return nil, utils.NewErrorResponse(utils.ConfirmPasswordRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetForgetPasswordCodeRequest decode request
func decodeHTTPGetForgetPasswordCodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetForgetPasswordCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Email == "" {
			return nil, utils.NewErrorResponse(utils.MailRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPResetPasswordRequest decode request
func decodeHTTPResetPasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CreateNewPasswordWithCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.Email == "" {
			return nil, utils.NewErrorResponse(utils.MailRequired)
		}
		if req.Code == "" {
			return nil, utils.NewErrorResponse(utils.CodeRequired)
		}
		if req.NewPassword == "" {
			return nil, utils.NewErrorResponse(utils.NewPasswordRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGenerateAccessTokenRequest decode request
func decodeHTTPGenerateAccessTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GenerateAccessTokenRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.RefreshToken == "" {
			return nil, utils.NewErrorResponse(utils.RefreshTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetVerifyMailCodeRequest decode request
func decodeHTTPGetVerifyMailCodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetMatchCodeRequest decode request
func decodeHTTPGetMatchCodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPMatchLoverRequest decode request
func decodeHTTPMatchLoverRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.MatchLoverRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.Code == "" {
			return nil, utils.NewErrorResponse(utils.CodeRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPUnMatchLoverRequest decode request
func decodeHTTPUnMatchLoverRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetMatchedLoverRequest decode request
func decodeHTTPGetMatchedLoverRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPCreateLoveLetterRequest decode request
func decodeHTTPCreateLoveLetterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CreateLoveLetterRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.Title == "" {
			return nil, utils.NewErrorResponse(utils.TitleRequired)
		}
		if req.Body == "" {
			return nil, utils.NewErrorResponse(utils.BodyRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// encodeResponse encode response
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

// decodeHTTPGetFeedsRequest decode request
func decodeHTTPGetFeedsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	logger := utils.NewLogger()
	logger.Info("decodeHTTPGetFeedsRequest")
	return nil, nil
}

// decodeHTTPInsertPlayerDataRequest decode request
func decodeHTTPInsertPlayerDataRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.InsertPlayerDataRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.PlayerID == "" {
			return nil, utils.NewErrorResponse(utils.PlayerIdRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetPlayerDataRequest decode request
func decodeHTTPGetPlayerDataRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CommonAuthorizationRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

func errEncoder(ctx context.Context, err error, w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	cusErr, ok := err.(utils.ErrorResponse)
	if !ok {
		catchErr := utils.NewErrorResponse(utils.InternalServerError)
		res := authorization.GenericErrorResponse{
			Status:    false,
			ErrorCode: int(catchErr.ErrorType),
			Message:   catchErr.Error(),
		}
		w.WriteHeader(http.StatusInternalServerError)
		err := json.NewEncoder(w).Encode(res)
		if err != nil {
			return
		}
		return
	}
	errCode := int(cusErr.ErrorType)
	logger := utils.NewLogger()
	logger.Error(err.Error())
	if errCode == utils.TooManyRequests {
		w.WriteHeader(http.StatusForbidden)
	} else if errCode == utils.PasswordIncorrect || errCode == utils.ValidationTokenFailure {
		w.WriteHeader(http.StatusUnauthorized)
	} else if errCode >= 400 && errCode < 500 {
		w.WriteHeader(int(cusErr.ErrorType))
	} else {
		w.WriteHeader(http.StatusInternalServerError)
	}

	res := authorization.GenericErrorResponse{
		Status:    false,
		ErrorCode: errCode,
		Message:   cusErr.Error(),
	}
	err = json.NewEncoder(w).Encode(res)
	if err != nil {
		return
	}
}
