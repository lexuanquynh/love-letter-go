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
	m.Handle("/delete-user", httptransport.NewServer(
		ep.DeleteUserEndpoint,
		decodeHTTPDeleteUserRequest,
		encodeResponse,
		options...,
	))
	m.Handle("/cancel-delete-user", httptransport.NewServer(
		ep.CancelDeleteUserEndpoint,
		decodeHTTPCancelDeleteUserRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/confirm-cancel-delete-user", httptransport.NewServer(
		ep.ConfirmCancelDeleteUserEndpoint,
		decodeHTTPConfirmCancelDeleteUserRequest,
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

	m.Handle("/confirm-match-lover", httptransport.NewServer(
		ep.ConfirmMatchLoverEndpoint,
		decodeHTTPConfirmMatchLoverRequest,
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

	m.Handle("/insert-player-data", httptransport.NewServer(
		ep.InsertPlayerDataEndpoint,
		decodeHTTPInsertPlayerDataRequest,
		encodeResponse,
		options...,
	))
	// we don't public this API
	m.Handle("/get-player-data", httptransport.NewServer(
		ep.GetPlayerDataEndpoint,
		decodeHTTPGetPlayerDataRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/get-user-state", httptransport.NewServer(
		ep.GetUserStateDataEndpoint,
		decodeHTTPGetUserStateDataRequest,
		encodeResponse,
		options...,
	))

	m.Handle("/set-user-state", httptransport.NewServer(
		ep.SetUserStateDataEndpoint,
		decodeHTTPSetUserStateDataRequest,
		encodeResponse,
		options...,
	))

	// Get feeds
	m.Handle("/get-feeds", httptransport.NewServer(
		ep.GetFeedsEndpoint,
		decodeHTTPGetFeedsRequest,
		encodeResponse,
		options...,
	))

	// Update been love
	m.Handle("/update-been-love", httptransport.NewServer(
		ep.UpdateBeenLoveEndpoint,
		decodeHTTPUpdateBeenLoveRequest,
		encodeResponse,
		options...,
	))

	// Check passcode status
	m.Handle("/check-passcode-status", httptransport.NewServer(
		ep.CheckPassCodeStatusEndpoint,
		decodeHTTPCheckPasscodeStatusRequest,
		encodeResponse,
		options...,
	))

	// Set passcode
	m.Handle("/set-passcode", httptransport.NewServer(
		ep.SetPassCodeEndpoint,
		decodeHTTPSetPasscodeRequest,
		encodeResponse,
		options...,
	))

	// Compare passcode
	m.Handle("/compare-passcode", httptransport.NewServer(
		ep.ComparePassCodeEndpoint,
		decodeHTTPComparePasscodeRequest,
		encodeResponse,
		options...,
	))
	// create letter
	m.Handle("/create-letter", httptransport.NewServer(
		ep.CreateLetterEndpoint,
		decodeHTTPCreateLetterRequest,
		encodeResponse,
		options...,
	))

	// delete letter
	m.Handle("/delete-letter", httptransport.NewServer(
		ep.DeleteLetterEndpoint,
		decodeHTTPDeleteLetterRequest,
		encodeResponse,
		options...,
	))

	// get letters
	m.Handle("/get-letters", httptransport.NewServer(
		ep.GetLettersEndpoint,
		decodeHTTPGetLettersRequest,
		encodeResponse,
		options...,
	))

	// get letter
	m.Handle("/get-letter", httptransport.NewServer(
		ep.GetLetterEndpoint,
		decodeHTTPGetLetterRequest,
		encodeResponse,
		options...,
	))

	/*
			// insert psychology
			m.Handle("/insert-psychology", httptransport.NewServer(
				ep.InsertPsychologyEndpoint,
				decodeHTTPInsertPsychologyRequest,
				encodeResponse,
				options...,
			))

			// delete psychology
			m.Handle("/delete-psychology", httptransport.NewServer(
				ep.DeletePsychologyEndpoint,
				decodeHTTPDeletePsychologyRequest,
				encodeResponse,
				options...,
			))


		// Get psychologies
		m.Handle("/get-psychologies", httptransport.NewServer(
			ep.GetPsychologiesEndpoint,
			decodeHTTPGetPsychologiesRequest,
			encodeResponse,
			options...,
		))
	*/
	// create holiday
	m.Handle("/create-holiday", httptransport.NewServer(
		ep.CreateHolidayEndpoint,
		decodeHTTPCreateHolidayRequest,
		encodeResponse,
		options...,
	))
	// delete holiday
	m.Handle("/delete-holiday", httptransport.NewServer(
		ep.DeleteHolidayEndpoint,
		decodeHTTPDeleteHolidayRequest,
		encodeResponse,
		options...,
	))
	// get holidays
	m.Handle("/get-holidays", httptransport.NewServer(
		ep.GetHolidaysEndpoint,
		decodeHTTPGetHolidaysRequest,
		encodeResponse,
		options...,
	))

	// get notifications
	m.Handle("/get-notifications", httptransport.NewServer(
		ep.GetNotificationsEndpoint,
		decodeHTTPGetNotificationsRequest,
		encodeResponse,
		options...,
	))

	// get notification
	m.Handle("/get-notification", httptransport.NewServer(
		ep.GetNotificationEndpoint,
		decodeHTTPGetNotificationRequest,
		encodeResponse,
		options...,
	))

	// delete notification
	m.Handle("/delete-notification", httptransport.NewServer(
		ep.DeleteNotificationEndpoint,
		decodeHTTPDeleteNotificationRequest,
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

// decodeHTTPDeleteUserRequest decode request
func decodeHTTPDeleteUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.DeleteUserRequest
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

// decodeHTTPCancelDeleteUserRequest decode request
func decodeHTTPCancelDeleteUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CancelDeleteUserRequest
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

// decodeHTTPConfirmCancelDeleteUserRequest decode request
func decodeHTTPConfirmCancelDeleteUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.ConfirmCancelDeleteUserRequest
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

// decodeHTTPConfirmMatchLoverRequest decode request
func decodeHTTPConfirmMatchLoverRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.AcceptMatchLoverRequest
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

// decodeHTTPGetUserStateDataRequest decode request
func decodeHTTPGetUserStateDataRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetUserStateDataRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.KeyString == "" {
			return nil, utils.NewErrorResponse(utils.KeyStringRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPSetUserStateDataRequest decode request
func decodeHTTPSetUserStateDataRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.SetUserStateDataRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.KeyString == "" {
			return nil, utils.NewErrorResponse(utils.KeyStringRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}

}

// decodeHTTPGetFeedsRequest decode request
func decodeHTTPGetFeedsRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

// decodeHTTPUpdateBeenLoveRequest decode request
func decodeHTTPUpdateBeenLoveRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.UpdateBeenLoveRequest
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

// decodeHTTPCheckPasscodeStatusRequest decode request
func decodeHTTPCheckPasscodeStatusRequest(_ context.Context, r *http.Request) (interface{}, error) {
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

// decodeHTTPSetPasscodeRequest decode request
func decodeHTTPSetPasscodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.SetPassCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.PassCode == "" {
			return nil, utils.NewErrorResponse(utils.PassCodeRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPComparePasscodeRequest decode request
func decodeHTTPComparePasscodeRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.ComparePassCodeRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		if req.PassCode == "" {
			return nil, utils.NewErrorResponse(utils.PassCodeRequired)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPCreateLetterRequest decode request
func decodeHTTPCreateLetterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CreateLetterRequest
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

// decodeHTTPDeleteLetterRequest decode request
func decodeHTTPDeleteLetterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.DeleteLetterRequest
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

// decodeHTTPGetLettersRequest decode request
func decodeHTTPGetLettersRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetLettersRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		//Limit must not be negative
		if req.Limit < 0 {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetLetterRequest decode request
func decodeHTTPGetLetterRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetLetterRequest
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

// decodeHTTPInsertPsychologyRequest decode request
func decodeHTTPInsertPsychologyRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.InsertPsychologyRequest
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

// decodeHTTPDeletePsychologyRequest decode request
func decodeHTTPDeletePsychologyRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.DeletePsychologyRequest
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

// decodeHTTPGetPsychologiesRequest decode request
func decodeHTTPGetPsychologiesRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetPsychologiesRequest
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

// decodeHTTPCreateHolidayRequest decode request
func decodeHTTPCreateHolidayRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.CreateHolidayRequest
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

// decodeHTTPDeleteHolidayRequest decode request
func decodeHTTPDeleteHolidayRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.DeleteHolidayRequest
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

// decodeHTTPGetHolidaysRequest decode request
func decodeHTTPGetHolidaysRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetHolidaysRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		//Limit must not be negative
		if req.Limit < 0 {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetNotificationsRequest decode request
func decodeHTTPGetNotificationsRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.GetNotificationsRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}
		if req.AccessToken == "" {
			return nil, utils.NewErrorResponse(utils.AccessTokenRequired)
		}
		//Limit must not be negative
		if req.Limit < 0 {
			return nil, utils.NewErrorResponse(utils.BadRequest)
		}

		return req, nil
	} else {
		cusErr := utils.NewErrorResponse(utils.MethodNotAllowed)
		return nil, cusErr
	}
}

// decodeHTTPGetNotificationRequest decode request
func decodeHTTPGetNotificationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.NotificationRequest
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

// decodeHTTPDeleteNotificationRequest decode request
func decodeHTTPDeleteNotificationRequest(_ context.Context, r *http.Request) (interface{}, error) {
	if r.Method == "POST" {
		var req authorization.NotificationRequest
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
