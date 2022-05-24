package middleware

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"context"
	"encoding/json"
	"errors"
	"github.com/go-kit/kit/endpoint"
	"github.com/hashicorp/go-hclog"
	"github.com/juju/ratelimit"
	"regexp"
	"strings"
)

// UserIDKey is used as a key for storing the UserID in context at middleware
type UserIDKey struct{}

// ValidateRefreshToken is a middleware that validates the refresh token
func ValidateRefreshToken(auth Authentication, r database.UserRepository, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			userID, authErr := authorizedRefreshToken(ctx, auth, r, logger, request)
			if authErr != nil {
				return nil, authErr
			}
			ctx = context.WithValue(ctx, UserIDKey{}, userID)
			return next(ctx, request)
		}
	}
}

// authorizedRefreshToken validates the refresh token.
func authorizedRefreshToken(ctx context.Context, auth Authentication, r database.UserRepository, logger hclog.Logger, request interface{}) (string, error) {
	token, err := extractValue(request, "refresh_token")
	if err != nil {
		logger.Error("extract value token failed", "err", err)
		cusErr := utils.NewErrorResponse(utils.BadRequest)
		return "", cusErr
	}
	logger.Debug("token present in header", token)

	userID, customKey, err := auth.ValidateRefreshToken(token)
	if err != nil {
		logger.Error("token validation failed", "error", err)
		cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
		return "", cusErr
	}
	logger.Debug("refresh token validated")

	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		logger.Error("You're not authorized. Please try again latter.", err)
		cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
		return "", cusErr
	}

	actualCustomKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	if customKey != actualCustomKey {
		logger.Debug("wrong token: authentication failed")
		cusErr := utils.NewErrorResponse(utils.Unauthorized)
		return "", cusErr
	}
	return userID, nil
}

func extractValue(request interface{}, key string) (string, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	keyStr := "\"" + key + "\":[^,;\\]}]*"
	r, _ := regexp.Compile(keyStr)
	match := r.FindString(string(body))
	keyValMatch := strings.Split(match, ":")
	if len(keyValMatch) < 2 {
		return "", errors.New("key not found")
	}
	return strings.ReplaceAll(keyValMatch[1], "\"", ""), nil
}

// ValidateAccessToken is a middleware that validates the access token
func ValidateAccessToken(auth Authentication, r database.UserRepository, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			userID, err := authorizedAccessToken(ctx, auth, r, logger, request)
			if err != nil {
				logger.Error("You're not authorized. Please try again latter.")
				cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
				return nil, cusErr
			}
			ctx = context.WithValue(ctx, UserIDKey{}, userID)
			return next(ctx, request)
		}
	}
}

func authorizedAccessToken(ctx context.Context, auth Authentication, r database.UserRepository, logger hclog.Logger, request interface{}) (string, error) {
	token, err := extractValue(request, "access_token")
	if err != nil {
		logger.Error("token validation failed", "err", err)
		cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
		return "", cusErr
	}

	userID, customKey, err := auth.ValidateAccessToken(token)
	if err != nil {
		logger.Error("token validation failed", "error", err)
		cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
		return "", cusErr
	}

	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		logger.Error("You're not authorized. Please try again latter.", err)
		cusErr := utils.NewErrorResponse(utils.ValidationTokenFailure)
		return "", cusErr
	}

	actualCustomKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	if customKey != actualCustomKey {
		logger.Debug("wrong token: authentication failed")
		cusErr := utils.NewErrorResponse(utils.Unauthorized)
		return "", cusErr
	}

	logger.Debug("access token validated", userID)
	return userID, nil
}

// ValidateParamRequest validates the user in the request
func ValidateParamRequest(validator *database.Validation, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (resp interface{}, err error) {
			errs := validator.Validate(request)
			if len(errs) != 0 {
				logger.Error("validation of verification data json failed", "error", errs)
				cusErr := utils.NewErrorResponse(utils.ValidationJSONFailure)
				return nil, cusErr
			}
			return next(ctx, request)
		}
	}
}

// RateLimitRequest is a middleware that limits the number of requests
func RateLimitRequest(tb *ratelimit.Bucket, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (resp interface{}, err error) {
			if tb.TakeAvailable(1) == 0 {
				logger.Error("rate limit exceeded")
				cusErr := utils.NewErrorResponse(utils.QuicklyRequest)
				return nil, cusErr
			}
			return next(ctx, request)
		}
	}
}
