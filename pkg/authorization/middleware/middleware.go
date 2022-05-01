package middleware

import (
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
			authErr := authorizedRefreshToken(ctx, auth, r, logger, request)
			if authErr != nil {
				return nil, authErr
			}
			return next(ctx, request)
		}
	}
}

// authorizedRefreshToken validates the refresh token.
func authorizedRefreshToken(ctx context.Context, auth Authentication, r database.UserRepository, logger hclog.Logger, request interface{}) error {
	token, err := extractValue(request, "refresh_token")
	if err != nil {
		logger.Error("extract value token failed", "err", err)
		return errors.New("extract value token failed")
	}
	logger.Debug("token present in header", token)

	userID, customKey, err := auth.ValidateRefreshToken(token)
	if err != nil {
		logger.Error("token validation failed", "error", err)
		return errors.New("token validation failed")
	}
	logger.Debug("refresh token validated")

	user, err := r.GetUserByID(ctx, userID)
	if err != nil {
		logger.Error("You're not authorized. Please try again latter.", err)
		return errors.New("you're not authorized. Please try again latter")
	}

	actualCustomKey := auth.GenerateCustomKey(user.ID, user.TokenHash)
	if customKey != actualCustomKey {
		logger.Debug("wrong token: authentication failed")
		return errors.New("wrong token: authentication failed")
	}
	return nil
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
func ValidateAccessToken(auth Authentication, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			userID, valid := authorizedAccessToken(auth, logger, request)
			if !valid {
				return nil, errors.New("invalid token: authentication failed")
			}
			ctx = context.WithValue(ctx, UserIDKey{}, userID)
			return next(ctx, request)
		}
	}
}

func authorizedAccessToken(auth Authentication, logger hclog.Logger, request interface{}) (string, bool) {
	token, err := extractValue(request, "access_token")
	if err != nil {
		logger.Error("token validation failed", "err", err)
		return "", false
	}

	userID, err := auth.ValidateAccessToken(token)
	if err != nil {
		logger.Error("token validation failed", "error", err)
		return "", false
	}
	logger.Debug("access token validated", userID)
	return userID, true
}

// ValidateParamRequest validates the user in the request
func ValidateParamRequest(validator *database.Validation, logger hclog.Logger) endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (resp interface{}, err error) {
			errs := validator.Validate(request)
			if len(errs) != 0 {
				logger.Error("validation of verification data json failed", "error", errs)
				return nil, errors.New("please check your param request")
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
				return nil, errors.New("you request too fast, please slow down")
			}
			return next(ctx, request)
		}
	}
}
