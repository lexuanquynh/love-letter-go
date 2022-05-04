package authorization

import (
	"LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"time"
)

type userService struct {
	logger      hclog.Logger
	configs     *utils.Configurations
	repo        database.UserRepository
	mailService MailService
	auth        middleware.Authentication
}

// NewUserService creates a new user service.
func NewUserService(logger hclog.Logger,
	configs *utils.Configurations,
	repo database.UserRepository,
	mailService MailService,
	auth middleware.Authentication) *userService {
	return &userService{
		logger:      logger,
		configs:     configs,
		repo:        repo,
		mailService: mailService,
		auth:        auth,
	}
}

// HealthCheck checks the health of the service.
func (s *userService) HealthCheck(ctx context.Context) error {
	s.logger.Info("Health check successful")
	return nil
}

// SignUp creates a new user.
func (s *userService) SignUp(ctx context.Context, request *RegisterRequest) (string, error) {
	// Pass data from request to user struct
	user := database.User{
		Email:    request.Email,
		Password: request.Password,
	}

	// Hash password before saving
	hashedPassword, err := user.HashPassword()
	if err != nil {
		s.logger.Error("Error hashing password", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	user.Password = hashedPassword
	user.TokenHash = utils.GenerateRandomString(15)
	err = s.repo.CreateUser(ctx, &user)
	if err != nil {
		s.logger.Error("Error creating user", "error", err)
		cusErr := utils.NewErrorResponse(utils.ExistUser)
		return cusErr.Error(), cusErr
	}
	// Generate authentication code
	authedCode := utils.GenerateRandomString(8)
	// Saving the code authentication into database
	verificationData := database.VerificationData{
		Email:     request.Email,
		Code:      authedCode,
		Type:      database.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	err = s.repo.StoreVerificationData(ctx, &verificationData, true)
	if err != nil {
		s.logger.Error("Error storing verification data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Send email to user
	from := s.configs.MailSender
	to := []string{user.Email}
	subject := s.configs.MailTitle
	mailType := MailConfirmation
	mailData := &MailData{
		Username: user.Username,
		Code:     authedCode,
	}
	mailReq := s.mailService.NewMail(from, to, subject, mailType, mailData)
	err = s.mailService.SendMail(mailReq)
	if err != nil {
		s.logger.Error("unable to send mail", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	// Store user info into Profile database
	profile := database.ProfileData{
		UserID: user.ID,
		Email:  user.Email,
	}
	err = s.repo.StoreProfileData(ctx, &profile)
	if err != nil {
		s.logger.Error("Error storing profile data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	return "success created user. Please confirm your email to active your account.", nil
}

// VerifyMail verifies the user's email.
func (s *userService) VerifyMail(ctx context.Context, request *VerifyMailRequest) (string, error) {
	s.logger.Debug("verifying the confirmation code")
	user, err := s.repo.GetUserByEmail(ctx, request.Email)
	if err != nil {
		s.logger.Error("error fetching the user", "error", err)
		errMsg := err.Error()
		if strings.Contains(errMsg, utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return cusErr.Error(), cusErr
		} else {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr.Error(), cusErr
		}
	}
	// if user is verified, return success.
	if user.Verified == true {
		return "Email has been successfully verified.", nil
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLogin > s.configs.LoginLimit {
		s.logger.Error("Verify Mail limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// if user is not verified, check the code
	actualVerificationData, err := s.repo.GetVerificationData(ctx, request.Email, database.MailConfirmation)
	if err != nil {
		s.logger.Error("unable to fetch verification data", "error", err)
		if strings.Contains(err.Error(), utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return cusErr.Error(), cusErr
		}
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	valid, err := s.verify(ctx, actualVerificationData, request)
	if !valid {
		s.logger.Error("verification code is not valid", "error", err)
		cusErr := utils.NewErrorResponse(utils.CodeInvalid)
		return cusErr.Error(), cusErr
	}
	// Update user's verified status
	err = s.repo.UpdateUserVerificationStatus(ctx, request.Email, true)
	if err != nil {
		s.logger.Error("unable to set user verification status to true")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	// delete the VerificationData from db
	err = s.repo.DeleteVerificationData(ctx, request.Email, database.MailConfirmation)
	if err != nil {
		s.logger.Error("unable to delete the verification data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Reset limit data
	limitData.NumOfSendMailVerify = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Cannot reset number of login", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	s.logger.Debug("user mail verification succeeded")
	return "Email has been successfully verified.", nil
}

func (s *userService) verify(ctx context.Context, actualVerificationData *database.VerificationData, request *VerifyMailRequest) (bool, error) {
	// check for expiration
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		s.logger.Error("verification data provided is expired")
		err := s.repo.DeleteVerificationData(ctx, actualVerificationData.Email, actualVerificationData.Type)
		s.logger.Error("unable to delete verification data from db", "error", err)
		return false, utils.NewErrorResponse(utils.Unauthorized)
	}

	if actualVerificationData.Code != request.Code {
		s.logger.Error("verification of mail failed. Invalid verification code provided")
		return false, utils.NewErrorResponse(utils.Unauthorized)
	}
	return true, nil
}

//Login authenticates a user.
func (s *userService) Login(ctx context.Context, request *LoginRequest) (interface{}, error) {
	// Get user from database
	user, err := s.repo.GetUserByEmail(ctx, request.Email)
	if err != nil {
		s.logger.Error("Error getting user", "error", err)
		if strings.Contains(err.Error(), utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return cusErr.Error(), cusErr
		}
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check if user is verified
	if !user.Verified {
		s.logger.Error("User is not verified", "error", err)
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr.Error(), cusErr
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeLogin)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLogin > s.configs.LoginLimit {
		s.logger.Error("Login limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeLogin)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	// Check if password is correct
	if isSame := s.auth.ComparePassword(user.Password, request.Password); !isSame {
		s.logger.Error("Password is incorrect", "error", err)
		cusErr := utils.NewErrorResponse(utils.PasswordIncorrect)
		return cusErr.Error(), cusErr
	}
	// Generate accessToken
	accessToken, err := s.auth.GenerateAccessToken(user)
	if err != nil {
		s.logger.Error("Error generating accessToken", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Generate refreshToken
	refreshToken, err := s.auth.GenerateRefreshToken(user)
	if err != nil {
		s.logger.Error("Error generating refreshToken", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Reset limit data
	limitData.NumOfLogin = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeLogin)
	if err != nil {
		s.logger.Error("Cannot reset number of login", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	s.logger.Debug("successfully generated token")
	loginResponse := LoginResponse{
		Email:        user.Email,
		Username:     user.Username,
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Verified:     user.Verified,
	}
	return loginResponse, nil
}

// Logout user. Make refreshToken invalid.
func (s *userService) Logout(ctx context.Context, request *LogoutRequest) error {
	// Get user from database
	user, err := s.repo.GetUserByEmail(ctx, request.Email)
	if err != nil {
		s.logger.Error("Error getting user", "error", err)
		if strings.Contains(err.Error(), utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return cusErr
		}
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}

	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr
	}

	// Set new random text for token hash. It will make invalid the previous refreshToken.
	user.TokenHash = utils.GenerateRandomString(15)
	// Generate refreshToken
	refreshToken, err := s.auth.GenerateRefreshToken(user)

	if err != nil {
		s.logger.Error("Error generating refreshToken", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("successfully generated token", "refresh token", refreshToken)
	// Update user token hash to database
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Error updating user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}

	s.logger.Debug("Logout success", "email", request.Email)

	return nil
}

// GetUser returns user.
func (s *userService) GetUser(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr.Error(), cusErr
	}
	// Make response data
	userResponse := GetUserResponse{
		Email:    user.Email,
		Username: user.Username,
		Verified: user.Verified,
	}
	return userResponse, nil
}

// GetProfile returns user profile.
func (s *userService) GetProfile(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Make response data
	profileResponse := GetProfileResponse{
		Email:     profile.Email,
		FirstName: profile.FirstName,
		LastName:  profile.LastName,
		AvatarURL: profile.AvatarURL,
		Phone:     profile.Phone,
		Street:    profile.Street,
		City:      profile.City,
		State:     profile.State,
		ZipCode:   profile.ZipCode,
		Country:   profile.Country,
	}
	return profileResponse, nil
}

// UpdateUserName updates user name.
func (s *userService) UpdateUserName(ctx context.Context, request *UpdateUserNameRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr.Error(), cusErr
	}
	// Check if username is already taken
	if exist, err := s.repo.CheckUsernameExists(ctx, request.Username); exist || err != nil {
		s.logger.Error("Username is already taken", "error", err)
		cusErr := utils.NewErrorResponse(utils.ExistUserName)
		return cusErr.Error(), cusErr
	}
	// Update user name
	user.Username = request.Username
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Cannot update user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	s.logger.Debug("Update user name success", "email", user.Email)
	// Make response data
	userResponse := GetUserResponse{
		Email:    user.Email,
		Username: user.Username,
		Verified: user.Verified,
	}
	return userResponse, nil
}

// UpdateProfile updates user profile.
func (s *userService) UpdateProfile(ctx context.Context, request *UpdateProfileRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Get user by id
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr.Error(), cusErr
	}
	// Get profile by id
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Update profile profile
	if request.FirstName != "" {
		profile.FirstName = request.FirstName
	}
	if request.LastName != "" {
		profile.LastName = request.LastName
	}
	if request.AvatarURL != "" {
		profile.AvatarURL = request.AvatarURL
	}
	if request.Phone != "" {
		profile.Phone = request.Phone
	}
	if request.Street != "" {
		profile.Street = request.Street
	}
	if request.City != "" {
		profile.City = request.City
	}
	if request.State != "" {
		profile.State = request.State
	}
	if request.ZipCode != "" {
		profile.ZipCode = request.ZipCode
	}
	if request.Country != "" {
		profile.Country = request.Country
	}
	// Update profile
	err = s.repo.UpdateProfile(ctx, profile)
	if err != nil {
		s.logger.Error("Cannot update profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Make response data
	profileResponse := GetProfileResponse{
		Email:     profile.Email,
		FirstName: profile.FirstName,
		LastName:  profile.LastName,
		AvatarURL: profile.AvatarURL,
		Phone:     profile.Phone,
		Street:    profile.Street,
		City:      profile.City,
		State:     profile.State,
		ZipCode:   profile.ZipCode,
		Country:   profile.Country,
	}
	s.logger.Info("Profile updated", "userID", userID)
	return profileResponse, nil
}

// UpdatePassword changes user password.
func (s *userService) UpdatePassword(ctx context.Context, request *UpdatePasswordRequest) (string, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return "", cusErr
	}
	// Get user by id
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		err := errors.New("internal server error. Please try again later")
		return err.Error(), err
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		return "User is banned", errors.New("user is banned")
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, userID, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfChangePassword > s.configs.ChangePasswordLimit {
		s.logger.Error("Change password limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Compare new password and confirm password
	if request.NewPassword != request.ConfirmPassword {
		s.logger.Error("New password and confirm password are not the same", "error", err)
		cusErr := utils.NewErrorResponse(utils.PasswordNotMatch)
		return cusErr.Error(), cusErr
	}
	// Check if password is correct
	if isSame := s.auth.ComparePassword(user.Password, request.OldPassword); isSame == false {
		s.logger.Error("Password is incorrect", "error", err)
		cusErr := utils.NewErrorResponse(utils.PasswordIncorrect)
		return cusErr.Error(), cusErr
	}
	// Hash new password
	hashedPassword, err := s.hashPassword(request.NewPassword)
	if err != nil {
		s.logger.Error("Cannot hash password", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check hashed password is not contains in list of passwords
	listOfPasswords, err := s.repo.GetListOfPasswords(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get list of passwords", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	for _, password := range listOfPasswords {
		if isSame := s.auth.ComparePassword(password, request.NewPassword); isSame == true {
			s.logger.Error("New password is the same as old password", "error", err)
			cusErr := utils.NewErrorResponse(utils.ChoiceOtherPassword)
			return cusErr.Error(), cusErr
		}
	}
	// Update token hash. It makes refresh token tobe invalid.
	tokenHash := utils.GenerateRandomString(15)
	// Update user password
	err = s.repo.UpdatePassword(ctx, userID, hashedPassword, tokenHash)
	if err != nil {
		s.logger.Error("Cannot update password", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Insert password into list of passwords user
	passwordUsers := &database.PassworUsers{
		UserID:   userID,
		Password: hashedPassword,
	}
	err = s.repo.InsertListOfPasswords(ctx, passwordUsers)
	if err != nil {
		s.logger.Error("Cannot update password into list of passwords", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Reset limit data
	limitData.NumOfChangePassword = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Cannot delete limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	s.logger.Info("Password changed", "userID", userID)
	return "Password changed", nil
}

// hashPassword hashes password.
func (s *userService) hashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("unable to hash password", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	return string(hashedPass), nil
}

// GetForgetPasswordCode gets forget password code.
func (s *userService) GetForgetPasswordCode(ctx context.Context, email string) error {
	// Check if email is registered
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Email is not registered", "error", err)
		cusErr := utils.NewErrorResponse(utils.EmailNotRegistered)
		return cusErr
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeSendPassResetMail)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if user has reached limit send mail
	if limitData.NumOfSendResetPassword > s.configs.SendMailResetPasswordLimit {
		s.logger.Error("User has reached limit send mail.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	// Insert or update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeSendPassResetMail)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Generate forget password code
	forgetPasswordCode := utils.GenerateRandomString(8)

	// store the password reset code to db
	verificationData := &database.VerificationData{
		Email:     user.Email,
		Code:      forgetPasswordCode,
		Type:      database.PassReset,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.PassResetCodeExpiration)),
	}
	// Check insert or update
	isInsert := false
	_, err = s.repo.GetVerificationData(ctx, user.Email, database.PassReset)
	if err != nil {
		isInsert = true
		s.logger.Error("Cannot get verification data", "error", err)
	}

	err = s.repo.StoreVerificationData(ctx, verificationData, isInsert)
	if err != nil {
		s.logger.Error("unable to store password reset verification data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Send verification mail
	from := s.configs.MailSender
	to := []string{user.Email}
	subject := s.configs.MailTitle
	mailType := PassReset
	mailData := &MailData{
		Username: user.Username,
		Code:     forgetPasswordCode,
	}
	mailReq := s.mailService.NewMail(from, to, subject, mailType, mailData)
	err = s.mailService.SendMail(mailReq)
	if err != nil {
		s.logger.Error("unable to send mail", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("successfully mailed password reset code")
	return nil
}

// ResetPassword creates new password with code.
func (s *userService) ResetPassword(ctx context.Context, request *CreateNewPasswordWithCodeRequest) error {
	actualVerificationData, err := s.repo.GetVerificationData(ctx, request.Email, database.PassReset)
	if err != nil {
		s.logger.Error("unable to get verification data", "error", err)
		// no rows returned
		if err == sql.ErrNoRows {
			return utils.NewErrorResponse(utils.NotFound)
		}
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	if actualVerificationData.Code != request.Code {
		s.logger.Error("invalid code", "error", err)
		return utils.NewErrorResponse(utils.InvalidCode)
	}
	if actualVerificationData.ExpiresAt.Before(time.Now()) {
		s.logger.Error("verification data provided is expired")
		err := s.repo.DeleteVerificationData(ctx, actualVerificationData.Email, actualVerificationData.Type)
		s.logger.Error("unable to delete verification data from db", "error", err)
		return utils.NewErrorResponse(utils.ExpiredCode)
	}
	user, err := s.repo.GetUserByEmail(ctx, request.Email)
	if err != nil {
		s.logger.Error("unable to get user", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Hash new password
	hashedPassword, err := s.hashPassword(request.NewPassword)
	if err != nil {
		s.logger.Error("Cannot hash password", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Check hashed password is not contains in list of passwords
	listOfPasswords, err := s.repo.GetListOfPasswords(ctx, user.ID)
	if err != nil {
		s.logger.Error("Cannot get list of passwords", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	for _, password := range listOfPasswords {
		if isSame := s.auth.ComparePassword(password, request.NewPassword); isSame == true {
			s.logger.Error("New password is the same as old password", "error", err)
			return utils.NewErrorResponse(utils.ChoiceOtherPassword)
		}
	}
	// Update token hash. It makes refresh token tobe invalid.
	tokenHash := utils.GenerateRandomString(15)
	// Update user password
	err = s.repo.UpdatePassword(ctx, user.ID, hashedPassword, tokenHash)
	if err != nil {
		s.logger.Error("Cannot update password", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Insert password into list of passwords user
	passwordUsers := &database.PassworUsers{
		UserID:   user.ID,
		Password: hashedPassword,
	}
	err = s.repo.InsertListOfPasswords(ctx, passwordUsers)
	if err != nil {
		s.logger.Error("Cannot update password into list of passwords", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Cannot delete limit data", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// delete the VerificationData from db
	err = s.repo.DeleteVerificationData(ctx, actualVerificationData.Email, actualVerificationData.Type)
	if err != nil {
		s.logger.Error("unable to delete the verification data", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Reset change password limit data
	limitData.NumOfSendResetPassword = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeSendPassResetMail)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Info("Password changed", "userID", user.ID)
	return nil
}

// GenerateAccessToken generate access token
func (s *userService) GenerateAccessToken(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr.Error(), cusErr
	}
	accessToken, err := s.auth.GenerateAccessToken(user)
	if err != nil {
		s.logger.Error("unable to generate access token", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	s.logger.Debug("Successfully generated new access token")
	return GenerateAccessResponse{
		AccessToken: accessToken,
		Username:    user.Username,
	}, nil
}

// GetVerifyMailCode get verify mail code
func (s *userService) GetVerifyMailCode(ctx context.Context) error {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr
	}
	// Check if user is verified
	if user.Verified {
		s.logger.Error("Email has been successfully verified")
		return nil
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if user has reached limit send mail
	if limitData.NumOfSendMailVerify > s.configs.SendMailVerifyLimit {
		s.logger.Error("User has reached limit send mail.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	// Insert or update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Generate forget password code
	forgetPasswordCode := utils.GenerateRandomString(8)

	// store the password reset code to db
	verificationData := &database.VerificationData{
		Email:     user.Email,
		Code:      forgetPasswordCode,
		Type:      database.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	// Check insert or update
	isInsert := false
	_, err = s.repo.GetVerificationData(ctx, user.Email, database.MailConfirmation)
	if err != nil {
		isInsert = true
		s.logger.Error("Cannot get verification data", "error", err)
	}

	err = s.repo.StoreVerificationData(ctx, verificationData, isInsert)
	if err != nil {
		s.logger.Error("unable to store password reset verification data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Send verification mail
	from := s.configs.MailSender
	to := []string{user.Email}
	subject := s.configs.MailTitle
	mailType := MailConfirmation
	mailData := &MailData{
		Username: user.Username,
		Code:     forgetPasswordCode,
	}
	mailReq := s.mailService.NewMail(from, to, subject, mailType, mailData)
	err = s.mailService.SendMail(mailReq)
	if err != nil {
		s.logger.Error("unable to send mail", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("successfully mailed password reset code")
	return nil
}

// GetMatchCode get match code
func (s *userService) GetMatchCode(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return nil, cusErr
	}
	// Generate match code
	matchCode := utils.GenerateRandomString(8)
	// Store match code to db
	matchData := &database.MatchVerifyData{
		UserID:    user.ID,
		Code:      matchCode,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.MatchCodeExpiration)),
	}
	err = s.repo.InsertOrUpdateMatchVerifyData(ctx, matchData)
	if err != nil {
		s.logger.Error("unable to store match data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	s.logger.Debug("successfully generate & stored match code")
	getMatchCodeResponse := &GetMatchCodeResponse{
		Code:    matchCode,
		Message: fmt.Sprintf("Successfully generated match code. Match code will expire in %d minute or when a new match code is generated.", s.configs.MatchCodeExpiration),
	}
	return getMatchCodeResponse, nil
}

// MatchLover match love
func (s *userService) MatchLover(ctx context.Context, request *MatchLoverRequest) error {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr
	}
	// Check if user has match code
	matchData, err := s.repo.GetMatchVerifyDataByCode(ctx, request.Code)
	if err != nil {
		s.logger.Error("Cannot get match data", "error", err)
		cusErr := utils.NewErrorResponse(utils.MatchCodeIsNotFound)
		return cusErr
	}
	if matchData.Code == "" {
		s.logger.Error("User does not have match code")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Check if match code is expired
	if matchData.ExpiresAt.Before(time.Now()) {
		s.logger.Error("Match code is expired")
		cusErr := utils.NewErrorResponse(utils.MatchCodeIsExpired)
		return cusErr
	}
	// Check if match code is correct
	if matchData.Code != request.Code {
		s.logger.Error("Match code is incorrect")
		cusErr := utils.NewErrorResponse(utils.MatchCodeIsIncorrect)
		return cusErr
	}
	// Check if user has already matched
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User not match", "error", err)
	}
	// Check if user has already matched
	if matchLove.MatchID != "" {
		s.logger.Error("User has already matched")
		cusErr := utils.NewErrorResponse(utils.UserAlreadyMatched)
		return cusErr
	}
	// Match user with new love
	matchLove.UserID = user.ID
	matchLove.MatchID = matchData.UserID
	err = s.repo.InsertOrDeleteMatchLoveData(ctx, matchLove, false)
	if err != nil {
		s.logger.Error("Cannot insert or update match love data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Delete match data
	err = s.repo.DeleteMatchVerifyDataByUserID(ctx, matchData.UserID)
	if err != nil {
		s.logger.Error("Cannot delete match data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("Successfully matched user")
	return nil
}

// UnMatchedLover unmatched lover
func (s *userService) UnMatchedLover(ctx context.Context) error {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return cusErr
	}
	// Check if user has match code
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User does not match with someone", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return cusErr
	}
	if matchLove.MatchID == "" {
		s.logger.Error("User does not match with someone")
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return cusErr
	}
	// Delete match data
	err = s.repo.InsertOrDeleteMatchLoveData(ctx, matchLove, true)
	if err != nil {
		s.logger.Error("Cannot delete match love data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("Successfully unmatch lover")
	return nil
}

// GetMatchLover get lover
func (s *userService) GetMatchLover(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return nil, cusErr
	}
	// Check if user has match code
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User does not match with someone", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return nil, cusErr
	}
	if matchLove.MatchID == "" {
		s.logger.Error("User does not match with someone")
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return nil, cusErr
	}
	// Get lover
	lover, err := s.repo.GetUserByID(ctx, matchLove.MatchID)
	if err != nil {
		s.logger.Error("Cannot get lover", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Check if lover is banned
	if lover.Banned {
		s.logger.Error("Lover is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return nil, cusErr
	}
	s.logger.Debug("Successfully get lover")
	response := GetLoverResponse{
		UserID:   lover.ID,
		Email:    lover.Email,
		Username: lover.Username,
		Verified: lover.Verified,
	}
	return response, nil
}
