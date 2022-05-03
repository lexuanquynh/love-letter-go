package authorization

import (
	"LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"database/sql"
	"errors"
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
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
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
	isInsert := false
	limitData, err := s.repo.GetLimitData(ctx, user.ID)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
		// No row, need insert
		isInsert = true
		limitData.UserID = user.ID
		limitData.NumOfLogin = 1
	} else {
		limitData.NumOfLogin += 1
	}
	// Check if limit is reached
	if limitData.NumOfLogin > s.configs.LoginLimit {
		s.logger.Error("Verify Mail limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
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
		cusErr := utils.NewErrorResponse(utils.Unauthorized)
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
	limitData.NumOfLogin = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, false)
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
	isInsert := false
	limitData, err := s.repo.GetLimitData(ctx, user.ID)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
		// No row, need insert
		isInsert = true
		limitData.UserID = user.ID
		limitData.NumOfLogin = 1
	} else {
		limitData.NumOfLogin += 1
	}
	// Check if limit is reached
	if limitData.NumOfLogin > s.configs.LoginLimit {
		s.logger.Error("Login limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	// Check if password is correct
	if isSame := s.auth.ComparePassword(user.Password, request.Password); !isSame {
		s.logger.Error("Password is incorrect", "error", err)
		cusErr := utils.NewErrorResponse(utils.Unauthorized)
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
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, false)
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
	s.logger.Debug("successfully generated token", "refreshtoken", refreshToken)
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
	isInsert := false
	limitData, err := s.repo.GetLimitData(ctx, userID)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
		// No row, need insert
		isInsert = true
		limitData.UserID = userID
		limitData.NumOfChangePassword = 1
	} else {
		limitData.NumOfChangePassword += 1
	}
	// Check if limit is reached
	if limitData.NumOfChangePassword > s.configs.ChangePasswordLimit {
		s.logger.Error("Change password limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
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
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, false)
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
	isInsert := false
	limitData, err := s.repo.GetLimitData(ctx, user.ID)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
		// No row, need insert
		isInsert = true
		limitData.UserID = user.ID
		limitData.NumOfSendMail = 1
	} else {
		limitData.NumOfSendMail += 1
	}
	// Check if user has reached limit send mail
	if limitData.NumOfSendMail > s.configs.SendMailLimit {
		s.logger.Error("User has reached limit send mail.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	// Insert or update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
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
	isInsert = false
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
			return utils.NewErrorResponse(utils.PasswordNotMatch)
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
	isInsert := false
	limitData, err := s.repo.GetLimitData(ctx, user.ID)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
		// No row, need insert
		isInsert = true
		limitData.UserID = user.ID
		limitData.NumOfChangePassword = 1
	} else {
		limitData.NumOfChangePassword += 1
	}
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
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
	s.logger.Info("Password changed", "userID", user.ID)
	return nil
}
