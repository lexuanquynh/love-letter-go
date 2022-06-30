package authorization

import (
	"LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"database/sql"
	"fmt"
	"github.com/OneSignal/onesignal-go-client"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/bcrypt"
	"strings"
	"time"
)

type userService struct {
	logger              hclog.Logger
	configs             *utils.Configurations
	repo                database.UserRepository
	mailService         MailService
	auth                middleware.Authentication
	notificationService NotificationService
}

// NewUserService creates a new user service.
func NewUserService(logger hclog.Logger,
	configs *utils.Configurations,
	repo database.UserRepository,
	mailService MailService,
	auth middleware.Authentication,
	notificationService NotificationService) *userService {
	return &userService{
		logger:              logger,
		configs:             configs,
		repo:                repo,
		mailService:         mailService,
		auth:                auth,
		notificationService: notificationService,
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
		Role:     database.UserRoleTypeUser,
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
	authedCode := utils.GenerateRandomNumberString(6)
	// Saving the code authentication into database
	verificationData := database.VerificationData{
		Email:     request.Email,
		Code:      authedCode,
		Type:      database.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	err = s.repo.InsertVerificationData(ctx, &verificationData)
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
	err = s.repo.InsertProfile(ctx, &profile)
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
	// check if user deleted
	if user.Deleted {
		cusErr := utils.NewErrorResponse(utils.UserDeleted)
		return cusErr.Error(), cusErr
	}
	// if user is verified, return success.
	if user.Verified == true {
		return "Email has been successfully verified.", nil
	}
	// Get limit datalo
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeSendVerifyMail)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLimit >= s.configs.LoginLimit {
		s.logger.Error("Verify Mail limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.LimitType = database.LimitTypeSendVerifyMail
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	err = s.repo.InsertLimitData(ctx, limitData)
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
	// Reset limit
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeSendVerifyMail
	err = s.repo.InsertLimitData(ctx, limitData)
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
	// Check if user deleted
	if user.Deleted {
		s.logger.Error("User is deleted", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserDeleted)
		return cusErr.Error(), cusErr
	}

	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeLogin)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLimit >= s.configs.LoginLimit {
		s.logger.Error("Login limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.LimitType = database.LimitTypeLogin
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	err = s.repo.InsertLimitData(ctx, limitData)
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
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeLogin
	err = s.repo.InsertLimitData(ctx, limitData)
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

func (s *userService) commonCheckUserStatus(ctx context.Context, email string) (*database.User, error) {
	// Get user from database
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Error getting user", "error", err)
		if strings.Contains(err.Error(), utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return nil, cusErr
		}
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}

	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return nil, cusErr
	}

	// Check if user is deleted
	if user.Deleted {
		s.logger.Error("User is deleted", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserDeleted)
		return nil, cusErr
	}

	return user, nil
}

func (s *userService) commonCheckUserStatusByUserId(ctx context.Context, userID string) (*database.User, error) {
	// Get user from database
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Error getting user", "error", err)
		if strings.Contains(err.Error(), utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.NotFound)
			return nil, cusErr
		}
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}

	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		cusErr := utils.NewErrorResponse(utils.Forbidden)
		return nil, cusErr
	}

	// Check if user is deleted
	if user.Deleted {
		s.logger.Error("User is deleted", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserDeleted)
		return nil, cusErr
	}

	return user, nil
}

// Logout user. Make refreshToken invalid.
func (s *userService) Logout(ctx context.Context, request *LogoutRequest) error {
	// Common check user status
	user, err := s.commonCheckUserStatus(ctx, request.Email)
	if err != nil {
		return err
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

// DeleteUser deletes a user.
func (s *userService) DeleteUser(ctx context.Context, request *DeleteUserRequest) error {
	// Common check user status
	user, err := s.commonCheckUserStatus(ctx, request.Email)
	if err != nil {
		return err
	}
	// Change user to delete
	user.Deleted = true
	// Update user
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Error updating user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Delete user by InsertSchedule. After 30 days, user really deleted.
	schedule := database.Schedule{
		UserID:         user.ID,
		Name:           database.ScheduleActionTypeDeleteUser,
		ScheduleType:   database.ScheduleTypeAnnually,
		Description:    "Delete user after 30 days",
		Parameter:      "30",
		TimeExecute:    time.Now().AddDate(0, 0, 30),
		RemoveAfterRun: true,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}
	err = s.repo.InsertSchedule(ctx, &schedule)
	if err != nil {
		s.logger.Error("Error inserting schedule", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("User will delete after 30 days", "email", request.Email)
	return nil
}

// CancelDeleteUser cancels delete user.
func (s *userService) CancelDeleteUser(ctx context.Context, request *CancelDeleteUserRequest) error {
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
	// Check if user is not deleted
	if !user.Deleted {
		s.logger.Error("User is not deleted", "error", err)
		cusErr := utils.NewErrorResponse(utils.BadRequest)
		return cusErr
	}

	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeCancelDeleteUser)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if user has reached limit send mail
	if limitData.NumOfLimit >= s.configs.SendMailCancelDeleteLimit {
		s.logger.Error("User has reached limit send mail for cancel delete account.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.LimitType = database.LimitTypeCancelDeleteUser
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	err = s.repo.InsertLimitData(ctx, limitData)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}

	// Generate cancel delete user code
	cancelCode := utils.GenerateRandomNumberString(6)
	// Saving the code into database
	verificationData := database.VerificationData{
		Email:     request.Email,
		Code:      cancelCode,
		Type:      database.CancelDeleteUser,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	err = s.repo.InsertVerificationData(ctx, &verificationData)
	if err != nil {
		s.logger.Error("Error storing verification data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Send email to user
	from := s.configs.MailSender
	to := []string{user.Email}
	subject := s.configs.MailTitle
	mailType := CancelDeleteUser
	mailData := &MailData{
		Username: user.Username,
		Code:     cancelCode,
	}
	mailReq := s.mailService.NewMail(from, to, subject, mailType, mailData)
	err = s.mailService.SendMail(mailReq)
	if err != nil {
		s.logger.Error("unable to send mail", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("Send mail for cancel delete user success", "email", request.Email)
	return nil
}

// ConfirmCancelDeleteUser confirm cancel delete user.
func (s *userService) ConfirmCancelDeleteUser(ctx context.Context, request *ConfirmCancelDeleteUserRequest) error {
	actualVerificationData, err := s.repo.GetVerificationData(ctx, request.Email, database.CancelDeleteUser)
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
	// Change user status to not deleted
	user.Deleted = false
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("unable to update user", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeCancelDeleteUser)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Reset login failed count
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeCancelDeleteUser
	err = s.repo.InsertLimitData(ctx, limitData)
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
	// delete schedule job
	err = s.repo.DeleteSchedule(ctx, user.ID, database.ScheduleActionTypeDeleteUser)
	if err != nil {
		s.logger.Error("unable to delete schedule", "error", err)
		return utils.NewErrorResponse(utils.InternalServerError)
	}
	s.logger.Debug("Confirm cancel delete user success", "email", request.Email)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
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
		errMsg := err.Error()
		if !strings.Contains(errMsg, utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr.Error(), cusErr
		}
	}
	// Make response data
	profileResponse := GetProfileResponse{
		Email:     profile.Email,
		Gender:    profile.Gender,
		Birthday:  profile.Birthday.String(),
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
	}
	// change username to lowercase
	request.Username = strings.ToLower(request.Username)

	// Check if username is already taken
	if exist, err := s.repo.CheckUsernameExists(ctx, request.Username); exist || err != nil {
		s.logger.Error("Username is already taken", "error", err)
		cusErr := utils.NewErrorResponse(utils.ExistUserName)
		return cusErr.Error(), cusErr
	}

	// Update username
	user.Username = strings.ToLower(request.Username)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
	}
	// Get profile by id
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		errMsg := err.Error()
		s.logger.Error("Cannot get profile", "error", err)
		if !strings.Contains(errMsg, utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr.Error(), cusErr
		}
	}
	// Update profile profile
	profile.UserID = user.ID
	profile.Email = user.Email
	if request.Birthday != "" {
		birthday, error := time.Parse("2006-01-02", request.Birthday)

		if error != nil {
			s.logger.Error("Cannot parse birthday", "error", error)
			return nil, error
		}
		profile.Birthday = birthday
	}
	profile.Gender = request.Gender

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
	err = s.repo.InsertProfile(ctx, profile)
	if err != nil {
		s.logger.Error("Cannot update profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}
	// Make response data
	profileResponse := GetProfileResponse{
		Email:     profile.Email,
		Birthday:  profile.Birthday.String(),
		Gender:    profile.Gender,
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
	}
	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, userID, database.LimitTypeChangePassword)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLimit >= s.configs.ChangePasswordLimit {
		s.logger.Error("Change password limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	limitData.LimitType = database.LimitTypeChangePassword
	err = s.repo.InsertLimitData(ctx, limitData)
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
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeChangePassword
	err = s.repo.InsertLimitData(ctx, limitData)
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
	if limitData.NumOfLimit >= s.configs.SendMailResetPasswordLimit {
		s.logger.Error("User has reached limit send mail.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	//  Update limit data
	limitData.UserID = user.ID
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	limitData.LimitType = database.LimitTypeSendPassResetMail
	err = s.repo.InsertLimitData(ctx, limitData)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Generate forget password code
	forgetPasswordCode := utils.GenerateRandomNumberString(6)

	// store the password reset code to db
	verificationData := &database.VerificationData{
		Email:     user.Email,
		Code:      forgetPasswordCode,
		Type:      database.PassReset,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.PassResetCodeExpiration)),
	}

	err = s.repo.InsertVerificationData(ctx, verificationData)
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
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeLogin)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Reset login failed count
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeLogin
	err = s.repo.InsertLimitData(ctx, limitData)
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
	limitData.UserID = user.ID
	limitData.NumOfLimit = 0
	limitData.LimitType = database.LimitTypeSendPassResetMail
	err = s.repo.InsertLimitData(ctx, limitData)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err
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
	if limitData.NumOfLimit >= s.configs.SendMailVerifyLimit {
		s.logger.Error("User has reached limit send mail.", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr

	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.LimitType = database.LimitTypeSendVerifyMail
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	err = s.repo.InsertLimitData(ctx, limitData)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Generate forget password code
	forgetPasswordCode := utils.GenerateRandomNumberString(6)

	// store the password reset code to db
	verificationData := &database.VerificationData{
		Email:     user.Email,
		Code:      forgetPasswordCode,
		Type:      database.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	// Insert verification data
	err = s.repo.InsertVerificationData(ctx, verificationData)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Check user is in relationship
	lover, _ := s.GetMatchLover(ctx)
	if lover != nil {
		s.logger.Error("User is in a relationship")
		cusErr := utils.NewErrorResponse(utils.UserInRelationship)
		return nil, cusErr
	}
	// Generate number match code
	matchCode := utils.GenerateRandomNumberString(6)
	// Store match code to db
	matchData := &database.MatchVerifyData{
		UserID:    user.ID,
		Email:     user.Email,
		Code:      matchCode,
		ExpiresAt: time.Now().Add(time.Minute * time.Duration(s.configs.MatchCodeExpiration)),
	}
	err = s.repo.InsertMatchVerifyData(ctx, matchData)
	if err != nil {
		s.logger.Error("unable to store match data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	s.logger.Debug("successfully generate & stored match code")
	getMatchCodeResponse := &GetMatchCodeResponse{
		Code:    matchCode,
		Minutes: s.configs.MatchCodeExpiration,
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err
	}
	// Check if user has already matched
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err == nil {
		s.logger.Error("User are in a relationship")
		cusErr := utils.NewErrorResponse(utils.UserAlreadyMatched)
		return cusErr
	}
	s.logger.Info("User not match", "error", err)
	// Check match code is exactly match
	matchData, err := s.repo.GetMatchVerifyDataByCode(ctx, request.Code)
	if err != nil {
		s.logger.Error("Cannot get match data", "error", err)
		cusErr := utils.NewErrorResponse(utils.MatchCodeIsNotExactly)
		return cusErr
	}
	// check mathId need different user id
	if matchData.UserID == user.ID {
		s.logger.Error("User cannot match with himself")
		cusErr := utils.NewErrorResponse(utils.UserCannotMatchWithHimself)
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
	// Match user with new love
	matchLove.UserID1 = user.ID
	matchLove.UserID2 = matchData.UserID
	matchLove.Accept1 = database.MatchLoverStateAccept
	matchLove.Accept2 = database.MatchLoverStateNone
	matchLove.Email1 = user.Email
	matchLove.Email2 = matchData.Email
	matchLove.StartDate = time.Now()

	err = s.repo.InsertMatchLoveData(ctx, matchLove)
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
	// Send notification to matched user
	var viContent = "💌 💕Có một người đã phải lòng bạn❤😘"
	contents := onesignal.StringMap{
		En: "💌 💕Someone has a crush on you❤😘",
		Vi: &viContent,
	}
	data := map[string]interface{}{
		"userid": matchLove.UserID1,
		"email":  matchLove.Email1,
	}
	// get playerData of matched user
	playerData, err := s.repo.GetPlayerData(ctx, matchLove.UserID2)
	// if user not enable notification, skip
	if err != nil {
		s.logger.Error("Cannot get player data", "error", err)
		return nil
	}
	notificationData := NotificationData{
		PlayerID: playerData.PlayerId,
		Message:  contents,
		Data:     data,
	}
	s.logger.Info("Sending notification to user")
	s.notificationService.SendNotification(ctx, &notificationData)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err
	}
	// Check if user has match code
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User does not match with someone", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return cusErr
	}
	if matchLove.UserID2 == "" {
		s.logger.Error("User does not match with someone")
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return cusErr
	}
	// Delete match data
	err = s.repo.DeleteMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("Cannot delete match love data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("Successfully unmatched lover")
	// Send notification to matched user
	var viContent = "Rất tiếc! Người ấy đã từ chối kết nối với bạn😔"
	var enContent = "Sorry! Someone declined connect with you😔"

	contents := onesignal.StringMap{
		En: enContent,
		Vi: &viContent,
	}
	data := map[string]interface{}{
		"userid": matchLove.UserID1,
		"email":  matchLove.Email1,
	}
	// get playerData of matched user
	playerData, err := s.repo.GetPlayerData(ctx, matchLove.UserID2)
	// if user not enable notification, skip
	if err != nil {
		s.logger.Error("Cannot get player data", "error", err)
		return nil
	}
	notificationData := NotificationData{
		PlayerID: playerData.PlayerId,
		Message:  contents,
		Data:     data,
	}
	s.logger.Info("Sending notification to user")
	s.notificationService.SendNotification(ctx, &notificationData)
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
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err.Error(), err
	}
	// Check if user has match code
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User does not match with someone", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return nil, cusErr
	}
	// Get lover
	requestID := ""
	if matchLove.UserID1 == user.ID {
		requestID = matchLove.UserID2
	} else {
		requestID = matchLove.UserID1
	}
	lover, err := s.repo.GetUserByID(ctx, requestID)
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
	// Get user1's profile
	userInfor1, err := s.repo.GetProfileByID(ctx, matchLove.UserID1)
	if err != nil {
		s.logger.Error("Cannot get lover's profile", "error", err)
		errMsg := err.Error()
		if !strings.Contains(errMsg, utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}
	}
	// Get user2's profile
	userInfor2, err := s.repo.GetProfileByID(ctx, matchLove.UserID2)
	if err != nil {
		s.logger.Error("Cannot get user's profile", "error", err)
		errMsg := err.Error()
		if !strings.Contains(errMsg, utils.PgNoRowsMsg) {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}
	}
	response := GetMatchLoverResponse{
		userid1:   matchLove.UserID1,
		userid2:   matchLove.UserID2,
		Email1:    matchLove.Email1,
		Email2:    matchLove.Email2,
		Accept1:   matchLove.Accept1,
		Accept2:   matchLove.Accept2,
		FullName1: userInfor1.FirstName,
		FullName2: userInfor2.FirstName,
		Birthday1: userInfor1.Birthday.Format("2006-01-02"),

		Birthday2: userInfor2.Birthday.Format("2006-01-02"),
		Gender1:   userInfor1.Gender,
		Gender2:   userInfor2.Gender,
		StartDate: matchLove.StartDate.Format("2006-01-02"),
	}
	return response, nil
}

// ConfirmMatchLover accept lover
func (s *userService) ConfirmMatchLover(ctx context.Context, request *AcceptMatchLoverRequest) error {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err
	}
	// Check if user has match code
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("User does not match with someone", "error", err)
		cusErr := utils.NewErrorResponse(utils.UserNotMatch)
		return cusErr
	}
	// Update match love
	if matchLove.UserID1 == user.ID {
		matchLove.Accept1 = request.Accept
	} else {
		matchLove.Accept2 = request.Accept
	}
	s.logger.Debug("Successfully accept lover")
	// if lover reject match
	if request.Accept == database.MatchLoverStateReject {
		// Delete match love
		err = s.repo.DeleteMatchLoveDataByUserID(ctx, matchLove.UserID1)
		if err != nil {
			s.logger.Error("Cannot delete match love", "error", err)
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr
		}
		s.logger.Debug("Successfully delete match love")
		// Delete user state data
		err = s.repo.DeleteUserStateData(ctx, user.ID, database.MatchLoverStateKey)
		if err != nil {
			s.logger.Error("Cannot delete user state", "error", err)
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr
		}
	} else if request.Accept == database.MatchLoverStateAccept {
		// lover accept match
		err = s.repo.InsertMatchLoveData(ctx, matchLove)
		if err != nil {
			s.logger.Error("Cannot update match love", "error", err)
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr
		}
	}
	s.logger.Info("Successfully accept lover")
	// Send notification to lover
	var viContent = "💌 💕Có một người đã phải lòng bạn❤😘"
	var enContent = "💌 💕Someone has a crush on you❤😘"
	if request.Accept == database.MatchLoverStateReject {
		viContent = "Rất tiếc! Người ấy đã từ chối lời đề nghị kết nối với bạn😔"
		enContent = "Sorry! Someone declined your offer to connect with you😔"
	} else if request.Accept == database.MatchLoverStateAccept {
		viContent = "Xin chúc mừng! Hai bạn đã kết nối thành công!❤😘"
		enContent = "Congratulations! You are now connected!❤😘"
	}
	contents := onesignal.StringMap{
		En: enContent,
		Vi: &viContent,
	}
	data := map[string]interface{}{
		"userid": matchLove.UserID1,
		"email":  matchLove.Email1,
	}
	// get playerData of matched user
	playerData, err := s.repo.GetPlayerData(ctx, matchLove.UserID1)
	// if user not enable notification, skip
	if err != nil {
		s.logger.Error("Cannot get player data", "error", err)
		return nil
	}
	notificationData := NotificationData{
		PlayerID: playerData.PlayerId,
		Message:  contents,
		Data:     data,
	}
	s.logger.Info("Sending notification to user")
	s.notificationService.SendNotification(ctx, &notificationData)

	return nil
}

// InsertPlayerData save player data
func (s *userService) InsertPlayerData(ctx context.Context, request *InsertPlayerDataRequest) error {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return err
	}
	// Create player data for insert
	insertPlayerData := database.PlayerData{
		UserID:         user.ID,
		UUID:           request.UUID,
		PlayerId:       request.PlayerID,
		DeviceName:     request.DeviceName,
		DeviceVersion:  request.DeviceVersion,
		DeviceModel:    request.DeviceModel,
		DeviceOS:       request.DeviceOS,
		DeviceLocalize: request.DeviceLocalize,
	}
	// Insert player data
	err = s.repo.InsertPlayerData(ctx, &insertPlayerData)
	if err != nil {
		s.logger.Error("Cannot insert player data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr
	}
	s.logger.Debug("Successfully update player data")
	return nil
}

// GetPlayerData get player data
func (s *userService) GetPlayerData(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get player data
	playerData, err := s.repo.GetPlayerData(ctx, user.ID)
	if err != nil {
		s.logger.Error("Cannot get player data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	s.logger.Debug("Successfully get player data")
	response := GetPlayerDataResponse{
		UserID:         playerData.UserID,
		PlayerID:       playerData.UUID,
		DeviceName:     playerData.DeviceName,
		DeviceVersion:  playerData.DeviceVersion,
		DeviceModel:    playerData.DeviceModel,
		DeviceOS:       playerData.DeviceOS,
		DeviceLocalize: playerData.DeviceLocalize,
	}
	return response, nil
}

// GetUserStateData get user state data by userID and keyString
func (s *userService) GetUserStateData(ctx context.Context, request *GetUserStateDataRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get user state data
	userStateData, err := s.repo.GetUserStateData(ctx, user.ID, request.KeyString)
	if err != nil {
		// if sql: no rows in result s
		if err.Error() == "sql: no rows in result set" {
			s.logger.Debug("User state data not found")
			response := GetUserStateDataResponse{
				KeyString: request.KeyString,
				UserID:    user.ID,
			}
			return response, nil
		}

		s.logger.Error("Cannot get user state data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	s.logger.Debug("Successfully get user state data")
	response := GetUserStateDataResponse{
		UserID:      userStateData.UserID,
		KeyString:   userStateData.KeyString,
		StringValue: userStateData.StringValue,
		IntValue:    userStateData.IntValue,
		FloatValue:  userStateData.FloatValue,
		BoolValue:   userStateData.BoolValue,
		TimeValue:   userStateData.TimeValue,
	}
	return response, nil
}

// SetUserStateData set user state data
func (s *userService) SetUserStateData(ctx context.Context, request *SetUserStateDataRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	var timeValue time.Time

	if request.TimeValue != "" {
		timeValue, err = time.Parse("2006-01-02", request.TimeValue)
		if err != nil {
			s.logger.Error("Cannot parse birthday", "error", err)
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
	}

	// Set user state data
	setUserStateData := database.UserStateData{
		UserID:      user.ID,
		KeyString:   request.KeyString,
		StringValue: request.StringValue,
		IntValue:    request.IntValue,
		FloatValue:  request.FloatValue,
		BoolValue:   request.BoolValue,
		TimeValue:   timeValue,
	}
	err = s.repo.InsertUserStateData(ctx, &setUserStateData)
	if err != nil {
		s.logger.Error("Cannot set user state data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	s.logger.Debug("Successfully set user state data")
	return nil, nil
}

// GetFeeds get feeds
func (s *userService) GetFeeds(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	//Get feeds
	//Create slice for feeds
	var feeds []Feed
	// Build 1: Build CodeComponent & FillMatchComponent show when user not match with other user
	// Check user is in relationship
	matchResponse, _ := s.GetMatchLover(ctx)
	index := 0
	if matchResponse == nil {
		// If user not in relationship, append codeComponent & FillMatchComponent into feeds
		codeComponent := Feed{
			Index: index,
			Type:  "CodeComponent",
			Data:  "",
		}
		index++
		fillMatchComponent := Feed{
			Index: index,
			Type:  "FillMatchComponent",
			Data:  "",
		}
		feeds = append(feeds, codeComponent)
		feeds = append(feeds, fillMatchComponent)
	} else {
		// If user not answer match
		matchloveResponse, ok := matchResponse.(GetMatchLoverResponse)
		if !ok {
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return nil, cusErr
		}
		// Map data from GetMatchLoverResponse
		matchInfo := database.MatchLoveData{
			UserID1: matchloveResponse.userid1,
			UserID2: matchloveResponse.userid2,
			Email1:  matchloveResponse.Email1,
			Email2:  matchloveResponse.Email2,
			Accept1: matchloveResponse.Accept1,
			Accept2: matchloveResponse.Accept2,
		}
		// Check if user request confirm and waiting for response from other user
		if matchInfo.UserID1 == userID && matchInfo.Accept1 == database.MatchLoverStateAccept && matchInfo.Accept2 == database.MatchLoverStateNone {
			rejectComponent := Feed{
				Index: index,
				Type:  "RejectComponent",
				Data:  nil,
			}
			index++
			feeds = append(feeds, rejectComponent)
		} else if matchInfo.UserID2 == userID && matchInfo.Accept2 == database.MatchLoverStateNone {
			// if user 2 not accept yet
			confirmComponent := Feed{
				Index: index,
				Type:  "ConfirmComponent",
				Data:  nil,
			}
			index++
			feeds = append(feeds, confirmComponent)
		} else {
			if matchInfo.Accept1 == database.MatchLoverStateAccept && matchInfo.Accept2 == database.MatchLoverStateAccept {
				// if user 1 and 2 accept, append BeenComponent & LetterComponent && TodayComponent into feeds
				beenComponent := Feed{
					Index: index,
					Type:  "BeenComponent",
					Data:  nil,
				}
				index++
				letterComponent := Feed{
					Index: index,
					Type:  "LetterComponent",
					Data:  nil,
				}
				index++
				todayComponent := Feed{
					Index: index,
					Type:  "TodayComponent",
					Data:  nil,
				}
				index++
				feeds = append(feeds, beenComponent)
				feeds = append(feeds, letterComponent)
				feeds = append(feeds, todayComponent)
			}
		}

	}

	response := map[string]interface{}{"components": feeds}
	return response, nil
}

// UpdateBeenLove update been love
func (s *userService) UpdateBeenLove(ctx context.Context, request *UpdateBeenLoveRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Check if user is in relationship
	matchResponse, _ := s.GetMatchLover(ctx)
	if matchResponse == nil {
		// If user not in relationship, return error
		cusErr := utils.NewErrorResponse(utils.BadRequest)
		return nil, cusErr
	}
	// Get profile of user
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Fill profile
	profile.FirstName = request.FirstName
	profile.LastName = request.LastName
	profile.Gender = request.Gender
	// convert birthday string to time
	if request.Birthday != "" {
		birthday, error := time.Parse("2006-01-02", request.Birthday)
		if error != nil {
			s.logger.Error("Cannot parse birthday", "error", error)
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		profile.Birthday = birthday
	}
	// Update first name, last name, gender and birthday by InsertProfile API
	err = s.repo.InsertProfile(ctx, profile)
	if err != nil {
		s.logger.Error("Cannot update profile", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Confirm if user has already matched
	matchLove, err := s.repo.GetMatchLoveDataByUserID(ctx, user.ID)
	if err != nil {
		s.logger.Error("Cannot get match love data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Convert start date string to time
	startDate, error := time.Parse("2006-01-02", request.StartDate)
	if error != nil {
		s.logger.Error("Cannot parse start day", "error", error)
		cusErr := utils.NewErrorResponse(utils.BadRequest)
		return nil, cusErr
	}
	// Update start date by InsertMatchLoveData API
	matchLove.StartDate = startDate
	err = s.repo.InsertMatchLoveData(ctx, matchLove)
	if err != nil {
		s.logger.Error("Cannot update match love data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Update been love success
	s.logger.Info("Update been love success")
	return matchLove, nil
}

// CheckPassCodeStatus check pass code status
func (s *userService) CheckPassCodeStatus(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	passCodeStatus := true
	if len(user.PassCode) == 0 {
		// If user not have pass code, return false
		passCodeStatus = false
	}
	response := map[string]interface{}{"passCodeStatus": passCodeStatus}
	return response, nil
}

// SetPassCode set pass code
func (s *userService) SetPassCode(ctx context.Context, request *SetPassCodeRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Hash passcode before saving
	passCode, err := utils.HashString(request.PassCode)
	if err != nil {
		s.logger.Error("Cannot hash passcode", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Update pass code by InsertUser API
	user.PassCode = passCode
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Cannot update user", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Update pass code success
	s.logger.Info("Update pass code success")
	return "Update pass code success", nil
}

// ComparePassCode compare pass code
func (s *userService) ComparePassCode(ctx context.Context, request *ComparePassCodeRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Get limit data
	limitData, err := s.repo.GetLimitData(ctx, user.ID, database.LimitTypeComparePassCode)
	if err != nil {
		s.logger.Error("Empty row get limit data", "error", err)
	}
	// Check if limit is reached
	if limitData.NumOfLimit >= s.configs.CheckPassCodeLimit {
		s.logger.Error("Verify Mail limit reached", "error", err)
		cusErr := utils.NewErrorResponse(utils.TooManyRequests)
		return cusErr.Error(), cusErr
	}
	// Update limit data
	limitData.UserID = user.ID
	limitData.LimitType = database.LimitTypeComparePassCode
	limitData.NumOfLimit = limitData.NumOfLimit + 1
	err = s.repo.InsertLimitData(ctx, limitData)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return cusErr.Error(), cusErr
	}

	isCorrect := true
	// Check if user have pass code
	if len(user.PassCode) == 0 {
		s.logger.Error("User not have pass code", "error", err)
		isCorrect = false
	}
	// Check if passcode is correct
	if isSame := s.auth.ComparePassword(user.PassCode, request.PassCode); !isSame {
		s.logger.Error("Password is incorrect", "error", err)
		isCorrect = false
	}

	// Reset limit data
	if isCorrect {
		limitData.UserID = user.ID
		limitData.LimitType = database.LimitTypeComparePassCode
		limitData.NumOfLimit = 0
		err = s.repo.InsertLimitData(ctx, limitData)
		if err != nil {
			s.logger.Error("Cannot insert or update limit data", "error", err)
			cusErr := utils.NewErrorResponse(utils.InternalServerError)
			return cusErr.Error(), cusErr
		}
	}

	// Return response
	response := map[string]interface{}{"isCorrect": isCorrect}
	return response, nil
}

// CreateLetter create letter
func (s *userService) CreateLetter(ctx context.Context, request *CreateLetterRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// get aes key from database
	aeskeyInDatabase, err := s.repo.GetAESKey(ctx, user.ID)
	aesKey := ""
	if err != nil {
		s.logger.Error("Cannot get aes key", "error", err)
		// no key data found. create a new key
		// generate aes key with 32 bits
		aesKey = utils.GenerateRandomNumberAndString(32)
		// save key to database
		newAESData := database.AESKey{
			UserID:    user.ID,
			KeyString: aesKey,
		}
		err = s.repo.CreateAESKey(ctx, &newAESData)
		if err != nil {
			return nil, utils.NewErrorResponse(utils.InternalServerError)
		}
	} else {
		aesKey = aeskeyInDatabase
	}

	// using aes encryption to encrypt data
	// encrypt title
	title, err := utils.EncryptAES(request.Title, aesKey)
	if err != nil {
		s.logger.Error("Cannot encrypt title", "error", err)
		return nil, err
	}
	// encrypt body
	body, err := utils.EncryptAES(request.Body, aesKey)
	if err != nil {
		s.logger.Error("Cannot encrypt body", "error", err)
		return nil, err
	}
	// Create letter
	letter := &database.Letter{
		UserID: user.ID,
		Title:  title,
		Body:   body,
	}
	err = s.repo.CreateLetter(ctx, letter)
	if err != nil {
		s.logger.Error("Cannot create letter", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Create letter success
	s.logger.Info("Create letter success")
	return "Create letter success", nil
}

// DeleteLetter delete letter
func (s *userService) DeleteLetter(ctx context.Context, request *DeleteLetterRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Delete letter
	err = s.repo.DeleteLetter(ctx, user.ID, request.LetterID)
	if err != nil {
		s.logger.Error("Cannot delete letter", "error", err)
		cusErr := utils.NewErrorResponse(utils.NotFound)
		return nil, cusErr
	}
	// Delete letter success
	s.logger.Info("Delete letter success")
	return "Delete letter success", nil
}

// GetLetters get letters
func (s *userService) GetLetters(ctx context.Context, request *GetLettersRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get letters
	letters, err := s.repo.GetLetters(ctx, user.ID, request.Page, request.Limit)
	if err != nil {
		s.logger.Error("Cannot get letters", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Get letters success
	s.logger.Info("Get letters success")

	// get AES key from database
	aeskeyInDatabase, err := s.repo.GetAESKey(ctx, user.ID)
	if err != nil {
		s.logger.Error("Cannot get aes key", "error", err)
		// return empty list
		var responses []GetLettersResponse
		return responses, nil
	}
	var responses []GetLettersResponse
	for i := 0; i < len(letters); i++ {
		// decrypt title
		title, err := utils.DecryptAES(letters[i].Title, aeskeyInDatabase)
		if err != nil {
			s.logger.Error("Cannot decrypt title", "error", err)
			return nil, err
		}
		response := GetLettersResponse{
			ID:        letters[i].ID,
			Title:     title,
			IsRead:    letters[i].IsRead,
			IsDelete:  letters[i].IsDelete,
			TimeOpen:  letters[i].TimeOpen,
			CreatedAt: letters[i].CreatedAt,
			UpdatedAt: letters[i].UpdatedAt,
		}
		responses = append(responses, response)
	}
	return responses, nil
}

// GetLetter get letter
func (s *userService) GetLetter(ctx context.Context, request *GetLetterRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	user, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get letter
	letter, err := s.repo.GetLetter(ctx, user.ID, request.LetterID)
	if err != nil {
		s.logger.Error("Cannot get letter", "error", err)
		cusErr := utils.NewErrorResponse(utils.NotFound)
		return nil, cusErr
	}
	// Get letter success
	s.logger.Info("Get letter success")
	// get AESKey from database
	aeskeyInDatabase, err := s.repo.GetAESKey(ctx, user.ID)
	if err != nil {
		s.logger.Error("Error getting aes key", "error", err)
		// return
		return nil, err
	}

	// decrypt title
	title, err := utils.DecryptAES(letter.Title, aeskeyInDatabase)
	if err != nil {
		s.logger.Error("Cannot decrypt title", "error", err)
		return nil, err
	}

	// decrypt body
	body, err := utils.DecryptAES(letter.Body, aeskeyInDatabase)
	if err != nil {
		s.logger.Error("Cannot decrypt body", "error", err)
		return nil, err
	}
	response := GetLettersResponse{
		ID:        letter.ID,
		Title:     title,
		Body:      body,
		IsRead:    letter.IsRead,
		IsDelete:  letter.IsDelete,
		TimeOpen:  letter.TimeOpen,
		CreatedAt: letter.CreatedAt,
		UpdatedAt: letter.UpdatedAt,
	}
	return response, nil
}

// InsertPsychology insert psychology
func (s *userService) InsertPsychology(ctx context.Context, request *InsertPsychologyRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	psychology := &database.Psychology{
		Title:       request.Title,
		Description: request.Description,
		Level:       request.Level,
	}
	err = s.repo.InsertPsychology(ctx, psychology)
	if err != nil {
		s.logger.Error("Cannot insert psychology", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Insert psychology success
	s.logger.Info("Insert psychology success")
	return "Insert psychology success", nil
}

// DeletePsychology delete psychology
func (s *userService) DeletePsychology(ctx context.Context, request *DeletePsychologyRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Delete psychology
	err = s.repo.DeletePsychology(ctx, request.PsychologyID)
	if err != nil {
		s.logger.Error("Cannot delete psychology", "error", err)
		cusErr := utils.NewErrorResponse(utils.NotFound)
		return nil, cusErr
	}
	// Delete psychology success
	s.logger.Info("Delete psychology success")
	return "Delete psychology success", nil
}

// GetPsychologies get psychologies
func (s *userService) GetPsychologies(ctx context.Context, request *GetPsychologiesRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get psychologies
	psychologies, err := s.repo.GetPsychologies(ctx, request.Limit, request.Page)
	if err != nil {
		s.logger.Error("Cannot get psychologies", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Get psychologies success
	s.logger.Info("Get psychologies success")
	return psychologies, nil

}

// CreateHoliday create holiday
func (s *userService) CreateHoliday(ctx context.Context, request *CreateHolidayRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}

	holiday := &database.Holiday{
		UserID:      userID,
		Title:       request.Title,
		Description: request.Description,
	}

	if request.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", request.StartDate)
		if err != nil {
			s.logger.Error("Cannot parse birthday", "error", err)
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		holiday.StartDate = startDate
	}
	if request.EndDate != "" {
		endDate, err := time.Parse("2006-01-02", request.EndDate)
		if err != nil {
			s.logger.Error("Cannot parse birthday", "error", err)
			cusErr := utils.NewErrorResponse(utils.BadRequest)
			return nil, cusErr
		}
		holiday.EndDate = endDate
	}
	err = s.repo.CreateHoliday(ctx, holiday)
	if err != nil {
		s.logger.Error("Cannot create holiday", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Create holiday success
	s.logger.Info("Create holiday success")
	return "Create holiday success", nil
}

// DeleteHoliday delete holiday
func (s *userService) DeleteHoliday(ctx context.Context, request *DeleteHolidayRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Delete holiday
	err = s.repo.DeleteHoliday(ctx, request.HolidayID)
	if err != nil {
		s.logger.Error("Cannot delete holiday", "error", err)
		cusErr := utils.NewErrorResponse(utils.NotFound)
		return nil, cusErr
	}
	// Delete holiday success
	s.logger.Info("Delete holiday success")
	return "Delete holiday success", nil
}

// GetHolidays get holidays
func (s *userService) GetHolidays(ctx context.Context, request *GetHolidaysRequest) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		s.logger.Error("Error getting userID from context")
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Common check user status
	_, err := s.commonCheckUserStatusByUserId(ctx, userID)
	if err != nil {
		return nil, err
	}
	// Get holidays
	holidays, err := s.repo.GetHolidays(ctx, request.Limit, request.Page)
	if err != nil {
		s.logger.Error("Cannot get holidays", "error", err)
		cusErr := utils.NewErrorResponse(utils.InternalServerError)
		return nil, cusErr
	}
	// Get holidays success
	s.logger.Info("Get holidays success")
	return holidays, nil
}
