package authorization

import (
	"LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"errors"
	"github.com/hashicorp/go-hclog"
	"golang.org/x/crypto/bcrypt"
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
		return "Cannot hash password", err
	}
	user.Password = hashedPassword
	user.TokenHash = utils.GenerateRandomString(15)
	err = s.repo.CreateUser(ctx, &user)
	if err != nil {
		s.logger.Error("Error creating user", "error", err)
		return "Cannot create user", err
	}
	// Send email to user
	authedCode := utils.GenerateRandomString(8)
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
		return "Cannot send mail", errors.New("unable to send mail")
	}
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
		return "Cannot create verification data", errors.New("cannot create verification data")
	}

	// Store user info into Profile database
	profile := database.ProfileData{
		UserID: user.ID,
		Email:  user.Email,
	}
	err = s.repo.StoreProfileData(ctx, &profile)
	if err != nil {
		s.logger.Error("Error storing profile data", "error", err)
		return "Cannot create profile data", errors.New("cannot create profile data")
	}
	return "success created user. Please confirm your email to active your account.", nil
}

//Login authenticates a user.
func (s *userService) Login(ctx context.Context, request *LoginRequest) (interface{}, error) {
	// Get user from database
	user, err := s.repo.GetUserByEmail(ctx, request.Email)
	if err != nil {
		s.logger.Error("Error getting user", "error", err)
		return "Cannot get user", err
	}
	// Check if user is verified
	if !user.Verified {
		s.logger.Error("User is not verified", "error", err)
		//return "User is not verified", err
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		return "User is banned", err
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
		return "You've tried to Sign-in too many times. try again tomorrow", errors.New("you've tried to sign in too many times. try again tomorrow")
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		return "Internal Error, Please Try Again Later.", errors.New("internal Error, Please Try Again Later")
	}

	// Check if password is correct
	if isSame := s.auth.ComparePassword(user.Password, request.Password); !isSame {
		s.logger.Error("Password is incorrect", "error", err)
		return "Password is incorrect. Please try again.", err
	}
	// Generate accessToken
	accessToken, err := s.auth.GenerateAccessToken(user)
	if err != nil {
		s.logger.Error("Error generating accessToken", "error", err)
		return "Internal Error, Please Try Again Later.", err
	}
	// Generate refreshToken
	refreshToken, err := s.auth.GenerateRefreshToken(user)
	if err != nil {
		s.logger.Error("Error generating refreshToken", "error", err)
		return "Internal Error, Please Try Again Later.", err
	}
	// Reset limit data
	limitData.NumOfLogin = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, false)
	if err != nil {
		s.logger.Error("Cannot reset number of login", "error", err)
		return "Internal Error, Please Try Again Later.", errors.New("internal Error, Please Try Again Later")
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
		return err
	}

	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		return err
	}

	// Set new random text for token hash. It will make invalid the previous refreshToken.
	user.TokenHash = utils.GenerateRandomString(15)
	// Generate refreshToken
	refreshToken, err := s.auth.GenerateRefreshToken(user)
	if err != nil {
		s.logger.Error("Error generating refreshToken", "error", err)
		return err
	}
	s.logger.Debug("successfully generated token", "refreshtoken", refreshToken)
	// Update user token hash to database
	err = s.repo.UpdateUser(ctx, user)
	if err != nil {
		s.logger.Error("Error updating user", "error", err)
		return err
	}

	s.logger.Debug("Logout success", "email", request.Email)

	return nil
}

// GetUser returns user.
func (s *userService) GetUser(ctx context.Context) (interface{}, error) {
	userID, ok := ctx.Value(middleware.UserIDKey{}).(string)
	if !ok {
		return nil, errors.New("userID not found")
	}
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		return nil, errors.New("cannot get user")
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		return "User is banned", errors.New("user is banned")
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
		return nil, errors.New("userID not found")
	}
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get profile", "error", err)
		return nil, errors.New("cannot get profile")
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
		return nil, errors.New("userID not found")
	}
	// Get user by id
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		return nil, errors.New("cannot get user")
	}
	// Check if user is banned
	if user.Banned {
		s.logger.Error("User is banned", "error", err)
		return "User is banned", errors.New("user is banned")
	}
	// Get profile by id
	profile, err := s.repo.GetProfileByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get profile", "error", err)
		return nil, errors.New("cannot get profile")
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
		return nil, errors.New("cannot update profile")
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
		return "userID not found", errors.New("userID not found")
	}
	// Get user by id
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get user", "error", err)
		return "cannot get user", errors.New("cannot get user")
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
		return "You've tried to change password too many times. try again tomorrow", errors.New("you've tried to change password too many times. try again tomorrow")
	}
	// Update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
	if err != nil {
		s.logger.Error("Cannot insert or update limit data", "error", err)
		return "Internal Error, Please Try Again Later.", errors.New("internal Error, Please Try Again Later")
	}
	// Compare new password and confirm password
	if request.NewPassword != request.ConfirmPassword {
		s.logger.Error("New password and confirm password are not the same", "error", err)
		return "New password and confirm password are not the same", errors.New("new password and confirm password are not the same")
	}
	// Check if password is correct
	if isSame := s.auth.ComparePassword(user.Password, request.OldPassword); isSame == false {
		s.logger.Error("Password is incorrect", "error", err)
		return "Password is incorrect", errors.New("password is incorrect")
	}
	// Hash new password
	hashedPassword, err := s.hashPassword(request.NewPassword)
	if err != nil {
		s.logger.Error("Cannot hash password", "error", err)
		return "cannot change password", errors.New("cannot hash password")
	}
	// Check hashed password is not contains in list of passwords
	listOfPasswords, err := s.repo.GetListOfPasswords(ctx, userID)
	if err != nil {
		s.logger.Error("Cannot get list of passwords", "error", err)
		return "cannot change passwords", errors.New("cannot get list of passwords")
	}
	for _, password := range listOfPasswords {
		if isSame := s.auth.ComparePassword(password, request.NewPassword); isSame == true {
			s.logger.Error("New password is the same as old password", "error", err)
			return "Password has been used. Please choose another password.", errors.New("password has been used. please choose another password")
		}
	}
	// Update token hash. It makes refresh token tobe invalid.
	tokenHash := utils.GenerateRandomString(15)
	// Update user password
	err = s.repo.UpdatePassword(ctx, userID, hashedPassword, tokenHash)
	if err != nil {
		s.logger.Error("Cannot update password", "error", err)
		return "cannot update password", errors.New("cannot update password")
	}
	// Insert password into list of passwords user
	passwordUsers := &database.PassworUsers{
		UserID:   userID,
		Password: hashedPassword,
	}
	err = s.repo.InsertListOfPasswords(ctx, passwordUsers)
	if err != nil {
		s.logger.Error("Cannot update password into list of passwords", "error", err)
		return "cannot update password into list of passwords", errors.New("cannot update password into list of passwords")
	}
	// Reset limit data
	limitData.NumOfChangePassword = 0
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, false)
	if err != nil {
		s.logger.Error("Cannot delete limit data", "error", err)
		return "cannot delete limit data", errors.New("cannot delete limit data")
	}
	s.logger.Info("Password changed", "userID", userID)
	return "Password changed", nil
}

// hashPassword hashes password.
func (s *userService) hashPassword(password string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("unable to hash password", "error", err)
		return "", err
	}
	return string(hashedPass), nil
}

// GetForgetPasswordCode gets forget password code.
func (s *userService) GetForgetPasswordCode(ctx context.Context, email string) error {
	// Check if email is registered
	user, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		s.logger.Error("Email is not registered", "error", err)
		return errors.New("email is not registered")
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
		return errors.New("successfully mailed password reset code. Please check your email")

	}
	// Insert or update limit data
	err = s.repo.InsertOrUpdateLimitData(ctx, limitData, isInsert)
	if err != nil {
		s.logger.Error("Cannot update limit data", "error", err)
		return errors.New("cannot update limit data")
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

	err = s.repo.StoreVerificationData(ctx, verificationData, false)
	if err != nil {
		s.logger.Error("unable to store password reset verification data", "error", err)
		return errors.New("unable to store password reset verification data")
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
		return errors.New("unable to send mail")
	}
	s.logger.Debug("successfully mailed password reset code")
	return nil
}
