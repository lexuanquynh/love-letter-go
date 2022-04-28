package authorization

import (
	"LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization/middleware"
	"context"
	"github.com/hashicorp/go-hclog"
	"time"
)

type userService struct {
	logger      hclog.Logger
	configs     *utils.Configurations
	repo        database.UserRepository
	mailService MailService
	validator   *database.Validation
	auth        middleware.Authentication
}

// NewUserService creates a new user service.
func NewUserService(logger hclog.Logger,
	configs *utils.Configurations,
	repo database.UserRepository,
	mailService MailService,
	validator *database.Validation,
	auth middleware.Authentication) *userService {
	return &userService{
		logger:      logger,
		configs:     configs,
		repo:        repo,
		mailService: mailService,
		validator:   validator,
		auth:        auth,
	}
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
		return "Cannot send mail", err
	}
	// Saving the code authentication into database
	verificationData := database.VerificationData{
		Email:       request.Email,
		Code:        authedCode,
		Type:        database.MailConfirmation,
		ExpiresAt:   time.Now().Add(time.Hour * time.Duration(s.configs.MailVerifCodeExpiration)),
		Numofresets: 1,
	}
	err = s.repo.StoreVerificationData(ctx, &verificationData)
	if err != nil {
		s.logger.Error("Error storing verification data", "error", err)
		return "Cannot create verification data", err
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
	// Check if password is correct
	if err := s.auth.ComparePassword(user.Password, request.Password); err != nil {
		s.logger.Error("Password is incorrect", "error", err)
		return "Password is incorrect", err
	}
	// Generate accessToken
	accessToken, err := s.auth.GenerateAccessToken(user)
	if err != nil {
		s.logger.Error("Error generating accessToken", "error", err)
		return "Cannot generate accessToken", err
	}
	// Generate refreshToken
	refreshToken, err := s.auth.GenerateRefreshToken(user)
	if err != nil {
		s.logger.Error("Error generating refreshToken", "error", err)
		return "Cannot generate refreshToken", err
	}
	s.logger.Debug("successfully generated token", "accesstoken", accessToken, "refreshtoken", refreshToken)
	loginResponse := LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}
	return loginResponse, nil
}
