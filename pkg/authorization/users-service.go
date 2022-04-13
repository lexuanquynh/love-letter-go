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
	// Skip send email here
	// Now we save the code authentication into database
	authedCode := utils.GenerateRandomString(8)
	verificationData := database.VerificationData{
		Email:     request.Email,
		Code:      authedCode,
		Type:      database.MailConfirmation,
		ExpiresAt: time.Now().Add(time.Hour * time.Duration(s.configs.MailVerifCodeExpiration)),
	}
	err = s.repo.StoreVerificationData(ctx, &verificationData)
	if err != nil {
		s.logger.Error("Error storing verification data", "error", err)
		return "Cannot create verification data", err
	}

	return "success created user", nil
}
