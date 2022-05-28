package authorization

import (
	utils "LoveLetterProject/internal"
	"context"
	onesignal "github.com/OneSignal/onesignal-go-client"
	"github.com/hashicorp/go-hclog"
)

// NotificationData is the data that is sent to the notification service
type NotificationData struct {
	PlayerID string
	Message  onesignal.StringMap
	Data     map[string]interface{}
}

// NotificationService provides access to the notification API.
type NotificationService interface {
	CreateNotification() *onesignal.Notification
	SendNotification(ctx context.Context, notification *NotificationData) error
}

// OneSignalService provides access to the OneSignal API.
type OneSignalService struct {
	logger  hclog.Logger
	configs *utils.Configurations
}

// NewOneSignalService returns a new OneSignalService.
func NewOneSignalService(logger hclog.Logger, configs *utils.Configurations) *OneSignalService {
	return &OneSignalService{
		logger:  logger,
		configs: configs,
	}
}

// CreateNotification create a notification to the OneSignal API.
func (s *OneSignalService) CreateNotification() *onesignal.Notification {
	client := *onesignal.NewNotification(s.configs.OneSignalAppId)
	return &client
}

// SendNotification sends a notification to the OneSignal API.
func (s *OneSignalService) SendNotification(ctx context.Context, notification *NotificationData) error {
	client := s.CreateNotification()
	client.SetContents(notification.Message)
	client.SetData(notification.Data)
	client.IncludeIosTokens = []string{notification.PlayerID}
	configuration := onesignal.NewConfiguration()
	apiClient := onesignal.NewAPIClient(configuration)
	appAuth := context.WithValue(ctx, onesignal.AppAuth, s.configs.OneSignalAPIKey)
	resp, r, err := apiClient.DefaultApi.CreateNotification(appAuth).Notification(*client).Execute()
	if err != nil {
		s.logger.Error("Error sending notification", "error", err)
		s.logger.Error("Full HTTP response:", "response", r)
		return err
	}
	// response from `CreateNotification`: InlineResponse200
	s.logger.Info("Notification sent", "response", resp)
	return nil
}
