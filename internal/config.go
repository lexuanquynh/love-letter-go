package utils

import (
	"github.com/hashicorp/go-hclog"
	"github.com/spf13/viper"
	"log"
)

// Configurations wraps all the config variables required by the auth service
type Configurations struct {
	//ServerAddress              string `mapstructure:"SERVER_ADDRESS"`
	DBHost                     string `mapstructure:"DB_HOST"`
	DBName                     string `mapstructure:"DB_NAME"`
	DBUser                     string `mapstructure:"DB_USER"`
	DBPass                     string `mapstructure:"DB_PASSWORD"`
	DBPort                     string `mapstructure:"DB_PORT"`
	DBConn                     string
	JwtExpiration              int    `mapstructure:"JWT_EXPIRATION"` // in minutes
	AccessTokenPrivateKeyPath  string `mapstructure:"ACCESS_TOKEN_PRIVATE_KEY_PATH"`
	AccessTokenPublicKeyPath   string `mapstructure:"ACCESS_TOKEN_PUBLIC_KEY_PATH"`
	RefreshTokenPrivateKeyPath string `mapstructure:"REFRESH_TOKEN_PRIVATE_KEY_PATH"`
	RefreshTokenPublicKeyPath  string `mapstructure:"REFRESH_TOKEN_PUBLIC_KEY_PATH"`
	SendGridApiKey             string `mapstructure:"SENDGRID_API_KEY"`
	MailVerifCodeExpiration    int    `mapstructure:"MAIL_VERIFICATION_CODE_EXPIRATION"` // in hours
	PassResetCodeExpiration    int    `mapstructure:"PASSWORD_RESET_CODE_EXPIRATION"`    // in minutes
	MailVerifTemplateID        string `mapstructure:"MAIL_VERIFICATION_TEMPLATE_ID"`
	PassResetTemplateID        string `mapstructure:"PASSWORD_RESET_TEMPLATE_ID"`
	MailSender                 string `mapstructure:"MAIL_SENDER"`
	Issuer                     string `mapstructure:"ISSUER"`
	HttpPort                   string `mapstructure:"HTTP_PORT"`
	MailTitle                  string `mapstructure:"MAIL_TITLE"`
	ChangePasswordLimit        int    `mapstructure:"CHANGE_PASSWORD_LIMIT"`
	SendMailLimit              int    `mapstructure:"SEND_MAIL_LIMIT"`
	LoginLimit                 int    `mapstructure:"LOGIN_LIMIT"`
}

// NewConfigurations returns a new Configuration object
func NewConfigurations(logger hclog.Logger) *Configurations {
	//configs, err := LoadConfig("./") // for local development
	configs, err := LoadConfig("/usr/local/src/love_letter") // for production
	if err != nil {
		log.Fatal("cannot load config: ", err)
	}
	//logger.Debug("serve port", configs.ServerAddress)
	logger.Debug("db host", configs.DBHost)
	logger.Debug("db name", configs.DBName)
	logger.Debug("db port", configs.DBPort)
	logger.Debug("jwt expiration", configs.JwtExpiration)

	return configs
}

// LoadConfig reads configuration from file or environment variables.
func LoadConfig(path string) (config *Configurations, err error) {
	viper.AddConfigPath(path)
	viper.SetConfigName("app")
	viper.SetConfigType("env")

	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return
	}

	err = viper.Unmarshal(&config)
	return
}
