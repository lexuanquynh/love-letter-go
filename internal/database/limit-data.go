package database

import "time"

type LimitData struct {
	ID                     string    `json:"id" sql:"id"`
	UserID                 string    `json:"user_id" sql:"userid"`
	NumOfSendMailVerify    int       `json:"num_of_send_mail_verify" sql:"numofsendmailverify"`
	NumOfSendResetPassword int       `json:"num_of_send_reset_password" sql:"numofsendresetpassword"`
	NumOfChangePassword    int       `json:"num_of_change_password" sql:"numofchangepassword"`
	NumOfLogin             int       `json:"num_of_login" sql:"numoflogin"`
	CreatedAt              time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt              time.Time `json:"updatedat" sql:"updatedat"`
}
