package database

import "time"

type LimitData struct {
	ID                  string    `json:"id" sql:"id"`
	UserID              string    `json:"user_id" sql:"userid"`
	NumOfSendMail       int       `json:"num_of_send_mail" sql:"numofsendmail"`
	NumOfChangePassword int       `json:"num_of_change_password" sql:"numofchangepassword"`
	NumOfLogin          int       `json:"num_of_login" sql:"numoflogin"`
	CreatedAt           time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt           time.Time `json:"updatedat" sql:"updatedat"`
}
