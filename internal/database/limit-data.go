package database

import "time"

type LimitData struct {
	UserID     string    `json:"user_id" sql:"userid"`
	LimitType  LimitType `json:"limit_type" sql:"limittype"`
	NumOfLimit int       `json:"num_of_limit" sql:"numoflimit"`
	CreatedAt  time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt  time.Time `json:"updatedat" sql:"updatedat"`
}
