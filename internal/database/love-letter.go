package database

import "time"

// LoveLetter type for love letter
type LoveLetter struct {
	ID        string    `json:"id" sql:"id"`
	UserID    string    `json:"userid" sql:"userid"`
	MatchID   string    `json:"matchid" sql:"matchid"`
	Title     string    `json:"title" sql:"title"`
	Body      string    `json:"body" sql:"body"`
	IsRead    bool      `json:"isread" sql:"isread"`
	IsDelete  bool      `json:"isdelete" sql:"isdelete"`
	TimeOpen  time.Time `json:"timeopen" sql:"timeopen"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}
