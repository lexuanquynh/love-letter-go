package database

import "time"

type VerificationDataType int

const (
	MailConfirmation VerificationDataType = iota + 1
	PassReset
)

type LimitType int

const (
	LimitTypeNone LimitType = iota
	LimitTypeLogin
	LimitTypeSendVerifyMail
	LimitTypeSendPassResetMail
	LimitTypeChangePassword
)

// Type of verification data
const (
	RefreshType = "refresh"
	AccessType  = "access"
)

// VerificationData represents the type for the data stored for verification.
type VerificationData struct {
	ID        string               `json:"id"`
	Email     string               `json:"email" validate:"required,email" sql:"email"`
	Code      string               `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time            `json:"expiresat" sql:"expiresat"`
	Type      VerificationDataType `json:"type" sql:"type"`
}

// MatchVerifyData represents the type for the data stored for matching.
type MatchVerifyData struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userid" sql:"userid"`
	Code      string    `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// MatchLoveData represents the type for the data stored for matching.
type MatchLoveData struct {
	ID        string    `json:"id"`
	UserID    string    `json:"userid" sql:"userid"`
	MatchID   string    `json:"matchid" sql:"matchid"`
	Accept    bool      `json:"accept" sql:"accept"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
}

// FeedsData represents the type for the data stored for verification.
type FeedsData struct {
	ID       int    `json:"id"`
	Title    string `json:"title" validate:"required" sql:"title"`
	IsEnable bool   `json:"is_enable" sql:"isenable"`
}

type PlayerData struct {
	UserID    string    `json:"userid" sql:"userid"`
	UUID      string    `json:"uuid" sql:"uuid"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}
