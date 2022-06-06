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
	UserID    string    `json:"userid" sql:"userid"`
	Code      string    `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// MatchLoveData represents the type for the data stored for matching.
type MatchLoveData struct {
	UserID    string    `json:"userid" sql:"userid"`
	MatchID   string    `json:"matchid" sql:"matchid"`
	Accept1   int       `json:"accept1" sql:"accept1"`
	Accept2   int       `json:"accept2" sql:"accept2"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// FeedsData represents the type for the data stored for verification.
type FeedsData struct {
	ID       int    `json:"id"`
	Title    string `json:"title" validate:"required" sql:"title"`
	IsEnable bool   `json:"is_enable" sql:"isenable"`
}

// PlayerData represents the type for the data stored for send notification.
type PlayerData struct {
	UserID    string    `json:"userid" sql:"userid"`
	UUID      string    `json:"uuid" sql:"uuid"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// UserStateData represents the type for the data stored for user state.
type UserStateData struct {
	UserID      string    `json:"userid" sql:"userid"`
	KeyString   string    `json:"keystring" sql:"keystring"`
	StringValue string    `json:"stringvalue" sql:"stringvalue"`
	IntValue    int       `json:"intvalue" sql:"intvalue"`
	BoolValue   bool      `json:"boolvalue" sql:"boolvalue"`
	FloatValue  float64   `json:"floatvalue" sql:"floatvalue"`
	TimeValue   time.Time `json:"timevalue" sql:"timevalue"`
	CreatedAt   time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt   time.Time `json:"updatedat" sql:"updatedat"`
}

const MatchLoverStateKey = "state"

const (
	MatchLoverStateNone   = -1 // User no response answer
	MatchLoverStateAccept = 1  // User accept matched
	MatchLoverStateReject = 2  // user reject matched
)
