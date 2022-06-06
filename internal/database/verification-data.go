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
	Email     string    `json:"email" sql:"email"`
	Code      string    `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time `json:"expiresat" sql:"expiresat"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// MatchLoveData represents the type for the data stored for matching.
type MatchLoveData struct {
	UserID1   string    `json:"userid1" sql:"userid1"`
	UserID2   string    `json:"userid2" sql:"userid2"`
	Email1    string    `json:"email1" sql:"email1"`
	Email2    string    `json:"email2" sql:"email2"`
	Accept1   int       `json:"accept1" sql:"accept1"`
	Accept2   int       `json:"accept2" sql:"accept2"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// PlayerData represents the type for the data stored for send notification.
type PlayerData struct {
	UserID         string    `json:"userid" sql:"userid"`
	UUID           string    `json:"uuid" sql:"uuid"`
	DeviceName     string    `json:"device_name" sql:"devicename"`
	DeviceVersion  string    `json:"device_version" sql:"deviceversion"`
	DeviceModel    string    `json:"device_model" sql:"devicemodel"`
	DeviceOS       string    `json:"device_os" sql:"deviceos"`
	DeviceLocalize string    `json:"device_localize" sql:"devicelocalize"`
	CreatedAt      time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt      time.Time `json:"updatedat" sql:"updatedat"`
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
