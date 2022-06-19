package database

import "time"

type VerificationDataType int

const (
	MailConfirmation VerificationDataType = iota + 1
	PassReset
	CancelDeleteUser
)

type LimitType int

const (
	LimitTypeNone LimitType = iota
	LimitTypeLogin
	LimitTypeSendVerifyMail
	LimitTypeSendPassResetMail
	LimitTypeChangePassword
	LimitTypeCancelDeleteUser
	LimitTypeComparePassCode
)

// Type of verification data
const (
	RefreshType = "refresh"
	AccessType  = "access"
)

// VerificationData represents the type for the data stored for verification.
type VerificationData struct {
	Email     string               `json:"email" validate:"required,email" sql:"email"`
	Code      string               `json:"code" validate:"required" sql:"code"`
	ExpiresAt time.Time            `json:"expiresat" sql:"expiresat"`
	Type      VerificationDataType `json:"type" sql:"type"`
	CreatedAt time.Time            `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time            `json:"updatedat" sql:"updatedat"`
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
	StartDate time.Time `json:"startdate" sql:"startdate"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// PlayerData represents the type for the data stored for send notification.
type PlayerData struct {
	UserID         string    `json:"userid" sql:"userid"`
	UUID           string    `json:"uuid" sql:"uuid"`
	PlayerId       string    `json:"playerid" sql:"playerid"`
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
	StringValue string    `json:"string_value" sql:"stringvalue"`
	IntValue    int       `json:"int_value" sql:"intvalue"`
	BoolValue   bool      `json:"bool_value" sql:"boolvalue"`
	FloatValue  float64   `json:"float_value" sql:"floatvalue"`
	TimeValue   time.Time `json:"time_value" sql:"timevalue"`
	CreatedAt   time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt   time.Time `json:"updatedat" sql:"updatedat"`
}

// Schedule represents the type for the data stored for schedule.
type Schedule struct {
	ID             string    `json:"id" sql:"id"`
	UserID         string    `json:"userid" sql:"userid"`
	Name           string    `json:"name" sql:"name"`
	ScheduleType   string    `json:"schedule_type" sql:"schedule_type"`
	Description    string    `json:"description" sql:"description"`
	Parameter      string    `json:"parameter" sql:"parameter"`
	TimeExecute    time.Time `json:"timeexecute" sql:"timeexecute"`
	RemoveAfterRun bool      `json:"remove_after_run" sql:"removeafterrun"`
	CreatedAt      time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt      time.Time `json:"updatedat" sql:"updatedat"`
}

// Letter represents the type for the data stored for letter.
type Letter struct {
	ID        string    `json:"id" sql:"id"`
	UserID    string    `json:"userid" sql:"userid"`
	Title     string    `json:"title" sql:"title"`
	Body      string    `json:"body" sql:"body"`
	IsRead    bool      `json:"isread" sql:"isread"`
	IsDelete  bool      `json:"isdelete" sql:"isdelete"`
	TimeOpen  time.Time `json:"timeopen" sql:"timeopen"`
	CreatedAt time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt time.Time `json:"updatedat" sql:"updatedat"`
}

// Psychology represents the type for the data stored for psychology.
type Psychology struct {
	ID          string    `json:"id" sql:"id"`
	Title       string    `json:"title" sql:"title"`
	Description string    `json:"description" sql:"description"`
	Level       int       `json:"level" sql:"level"`
	CreatedAt   time.Time `json:"createdat" sql:"createdat"`
	UpdatedAt   time.Time `json:"updatedat" sql:"updatedat"`
}

const MatchLoverStateKey = "state"

const (
	MatchLoverStateNone   = -1 // User no response answer
	MatchLoverStateAccept = 1  // User accept matched
	MatchLoverStateReject = 2  // user reject matched
)

const (
	ScheduleTypeOneTime  = "onetime"
	ScheduleTypeAnnually = "annually"
	ScheduleTypeMonthly  = "monthly"
	ScheduleTypeWeekly   = "weekly"
	ScheduleTypeDaily    = "daily"
	ScheduleTypeHourly   = "hourly"
	ScheduleTypeMinutely = "minutely"
)

const (
	ScheduleActionTypeDeleteUser = "deleteuser"
)

const (
	UserStateTypePassCode = "PASSCODE"
)

const (
	PsychologyTypeHappiness  = 4
	PsychologyTypeLove       = 3
	PsychologyTypeHealth     = 2
	PsychologyTypeMoney      = 1
	PsychologyTypeFun        = 2
	PsychologyTypeNormal     = 1
	PsychologyTypeSad        = 0
	PsychologyTypeAngry      = -1
	PsychologyTypeFear       = -2
	PsychologyTypeDisgust    = -3
	PsychologyTypeSurprise   = -4
	PsychologyTypeSadness    = -5
	PsychologyTypeAnxiety    = -6
	PsychologyTypeDepression = -7
)
