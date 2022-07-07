package database

import (
	"context"
	"database/sql"
	"github.com/hashicorp/go-hclog"
	"github.com/jmoiron/sqlx"
	uuid "github.com/satori/go.uuid"
	"log"
	"time"
)

// postgresRepository has the implementation of the db methods.
type postgresRepository struct {
	db     *sqlx.DB
	logger hclog.Logger
}

// NewPostgresRepository creates a new PostgresRepository.
func NewPostgresRepository(db *sqlx.DB, logger hclog.Logger) *postgresRepository {
	return &postgresRepository{
		db:     db,
		logger: logger,
	}
}

// CreateUser inserts the given user into the database.
func (repo *postgresRepository) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.NewV4().String()
	}
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	query := "insert into users (id, username, email, password, tokenhash, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7)"
	_, err := repo.db.ExecContext(ctx, query, user.ID, user.Username, user.Email, user.Password, user.TokenHash, user.CreatedAt, user.UpdatedAt)
	return err
}

// UpdateUser updates the user with the given id.
func (repo *postgresRepository) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	query := "update users set username = $2, email = $3, password = $4, tokenhash = $5, verified = $6, banned = $7, deleted = $8, role = $9, updatedat = $10 where id = $1"
	_, err := repo.db.ExecContext(ctx, query, user.ID, user.Username, user.Email, user.Password, user.TokenHash, user.Verified, user.Banned, user.Deleted, user.Role, user.UpdatedAt)
	return err
}

// UpdateUserVerificationStatus updates user verification status to true
func (repo *postgresRepository) UpdateUserVerificationStatus(ctx context.Context, email string, status bool) error {
	query := "update users set verified = $1 where email = $2"
	if _, err := repo.db.ExecContext(ctx, query, status, email); err != nil {
		return err
	}
	return nil
}

// CheckUsernameExists checks if the given username exists in the database.
func (repo *postgresRepository) CheckUsernameExists(ctx context.Context, username string) (bool, error) {
	query := "select count(*) from users where username = $1"
	var count int
	if err := repo.db.GetContext(ctx, &count, query, username); err != nil {
		return false, err
	}
	return count > 0, nil
}

// InsertVerificationData adds a mail verification data to db
func (repo *postgresRepository) InsertVerificationData(ctx context.Context, verificationData *VerificationData) error {
	verificationData.CreatedAt = time.Now()
	verificationData.UpdatedAt = time.Now()
	query := "insert into verifications (email, code, expiresat, type, createdat, updatedat) values ($1, $2, $3, $4, $5, $6)" +
		"on conflict (email, type) do update set code = $2, expiresat = $3, updatedat = $6"
	_, err := repo.db.ExecContext(ctx,
		query,
		verificationData.Email,
		verificationData.Code,
		verificationData.ExpiresAt,
		verificationData.Type,
		verificationData.CreatedAt,
		verificationData.UpdatedAt)
	return err
}

// GetVerificationData retrieves the stored verification code.
func (repo *postgresRepository) GetVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) (*VerificationData, error) {
	query := "select * from verifications where email = $1 and type = $2"

	var verificationData VerificationData
	if err := repo.db.GetContext(ctx, &verificationData, query, email, verificationDataType); err != nil {
		return nil, err
	}
	return &verificationData, nil
}

// DeleteVerificationData deletes a used verification data
func (repo *postgresRepository) DeleteVerificationData(ctx context.Context, email string, verificationDataType VerificationDataType) error {
	query := "delete from verifications where email = $1 and type = $2"
	_, err := repo.db.ExecContext(ctx, query, email, verificationDataType)
	return err
}

// GetUserByEmail returns the user with the given email.
func (repo *postgresRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	query := "select * from users where email = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, email)
	return user, err
}

// GetUserByID returns the user with the given id.
func (repo *postgresRepository) GetUserByID(ctx context.Context, id string) (*User, error) {
	query := "select  * from users where id = $1"
	user := &User{}
	err := repo.db.GetContext(ctx, user, query, id)
	return user, err
}

// DeleteUser deletes the user with the given id.
func (repo *postgresRepository) DeleteUser(ctx context.Context, id string) error {
	query := "delete from users where id = $1"
	_, err := repo.db.ExecContext(ctx, query, id)
	return err
}

// GetProfileByID returns the profile with the given user id.
func (repo *postgresRepository) GetProfileByID(ctx context.Context, userId string) (*ProfileData, error) {
	query := "select * from profiles where userid = $1"
	profile := &ProfileData{}
	err := repo.db.GetContext(ctx, profile, query, userId)
	return profile, err
}

// InsertProfile insert profile data into db
func (repo *postgresRepository) InsertProfile(ctx context.Context, profile *ProfileData) error {
	profile.CreatedAt = time.Now()
	profile.UpdatedAt = time.Now()
	query := "insert into profiles (userid, email, gender, birthday, firstname, lastname, avatarurl, phone, street, city, state, zipcode, country, createdat, updatedat) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)" +
		"on conflict (userid) do update set email = $2, gender = $3, birthday = $4, firstname = $5, lastname = $6, avatarurl = $7, phone = $8, street = $9, city = $10, state = $11, zipcode = $12, country = $13, updatedat = $15"
	_, err := repo.db.ExecContext(
		ctx,
		query,
		profile.UserID,
		profile.Email,
		profile.Gender,
		profile.Birthday,
		profile.FirstName,
		profile.LastName,
		profile.AvatarURL,
		profile.Phone,
		profile.Street,
		profile.City,
		profile.State,
		profile.ZipCode,
		profile.Country,
		profile.CreatedAt,
		profile.UpdatedAt)
	return err
}

// UpdatePassword updates the user password
func (repo *postgresRepository) UpdatePassword(ctx context.Context, userID string, password string, tokenHash string) error {
	query := "update users set password = $1, tokenhash = $2 where id = $3"
	_, err := repo.db.ExecContext(ctx, query, password, tokenHash, userID)
	return err
}

// GetListOfPasswords returns the list of passwords
func (repo *postgresRepository) GetListOfPasswords(ctx context.Context, userID string) ([]string, error) {
	query := "select password from passworusers where userid = $1"
	rows, err := repo.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer func(rows *sql.Rows) {
		err := rows.Close()
		if err != nil {
			log.Println(err)
		}
	}(rows)
	var passwords []string
	for rows.Next() {
		var password string
		err := rows.Scan(&password)
		if err != nil {
			return nil, err
		}
		passwords = append(passwords, password)
	}
	return passwords, nil
}

// InsertListOfPasswords updates the list of passwords
func (repo *postgresRepository) InsertListOfPasswords(ctx context.Context, passwordUsers *PassworUsers) error {
	passwordUsers.ID = uuid.NewV4().String()
	passwordUsers.CreatedAt = time.Now()
	passwordUsers.UpdatedAt = time.Now()

	query := "insert into passworusers(id, userid, password, createdat, updatedat) values($1, $2, $3, $4, $5)"
	_, err := repo.db.ExecContext(ctx, query,
		passwordUsers.ID,
		passwordUsers.UserID,
		passwordUsers.Password,
		passwordUsers.CreatedAt,
		passwordUsers.UpdatedAt)

	return err
}

// GetLimitData returns the limit data
func (repo *postgresRepository) GetLimitData(ctx context.Context, userID string, limitType LimitType) (*LimitData, error) {
	query := "select * from limitdata where userid = $1 and limittype = $2"
	limitData := &LimitData{}
	err := repo.db.GetContext(ctx, limitData, query, userID, limitType)
	return limitData, err
}

// InsertLimitData updates the limit data
func (repo *postgresRepository) InsertLimitData(ctx context.Context, limitData *LimitData) error {
	limitData.CreatedAt = time.Now()
	limitData.UpdatedAt = time.Now()
	query := "insert into limitdata(userid, limittype, numoflimit, createdat, updatedat) values($1, $2, $3, $4, $5)" +
		"on conflict (userid, limittype) do update set numoflimit = $3, updatedat = $5"
	_, err := repo.db.ExecContext(ctx, query,
		limitData.UserID,
		limitData.LimitType,
		limitData.NumOfLimit,
		limitData.CreatedAt,
		limitData.UpdatedAt)
	return err
}

// ResetLimitData clears the limit data
func (repo *postgresRepository) ResetLimitData(ctx context.Context, limitType LimitType) error {
	query := "update limitdata set numoflimit = 0 where limittype = $1"
	_, err := repo.db.ExecContext(ctx, query, limitType)
	return err
}

// InsertMatchVerifyData inserts the match data
func (repo *postgresRepository) InsertMatchVerifyData(ctx context.Context, matchData *MatchVerifyData) error {
	// Insert the match data
	matchData.CreatedAt = time.Now()
	matchData.UpdatedAt = time.Now()
	query := "insert into generatematchcodes(userid, email, code, expiresat, createdat, updatedat) values($1, $2, $3, $4, $5, $6)" +
		" on conflict (userid) do update set email = $2, code = $3, expiresat = $4, updatedat = $6"
	_, err := repo.db.ExecContext(ctx, query,
		matchData.UserID,
		matchData.Email,
		matchData.Code,
		matchData.ExpiresAt,
		matchData.CreatedAt,
		matchData.UpdatedAt)
	return err
}

// GetMatchVerifyDataByCode returns the match data
func (repo *postgresRepository) GetMatchVerifyDataByCode(ctx context.Context, code string) (*MatchVerifyData, error) {
	query := "select * from generatematchcodes where code = $1"
	matchData := &MatchVerifyData{}
	err := repo.db.GetContext(ctx, matchData, query, code)
	return matchData, err
}

// DeleteMatchVerifyDataByUserID deletes the match data
func (repo *postgresRepository) DeleteMatchVerifyDataByUserID(ctx context.Context, userID string) error {
	query := "delete from generatematchcodes where userid = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// GetMatchLoveDataByUserID returns the match love data
func (repo *postgresRepository) GetMatchLoveDataByUserID(ctx context.Context, userID string) (*MatchLoveData, error) {
	query := "select * from matchloves where userid1 = $1"
	matchData := &MatchLoveData{}
	err := repo.db.GetContext(ctx, matchData, query, userID)
	if err != nil {
		query = "select * from matchloves where userid2 = $1"
		err = repo.db.GetContext(ctx, matchData, query, userID)
	}
	return matchData, err
}

// InsertMatchLoveData inserts the match love data
func (repo *postgresRepository) InsertMatchLoveData(ctx context.Context, matchData *MatchLoveData) error {
	matchData.CreatedAt = time.Now()
	matchData.UpdatedAt = time.Now()
	query := "insert into matchloves(userid1, userid2, email1, email2, accept1, accept2, startdate, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7, $8, $9)" +
		" on conflict (userid1, userid2) do update set email1 = $3, email2 = $4, accept1 = $5, accept2 = $6, startdate = $7, updatedat = $9"
	_, err := repo.db.ExecContext(ctx, query,
		matchData.UserID1,
		matchData.UserID2,
		matchData.Email1,
		matchData.Email2,
		matchData.Accept1,
		matchData.Accept2,
		matchData.StartDate,
		matchData.CreatedAt,
		matchData.UpdatedAt)
	return err
}

// DeleteMatchLoveDataByUserID deletes the match love data
func (repo *postgresRepository) DeleteMatchLoveDataByUserID(ctx context.Context, userID string) error {
	query := "delete from matchloves where userid1 = $1 or userid2 = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// InsertPlayerData inserts player data
func (repo *postgresRepository) InsertPlayerData(ctx context.Context, playerData *PlayerData) error {
	playerData.CreatedAt = time.Now()
	playerData.UpdatedAt = time.Now()
	query := "insert into players(userid, uuid, playerid, devicename, deviceversion, devicemodel, deviceos, devicelocalize, createdat, updatedat) values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)" +
		" on conflict (userid) do update set uuid = $2, playerid = $3, devicename = $4, deviceversion = $5, devicemodel = $6, deviceos = $7, devicelocalize = $8, updatedat = $10"
	_, err := repo.db.ExecContext(ctx, query,
		playerData.UserID,
		playerData.UUID,
		playerData.PlayerId,
		playerData.DeviceName,
		playerData.DeviceVersion,
		playerData.DeviceModel,
		playerData.DeviceOS,
		playerData.DeviceLocalize,
		playerData.CreatedAt,
		playerData.UpdatedAt)
	return err
}

// GetPlayerData returns player data
func (repo *postgresRepository) GetPlayerData(ctx context.Context, userID string) (*PlayerData, error) {
	query := "select * from players where userid = $1"
	var playerData PlayerData
	err := repo.db.GetContext(ctx, &playerData, query, userID)
	return &playerData, err
}

// InsertUserStateData inserts user state data
func (repo *postgresRepository) InsertUserStateData(ctx context.Context, userStateData *UserStateData) error {
	userStateData.CreatedAt = time.Now()
	userStateData.UpdatedAt = time.Now()
	query := "insert into userstates(userid, keystring, stringvalue, intvalue, boolvalue, floatvalue, timevalue, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8, $9) " +
		"on conflict (userid, keystring) do update set stringvalue = $3, intvalue = $4, boolvalue = $5, floatvalue = $6, timevalue = $7, updatedat = $9"
	_, err := repo.db.ExecContext(ctx, query,
		userStateData.UserID,
		userStateData.KeyString,
		userStateData.StringValue,
		userStateData.IntValue,
		userStateData.BoolValue,
		userStateData.FloatValue,
		userStateData.TimeValue,
		userStateData.CreatedAt,
		userStateData.UpdatedAt)
	return err
}

// DeleteUserStateData deletes user state data
func (repo *postgresRepository) DeleteUserStateData(ctx context.Context, userID string, keyString string) error {
	query := "delete from userstates where userid = $1 and keystring = $2"
	_, err := repo.db.ExecContext(ctx, query, userID, keyString)
	return err
}

// GetUserStateData returns user state data
func (repo *postgresRepository) GetUserStateData(ctx context.Context, userID string, keyString string) (*UserStateData, error) {
	query := "select * from userstates where userid = $1 and keystring = $2"
	var userStateData UserStateData
	err := repo.db.GetContext(ctx, &userStateData, query, userID, keyString)
	return &userStateData, err
}

// InsertSchedule sets the schedule
func (repo *postgresRepository) InsertSchedule(ctx context.Context, schedule *Schedule) error {
	schedule.ID = uuid.NewV4().String()
	schedule.CreatedAt = time.Now()
	schedule.UpdatedAt = time.Now()
	query := "insert into schedules(id, userid, name, scheduletype, description, parameter, timeexecute, removeafterrun, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)"
	_, err := repo.db.ExecContext(ctx, query,
		schedule.ID,
		schedule.UserID,
		schedule.Name,
		schedule.ScheduleType,
		schedule.Description,
		schedule.Parameter,
		schedule.TimeExecute,
		schedule.RemoveAfterRun,
		schedule.CreatedAt,
		schedule.UpdatedAt)
	return err
}

// DeleteSchedule deletes the schedule
func (repo *postgresRepository) DeleteSchedule(ctx context.Context, userID string, name string) error {
	query := "delete from schedules where userid = $1 and name = $2"
	_, err := repo.db.ExecContext(ctx, query, userID, name)
	return err
}

// GetSchedules returns the schedules
func (repo *postgresRepository) GetSchedules(ctx context.Context) ([]*Schedule, error) {
	query := "select * from schedules"
	var schedules []*Schedule
	err := repo.db.SelectContext(ctx, &schedules, query)
	return schedules, err
}

// CreateLetter create letter
func (repo *postgresRepository) CreateLetter(ctx context.Context, letter *Letter) error {
	letter.ID = uuid.NewV4().String()
	letter.CreatedAt = time.Now()
	letter.UpdatedAt = time.Now()
	query := "insert into letters(id, userid, title, body, isread, isdelete, timeopen, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8, $9)" +
		"on conflict (id) do update set userid = $2, title = $3, body = $4, isread = $5, isdelete = $6, timeopen = $7, createdat = $8, updatedat = $9"
	_, err := repo.db.ExecContext(ctx, query,
		letter.ID,
		letter.UserID,
		letter.Title,
		letter.Body,
		letter.IsRead,
		letter.IsDelete,
		letter.TimeOpen,
		letter.CreatedAt,
		letter.UpdatedAt)
	return err
}

// DeleteLetter delete letter
func (repo *postgresRepository) DeleteLetter(ctx context.Context, userID string, letterID string) error {
	query := "delete from letters where userid = $1 and id = $2"
	_, err := repo.db.ExecContext(ctx, query, userID, letterID)
	return err
}

// GetLetters Get letters by user id and page. maximum by pageSize letters, default is 10
func (repo *postgresRepository) GetLetters(ctx context.Context, userID string, page int, pageSize int) ([]Letter, error) {
	query := "select * from letters where userid = $1 order by createdat desc limit $2 offset $3"
	var letters []Letter
	err := repo.db.SelectContext(ctx, &letters, query, userID, pageSize, page*pageSize)
	return letters, err
}

// GetLetter Get letter by id
func (repo *postgresRepository) GetLetter(ctx context.Context, userID string, letterID string) (*Letter, error) {
	query := "select * from letters where userid = $1 and id = $2"
	var letter Letter
	err := repo.db.GetContext(ctx, &letter, query, userID, letterID)
	return &letter, err
}

// InsertPsychology insert psychology
func (repo *postgresRepository) InsertPsychology(ctx context.Context, psychology *Psychology) error {
	psychology.ID = uuid.NewV4().String()
	psychology.CreatedAt = time.Now()
	psychology.UpdatedAt = time.Now()
	query := "insert into psychologies(id, title, description, level, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6)" +
		"on conflict (id) do update set title = $2, description = $3, level = $4, createdat = $5, updatedat = $6"
	_, err := repo.db.ExecContext(ctx, query,
		psychology.ID,
		psychology.Title,
		psychology.Description,
		psychology.Level,
		psychology.CreatedAt,
		psychology.UpdatedAt)
	return err
}

// DeletePsychology Delete psychology by psychologyID
func (repo *postgresRepository) DeletePsychology(ctx context.Context, psychologyID string) error {
	query := "delete from psychologies where id = $1"
	_, err := repo.db.ExecContext(ctx, query, psychologyID)
	return err
}

// GetPsychologies Get psychology by limit and offset
func (repo *postgresRepository) GetPsychologies(ctx context.Context, limit int, offset int) ([]Psychology, error) {
	query := "select * from psychologies order by level desc limit $1 offset $2"
	var psychologies []Psychology
	err := repo.db.SelectContext(ctx, &psychologies, query, limit, offset)
	return psychologies, err
}

// CreateHoliday create holiday
func (repo *postgresRepository) CreateHoliday(ctx context.Context, holiday *Holiday) error {
	holiday.ID = uuid.NewV4().String()
	holiday.CreatedAt = time.Now()
	holiday.UpdatedAt = time.Now()
	query := "insert into holidays(id, userid, title, description, startdate, enddate, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8)" +
		"on conflict (id) do update set userid = $2, title = $3, description = $4, startdate = $5, enddate = $6, createdat = $7, updatedat = $8"
	_, err := repo.db.ExecContext(ctx, query,
		holiday.ID,
		holiday.UserID,
		holiday.Title,
		holiday.Description,
		holiday.StartDate,
		holiday.EndDate,
		holiday.CreatedAt,
		holiday.UpdatedAt)
	return err
}

// DeleteHoliday Delete holiday by holidayID
func (repo *postgresRepository) DeleteHoliday(ctx context.Context, holidayID string) error {
	query := "delete from holidays where id = $1"
	_, err := repo.db.ExecContext(ctx, query, holidayID)
	return err
}

// GetHolidays Get holidays by limit and offset
func (repo *postgresRepository) GetHolidays(ctx context.Context, userID string, limit int, offset int) ([]Holiday, error) {
	query := "select * from holidays where userid = $1 order by startdate desc limit $2 offset $3"
	var holidays []Holiday
	err := repo.db.SelectContext(ctx, &holidays, query, userID, limit, offset)
	return holidays, err
}

// GetHoliday Get holiday by holidayID
func (repo *postgresRepository) GetHoliday(ctx context.Context, holidayID string) (*Holiday, error) {
	query := "select * from holidays where id = $1"
	var holiday Holiday
	err := repo.db.GetContext(ctx, &holiday, query, holidayID)
	return &holiday, err
}

// CreateAESKey create aes key
func (repo *postgresRepository) CreateAESKey(ctx context.Context, aesKey *AESKey) error {
	aesKey.CreatedAt = time.Now()
	aesKey.UpdatedAt = time.Now()
	query := "insert into aeskeys(userid, keystring, createdat, updatedat) " +
		"values($1, $2, $3, $4)" +
		"on conflict (userid, keystring) do update set keystring = $2, createdat = $3, updatedat = $4"
	_, err := repo.db.ExecContext(ctx, query,
		aesKey.UserID,
		aesKey.KeyString,
		aesKey.CreatedAt,
		aesKey.UpdatedAt)
	return err
}

// DeleteAESKey Delete aes key by userID
func (repo *postgresRepository) DeleteAESKey(ctx context.Context, userID string) error {
	query := "delete from aeskeys where userid = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// GetAESKey Get AES keys by user id
func (repo *postgresRepository) GetAESKey(ctx context.Context, userID string) (string, error) {
	query := "select keystring from aeskeys where userid = $1"
	var keystring string
	err := repo.db.GetContext(ctx, &keystring, query, userID)
	return keystring, err
}

// InsertNotification create notification
func (repo *postgresRepository) InsertNotification(ctx context.Context, notification *Notification) error {
	notification.ID = uuid.NewV4().String()
	notification.CreatedAt = time.Now()
	notification.UpdatedAt = time.Now()
	query := "insert into notifications(id, userid, notitype, title, description, isread, isdelete, timeopen, createdat, updatedat) " +
		"values($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)" +
		"on conflict (id) do update set userid = $2, notitype = $3, title = $4, description = $5, isread = $6, isdelete = $7, timeopen = $8, createdat = $9, updatedat = $10"
	_, err := repo.db.ExecContext(ctx, query,
		notification.ID,
		notification.UserID,
		notification.NotiType,
		notification.Title,
		notification.Description,
		notification.IsRead,
		notification.IsDelete,
		notification.TimeOpen,
		notification.CreatedAt,
		notification.UpdatedAt)
	return err
}

// UpdateNotification Update notification
func (repo *postgresRepository) UpdateNotification(ctx context.Context, notification *Notification) error {
	notification.UpdatedAt = time.Now()
	query := "update notifications set userid = $2, notitype = $3, title = $4, description = $5, isread = $6, isdelete = $7, timeopen = $8, updatedat = $9 where id = $1"
	_, err := repo.db.ExecContext(ctx, query,
		notification.ID,
		notification.UserID,
		notification.NotiType,
		notification.Title,
		notification.Description,
		notification.IsRead,
		notification.IsDelete,
		notification.TimeOpen,
		notification.UpdatedAt)
	return err
}

// DeleteNotification Delete notification by userId and notificationID
func (repo *postgresRepository) DeleteNotification(ctx context.Context, userID string, notificationID string) error {
	// delete just change isdelete to true
	query := "update notifications set isdelete = true where userid = $1 and id = $2"
	_, err := repo.db.ExecContext(ctx, query, userID, notificationID)
	return err
}

// GetNotifications Get notifications by user id, offset and limit
func (repo *postgresRepository) GetNotifications(ctx context.Context, userID string, offset int, limit int) ([]Notification, error) {
	// get notifications by user id and offset and limit, and isdelete is false
	query := "select * from notifications where userid = $1 and isdelete = false order by timeopen desc limit $2 offset $3"
	var notifications []Notification
	err := repo.db.SelectContext(ctx, &notifications, query, userID, limit, offset)
	return notifications, err
}

// GetNotification Get notification by notificationID
func (repo *postgresRepository) GetNotification(ctx context.Context, notificationID string) (*Notification, error) {
	// get notification by notificationID and isdelete is false
	query := "select * from notifications where id = $1 and isdelete = false"
	var notification Notification
	err := repo.db.GetContext(ctx, &notification, query, notificationID)
	return &notification, err
}

//userid 		Varchar(36) not null,
//shareuserid Varchar(36) not null,
//createdat  	Timestamp not null,
//updatedat  	Timestamp not null,
//unique(userid, shareuserid),

// InsertShare create share
func (repo *postgresRepository) InsertShare(ctx context.Context, share *Share) error {
	share.CreatedAt = time.Now()
	share.UpdatedAt = time.Now()
	query := "insert into shares(userid, shareuserid, createdat, updatedat) " +
		"values($1, $2, $3, $4)" +
		"on conflict (userid, shareuserid) do update set shareuserid = $2, createdat = $3, updatedat = $4"
	_, err := repo.db.ExecContext(ctx, query,
		share.UserID,
		share.ShareUserID,
		share.CreatedAt,
		share.UpdatedAt)
	return err
}

// DeleteShare Delete share by userID
func (repo *postgresRepository) DeleteShare(ctx context.Context, userID string) error {
	query := "delete from shares where userid = $1 or shareuserid = $1"
	_, err := repo.db.ExecContext(ctx, query, userID)
	return err
}

// GetShare Get shares by userID
func (repo *postgresRepository) GetShare(ctx context.Context, userID string) (Share, error) {
	query := "select * from shares where userid = $1 or shareuserid = $1"
	var share Share
	err := repo.db.GetContext(ctx, &share, query, userID)
	return share, err
}
