package main

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/endpoints"
	"LoveLetterProject/pkg/authorization/middleware"
	"LoveLetterProject/pkg/authorization/transport"
	"context"
	"fmt"
	"github.com/go-co-op/gocron"
	"github.com/jmoiron/sqlx"
	"github.com/juju/ratelimit"
	"github.com/oklog/oklog/pkg/group"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// schema for user table
const userSchema = `
		create table if not exists users (
			id 		   Varchar(36) not null,
			email 	   Varchar(100) not null unique,
			username   Varchar(225),
			password   Varchar(225) not null,
			tokenhash  Varchar(15) not null,
			verified   Boolean default false,
		    banned     Boolean default false,
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (id)
		);
`

// schema for verification table
const verificationSchema = `
		create table if not exists verifications (
			id 		   Varchar(36) not null,
			email 		Varchar(100) not null,
			code  		Varchar(10) not null,
			expiresat 	Timestamp not null,
			type        Varchar(10) not null,		
			Primary Key (id),
			Constraint fk_user_email Foreign Key(email) References users(email)
				On Delete Cascade On Update Cascade
		)
`

// schema for profile table
const profileSchema = `
		create table if not exists profiles (		
			userid 	Varchar(36) not null,
		    email 	   Varchar(100) not null,
		    birthday  Date null,
		    gender 		int null,
			firstname   Varchar(225) default '',
			lastname    Varchar(225) default '',
			avatarurl  Varchar(255) default '',
			phone      Varchar(25) default '',
			street     Varchar(255) default '',
			city       Varchar(255) default '',
			state      Varchar(10) default '',
			zipcode   Varchar(5) default '',
			country    Varchar(255) default '',
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (userid),
			Constraint fk_user_id Foreign Key(userid) References users(id)
				On Delete Cascade On Update Cascade
		)
`

// schema for security user table
const securityUserSchema = `
		create table if not exists passworusers (
			id 		   Varchar(36) not null,
			userid 	Varchar(36) not null,
			password   Varchar(225) not null,	
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (id),
			Constraint fk_user_id Foreign Key(userid) References users(id)
				On Delete Cascade On Update Cascade
		)
`

// schema for limit table
const limitSchema = `
		create table if not exists limits (
			id 		   Varchar(36) not null,
			userid 	Varchar(36) not null,
			numofsendmailverify 	   Int default 0,
			numofsendresetpassword  Int default 0,
			numofchangepassword Int default 0,
		    numoflogin 	   Int default 0,
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (id),
			Constraint fk_user_id Foreign Key(userid) References users(id)
				On Delete Cascade On Update Cascade
		)
`

// schema for match love table. accept: -1: not answer, 1: accept, 2: reject
const matchLoveSchema = `
		create table if not exists matchloves (		
			userid1 	Varchar(36) not null,
			userid2 	Varchar(36) not null,
		    email1 	   Varchar(100) not null,
			email2 	   Varchar(100) not null,
		    accept1     int default -1,
		    accept2     int default -1,
		    startdate   Timestamp not null,
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			unique(userid1, userid2)
			
		)
`

// schema for generate match code table
const generateMatchCodeSchema = `
		create table if not exists generatematchcodes (
			userid 	Varchar(36) not null,
		    email 	   Varchar(100) not null,
			code  		Varchar(10) not null,
			expiresat 	Timestamp not null,
		    createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (userid),
			Constraint fk_user_id Foreign Key(userid) References users(id)
				On Delete Cascade On Update Cascade
		)
`

// schema for user state table
const userStateSchema = `
		create table if not exists userstates (	
			userid 			Varchar(36) not null,
			keystring 		Varchar(36) not null,
			stringvalue 	Varchar(255) null,
			intvalue 		int null,
			boolvalue 		Boolean default false,
			floatvalue 		float null,
			timevalue 		Timestamp null,
			createdat  		Timestamp not null,
			updatedat   	Timestamp not null,
		    unique(userid, keystring)			
		)
`

// Schema for save uuid, we will use this for send notification after
const playerSchema = `
		create table if not exists players (			
			userid 				Varchar(36) not null,
			uuid 				Varchar(100) not null,
		    playerid 			Varchar(100)  null,
		    devicename 			Varchar(100)  null,
		    deviceversion 		Varchar(10)  null,
		    devicemodel 		Varchar(20)  null,
		    deviceos 			Varchar(10)  null,
		    devicelocalize 		Varchar(20)  null,
			createdat  			Timestamp not null,
			updatedat  			Timestamp not null,
			Primary Key (userid),
			Constraint fk_user_id Foreign Key(userid) References users(id)
				On Delete Cascade On Update Cascade
		)
`

func main() {
	logger := utils.NewLogger()
	// quynhlx change config with multi environments
	//configs := utils.NewConfigurations(logger, utils.DeployLocal)
	//configs := utils.NewConfigurations(logger, utils.DeployStage)
	configs := utils.NewConfigurations(logger, utils.DeployProd)
	// validator contains all the methods that are need to validate the user json in request
	validator := database.NewValidation()
	// create a new connection to the postgres db store
	db, err := database.NewConnection(configs, logger)
	defer func(db *sqlx.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)
	if err != nil {
		logger.Error("unable to connect to db", "error", err)
		return
	}
	// creation of user table.
	db.MustExec(userSchema)
	db.MustExec(verificationSchema)
	db.MustExec(profileSchema)
	db.MustExec(securityUserSchema)
	db.MustExec(limitSchema)
	db.MustExec(matchLoveSchema)
	db.MustExec(generateMatchCodeSchema)
	db.MustExec(playerSchema)
	db.MustExec(userStateSchema)

	logger.Info("database created")
	// repository contains all the methods that interact with DB to perform CURD operations for user.
	repository := database.NewPostgresRepository(db, logger)
	// mailService contains the utility methods to send an email
	mailService := authorization.NewSGMailService(logger, configs)
	// NotificationService contains the utility methods to send an notification
	notificationService := authorization.NewOneSignalService(logger, configs)
	// authService contains all methods that help in authorizing a user request
	auth := middleware.NewAuthService(logger, configs)

	s := gocron.NewScheduler(time.UTC)
	// Reset limit send mail for users.
	_, err = s.Every(1).Day().At("00:01").Do(func() {
		logger.Info("Clear limit data for users after 1 day at 00:01.")
		var ctx = context.Background()
		err := repository.ClearLimitData(ctx, database.LimitTypeSendVerifyMail)
		if err != nil {
			logger.Error("Error clearing limit send mail data", "error", err)
		}
		// Reset limit login for users.
		err = repository.ClearLimitData(ctx, database.LimitTypeLogin)
		if err != nil {
			logger.Error("Error clearing limit login data", "error", err)
		}
	})
	if err != nil {
		logger.Error("Error scheduling limit data", "error", err)
		return
	}
	// Reset limit change password for users after 15 minutes.
	_, err = s.Every(15).Minute().Do(func() {
		logger.Info("Clear change password, send pass reset mail limit data for users after 15 minutes.")
		var ctx = context.Background()
		err := repository.ClearLimitData(ctx, database.LimitTypeChangePassword)
		if err != nil {
			logger.Error("Error clearing limit change password data", "error", err)
		}
		// Limit for send mail get password code reset
		err = repository.ClearLimitData(ctx, database.LimitTypeSendPassResetMail)
		if err != nil {
			logger.Error("Error clearing limit send mail data", "error", err)
		}
	})
	if err != nil {
		logger.Error("Error scheduling limit data", "error", err)
	}
	s.StartAsync()

	// Create rate limiter for users.
	rlBucket := ratelimit.NewBucket(1*time.Second, 5)

	var (
		httpAddr    = net.JoinHostPort("localhost", configs.HttpPort)
		service     = authorization.NewUserService(logger, configs, repository, mailService, auth, notificationService)
		eps         = endpoints.NewEndpointSet(service, auth, repository, logger, validator, rlBucket)
		httpHandler = transport.NewHTTPHandler(eps)
	)

	var g group.Group
	{
		// The HTTP listener mounts the Go kit HTTP handler we created.
		httpListener, err := net.Listen("tcp", httpAddr)
		if err != nil {
			//logger.Log("transport", "HTTP", "during", "Listen", "err", err)
			logger.Error("could not start the server", "error", err)
			os.Exit(1)
		}
		g.Add(func() error {
			//logger.Log("transport", "HTTP", "addr", httpAddr)
			logger.Info("starting the server at port", httpAddr)
			return http.Serve(httpListener, httpHandler)
		}, func(error) {
			logger.Error("could not start the server", "error", err)
			err := httpListener.Close()
			if err != nil {
				logger.Error("could not close the listener", "error", err)
				return
			}
		})
	}
	{
		// This function just sits and waits for ctrl-C.
		cancelInterrupt := make(chan struct{})
		g.Add(func() error {
			c := make(chan os.Signal, 1)
			signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-c:
				return fmt.Errorf("received signal %s", sig)
			case <-cancelInterrupt:
				return nil
			}
		}, func(error) {
			close(cancelInterrupt)
		})
	}
	logger.Info("exit", g.Run())
}
