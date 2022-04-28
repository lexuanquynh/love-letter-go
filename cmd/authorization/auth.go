package main

import (
	utils "LoveLetterProject/internal"
	"LoveLetterProject/internal/database"
	"LoveLetterProject/pkg/authorization"
	"LoveLetterProject/pkg/authorization/endpoints"
	"LoveLetterProject/pkg/authorization/middleware"
	"LoveLetterProject/pkg/authorization/transport"
	"fmt"
	"github.com/oklog/oklog/pkg/group"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
		    banner     Boolean default false,
			createdat  Timestamp not null,
			updatedat  Timestamp not null,
			Primary Key (id)
		);
`

const verificationSchema = `
		create table if not exists verifications (
			email 		Varchar(100) not null,
			code  		Varchar(10) not null,
			expiresat 	Timestamp not null,
			type        Varchar(10) not null,
		    numofresets Int not null,
			Primary Key (email),
			Constraint fk_user_email Foreign Key(email) References users(email)
				On Delete Cascade On Update Cascade
		)
`

const (
//defaultHTTPPort = "8081"
//defaultGRPCPort = "8082"
)

func main() {
	logger := utils.NewLogger()

	configs := utils.NewConfigurations(logger)
	// validator contains all the methods that are need to validate the user json in request
	validator := database.NewValidation()
	// create a new connection to the postgres db store
	db, err := database.NewConnection(configs, logger)
	defer db.Close()
	if err != nil {
		logger.Error("unable to connect to db", "error", err)
		return
	}
	// creation of user table.
	db.MustExec(userSchema)
	db.MustExec(verificationSchema)
	// repository contains all the methods that interact with DB to perform CURD operations for user.
	repository := database.NewPostgresRepository(db, logger)
	// mailService contains the utility methods to send an email
	mailService := authorization.NewSGMailService(logger, configs)
	// authService contains all methods that help in authorizing a user request
	auth := middleware.NewAuthService(logger, configs)

	var (
		httpAddr    = net.JoinHostPort("localhost", configs.HttpPort)
		service     = authorization.NewUserService(logger, configs, repository, mailService, validator, auth)
		eps         = endpoints.NewEndpointSet(service)
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
			httpListener.Close()
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
