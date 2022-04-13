package database

import (
	"context"
	"github.com/jmoiron/sqlx"
	"reflect"
	"testing"
)

func TestNewPostgresRepository(t *testing.T) {
	type args struct {
		db *sqlx.DB
	}
	tests := []struct {
		name string
		args args
		want *PostgresRepository
	}{
		// TODO: Add test cases.

	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewPostgresRepository(tt.args.db); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewPostgresRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPostgresRepository_CreateUser(t *testing.T) {
	type fields struct {
		db *sqlx.DB
	}
	type args struct {
		ctx  context.Context
		user *User
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &PostgresRepository{
				db: tt.fields.db,
			}
			if err := repo.CreateUser(tt.args.ctx, tt.args.user); (err != nil) != tt.wantErr {
				t.Errorf("CreateUser() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
