package authorization

import (
	"LoveLetterProject/internal/database"
	"context"
	"reflect"
	"testing"
)

func TestNewUserService(t *testing.T) {
	type args struct {
		repo database.UserRepository
	}
	tests := []struct {
		name string
		args args
		want *userService
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewUserService(tt.args.repo); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewUserService() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_userService_SignUp(t *testing.T) {
	type fields struct {
		repo database.UserRepository
	}
	type args struct {
		ctx     context.Context
		request *RegisterRequest
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &userService{
				repo: tt.fields.repo,
			}
			got, err := s.SignUp(tt.args.ctx, tt.args.request)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignUp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignUp() got = %v, want %v", got, tt.want)
			}
		})
	}
}
