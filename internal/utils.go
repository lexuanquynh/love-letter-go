package utils

import (
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"strings"
	"time"
)

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
const numberBytes = "0123456789"
const numberLetters = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func init() {
	rand.Seed(time.Now().UnixNano())
}

// GenerateRandomString generate a string of random characters of given length
func GenerateRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx := rand.Int63() % int64(len(letterBytes))
		sb.WriteByte(letterBytes[idx])
	}
	return sb.String()
}

// GenerateRandomNumberString generate a string of random numbers of given length
func GenerateRandomNumberString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx := rand.Int63() % int64(len(numberBytes))
		sb.WriteByte(numberBytes[idx])
	}
	return sb.String()
}

// GenerateRandomNumberAndString generates a random number and a random string of given length
func GenerateRandomNumberAndString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		idx := rand.Int63() % int64(len(numberLetters))
		sb.WriteByte(numberLetters[idx])
	}
	return sb.String()
}

// HashString hashes the password
func HashString(clearString string) (string, error) {
	hashedPass, err := bcrypt.GenerateFromPassword([]byte(clearString), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPass), nil
}
