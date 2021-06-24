package auth

import (
	"github.com/stricklerxc/jwt-login-demo/mongodb"
	"golang.org/x/crypto/bcrypt"
)

func Authenticate(username, password string) bool {
	user, err := mongodb.GetUser(username)
	if err != nil {
		return false
	}

	if err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); username == user.Username && err == nil {
		return true
	}

	return false
}
