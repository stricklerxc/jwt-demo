package jwt

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var secret = []byte("AllYourBase")

func CreateToken(userid, password string) (string, error) {
	var err error

	claims := jwt.MapClaims{
		"authorized": true,
		"user_id":    userid,
		"exp":        time.Now().Add(time.Minute * 15).Unix(),
	}

	at := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := at.SignedString(secret)
	if err != nil {
		return "", err
	}

	return token, nil

}

func ValidateToken(req *http.Request) error {
	var token string
	p := jwt.Parser{
		SkipClaimsValidation: false,
	}

	if len(req.Header.Get("Authorization")) != 0 {
		token = strings.Split(req.Header.Get("Authorization"), "Bearer ")[1]
	} else if cookie, err := req.Cookie("jwt-login"); err == nil {
		token = cookie.Value
	} else {
		return fmt.Errorf("no token cookie or authorization header sent")
	}

	jwtToken, err := p.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return secret, nil
	})
	if err != nil {
		log.Print("0")
		return err
	}

	if jwtToken.Valid {
		return nil
	} else if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return fmt.Errorf("invalid token")
		} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
			return fmt.Errorf("expired token")
		} else {
			return fmt.Errorf("unable to handle token: %v", err)
		}
	} else {
		return fmt.Errorf("unable to handle token: %v", err)
	}
}
