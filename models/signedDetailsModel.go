package models

import "github.com/dgrijalva/jwt-go"

type SignedDetails struct {
	Email      string
	First_name string
	Last_name  string
	User_id    string
	User_type  string
	jwt.StandardClaims
}
