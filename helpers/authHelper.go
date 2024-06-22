package helpers

import (
	"errors"
	"net/http"

	"github.com/ramyasreetejo/jwt-authentication-golang/contextKeys"
)

func CheckUserType(r *http.Request) (err error) {
	userType := r.Context().Value(contextKeys.ContextKey("user_type")).(string)
	err = nil
	if userType != "ADMIN" {
		err = errors.New("error: unauthorized to access this resource")
		return err
	}
	return err
}

func CheckUserTypeAndMatchUserIdFromURLToToken(r *http.Request, user_id_from_url string) (err error) {
	userType := r.Context().Value(contextKeys.ContextKey("user_type")).(string)
	userId := r.Context().Value(contextKeys.ContextKey("user_id")).(string)
	err = nil
	if !(userType == "ADMIN" || user_id_from_url == userId) {
		err = errors.New("error: unauthorized to access this resource")
		return err
	}
	return err
}
