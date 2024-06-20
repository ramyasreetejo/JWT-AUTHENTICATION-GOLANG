package helpers

import (
	"errors"
	"net/http"
)

func CheckUserType(r *http.Request, role string) (err error) {
	userType := r.Context().Value("user_type").(string)
	err = nil
	if userType != role {
		err = errors.New("error: unauthorized to access this resource")
		return err
	}
	return err
}

func MatchUserTypeToUid(r *http.Request, userId string) (err error) {
	userType := r.Context().Value("user_type").(string)
	uid := r.Context().Value("uid").(string)
	err = nil

	if userType == "USER" && uid != userId {
		err = errors.New("unauthorized to access this resource")
		return err
	}
	err = CheckUserType(r, userType)
	return err
}
