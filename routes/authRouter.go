package routes

import (
	"net/http"

	controller "github.com/ramyasreetejo/jwt-authentication-golang/controllers"
)

func AuthRoutes(incomingRoutes *http.ServeMux) {
	incomingRoutes.HandleFunc("/users/signup", controller.Signup)
	incomingRoutes.HandleFunc("/users/login", controller.Login)
}
