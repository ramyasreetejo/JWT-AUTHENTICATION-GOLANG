package routes

import (
	"net/http"

	controller "github.com/ramyasreetejo/jwt-authentication-golang/controllers"
	"github.com/ramyasreetejo/jwt-authentication-golang/middleware"
)

func UserRoutes(incomingRoutes *http.ServeMux) {
	incomingRoutes.HandleFunc("/users", middleware.Authenticate(controller.GetUsers)) //get
	incomingRoutes.HandleFunc("/users/", middleware.Authenticate(controller.GetUser)) //get
}
