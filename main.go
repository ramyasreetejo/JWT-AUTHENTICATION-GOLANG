package main

import (
	"log"
	"net/http"
	"os"

	"github.com/joho/godotenv"
	"github.com/ramyasreetejo/jwt-authentication-golang/routes"
)

func main() {
	err := godotenv.Load(".env")
	if err != nil {
		log.Fatal("Failed to load env.")
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	router := http.NewServeMux()

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	// Start the HTTP server
	http.ListenAndServe(":"+port, router)
}
